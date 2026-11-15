package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// Event ist das gemeinsame Ereignisformat (siehe docs/events.md).
type Event struct {
	EID        string         `json:"eid"` // zufällige ID, damit der Hive Wiederholungen erkennt
	TS         time.Time      `json:"ts"`
	Sensor     string         `json:"sensor"`
	Service    string         `json:"service"`
	Type       string         `json:"type"`
	SrcIP      string         `json:"src_ip"`
	SrcPort    int            `json:"src_port"`
	DstPort    int            `json:"dst_port"`
	Session    string         `json:"session,omitempty"`
	Username   string         `json:"username,omitempty"`
	Password   string         `json:"password,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
	DurationMs int64          `json:"duration_ms,omitempty"`
	Tarpit     bool           `json:"tarpit,omitempty"`
	TarpitMs   int64          `json:"tarpit_ms,omitempty"`
}

// Größenbudget (muss zum Hive passen, siehe Vertragstest):
const (
	maxEventBytes = 12 << 10 // ein Ereignis als JSON; der Hive akzeptiert 16 KB "data"
	maxBatchBytes = 1 << 20  // ein Block an den Hive (Hive-Limit: 16 MB)
	maxBatchCount = 200
	maxQueueBytes = 8 << 20 // alles, was auf den Versand wartet
)

type HiveClient struct {
	URL    string
	Token  string
	Sensor string
	HTTP   *http.Client
}

// httpStatusError trägt den Status, damit der Emitter 4xx (verwerfen) von 5xx (wiederholen) trennt.
type httpStatusError struct{ code int }

func (e httpStatusError) Error() string {
	return fmt.Sprintf("hive antwortet %d %s", e.code, http.StatusText(e.code))
}

func (h *HiveClient) do(method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, h.URL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	req.Header.Set("X-Sensor", h.Sensor)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return h.HTTP.Do(req)
}

func (h *HiveClient) doJSON(method, path string, v any) (*http.Response, error) {
	var rd io.Reader
	if v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	return h.do(method, path, rd)
}

func finish(resp *http.Response) error {
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return httpStatusError{resp.StatusCode}
	}
	return nil
}

// SendRaw schickt bereits kodierte Ereignisse als einen Block.
func (h *HiveClient) SendRaw(events [][]byte) error {
	var buf bytes.Buffer
	buf.WriteString(`{"sensor":`)
	s, _ := json.Marshal(h.Sensor)
	buf.Write(s)
	buf.WriteString(`,"events":[`)
	for i, e := range events {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(e)
	}
	buf.WriteString("]}")
	resp, err := h.do("POST", "/api/ingest", &buf)
	if err != nil {
		return err
	}
	return finish(resp)
}

// FetchConfig liefert nil, nil wenn der Hive noch keine Konfiguration hat.
func (h *HiveClient) FetchConfig() (*Config, error) {
	resp, err := h.do("GET", "/api/sensor/config", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, httpStatusError{resp.StatusCode}
	}
	var c Config
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (h *HiveClient) Heartbeat(hb any) error {
	resp, err := h.doJSON("POST", "/api/sensor/heartbeat", hb)
	if err != nil {
		return err
	}
	return finish(resp)
}

// Emitter sammelt Ereignisse und schickt sie gebündelt an den Hive. Warteschlange
// und Blöcke sind nach Anzahl UND Bytes begrenzt, damit Angreifer den Speicher nicht füllen.
type Emitter struct {
	ch        chan []byte
	queued    atomic.Int64 // Bytes in ch
	hive      *HiveClient
	sensor    string
	stdout    bool
	dropped   atomic.Int64 // verworfen, weil Warteschlange voll oder Hive ablehnt
	sent      atomic.Int64
	throttled atomic.Int64 // durch die Drossel pro IP unterdrückt
	lastErr   atomic.Value // string
}

func NewEmitter(h *HiveClient, sensor string) *Emitter {
	e := &Emitter{ch: make(chan []byte, 20000), hive: h, sensor: sensor, stdout: os.Getenv("HONEYPOT_LOG_EVENTS") == "1"}
	e.lastErr.Store("")
	return e
}

func (e *Emitter) Emit(ev Event) {
	ev.Sensor = e.sensor
	if ev.EID == "" {
		ev.EID = randHex(8)
	}
	if ev.TS.IsZero() {
		ev.TS = time.Now().UTC()
	}
	b, err := marshalEvent(ev)
	if err != nil {
		e.dropped.Add(1)
		return
	}
	if len(b) > maxEventBytes { // sollte durch die Budgets nie passieren; dann Inhalt kürzen
		ev.Data = map[string]any{"truncated": true}
		if b, err = marshalEvent(ev); err != nil || len(b) > maxEventBytes {
			e.dropped.Add(1)
			return
		}
	}
	if e.queued.Load()+int64(len(b)) > maxQueueBytes {
		e.dropped.Add(1)
		return
	}
	select {
	case e.ch <- b:
		e.queued.Add(int64(len(b)))
	default:
		e.dropped.Add(1)
	}
}

func (e *Emitter) Run(stop <-chan struct{}) {
	var buf [][]byte
	var bufBytes int
	failing := false
	backoff := time.Second
	nextTry := time.Time{}
	t := time.NewTicker(time.Second)
	defer t.Stop()

	push := func(b []byte) {
		e.queued.Add(-int64(len(b)))
		buf = append(buf, b)
		bufBytes += len(b)
		for bufBytes > maxQueueBytes && len(buf) > 0 { // älteste verwerfen
			bufBytes -= len(buf[0])
			buf = buf[1:]
			e.dropped.Add(1)
		}
		if e.stdout {
			os.Stdout.Write(append(b, '\n'))
		}
	}
	flush := func(force bool) {
		for len(buf) > 0 {
			if !force && time.Now().Before(nextTry) {
				return
			}
			n, size := 0, 0
			for n < len(buf) && n < maxBatchCount && size+len(buf[n]) <= maxBatchBytes {
				size += len(buf[n])
				n++
			}
			if n == 0 {
				n, size = 1, len(buf[0])
			}
			err := e.hive.SendRaw(buf[:n])
			var se httpStatusError
			if err != nil && !(errors.As(err, &se) && se.code >= 400 && se.code < 500 && se.code != 429) {
				// Netzwerkfehler, 5xx oder 429: später erneut, mit wachsender Pause
				e.lastErr.Store(err.Error())
				if !failing {
					log.Printf("Ereignisse konnten nicht gesendet werden (%v), versuche es weiter", err)
					failing = true
				}
				nextTry = time.Now().Add(backoff)
				backoff = min(backoff*2, 30*time.Second)
				return
			}
			if err != nil { // 4xx: Block ist ungültig, Wiederholen hilft nicht
				e.lastErr.Store(err.Error())
				log.Printf("Hive lehnt %d Ereignisse ab (%v), verworfen", n, err)
				e.dropped.Add(int64(n))
			} else {
				e.sent.Add(int64(n))
				e.lastErr.Store("")
				if failing {
					log.Printf("Verbindung zum Hive wieder da")
					failing = false
				}
			}
			backoff = time.Second
			buf = buf[n:]
			bufBytes -= size
		}
		buf = nil // Speicher des alten Slices freigeben
		bufBytes = 0
	}
	for {
		select {
		case b := <-e.ch:
			push(b)
			if len(buf) >= maxBatchCount || bufBytes >= maxBatchBytes {
				flush(false)
			}
		case <-t.C:
			flush(false)
		case <-stop:
			for drained := false; !drained; {
				select {
				case b := <-e.ch:
					push(b)
				default:
					drained = true
				}
			}
			flush(true)
			return
		}
	}
}

// marshalEvent kodiert ein Ereignis als JSON ohne HTML-Maskierung. Go schreibt sonst
// &, < und > als & usw. (sechs Zeichen statt einem); Angreiferdaten voller "&"
// würden so das Größenbudget sprengen. Der Hive fügt Text nie als HTML ein.
func marshalEvent(ev Event) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(ev); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
