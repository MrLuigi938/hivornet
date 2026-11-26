package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Broker verteilt neue Ereignisse live an offene Browser (Server-Sent Events).
//
// Grenzen (N7 des dritten Audits): höchstens sseMaxPerClient offene Verbindungen je Sitzung
// (bzw. IP) und sseMaxTotal insgesamt; jede Verbindung hält einen Puffer und eine Goroutine.
// Ein Browser, der nichts mehr abnimmt, fliegt nach sseWriteTimeout.
type Broker struct {
	mu     sync.Mutex
	subs   map[chan []byte]struct{}
	perKey map[string]int
}

const (
	sseMaxPerClient = 8
	sseMaxTotal     = 64
)

var sseWriteTimeout = 30 * time.Second

func NewBroker() *Broker { return &Broker{subs: map[chan []byte]struct{}{}, perKey: map[string]int{}} }

// sseKey: Sitzung (Hash des Cookies), ohne Cookie die IP.
func sseKey(r *http.Request) string {
	if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
		return "s:" + tokenHash(c.Value)
	}
	return "ip:" + clientIP(r)
}

func (b *Broker) Publish(e *Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.subs) == 0 {
		return
	}
	// eigene Tests (ownnet.go) kennzeichnen, damit die Ansicht "Einzelne Ereignisse" sie wie die Angriffe ausblenden kann
	msg, err := json.Marshal(struct {
		*Event
		Own bool `json:"own,omitempty"`
	}{e, ownHidden(e.SrcIP)})
	if err != nil {
		return
	}
	for ch := range b.subs {
		select {
		case ch <- msg:
		default: // langsamer Browser: Ereignis auslassen
		}
	}
}

func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		httpErr(w, 500, "Streaming nicht unterstützt")
		return
	}
	key := sseKey(r)
	ch := make(chan []byte, 256)
	b.mu.Lock()
	if len(b.subs) >= sseMaxTotal || b.perKey[key] >= sseMaxPerClient {
		b.mu.Unlock()
		w.Header().Set("Retry-After", "30")
		httpErr(w, 429, "zu viele offene Live-Verbindungen")
		return
	}
	b.subs[ch] = struct{}{}
	b.perKey[key]++
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.subs, ch)
		if b.perKey[key]--; b.perKey[key] <= 0 {
			delete(b.perKey, key)
		}
		b.mu.Unlock()
	}()
	rc := http.NewResponseController(w)
	deadline := func() { rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout)) }
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	deadline()
	w.Write([]byte(": ok\n\n"))
	fl.Flush()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-ch:
			deadline()
			w.Write([]byte("data: "))
			w.Write(msg)
			w.Write([]byte("\n\n"))
			// weitere wartende Ereignisse gleich mitschicken
			for n := 0; n < 50; n++ {
				select {
				case m := <-ch:
					w.Write([]byte("data: "))
					w.Write(m)
					w.Write([]byte("\n\n"))
					continue
				default:
				}
				break
			}
			fl.Flush()
		case <-ping.C:
			deadline()
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			fl.Flush()
		}
	}
}
