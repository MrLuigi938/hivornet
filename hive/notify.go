package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Notifier schickt Meldungen über wichtige Ereignisse an ntfy, Telegram und/oder
// einen Webhook. Er hängt hinter dem Writer (nur gespeicherte Ereignisse lösen aus)
// und ist nach oben begrenzt, damit ein Angreifer weder das Handy noch den
// Speicher fluten kann:
//   - je Art und IP höchstens eine Meldung in 10 Minuten,
//   - insgesamt höchstens MaxPerHour pro Stunde (der Rest wird gezählt),
//   - Warteschlange mit 64 Plätzen, ein einzelner Sender.
type Notifier struct {
	cfg  func() NotifyConfig
	http *http.Client
	ch   chan notice

	mu         sync.Mutex
	recent     map[string]time.Time // "art|ip" -> letzte Meldung
	cmdSeen    map[string]time.Time // Sitzungen, deren erster Befehl schon gemeldet ist
	hourStart  time.Time
	hourCount  int
	sent       int64
	suppressed int64
	lastErr    string
	lastSent   time.Time

	// Adresse der Telegram-API; in Tests überschrieben.
	telegramBase string
}

type notice struct {
	Kind  string    `json:"kind"`
	Title string    `json:"title"`
	Text  string    `json:"text"`
	IP    string    `json:"ip,omitempty"`
	Time  time.Time `json:"time"`
}

type NotifyStatus struct {
	Sent       int64     `json:"sent"`
	Suppressed int64     `json:"suppressed"`
	LastError  string    `json:"last_error"`
	LastSent   time.Time `json:"last_sent"`
}

const notifyCooldown = 10 * time.Minute

func NewNotifier(cfg func() NotifyConfig) *Notifier {
	return &Notifier{cfg: cfg, http: &http.Client{Timeout: 10 * time.Second}, ch: make(chan notice, 64),
		recent: map[string]time.Time{}, cmdSeen: map[string]time.Time{}, telegramBase: "https://api.telegram.org"}
}

func (n *Notifier) Status() NotifyStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	return NotifyStatus{n.sent, n.suppressed, n.lastErr, n.lastSent}
}

// allow prüft Abklingzeit und Stundenlimit und zählt die Meldung.
func (n *Notifier) allow(key string, maxPerHour int) bool {
	now := time.Now()
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.recent) > 5000 || len(n.cmdSeen) > 5000 { // Speicher begrenzen
		for k, t := range n.recent {
			if now.Sub(t) > notifyCooldown {
				delete(n.recent, k)
			}
		}
		for k, t := range n.cmdSeen {
			if now.Sub(t) > time.Hour {
				delete(n.cmdSeen, k)
			}
		}
	}
	if t, ok := n.recent[key]; ok && now.Sub(t) < notifyCooldown {
		n.suppressed++
		return false
	}
	if now.Sub(n.hourStart) > time.Hour {
		n.hourStart, n.hourCount = now, 0
	}
	if n.hourCount >= maxPerHour {
		n.suppressed++
		return false
	}
	n.hourCount++
	n.recent[key] = now
	return true
}

// push stellt eine Meldung ein; key bestimmt die Abklingzeit (gleiche Art und Quelle).
func (n *Notifier) push(nt notice, key string, maxPerHour int) {
	if !n.allow(nt.Kind+"|"+key, maxPerHour) {
		return
	}
	select {
	case n.ch <- nt:
	default:
		n.mu.Lock()
		n.suppressed++
		n.mu.Unlock()
	}
}

func origin(e *Event) string {
	s := e.SrcIP
	if e.Country != "" {
		s += " (" + strings.Join(nonEmpty(e.City, e.CountryName), ", ") + ")"
	}
	return s
}

// OnEvent wird vom Writer für jedes gespeicherte Ereignis aufgerufen. Darf nicht blockieren.
func (n *Notifier) OnEvent(e *Event) {
	c := n.cfg()
	if !c.Enabled {
		return
	}
	nt := notice{IP: e.SrcIP, Time: e.TS}
	switch e.Type {
	case "login":
		if !c.OnLogin || !strings.Contains(string(e.Data), `"success":true`) {
			return
		}
		nt.Kind, nt.Title = "login", "Erfolgreicher Login am Honeypot"
		nt.Text = fmt.Sprintf("%s auf Port %d von %s\nZugangsdaten: %s / %s", e.Service, e.DstPort, origin(e), e.Username, e.Password)
	case "download":
		if !c.OnDownload || strings.Contains(string(e.Data), `"failed":true`) {
			return
		}
		nt.Kind, nt.Title = "download", "Angreifer hat eine Datei geladen"
		nt.Text = fmt.Sprintf("%s von %s\n%s\nSHA-256: %s", e.Service, origin(e),
			clip(dataString(e.Data, "url")+dataString(e.Data, "filename"), 300), dataString(e.Data, "sha256"))
	case "command", "request":
		text, on := eventText(e)
		severe := ""
		for _, id := range matchPatterns(text, on) {
			if patternByID[id].Sev >= 3 {
				severe = patternByID[id].Name
				break
			}
		}
		switch {
		case severe != "" && c.OnSevere:
			nt.Kind, nt.Title = "severe", "Angriffsmuster erkannt: "+severe
			nt.Text = fmt.Sprintf("%s auf Port %d von %s\n%s", e.Service, e.DstPort, origin(e), clip(strings.TrimSpace(text), 300))
		case e.Type == "command" && c.OnCommand && e.Session != "":
			n.mu.Lock()
			_, seen := n.cmdSeen[e.Session]
			n.cmdSeen[e.Session] = time.Now()
			n.mu.Unlock()
			if seen {
				return
			}
			nt.Kind, nt.Title = "command", "Befehle in einer Honeypot-Sitzung"
			nt.Text = fmt.Sprintf("%s von %s\nErster Befehl: %s", e.Service, origin(e), clip(text, 300))
		default:
			return
		}
	default:
		return
	}
	n.push(nt, nt.IP, c.MaxPerHour)
}

// Warn meldet eine kritische Systemwarnung (Sensor still, Netzsperre fehlt ...).
func (n *Notifier) Warn(text string) {
	c := n.cfg()
	if !c.Enabled || !c.OnWarning {
		return
	}
	n.push(notice{Kind: "warning", Title: "Hivornet: Warnung", Text: text, Time: time.Now()}, clip(text, 60), c.MaxPerHour)
}

// Run verschickt Meldungen, bis stop geschlossen wird.
func (n *Notifier) Run(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case nt := <-n.ch:
			err := n.Send(n.cfg(), nt)
			n.mu.Lock()
			if err != nil {
				n.lastErr = time.Now().Format("02.01. 15:04") + ": " + err.Error()
				log.Printf("Benachrichtigung: %v", err)
			} else {
				n.sent++
				n.lastSent = time.Now()
				n.lastErr = ""
			}
			n.mu.Unlock()
		}
	}
}

// Send schickt eine Meldung an alle eingerichteten Ziele und liefert den ersten Fehler.
// Ist kein Ziel eingerichtet, ist das ein Fehler (für den Test-Knopf in der UI).
func (n *Notifier) Send(c NotifyConfig, nt notice) error {
	var errs []string
	targets := 0
	try := func(name string, req *http.Request, err error) {
		targets++
		if err == nil {
			var resp *http.Response
			if resp, err = n.http.Do(req); err == nil {
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
				resp.Body.Close()
				if resp.StatusCode >= 300 {
					// Ein Auszug der Antwort zeigt, was der Empfänger bemängelt (z. B. fehlendes Feld).
					err = fmt.Errorf("Antwort %s", resp.Status)
					if detail := clip(strings.Join(strings.Fields(string(b)), " "), 200); detail != "" {
						err = fmt.Errorf("Antwort %s: %s", resp.Status, detail)
					}
				}
			}
		}
		if err != nil {
			// Adressen können Token enthalten (Telegram): nie im Fehlertext ausgeben.
			msg := err.Error()
			if c.TelegramToken != "" {
				msg = strings.ReplaceAll(msg, c.TelegramToken, "…")
			}
			errs = append(errs, name+": "+msg)
		}
	}
	if c.NtfyURL != "" {
		req, err := http.NewRequest("POST", c.NtfyURL, strings.NewReader(nt.Text))
		if err == nil {
			// Kopfzeilen dürfen nur ASCII enthalten; ntfy versteht RFC 2047 für den Titel.
			req.Header.Set("Title", asciiHeader(nt.Title))
			req.Header.Set("Tags", "honeybee")
			if nt.Kind == "login" || nt.Kind == "severe" || nt.Kind == "warning" {
				req.Header.Set("Priority", "high")
			}
			if c.NtfyToken != "" {
				req.Header.Set("Authorization", "Bearer "+c.NtfyToken)
			}
		}
		try("ntfy", req, err)
	}
	if c.TelegramToken != "" && c.TelegramChat != "" {
		body, _ := json.Marshal(map[string]any{"chat_id": c.TelegramChat, "text": nt.Title + "\n\n" + nt.Text, "disable_web_page_preview": true})
		req, err := http.NewRequest("POST", n.telegramBase+"/bot"+c.TelegramToken+"/sendMessage", bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
		try("Telegram", req, err)
	}
	if c.WebhookURL != "" {
		body, _ := json.Marshal(webhookBody(nt))
		req, err := http.NewRequest("POST", c.WebhookURL, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
		try("Webhook", req, err)
	}
	if targets == 0 {
		return fmt.Errorf("kein Ziel eingerichtet (ntfy, Telegram oder Webhook)")
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// webhookBody: die Felder der Meldung (title, text, kind, ip, time) und zusätzlich
// "content" mit Titel und Text, damit Discord-Webhooks die Meldung annehmen (Discord
// verlangt dieses Feld, höchstens 2000 Zeichen; Slack und Mattermost lesen "text").
func webhookBody(nt notice) map[string]any {
	m := map[string]any{"kind": nt.Kind, "title": nt.Title, "text": nt.Text, "time": nt.Time,
		"content": clip(nt.Title+"\n"+nt.Text, 1900)}
	if nt.IP != "" {
		m["ip"] = nt.IP
	}
	return m
}

// asciiHeader ersetzt Umlaute und entfernt alles außerhalb von ASCII (HTTP-Kopfzeile).
func asciiHeader(s string) string {
	s = strings.NewReplacer("ä", "ae", "ö", "oe", "ü", "ue", "Ä", "Ae", "Ö", "Oe", "Ü", "Ue", "ß", "ss").Replace(s)
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// watchWarnings meldet neu aufgetretene kritische Warnungen (jede höchstens alle 6 Stunden).
func (h *Hive) watchWarnings(stop <-chan struct{}) {
	seen := map[string]time.Time{}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		for _, w := range h.warnings() {
			if w.Level != "critical" {
				continue
			}
			// Zahlen ändern sich laufend ("seit 3 Min"): Schlüssel ohne Ziffern bilden.
			key := strings.Map(func(r rune) rune {
				if r >= '0' && r <= '9' {
					return -1
				}
				return r
			}, w.Text)
			if time.Since(seen[key]) > 6*time.Hour {
				seen[key] = time.Now()
				h.notifier.Warn(w.Text)
			}
		}
	}
}

// testNotify: Knopf "Testnachricht senden" in den Einstellungen.
func (h *Hive) testNotify(w http.ResponseWriter, r *http.Request) {
	err := h.notifier.Send(h.Extras().Notify, notice{Kind: "test", Title: "Hivornet: Testnachricht",
		Text: "Die Benachrichtigungen sind eingerichtet.", Time: time.Now()})
	if err != nil {
		httpErr(w, 502, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
