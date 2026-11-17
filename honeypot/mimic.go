package main

// Antworten vom Sprachmodell für Unbekanntes (Gegenstück zu hive/mimic.go): Kennt die
// Telnet-Shell einen Befehl nicht oder der Web-Honeypot einen Pfad nicht, fragt der
// Honeypot den Hive. Der Honeypot selbst darf nicht ins Internet; der Hive ruft das Modell
// auf und speichert die Antwort. Antwortet der Hive nicht rechtzeitig, ist die Funktion
// aus oder ist eine Grenze erreicht, bleibt es bei der statischen Antwort.

import (
	"context"
	"encoding/json"
	"net/http"
	"path"
	"strings"
	"sync/atomic"
	"time"
)

const mimicWait = 13 * time.Second

// mimicOffUntil: Nach "aus" fragt der Honeypot eine Minute lang nicht nach.
var mimicOffUntil atomic.Int64

type mimicAnswer struct {
	Out         string `json:"out"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
}

func (s *Session) askMimic(kind, input string) (mimicAnswer, bool) {
	hc := s.m.em.hive
	if hc == nil || time.Now().UnixMilli() < mimicOffUntil.Load() {
		return mimicAnswer{}, false
	}
	p := s.m.prof()
	body, _ := json.Marshal(map[string]string{
		"kind": kind, "input": clip(input, 2048), "ip": s.SrcIP, "service": s.Service, "host": s.m.Hostname(),
		"shell": p.TelnetShell, "kernel": p.Kernel, "os": p.OSName, "http_server": p.HTTPServer,
	})
	ctx, cancel := context.WithTimeout(context.Background(), mimicWait)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", hc.URL+"/api/sensor/mimic", strings.NewReader(string(body)))
	if err != nil {
		return mimicAnswer{}, false
	}
	req.Header.Set("Authorization", "Bearer "+hc.Token)
	req.Header.Set("X-Sensor", hc.Sensor)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return mimicAnswer{}, false
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Mimic") == "off" {
		mimicOffUntil.Store(time.Now().Add(time.Minute).UnixMilli())
	}
	if resp.StatusCode != 200 {
		return mimicAnswer{}, false
	}
	var a mimicAnswer
	if json.NewDecoder(&limitedBody{r: resp.Body, n: 64 << 10}).Decode(&a) != nil {
		return mimicAnswer{}, false
	}
	return a, true
}

type limitedBody struct {
	r interface{ Read([]byte) (int, error) }
	n int
}

func (l *limitedBody) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, context.Canceled
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= n
	return n, err
}

// telnetUnknown: Die statische Antwort enthält "not found", die Shell kannte also etwas nicht.
func telnetUnknown(out string) bool {
	return strings.Contains(out, ": not found\r\n") || strings.Contains(out, "applet not found\r\n")
}

// mimicShell liefert die Antwort für eine Befehlszeile: statisch, und wenn dort etwas
// unbekannt war, vom Sprachmodell (Zeilenenden für Telnet als \r\n).
func (s *Session) mimicShell(host, line string) string {
	out := telnetReply(host, line)
	if !telnetUnknown(out) {
		return out
	}
	a, ok := s.askMimic("shell", line)
	if !ok {
		return out
	}
	t := strings.ReplaceAll(strings.ReplaceAll(a.Out, "\r\n", "\n"), "\n", "\r\n")
	return printableKeepNL(t)
}

// printableKeepNL ersetzt Steuerzeichen außer Zeilenenden und Tabulator.
func printableKeepNL(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' || r >= 0x20 && r != 0x7f {
			return r
		}
		return -1
	}, s)
}

// staticExt: Für Bilder, Skripte und Stile bleibt es beim 404 (Scanner fragen sie massenhaft).
var staticExt = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true, ".svg": true, ".css": true,
	".js": true, ".woff": true, ".woff2": true, ".ttf": true, ".map": true, ".webp": true}

// mimicWeb fragt für einen unbekannten Pfad das Sprachmodell; false = 404 wie bisher.
func (s *Session) mimicWeb(req *http.Request) (int, string, string, bool) {
	if req.Method != "GET" && req.Method != "POST" || staticExt[strings.ToLower(path.Ext(req.URL.Path))] || req.URL.Path == "/" {
		return 0, "", "", false
	}
	in := req.Method + " " + req.URL.RequestURI() + " HTTP/1.1\nHost: " + req.Host + "\nUser-Agent: " + req.UserAgent()
	a, ok := s.askMimic("web", in)
	if !ok || a.Out == "" {
		return 0, "", "", false
	}
	if a.Status == 0 {
		a.Status = 200
	}
	// Landet roh in einer Kopfzeile: nur einfache Zeichen, sonst Standard
	if a.ContentType == "" || len(a.ContentType) > 80 || strings.IndexFunc(a.ContentType, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("/+.;= -", r))
	}) >= 0 {
		a.ContentType = "text/html; charset=utf-8"
	}
	if a.Status < 200 || a.Status > 599 {
		a.Status = 200
	}
	return a.Status, a.ContentType, a.Out, true
}
