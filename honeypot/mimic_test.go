package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// mimicRecorder sammelt die Anfragen an den nachgebauten Hive. Der Server läuft in eigenen
// Goroutinen; ohne Sperre meldet der Race-Detector der CI einen Wettlauf.
type mimicRecorder struct {
	mu  sync.Mutex
	got []map[string]string
}

func (r *mimicRecorder) add(m map[string]string) {
	r.mu.Lock()
	r.got = append(r.got, m)
	r.mu.Unlock()
}

func (r *mimicRecorder) all() []map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]map[string]string(nil), r.got...)
}

func TestMimicShellAndWeb(t *testing.T) {
	mimicOffUntil.Store(0)
	rec := &mimicRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		json.NewDecoder(r.Body).Decode(&req)
		rec.add(req)
		if r.URL.Path != "/api/sensor/mimic" || r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		if req["kind"] == "web" {
			json.NewEncoder(w).Encode(map[string]any{"out": "<h1>Login</h1>", "status": 200, "content_type": "text/html"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"out": "child=inner\nparent=outer\n\x1b[31m"})
	}))
	defer srv.Close()
	m := testManager()
	m.em.hive = &HiveClient{URL: srv.URL, Token: "tok", Sensor: "test", HTTP: http.DefaultClient}
	s := &Session{m: m, SrcIP: "203.0.113.5", Service: "telnet"}

	// bekannter Befehl: keine Anfrage
	if out := s.mimicShell("cam", "id"); out != "uid=0(root) gid=0(root)\r\n" || len(rec.all()) != 0 {
		t.Fatalf("bekannt: %q %d", out, len(rec.all()))
	}
	out := s.mimicShell("cam", `v=outer; (v=inner; printf 'child=%s\n' "$v")`)
	if out != "child=inner\r\nparent=outer\r\n[31m" {
		t.Errorf("unbekannt: %q", out)
	}
	if got := rec.all(); len(got) != 1 || got[0]["kind"] != "shell" || got[0]["ip"] != "203.0.113.5" || got[0]["host"] == "" {
		t.Errorf("Anfrage: %+v", got)
	}
	req := httptest.NewRequest("GET", "/cgi-bin/luci", nil)
	if st, _, body, ok := s.mimicWeb(req); !ok || st != 200 || body != "<h1>Login</h1>" {
		t.Errorf("Web: %v %d %q", ok, st, body)
	}
	if _, _, _, ok := s.mimicWeb(httptest.NewRequest("GET", "/logo.png", nil)); ok {
		t.Error("statische Datei sollte 404 bleiben")
	}
	if got := rec.all(); !strings.Contains(got[len(got)-1]["input"], "GET /cgi-bin/luci") {
		t.Errorf("Web-Eingabe: %+v", got[len(got)-1])
	}
}

func TestMimicOffAndUnreachable(t *testing.T) {
	mimicOffUntil.Store(0)
	rec := &mimicRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(nil)
		w.Header().Set("X-Mimic", "off")
		w.WriteHeader(204)
	}))
	m := testManager()
	m.em.hive = &HiveClient{URL: srv.URL, Token: "tok", HTTP: http.DefaultClient}
	s := &Session{m: m, SrcIP: "203.0.113.5"}
	for i := 0; i < 3; i++ {
		if out := s.mimicShell("cam", "foo"); out != "sh: foo: not found\r\n" {
			t.Fatalf("statisch erwartet: %q", out)
		}
	}
	if n := len(rec.all()); n != 1 {
		t.Errorf("nach „aus“ weiter gefragt: %d", n)
	}
	srv.Close()
	mimicOffUntil.Store(0)
	if out := s.mimicShell("cam", "foo"); out != "sh: foo: not found\r\n" {
		t.Errorf("Hive nicht erreichbar: %q", out)
	}
}
