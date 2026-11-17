package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMimicEndpoint(t *testing.T) {
	h := testHive(t)
	calls := 0
	old := mimicAsk
	t.Cleanup(func() { mimicAsk = old })
	mimicAsk = func(_ context.Context, c AIConfig, msgs []map[string]string) (string, error) {
		calls++
		if c.Model != "eigenes-modell" || c.BaseURL != "https://openrouter.ai/api/v1" {
			t.Errorf("Konfiguration: %+v", c)
		}
		if strings.Contains(msgs[0]["content"], "web server") {
			return "```json\n{\"status\":200,\"content_type\":\"text/html\",\"body\":\"<h1>Router Login</h1>\"}\n```", nil
		}
		return "```\nprintf: usage\n```", nil
	}
	set := func(m MimicConfig) {
		x := h.Extras()
		x.AI = AIConfig{BaseURL: "https://openrouter.ai/api/v1", Model: "allgemein", APIKey: "k"}
		x.Mimic = m
		if err := x.Validate(); err != nil {
			t.Fatal(err)
		}
		h.extras.x = x
	}
	ask := func(body string) (int, mimicResp, string) {
		w := httptest.NewRecorder()
		h.mimic(w, httptest.NewRequest("POST", "/api/sensor/mimic", strings.NewReader(body)))
		var r mimicResp
		json.Unmarshal(w.Body.Bytes(), &r)
		return w.Code, r, w.Header().Get("X-Mimic")
	}
	shell := `{"kind":"shell","input":"printf","ip":"203.0.113.9","host":"cam1","shell":"BusyBox"}`

	set(defaultMimic())
	if code, _, off := ask(shell); code != 204 || off != "off" {
		t.Fatalf("ausgeschaltet: %d %q", code, off)
	}
	m := defaultMimic()
	m.Enabled, m.Model, m.MaxPerIPHour = true, "eigenes-modell", 2
	set(m)
	code, r, _ := ask(shell)
	if code != 200 || r.Out != "printf: usage\n" || r.Cached {
		t.Fatalf("Shell: %d %+v", code, r)
	}
	if _, r, _ = ask(shell); !r.Cached || calls != 1 {
		t.Errorf("Zwischenspeicher: %+v, %d Aufrufe", r, calls)
	}
	code, r, _ = ask(`{"kind":"web","input":"GET /cgi-bin/login.cgi HTTP/1.1","ip":"203.0.113.9","host":"cam1"}`)
	if code != 200 || r.Status != 200 || r.Out != "<h1>Router Login</h1>" {
		t.Fatalf("Web: %d %+v", code, r)
	}
	// Grenze je IP: 2 Anfragen ans Modell sind verbraucht; Zwischenspeicher geht weiter
	if code, _, _ := ask(`{"kind":"shell","input":"neu","ip":"203.0.113.9"}`); code != 204 {
		t.Errorf("Grenze je IP: %d", code)
	}
	if _, r, _ := ask(shell); !r.Cached {
		t.Error("Zwischenspeicher trotz Grenze erwartet")
	}
	if calls != 2 {
		t.Errorf("Aufrufe: %d", calls)
	}
	// nur Web eingeschaltet: Shell wird abgelehnt
	m.Shell = false
	set(m)
	if code, _, _ := ask(`{"kind":"shell","input":"x","ip":"203.0.113.10"}`); code != 204 {
		t.Errorf("Shell aus: %d", code)
	}
}

func TestMimicValidate(t *testing.T) {
	m := defaultMimic()
	m.Enabled = true
	if m.validate(AIConfig{}) == nil {
		t.Error("ohne Adresse und Modell angenommen")
	}
	if m.validate(AIConfig{BaseURL: "http://ollama:11434/v1", Model: "llama3.1:8b"}) != nil {
		t.Error("Angaben der KI-Auswertung müssen genügen")
	}
	if got := cleanShellOut("```bash\nls\n```"); got != "ls\n" {
		t.Errorf("Code-Zaun: %q", got)
	}
	if _, ok := parseWebOut("kein json"); ok {
		t.Error("ungültige Web-Antwort angenommen")
	}
}
