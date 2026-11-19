package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHostnameRules(t *testing.T) {
	for _, ok := range []string{"", "web01", "nas-backup01", "srv-web01.example.de", "A1", "x"} {
		if p := hostnameProblem(ok); p != "" {
			t.Errorf("%q: %s", ok, p)
		}
	}
	for _, bad := range []string{"HOME_dennis_srv-web01", "-web", "web-", "a..b", "mein server", "büro", "a/b", strings.Repeat("a", 64) + ".x", strings.Repeat("a", 65)} {
		if hostnameProblem(bad) == "" {
			t.Errorf("%q gilt als gültig", bad)
		}
	}
	cases := map[string]string{
		"HOME_dennis_srv-web01": "home-dennis-srv-web01",
		"  Büro PC ":            "buero-pc",
		"-web__01-":             "web-01",
		"a..b":                  "a.b",
		"___":                   "",
	}
	for in, want := range cases {
		if got := suggestHostname(in); got != want {
			t.Errorf("Vorschlag %q: %q, erwartet %q", in, got, want)
		}
		if got := suggestHostname(in); got != "" && hostnameProblem(got) != "" {
			t.Errorf("Vorschlag %q ist selbst ungültig", got)
		}
	}
	err := hostnameError("HOME_dennis_srv-web01")
	if err == nil || !strings.Contains(err.Error(), "Unterstriche") || !strings.Contains(err.Error(), "Vorschlag: home-dennis-srv-web01") {
		t.Errorf("Meldung: %v", err)
	}
}

// Die API lehnt einen neuen ungültigen Namen ab; ein schon gespeicherter alter Name
// blockiert das Speichern der Ports nicht.
func TestHostnameAPI(t *testing.T) {
	h := testHive(t)
	h.auth = NewAuth(h.st, "tok", false)
	h.auth.EnsureAdmin("admin", "adminpasswort1")
	ui, _ := h.routes(false, "", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	if err := h.auth.startSession(rec, httptest.NewRequest("GET", "/", nil), "admin"); err != nil {
		t.Fatal(err)
	}
	c := rec.Result().Cookies()[0]
	put := func(host string) (int, string) {
		cfg := DefaultSensorConfigForTest()
		cfg.Hostname = host
		b, _ := json.Marshal(map[string]any{"sensor_config": cfg})
		req := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(string(b)))
		req.Header.Set("X-Requested-With", "hivornet")
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		ui.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, body := put("HOME_dennis_srv-web01"); code != 400 || !strings.Contains(body, "Vorschlag") {
		t.Fatalf("ungültiger Name: %d %s", code, body)
	}
	if code, body := put("web01"); code != 200 {
		t.Fatalf("gültiger Name: %d %s", code, body)
	}
	// alter, ungültiger Name (vor 0.7.6 gespeichert): Speichern ohne Namensänderung geht
	cfg := DefaultSensorConfigForTest()
	cfg.Hostname = "alt_name"
	b, _ := json.Marshal(cfg)
	h.st.SetKV(configKey(""), string(b))
	if code, body := put("alt_name"); code != 200 {
		t.Fatalf("unveränderter alter Name: %d %s", code, body)
	}
}

// DefaultSensorConfigForTest: gültige Konfiguration mit einem Port.
func DefaultSensorConfigForTest() SensorConfig {
	var c SensorConfig
	c.Profile = "linux-server"
	c.Listeners = []ListenerConfig{{Service: "redis", Port: 6379, Mode: "emulate", Enabled: true}}
	c.Tarpit.IntervalMs, c.Tarpit.MaxConns, c.Tarpit.MaxPerIP = 10000, 100, 5
	return c
}
