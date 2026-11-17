package main

// Tests zur Absicherung: Blockliste, Fehlertexte, Einstufung, reservierte Ports, Leserolle.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Fehlertexte enthalten weder ntfy-Thema noch Webhook-Token.
func TestNotifyErrorRedacted(t *testing.T) {
	n := NewNotifier(func() NotifyConfig { return NotifyConfig{} })
	n.http = &http.Client{Timeout: time.Second}
	c := NotifyConfig{NtfyURL: "http://127.0.0.1:1/geheimes-thema-4711", WebhookURL: "http://127.0.0.1:1/hooks/TOKEN-0815"}
	err := n.Send(c, notice{Title: "t", Text: "x"})
	if err == nil {
		t.Fatal("Fehler erwartet")
	}
	for _, secret := range []string{"geheimes-thema-4711", "TOKEN-0815", "hooks"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("Geheimnis %q im Fehlertext: %v", secret, err)
		}
	}
}

// geschützte Adressen, Vertrauen je Sensor, Obergrenze für neue Einträge.
func TestFeedProtection(t *testing.T) {
	h := testHive(t)
	h.auth = NewAuth(h.st, "gemeinsam", false)
	h.st.SetKV(feedKV, `{"never_block":["203.0.113.0/28"]}`)
	for ip, want := range map[string]bool{"1.1.1.1": true, "8.8.8.8": true, "203.0.113.5": true, "203.0.113.20": false, "2001:4860:4860::8888": true} {
		if got := h.neverBlock(ip); got != want {
			t.Errorf("neverBlock(%s) = %v", ip, got)
		}
	}
	h.auth.tokens.m = map[string]*sensorToken{"vps-1": {Hash: "x"}, "vps-2": {Hash: "y", Trusted: true}}
	h.auth.tokens.loaded = true
	un := h.untrustedSensors()
	if !un["vps-1"] || un["vps-2"] {
		t.Fatalf("untrusted: %v", un)
	}
	for _, c := range []struct {
		sensors []string
		want    bool
	}{{nil, true}, {[]string{"pi"}, true}, {[]string{"vps-1"}, false}, {[]string{"vps-1", "pi"}, true}, {[]string{"vps-2"}, true}} {
		if got := trustedAttack(&Attack{Sensors: c.sensors}, un); got != c.want {
			t.Errorf("trustedAttack(%v) = %v", c.sensors, got)
		}
	}
	pub := map[string]int64{}
	now := time.Now()
	var ips []string
	for i := 0; i < 10; i++ {
		ips = append(ips, fmt.Sprintf("198.51.100.%d", i))
	}
	out, held := capNew(ips, pub, 4, now)
	if len(out) != 4 || held != 6 {
		t.Fatalf("Obergrenze: %d gezeigt, %d zurückgehalten", len(out), held)
	}
	// bekannte bleiben, in der nächsten Stunde kommen weitere dazu
	out, held = capNew(ips, pub, 4, now.Add(61*time.Minute))
	if len(out) != 8 || held != 2 {
		t.Errorf("nächste Stunde: %d gezeigt, %d zurückgehalten", len(out), held)
	}
}

func TestSensorTrustEndpoint(t *testing.T) {
	h := testHive(t)
	h.auth = NewAuth(h.st, "gemeinsam", false)
	w := httptest.NewRecorder()
	h.sensorTokensAPI(w, httptest.NewRequest("POST", "/api/sensor-tokens", strings.NewReader(`{"name":"vps-1"}`)))
	if !h.untrustedSensors()["vps-1"] {
		t.Fatal("neuer Sensor muss zunächst nicht vertrauenswürdig sein")
	}
	w = httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/sensor-tokens/vps-1/trust", strings.NewReader(`{"trusted":true}`))
	r.SetPathValue("name", "vps-1")
	h.sensorTrust(w, r)
	if w.Code != 200 || h.untrustedSensors()["vps-1"] {
		t.Errorf("vertrauen: %d %v", w.Code, h.untrustedSensors())
	}
}

// Content-Type aus der Modellantwort nur aus einer festen Liste.
func TestSafeContentType(t *testing.T) {
	for in, want := range map[string]string{
		"text/html\r\nSet-Cookie: x=1": "text/html; charset=utf-8",
		"application/json":             "application/json",
		"TEXT/PLAIN":                   "text/plain; charset=utf-8",
		"image/png":                    "text/html; charset=utf-8",
	} {
		if got := safeContentType(in); got != want {
			t.Errorf("safeContentType(%q) = %q", in, got)
		}
	}
}

// nur wirksame Anfragen an die HTTP-APIs gelten als "Befehl ausgeführt".
func TestAPIChanging(t *testing.T) {
	for _, c := range []struct {
		svc, in string
		want    bool
	}{
		{"elasticsearch", "POST /customers/_search {\"query\":{}}", false},
		{"elasticsearch", "POST /x/_search {\"script_fields\":{}}", true},
		{"elasticsearch", "PUT /x/_doc/1 {}", true},
		{"elasticsearch", "POST /cgi-bin/luci", false}, // Webscanner, kein ES-Schreibpfad
		{"elasticsearch", "DELETE /customers", true},
		{"elasticsearch", "POST /customers/_doc", true},
		{"ollama", "prompt llama: hi", true},
		{"ollama", "show llama", false},
		{"ollama", "POST /cgi-bin/x", false},
		{"kubernetes", "run default/web/web: id", true},
		{"kubernetes", "POST /cgi-bin/x", false},
		{"kubernetes", "DELETE /api/v1/namespaces/a/pods/b", true},
	} {
		if got := commandExecuted(c.svc, c.in, false); got != c.want {
			t.Errorf("%s %q: %v", c.svc, c.in, got)
		}
	}
}

func TestReservedPorts(t *testing.T) {
	c := SensorConfig{Profile: "", Tarpit: TarpitConfig{IntervalMs: 10000, MaxConns: 10, MaxPerIP: 2, MaxDurationMin: 0}}
	c.Listeners = []ListenerConfig{{Service: "http", Port: 8089, Mode: "emulate", Enabled: true}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "reserviert") {
		t.Errorf("8089: %v", err)
	}
	t.Setenv("HIVE_DIRECT_PORTS", "1")
	c.Listeners = []ListenerConfig{{Service: "telnet", Port: 23, Mode: "emulate", Enabled: true}}
	if err := c.Validate(); err == nil {
		t.Error("23 auf dem Pi sollte reserviert sein")
	}
}

func TestViewerNoThirdPartyLookups(t *testing.T) {
	for _, p := range []string{"/api/lookup/urlhaus", "/api/sample", "/api/attackers/203.0.113.1/intel", "/api/attackers/203.0.113.1/greynoise"} {
		if viewerAllowed(httptest.NewRequest("GET", p, nil)) {
			t.Errorf("Leserolle darf %s", p)
		}
	}
	if !viewerAllowed(httptest.NewRequest("GET", "/api/attackers/203.0.113.1", nil)) {
		t.Error("Angreifer-Seite muss für die Leserolle offen bleiben")
	}
}
