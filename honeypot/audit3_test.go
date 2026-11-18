package main

// Tests zu den Funden des dritten Audits (docs/AUDIT-3.md, nur lokal).

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// M4: Kopfzeilen über 16 KB werden nicht mehr gepuffert; die Verbindung endet mit 400.
func TestM4HTTPHeaderLimit(t *testing.T) {
	big := "GET / HTTP/1.1\r\nHost: x\r\nX-Pad: " + strings.Repeat("a", 20<<10) + "\r\n\r\n"
	m := testManager()
	c, done := run(t, m, "http", "emulate")
	go func() { c.Write([]byte(big)) }()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err == nil && resp.StatusCode == 200 {
		t.Fatalf("20 KB Kopf angenommen: %d", resp.StatusCode)
	}
	c.Close()
	waitDone(t, done, 5*time.Second)
	// 12 KB gehen weiter (lange Cookies, Java4Shell-Auslöser in Kopfzeilen)
	ok := "GET /gibtsnicht HTTP/1.1\r\nHost: x\r\nCookie: " + strings.Repeat("b", 12<<10) + "\r\nConnection: close\r\n\r\n"
	if resp, _ := httpDo(t, "http", ok); resp.StatusCode != 404 {
		t.Errorf("12 KB Kopf: %d", resp.StatusCode)
	}
}

// M4: MySQL belegt die angekündigte Paketlänge nicht mehr vorab; zu große Pakete enden sofort.
func TestM4MySQLAnnouncedLength(t *testing.T) {
	m := testManager()
	c, done := run(t, m, "mysql", "emulate")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 4)
	io.ReadFull(c, hdr)
	io.ReadFull(c, make([]byte, int(hdr[0])|int(hdr[1])<<8))
	// 60 KB angekündigt (vorher erlaubt und vorab belegt), nichts geschickt
	c.Write([]byte{0x00, 0xf0, 0x00, 0x01})
	waitDone(t, done, 5*time.Second)
	if len(events(m)) > 0 {
		for _, e := range events(m) {
			if e.Type == "login" {
				t.Fatal("Login aus leerem Paket")
			}
		}
	}
}

// N9: Eingebettete Werte bleiben gültiges JSON, auch mit Anführungszeichen und Backslash.
func TestN9JSONSafe(t *testing.T) {
	for _, s := range []string{`foo"`, `"foo`, `a\`, `\"`, "x\ny", `""`, "ä "} {
		var v map[string]string
		if err := json.Unmarshal([]byte(`{"k":"`+jsonSafe(s)+`"}`), &v); err != nil || v["k"] != s {
			t.Errorf("%q: %v %q", s, err, v["k"])
		}
	}
	resp, body := httpDo(t, "elasticsearch", "PUT /idx%22x HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
	var v map[string]any
	if json.Unmarshal([]byte(body), &v) != nil {
		t.Errorf("Elasticsearch-Antwort ungültig (%d): %s", resp.StatusCode, body)
	}
}

// N10: Die MySQL-Fehlermeldung nennt nie die Gateway-Adresse des Docker-Netzes.
func TestN10MySQLClientHost(t *testing.T) {
	if got := mysqlClientHost("203.0.113.9", "nas"); got != "203.0.113.9" {
		t.Errorf("öffentliche Adresse: %s", got)
	}
	a, b := mysqlClientHost("172.30.252.1", "nas-backup01"), mysqlClientHost("172.30.252.1", "cam-02")
	if strings.HasPrefix(a, "172.30.") || !strings.HasPrefix(a, "192.168.") || !strings.HasSuffix(a, ".1") {
		t.Errorf("Gateway-Adresse: %s", a)
	}
	if a != mysqlClientHost("172.30.252.1", "nas-backup01") {
		t.Error("nicht fest je Installation")
	}
	_ = b // je Hostname verschieden (meist; Kollisionen sind möglich und harmlos)
	if got := mysqlClientHost("127.0.0.1", "nas"); got == "127.0.0.1" {
		t.Error("Loopback in der Meldung")
	}
}

// N11: Der Sensor begrenzt Fragen an den Hive selbst (je IP und gleichzeitig).
func TestN11MimicSensorLimits(t *testing.T) {
	mimicRate.Lock()
	mimicRate.n = map[string]int{}
	mimicRate.Unlock()
	t.Cleanup(func() {
		mimicRate.Lock()
		mimicRate.n = map[string]int{}
		mimicRate.Unlock()
	})
	for i := 0; i < mimicMaxPerIPHour; i++ {
		if !mimicAllowed("203.0.113.40") {
			t.Fatalf("Frage %d abgelehnt", i)
		}
	}
	if mimicAllowed("203.0.113.40") {
		t.Fatal("Grenze je IP greift nicht")
	}
	if !mimicAllowed("203.0.113.41") {
		t.Fatal("andere IP betroffen")
	}
	// alle Plätze belegt: sofort statisch, ohne den Hive zu fragen
	mimicOffUntil.Store(0)
	asked := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { asked++ }))
	defer srv.Close()
	m := testManager()
	m.em.hive = &HiveClient{URL: srv.URL, Token: "tok", HTTP: http.DefaultClient}
	s := &Session{m: m, SrcIP: "203.0.113.42"}
	for i := 0; i < mimicMaxConcurrent; i++ {
		mimicSlots <- struct{}{}
	}
	start := time.Now()
	if _, ok := s.askMimic("shell", "foo"); ok || asked != 0 || time.Since(start) > time.Second {
		t.Fatalf("trotz voller Plätze gefragt: %v %d", ok, asked)
	}
	for i := 0; i < mimicMaxConcurrent; i++ {
		<-mimicSlots
	}
}

// Hinweis (Audit 3): Zugangsdaten gehen ohne Steuer- und Richtungszeichen an den Hive.
func TestCleanCred(t *testing.T) {
	cases := map[string]string{
		"root":                 "root",
		"pässwort\\x":          "pässwort\\x", // Umlaut und Backslash bleiben
		"ad\x00min":            "ad\\u0000min",
		"abc\u202edcba":        "abc\\u202edcba",
		"a\u200bb\r\n":         "a\\u200bb\\u000d\\u000a",
		"root\\x1b[31m":        "root\\x1b[31m", // schon von printable bereinigt: unverändert
		strings.Repeat("x", 9): strings.Repeat("x", 9),
	}
	for in, want := range cases {
		if got := cleanCred(in); got != want {
			t.Errorf("%q: %q, erwartet %q", in, got, want)
		}
		if cleanCred(cleanCred(in)) != cleanCred(in) {
			t.Errorf("nicht idempotent: %q", in)
		}
	}
	if got := cleanCred("\xff\xfe"); !utf8.ValidString(got) {
		t.Errorf("ungültiges UTF-8 weitergegeben: %q", got)
	}
	m := testManager()
	s := &Session{m: m, SrcIP: "203.0.113.5", Service: "ftp"}
	s.Login("us\u202eer", "pa\x1bss", nil)
	for _, e := range events(m) {
		if e.Type == "login" && (e.Username != "us\\u202eer" || e.Password != "pa\\u001bss") {
			t.Errorf("Login-Ereignis: %q %q", e.Username, e.Password)
		}
	}
}

// M4: weiche Speichergrenze aus der cgroup, wenn GOMEMLIMIT fehlt.
func TestM4SoftMemLimit(t *testing.T) {
	files := map[string]string{}
	read := func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, errors.New("fehlt")
	}
	noEnv := func(string) string { return "" }
	if n := softMemLimit(noEnv, read); n != 0 {
		t.Errorf("ohne cgroup: %d", n)
	}
	files["/sys/fs/cgroup/memory.max"] = "201326592\n" // 192 MB
	if n := softMemLimit(noEnv, read); n != 201326592/100*85 {
		t.Errorf("cgroup v2: %d", n)
	}
	if n := softMemLimit(func(k string) string {
		if k == "GOMEMLIMIT" {
			return "100MiB"
		}
		return ""
	}, read); n != 0 {
		t.Errorf("GOMEMLIMIT gesetzt, trotzdem überschrieben: %d", n)
	}
	files["/sys/fs/cgroup/memory.max"] = "max"
	if n := softMemLimit(noEnv, read); n != 0 {
		t.Errorf("ohne Grenze: %d", n)
	}
	delete(files, "/sys/fs/cgroup/memory.max")
	files["/sys/fs/cgroup/memory/memory.limit_in_bytes"] = "9223372036854771712"
	if n := softMemLimit(noEnv, read); n != 0 {
		t.Errorf("v1 ohne Grenze: %d", n)
	}
	files["/sys/fs/cgroup/memory/memory.limit_in_bytes"] = "268435456"
	if n := softMemLimit(noEnv, read); n != 268435456/100*85 {
		t.Errorf("cgroup v1: %d", n)
	}
}
