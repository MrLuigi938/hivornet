package main

// Fehler aus dem Betrieb (0.9.4 auf dem Raspberry Pi): "Adresse nicht zulässig: Länge" bei
// Dateien sammeln, "User unknown" bei URLhaus als Erfolg, DShield mit Anmeldename statt ID.

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestURLFindingsUploadsAndLongURLs(t *testing.T) {
	allowDoc(t)
	setOwnNets(OwnNets{Private: true})
	h := shareHive(t)
	var skipped []string
	skip := func(u, why string) { skipped = append(skipped, u+" → "+why) }
	long := "http://198.51.100.20/bins/x.sh?" + strings.Repeat("a=1&", 300) // 1.231 Zeichen
	addEvent(h, "download", "ssh", "203.0.113.50", "", "", map[string]any{"filename": "/tmp/x", "sha256": strings.Repeat("a", 64), "upload": true})
	addEvent(h, "download", "ssh", "203.0.113.51", "", "", map[string]any{"url": long})
	addEvent(h, "command", "ssh", "203.0.113.52", "", "", map[string]any{"input": "wget http://192.168.1.5/x"})
	addEvent(h, "download", "ssh", "203.0.113.53", "", "", map[string]any{"url": "http://198.51.100.21/" + strings.Repeat("b", shareURLMax)})
	got, err := h.urlFindings(context.Background(), time.Now().Add(-time.Hour), skip)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].URL != long {
		t.Fatalf("Funde: %v", got)
	}
	all := strings.Join(skipped, "\n")
	if strings.Contains(all, "Länge") || strings.Contains(all, "leer") {
		t.Fatalf("Upload ohne Adresse als übersprungen gemeldet:\n%s", all)
	}
	// LAN bleibt gesperrt, überlange Adressen auch, mit verständlichem Grund
	if !strings.Contains(all, "192.168.1.5") || !strings.Contains(all, "länger als 2048 Zeichen") || len(skipped) != 2 {
		t.Fatalf("Gründe:\n%s", all)
	}
	if _, why := shareURLProblem("  ", ""); why != "leer" {
		t.Fatalf("leer: %q", why)
	}
}

func TestURLhausRefusal(t *testing.T) {
	for answer, want := range map[string]string{
		"User unknown, please visit https://urlhaus.abuse.ch/ and try again": "einmal unter https://urlhaus.abuse.ch/login/",
		"unknown_auth_key":                     "lehnt den abuse.ch-Schlüssel ab",
		"user_blacklisted":                     "gesperrt",
		"Thanks for your submission! inserted": "",
		"already_known":                        "",
	} {
		got := urlhausRefusal(answer)
		if want == "" && got != "" || want != "" && !strings.Contains(strings.ToLower(got), strings.ToLower(want)) {
			t.Errorf("%q → %q", answer, got)
		}
	}
}

func TestURLhausUserUnknownIsError(t *testing.T) {
	allowDoc(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "User unknown, please visit https://urlhaus.abuse.ch/ and try again")
	}))
	defer srv.Close()
	old := urlhausSubmitURL
	urlhausSubmitURL = srv.URL
	t.Cleanup(func() { urlhausSubmitURL = old })
	h := shareHive(t)
	x := h.Extras()
	x.AbuseChKey = "k"
	x.URLhausReport = URLhausReportConfig{Enabled: true, DailyLimit: 10}
	h.urlhausSubmit(context.Background(), x, []urlFinding{{URL: "http://198.51.100.20/x"}})
	h.share.mu.Lock()
	c := h.share.channel("urlhaus")
	st, msg := c.Log[0].Status, c.LastErr
	h.share.mu.Unlock()
	if st != "error" || !strings.Contains(msg, "urlhaus.abuse.ch/login") {
		t.Fatalf("Status %q, Fehler %q", st, msg)
	}
	if _, _, done := h.st.lookupGet(urlSubject("http://198.51.100.20/x"), "urlhaus_report", 0); done {
		t.Fatal("abgelehnte Meldung als gemeldet vermerkt")
	}
	if h.share.begin("urlhaus") {
		t.Fatal("nach Ablehnung nicht pausiert")
	}
}

func TestDShieldCheck(t *testing.T) {
	const email, key = "ich@example.org", "c2VjcmV0K2tleQ=="
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.EscapedPath())
		p := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		// /<email>/<nonce>/<hash>/<version>/<piid>
		if len(p) != 5 {
			http.Error(w, "bad", 404)
			return
		}
		m := hmac.New(sha512.New, []byte(p[1]))
		m.Write([]byte(p[0] + ":" + key))
		if p[0] == email && p[2] == hex.EncodeToString(m.Sum(nil)) {
			io.WriteString(w, "<?xml version=\"1.0\"?><checkapikey><result>ok</result><id>123456</id></checkapikey>")
			return
		}
		io.WriteString(w, "<?xml version=\"1.0\"?><checkapikey><result>failed</result></checkapikey>")
	}))
	defer srv.Close()
	old := dshieldCheckURL
	dshieldCheckURL = srv.URL + "/"
	t.Cleanup(func() { dshieldCheckURL = old })

	id, err := dshieldCheck(context.Background(), email, key)
	if err != nil || id != 123456 {
		t.Fatalf("ID %d, %v", id, err)
	}
	if !strings.Contains(paths[0], "ich@example.org/") && !strings.Contains(paths[0], "ich%40example.org/") {
		t.Fatalf("Pfad: %s", paths[0])
	}
	if _, err := dshieldCheck(context.Background(), email, "falsch"); err == nil || !strings.Contains(err.Error(), "kennt diese Kombination") {
		t.Fatalf("falscher Schlüssel: %v", err)
	}
	if _, err := dshieldCheck(context.Background(), "meinname", key); err == nil || !strings.Contains(err.Error(), "E-Mail") {
		t.Fatalf("Anmeldename statt E-Mail: %v", err)
	}

	// über die API: trägt ID, E-Mail und Schlüssel ein
	h := shareHive(t)
	body, _ := json.Marshal(map[string]string{"email": " " + email + " ", "api_key": key + "\n"})
	rec := httptest.NewRecorder()
	h.dshieldCheckAPI(rec, httptest.NewRequest("POST", "/api/share/dshield/check", strings.NewReader(string(body))))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "123456") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if d := h.Extras().DShield; d.UserID != 123456 || d.Email != email || d.APIKey != key {
		t.Fatalf("gespeichert: %+v", d)
	}
}

func TestDShieldRejectsMessage(t *testing.T) {
	allowDoc(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "<html><body>Authentication failed</body></html>", http.StatusUnauthorized)
	}))
	defer srv.Close()
	old := dshieldSubmitURL
	dshieldSubmitURL = srv.URL
	t.Cleanup(func() { dshieldSubmitURL = old })
	code, err := dshieldPost(context.Background(), DShieldConfig{UserID: 1, APIKey: "k"}, "firewall", nil)
	if code != 401 || err == nil || !strings.Contains(err.Error(), "nicht der Anmeldename") || !strings.Contains(err.Error(), "Authentication failed") {
		t.Fatalf("%d %v", code, err)
	}
}

func TestShareValidateTrimsKey(t *testing.T) {
	x := defaultExtras()
	x.DShield.APIKey = " c2VjcmV0\r\n"
	if err := x.Validate(); err != nil || x.DShield.APIKey != "c2VjcmV0" {
		t.Fatalf("%v %q", err, x.DShield.APIKey)
	}
	x.DShield.Email = "kein-at"
	if err := x.Validate(); err == nil {
		t.Fatal("E-Mail ohne @ angenommen")
	}
}
