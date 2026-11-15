package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeHosts(t *testing.T) {
	got, err := normalizeHosts([]string{" Hivornet.Example.de ", "", ".example.org", "hivornet.example.de"})
	if err != nil || strings.Join(got, ",") != "hivornet.example.de,.example.org" {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"*", "https://a.example.de", "a.example.de:443", "a.example.de/pfad", "nas", ".", "-a.example.de", "a..example.de", "ä.example.de"} {
		if _, err := normalizeHosts([]string{bad}); err == nil {
			t.Errorf("%q müsste abgelehnt werden", bad)
		}
	}
	many := make([]string, maxAllowedHosts+1)
	for i := range many {
		many[i] = "h" + strings.Repeat("x", i+1) + ".example.de"
	}
	if _, err := normalizeHosts(many); err == nil {
		t.Error("zu viele Einträge angenommen")
	}
}

// Die in der Web-UI gespeicherte Liste wirkt sofort und ergänzt HIVE_ALLOWED_HOSTS.
func TestAllowedHostsFromUI(t *testing.T) {
	t.Setenv("HIVE_ALLOWED_HOSTS", "env.example.com")
	h := testHive(t)
	h.auth = NewAuth(h.st, "tok", false)
	h.auth.EnsureAdmin("admin", "adminpasswort1")
	h.hosts.env = envAllowedHosts()
	h.reloadHosts()
	ui, _ := h.routes(false, "", http.NotFoundHandler())
	guarded := uiGuard(ui, nil, h.allowedHosts)

	rec := httptest.NewRecorder()
	if err := h.auth.startSession(rec, httptest.NewRequest("GET", "/", nil), "admin"); err != nil {
		t.Fatal(err)
	}
	c := rec.Result().Cookies()[0]
	do := func(method, host, body string) int {
		req := httptest.NewRequest(method, "/api/settings", strings.NewReader(body))
		req.Host = host
		req.Header.Set("X-Requested-With", "hivornet")
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := do("GET", "hivornet.example.de", ""); c != 421 {
		t.Fatalf("unbekannter Name vor dem Eintragen: %d", c)
	}
	if c := do("GET", "env.example.com", ""); c != 200 {
		t.Fatalf("Name aus HIVE_ALLOWED_HOSTS: %d", c)
	}
	if c := do("PUT", "192.168.178.192:8088", `{"allowed_hosts":["https://x"]}`); c != 400 {
		t.Fatalf("ungültiger Eintrag: %d", c)
	}
	if c := do("PUT", "192.168.178.192:8088", `{"allowed_hosts":["hivornet.example.de"]}`); c != 200 {
		t.Fatalf("speichern: %d", c)
	}
	if c := do("GET", "hivornet.example.de", ""); c != 200 {
		t.Fatalf("eingetragener Name: %d", c)
	}
	if c := do("GET", "env.example.com", ""); c != 200 {
		t.Fatalf("Name aus HIVE_ALLOWED_HOSTS nach dem Speichern: %d", c)
	}
	// Neustart: Liste kommt aus der Datenbank
	h.hosts.cur.Store(nil)
	h.reloadHosts()
	if !hostAllowed("hivornet.example.de", h.allowedHosts()) {
		t.Fatal("Liste nach Neustart verloren")
	}
	if c := do("PUT", "192.168.178.192:8088", `{"allowed_hosts":[]}`); c != 200 || hostAllowed("hivornet.example.de", h.allowedHosts()) {
		t.Fatalf("leeren: %d", c)
	}
}

func TestCookieSecureViaHTTPS(t *testing.T) {
	h := testHive(t)
	a := NewAuth(h.st, "", false)
	secure := func(r *http.Request) bool {
		rec := httptest.NewRecorder()
		if err := a.startSession(rec, r, "admin"); err != nil {
			t.Fatal(err)
		}
		return rec.Result().Cookies()[0].Secure
	}
	plain := httptest.NewRequest("POST", "/api/login", nil)
	if secure(plain) {
		t.Error("HTTP ohne Proxy: Cookie darf nicht Secure sein (sonst keine Anmeldung im Heimnetz)")
	}
	proxied := httptest.NewRequest("POST", "/api/login", nil)
	proxied.Header.Set("X-Forwarded-Proto", "https")
	if !secure(proxied) {
		t.Error("hinter HTTPS-Proxy muss das Cookie Secure sein")
	}
	direct := httptest.NewRequest("POST", "/api/login", nil)
	direct.TLS = &tls.ConnectionState{}
	if !secure(direct) {
		t.Error("direkt über TLS muss das Cookie Secure sein")
	}
}
