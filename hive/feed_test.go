package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFeedIPs(t *testing.T) {
	list := []*Attack{
		{IP: "203.0.113.1", Stufe: 3, Events: 5, Services: []string{"ssh"}},
		{IP: "203.0.113.2", Stufe: 0, Events: 50, Services: []string{"http"}}, // nur Abtasten
		{IP: "203.0.113.3", Stufe: 1, Events: 9, Services: []string{"sip"}},   // nur UDP
		{IP: "203.0.113.4", Stufe: 2, Events: 3, Services: []string{"http"}, Scanner: "Censys"},
		{IP: "192.168.1.9", Stufe: 4, Events: 1, Services: []string{"ssh"}},            // privat
		{IP: "203.0.113.5", Stufe: 1, Events: 2, Services: []string{"ftp"}, Own: true}, // eigener Test
		{IP: "203.0.113.6", Stufe: 1, Events: 7, Services: []string{"telnet", "sip"}},
		{IP: "203.0.113.1", Stufe: 1, Events: 1, Services: []string{"ftp"}}, // zweiter Angriff derselben IP
	}
	got := strings.Join(feedIPs(list, FeedConfig{MinStufe: 1, SkipScanners: true}, nil), ",")
	if got != "203.0.113.1,203.0.113.6" {
		t.Errorf("Auswahl: %s", got)
	}
	got = strings.Join(feedIPs(list, FeedConfig{MinStufe: 0, SkipScanners: false}, nil), ",")
	if got != "203.0.113.1,203.0.113.4,203.0.113.6,203.0.113.2" {
		t.Errorf("ohne Scanner-Filter, ab Abtasten: %s", got)
	}
}

func TestFeedToken(t *testing.T) {
	h := testHive(t)
	get := func(url string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.feedBlocklist(w, httptest.NewRequest("GET", url, nil))
		return w
	}
	if w := get("/feed/blocklist.txt?token="); w.Code != 404 {
		t.Fatalf("ausgeschaltet: %d", w.Code)
	}
	// einschalten: Token setzt der Hive, nicht der Aufrufer
	w := httptest.NewRecorder()
	h.feedSettings(w, httptest.NewRequest("PUT", "/api/feed", strings.NewReader(`{"enabled":true,"token":"vom-angreifer","range":"7d","min_stufe":1,"skip_scanners":true,"max_new_per_hour":300}`)))
	var out struct {
		Config FeedConfig `json:"config"`
		Path   string     `json:"path"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	if out.Config.Token == "" || out.Config.Token == "vom-angreifer" || !strings.HasSuffix(out.Path, out.Config.Token) {
		t.Fatalf("Token: %+v", out)
	}
	if w := get("/feed/blocklist.txt?token=falsch"); w.Code != 404 {
		t.Errorf("falsches Token: %d", w.Code)
	}
	w = get("/feed/blocklist.txt?token=" + out.Config.Token)
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Body.String(), "# Hivornet Blockliste") {
		t.Errorf("Abruf: %d %q", w.Code, w.Body.String())
	}
	// neues Token: altes gilt nicht mehr
	old := out.Config.Token
	w = httptest.NewRecorder()
	h.feedSettings(w, httptest.NewRequest("PUT", "/api/feed", strings.NewReader(`{"enabled":true,"rotate":true,"max_new_per_hour":300}`)))
	json.Unmarshal(w.Body.Bytes(), &out)
	if out.Config.Token == old {
		t.Fatal("Token nicht erneuert")
	}
	if w := get("/feed/blocklist.txt?token=" + old); w.Code != 404 {
		t.Errorf("altes Token gilt noch: %d", w.Code)
	}
	if viewerAllowed(httptest.NewRequest("GET", "/api/feed", nil)) {
		t.Error("Leserolle darf das Token nicht sehen")
	}
}
