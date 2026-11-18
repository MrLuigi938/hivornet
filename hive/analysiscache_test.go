package main

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// Der Zwischenspeicher der Musterprüfung liefert dasselbe wie die direkte Berechnung, und
// Angriffe sind mit und ohne Speicher gleich.
func TestAnalysisCacheSameResult(t *testing.T) {
	evs := benchEvents(400)
	for _, e := range evs {
		text, on := eventText(e)
		if text == "" {
			continue
		}
		resetAnalysisCache()
		cold := analyzeText(text, on)
		warm := analyzeText(text, on)
		if cold != warm {
			t.Fatal("zweiter Aufruf nicht aus dem Speicher")
		}
		var rev []string
		if !isTLSText(text) {
			rev = revealHidden(text)
		}
		if !reflect.DeepEqual(cold.ids, matchAll(text, on, rev)) || len(cold.cves) != len(matchCVEs(text, on)) {
			t.Fatalf("Ergebnis weicht ab: %q", text)
		}
	}
	build := func() []*Attack {
		byIP := map[string]*Attack{}
		var out []*Attack
		for _, e := range evs {
			a := byIP[e.SrcIP]
			if a == nil {
				a = newAttack(e)
				byIP[e.SrcIP] = a
				out = append(out, a)
			}
			a.add(e)
		}
		for _, a := range out {
			a.finish()
		}
		return out
	}
	resetAnalysisCache()
	first := build() // füllt den Speicher
	second := build()
	if !reflect.DeepEqual(first, second) {
		t.Fatal("Angriffe mit Zwischenspeicher weichen ab")
	}
	tags, urls := 0, 0
	for _, a := range first {
		tags += len(a.Tags)
		urls += len(a.URLs)
	}
	if tags == 0 || urls == 0 {
		t.Errorf("Testdaten ohne Muster (%d) oder Adressen (%d): Vergleich wäre wertlos", tags, urls)
	}
}

// Generationen: Der Speicher wächst nicht über zwei Generationen hinaus.
func TestAnalysisCacheBounded(t *testing.T) {
	resetAnalysisCache()
	t.Cleanup(resetAnalysisCache)
	for i := 0; i < analysisGenMax*2+10; i++ {
		analyzeText("uname -a #"+time.Duration(i).String(), "cmd")
	}
	c := &analysisCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cur) > analysisGenMax || len(c.prev) > analysisGenMax {
		t.Errorf("Speicher zu groß: %d + %d", len(c.cur), len(c.prev))
	}
}

// "Gerade aktiv" liest nur die aktiven IPs und liefert dasselbe wie der alte Weg (alle IPs
// der letzten sechs Stunden laden, dann filtern).
func TestActiveAttacksSameAsFiltered(t *testing.T) {
	h := testHive(t)
	now := time.Now()
	ins := func(ip string, ago time.Duration, typ string) {
		h.st.db.Exec(`INSERT INTO events(ts,type,service,src_ip,dst_port,data) VALUES(?,?,?,?,?,?)`,
			now.Add(-ago).UnixMilli(), typ, "telnet", ip, 23, `{"input":"uname -a"}`)
	}
	ins("198.51.100.1", 2*time.Hour, "connect") // aktiv, Angriff begann vor zwei Stunden …
	for m := 110; m >= 0; m -= 10 {
		ins("198.51.100.1", time.Duration(m)*time.Minute, "command") // … und läuft ohne Pause bis jetzt
	}
	ins("198.51.100.2", 3*time.Hour, "command") // früher aktiv, jetzt nicht
	ins("198.51.100.3", time.Minute, "connect") // gerade erst
	ins("198.51.100.2", 40*time.Minute, "command")
	since := now.Add(-6 * time.Hour)
	all, _, err := h.loadAttacks(context.Background(), since, nil)
	if err != nil {
		t.Fatal(err)
	}
	cut := now.Add(-attackGap).UnixMilli()
	var want []*Attack
	for _, a := range all {
		if a.Last >= cut {
			want = append(want, a)
		}
	}
	got, _, err := h.loadActiveAttacks(context.Background(), since)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !reflect.DeepEqual(got, want) {
		t.Fatalf("aktiv: %d Angriffe, erwartet %d", len(got), len(want))
	}
	if got[0].IP != "198.51.100.1" || got[0].First != now.Add(-2*time.Hour).UnixMilli() || got[1].IP != "198.51.100.3" {
		t.Errorf("Reihenfolge oder Beginn falsch: %s %d %s", got[0].IP, got[0].First, got[1].IP)
	}
}
