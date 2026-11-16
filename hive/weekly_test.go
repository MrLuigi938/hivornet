package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRareCred(t *testing.T) {
	for k, want := range map[string]bool{"root": false, "123456": false, "Raspberry": false, "98765": false, "xc3511": false,
		"Vk8#qp2LmZ": true, "hivornet-prod": true} {
		if got := rareCred(k, ""); got != want {
			t.Errorf("%q: %v", k, got)
		}
	}
	if rareRow("cred", "deploy / deploy") || !rareRow("cred", "root / Vk8#qp2LmZ") || rareRow("cred", "admin / admin") {
		t.Error("Kombinationen falsch eingestuft")
	}
}

func TestWeeklyDue(t *testing.T) {
	loc := time.Local
	mon8 := time.Date(2026, 11, 16, 8, 5, 0, 0, loc) // Montag
	if !weeklyDue(mon8, "") || weeklyDue(mon8, isoWeek(mon8)) {
		t.Error("Montag 8:05")
	}
	if weeklyDue(time.Date(2026, 11, 16, 7, 59, 0, 0, loc), "") || weeklyDue(time.Date(2026, 11, 17, 9, 0, 0, 0, loc), "") {
		t.Error("vor 8 Uhr oder Dienstag")
	}
}

func TestWeeklyText(t *testing.T) {
	setOwnNets(OwnNets{Private: true})
	h := testHive(t)
	w, wait := testWriter(t, h.st)
	now := time.Now()
	w.Submit(evAt(now.Add(-time.Hour), "connect", "ssh", "203.0.113.7", 22, nil))
	e := evAt(now.Add(-time.Hour), "login", "ssh", "203.0.113.7", 22, map[string]any{"success": true})
	e.Username, e.Password = "root", "Vk8#qp2LmZ"
	w.Submit(e)
	wait()
	text := h.weeklyStats(context.Background(), now.Add(time.Hour)).Text()
	for _, want := range []string{"1 Verbindungen von 1 IPs", "davon 1 angenommen", "Ungewöhnliche Zugangsdaten: root / Vk8#qp2LmZ"} {
		if !strings.Contains(text, want) {
			t.Errorf("%q fehlt in:\n%s", want, text)
		}
	}
}
