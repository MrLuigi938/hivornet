package main

import (
	"testing"
	"time"
)

// Gleicher Wert wie in honeypot/proto_tarnung_test.go.
func TestBaitDerivation(t *testing.T) {
	b := deriveBait("test-token")
	if b.User != "deploy" || b.Pass != "MySW-bzdBq!9Q7vH" || b.DBName != "files" || b.APIKey != "e5e3f2a21d9c9564f958b082a887a34f" {
		t.Fatalf("Ableitung weicht vom Honeypot ab: %+v", b)
	}
}

func TestBaitUsedRaisesAttack(t *testing.T) {
	setBaitSecret("test-token")
	t.Cleanup(func() { baitCur.Store(nil) })
	b := deriveBait("test-token")
	for _, e := range []*Event{
		loginEv("ftp", b.User, b.Pass, nil),
		loginEv("redis", "default", b.Pass, nil),
		loginEv("mysql", b.User, "", map[string]any{"password_hashed": true, "bait": true}),
		evAt(time.Time{}, "request", "http", "", 80, map[string]any{"path": "/api", "headers": "Authorization: Bearer " + b.APIKey}),
	} {
		a := attackOf(e)
		if !hasTag(a, "bait_used") || a.Stufe < stufeLogin || a.Profile != "Köder benutzt" {
			t.Errorf("%s: Muster %v, Stufe %d, Art %q", e.Service, a.Tags, a.Stufe, a.Profile)
		}
		found := false
		for _, k := range topKeys(e) {
			if k[0] == "tag" && k[1] == "bait_used" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: Zähltabelle ohne bait_used", e.Service)
		}
	}
	if a := attackOf(loginEv("ftp", b.User, "falsch", nil)); hasTag(a, "bait_used") {
		t.Error("falsches Passwort als Köder erkannt")
	}
}
