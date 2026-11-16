package main

import (
	"testing"
	"time"
)

func TestBuildCampaigns(t *testing.T) {
	setOwnNets(OwnNets{Private: true})
	list := func(ip string, creds ...string) []*Event {
		var evs []*Event
		for i := 0; i+1 < len(creds); i += 2 {
			e := loginEv("ssh", creds[i], creds[i+1], nil)
			e.SrcIP = ip
			evs = append(evs, e)
		}
		return evs
	}
	words := []string{"root", "123456", "admin", "admin", "pi", "raspberry"}
	a1 := attackOf(list("203.0.113.1", words...)...)
	a2 := attackOf(list("198.51.100.2", words...)...)
	a3 := attackOf(list("192.0.2.3", "root", "x", "a", "b", "c", "d")...) // andere Liste
	// a4 lädt von derselben Adresse wie a3
	dl := evAt(time.Time{}, "download", "ssh", "192.0.2.4", 22, map[string]any{"url": "http://evil.example/bins/x86"})
	dl3 := evAt(time.Time{}, "download", "ssh", "192.0.2.3", 22, map[string]any{"url": "http://EVIL.example/bins/arm7"})
	a4, a3b := attackOf(dl), attackOf(dl3)
	own := attackOf(list("192.168.1.5", words...)...)
	camps, _ := buildCampaigns([]*Attack{a1, a2, a3, a4, a3b, own})
	if len(camps) != 2 {
		t.Fatalf("Kampagnen: %+v", camps)
	}
	for _, c := range camps {
		if c.NIPs != 2 {
			t.Errorf("Kampagne %v: %d IPs", c.Reasons, c.NIPs)
		}
		for _, ip := range c.IPs {
			if ip == "192.168.1.5" {
				t.Error("eigener Test in Kampagne")
			}
		}
	}
}
