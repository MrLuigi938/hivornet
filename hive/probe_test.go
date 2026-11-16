package main

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestCowrieProbeTargets(t *testing.T) {
	t.Setenv("HIVE_COWRIE_PROBE", "")
	t.Setenv("HIVE_DIRECT_PORTS", "")
	if got := cowrieProbeTargets(); len(got) != 0 {
		t.Fatalf("Docker-Betrieb ohne Angabe: %v", got)
	}
	t.Setenv("HIVE_DIRECT_PORTS", "1")
	t.Setenv("HIVE_COWRIE_LOG", "/var/lib/hivornet-cowrie/log/cowrie.json")
	if got := cowrieProbeTargets(); len(got) != 2 || got[0].Addr != "127.0.0.1:22" || got[1].Name != "telnet" {
		t.Fatalf("Pi-Standard: %v", got)
	}
	t.Setenv("HIVE_COWRIE_PROBE", "off")
	if got := cowrieProbeTargets(); len(got) != 0 {
		t.Fatalf("off: %v", got)
	}
	t.Setenv("HIVE_COWRIE_PROBE", "ssh=cowrie:2222, rm=x:1, telnet=kaputt")
	if got := cowrieProbeTargets(); len(got) != 1 || got[0].Addr != "cowrie:2222" {
		t.Fatalf("eigene Liste: %v", got)
	}
}

func TestPortProbeWarnsAfterRepeatedFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n"))
			c.Close()
		}
	}()
	// freien Port finden, auf dem niemand lauscht
	tmp, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := tmp.Addr().String()
	tmp.Close()

	p := newPortProbe([]probeTarget{{"ssh", ln.Addr().String()}, {"telnet", closed}})
	p.hint = func(context.Context) string { return "nie aufgerufen" }
	ctx := context.Background()
	p.once(ctx)
	if w := p.warnings(); len(w) != 0 {
		t.Fatalf("nach einem Fehlschlag schon Warnung: %v", w)
	}
	p.once(ctx)
	w := p.warnings()
	if len(w) != 1 || w[0].Level != "critical" || !strings.Contains(w[0].Text, "Cowrie-Telnet") || strings.Contains(w[0].Text, "nie aufgerufen") {
		t.Fatalf("Warnung für Telnet erwartet: %v", w)
	}
	for _, r := range p.Results() {
		if r.Name == "ssh" && !r.OK {
			t.Fatalf("SSH-Kennung nicht erkannt: %+v", r)
		}
	}

	// SSH aus, Ursache im Cowrie-Protokoll erkannt
	ln.Close()
	p.hint = func(context.Context) string { return "Ein SSH-Host-Schlüssel von Cowrie ist leer oder beschädigt." }
	p.once(ctx)
	p.once(ctx)
	text := ""
	for _, w := range p.warnings() {
		text += w.Text + "\n"
	}
	if !strings.Contains(text, "Cowrie-SSH (Port") || !strings.Contains(text, "neues Image") {
		t.Fatalf("Hinweis auf Host-Schlüssel und Image fehlt: %s", text)
	}
}

func TestProbeSSHNeedsBanner(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Write([]byte("hallo\r\n"))
			time.Sleep(100 * time.Millisecond)
			c.Close()
		}
	}()
	if err := dialProbe(context.Background(), probeTarget{"ssh", ln.Addr().String()}); err == nil {
		t.Fatal("ohne SSH-Kennung darf die Prüfung nicht gelingen")
	}
}

func TestListenerWarnings(t *testing.T) {
	ls, _ := json.Marshal([]map[string]any{
		{"port": 80, "service": "http", "running": true},
		{"port": 3306, "service": "mysql", "running": false, "error": "listen tcp :3306: bind: address already in use"},
		{"port": 21, "service": "ftp", "running": false},
	})
	w := listenerWarnings(Heartbeat{Sensor: "pi", Listeners: ls})
	if len(w) != 1 || !strings.Contains(w[0].Text, "Port 3306 (mysql) lauscht nicht") {
		t.Fatalf("%v", w)
	}
}

func TestCowrieIgnoresLoopbackProbe(t *testing.T) {
	h := testHive(t)
	var got []*Event
	c := NewCowrieTail("x", "s", h.st, func(e *Event) { got = append(got, e) })
	c.handle([]byte(`{"eventid":"cowrie.session.connect","session":"p1","src_ip":"127.0.0.1","dst_port":22,"protocol":"ssh","timestamp":"2026-11-16T10:00:00.000000Z"}`))
	c.handle([]byte(`{"eventid":"cowrie.session.connect","session":"p2","src_ip":"::1","dst_port":23,"protocol":"telnet","timestamp":"2026-11-16T10:00:00.000000Z"}`))
	if len(got) != 0 {
		t.Fatalf("Prüfverbindungen als Ereignis: %+v", got[0])
	}
	if _, last := c.Status(); !last.IsZero() {
		t.Fatal("Prüfverbindung zählt als Cowrie-Aktivität")
	}
	c.handle([]byte(`{"eventid":"cowrie.session.connect","session":"a1","src_ip":"203.0.113.9","dst_port":22,"protocol":"ssh","timestamp":"2026-11-16T10:00:00.000000Z"}`))
	if len(got) != 1 {
		t.Fatal("echte Verbindung fehlt")
	}
}
