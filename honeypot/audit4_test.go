package main

// Tests zu den Funden des vierten Sicherheitsaudits (Ende-zu-Ende-Prüfung).

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// Kein CR/LF aus dem Pfad in Kopfzeilen: Vorher hängte der Tomcat-Köder über
// ?path=/x%0D%0ASet-Cookie:... eigene Kopfzeilen an die Antwort der Webshell.
func TestLureTomcatNoHeaderInjection(t *testing.T) {
	m := lureTest(t, "all")
	_, body, _ := lureDo(t, m, lureGet("/manager/text/deploy?path=/x%0D%0ASet-Cookie:hv_session=abc", basic("tomcat", "tomcat")))
	if strings.Contains(body, "\r") {
		t.Errorf("Pfad mit CR/LF angenommen: %q", body)
	}
	resp, _, _ := lureDo(t, m, lureGet("/x%0D%0ASet-Cookie:hv_session=abc/a"))
	for _, c := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(c, "hv_session") {
			t.Fatalf("eingeschleuster Cookie: %q", c)
		}
	}
}

func TestHasCtl(t *testing.T) {
	if !hasCtl("a\r\nb") || !hasCtl("a\x7f") || hasCtl("a\tb") || hasCtl("JSESSIONID=1; Path=/x") {
		t.Error("hasCtl")
	}
}

// IPv6-Absender zählen je /64: Jede Adresse eines Anschlusses hatte sonst eigene Plätze.
func TestLimitsIPv6Per64(t *testing.T) {
	if limitKey("2001:db8:1:2::5") != limitKey("2001:db8:1:2:ffff::9") || limitKey("2001:db8:1:2::5") == limitKey("2001:db8:1:3::5") {
		t.Fatal("limitKey fasst /64 nicht zusammen")
	}
	if limitKey("192.0.2.4") != "192.0.2.4" || limitKey("::ffff:192.0.2.4") != "::ffff:192.0.2.4" {
		t.Fatal("IPv4 verändert")
	}
	l := NewLimits()
	n := 0
	for i := 0; i < 500; i++ {
		if l.AcquireConn(fmt.Sprintf("2001:db8::%x", i+1)) {
			n++
		}
	}
	if n != l.maxTarpitPerIP+extraConnsPerIP {
		t.Fatalf("%d Verbindungen aus einem /64", n)
	}
	r := &RateLimiter{buckets: map[string]*bucket{}, rate: 0, burst: 1, max: rateMaxIPs}
	if !r.Allow("2001:db8::1") || r.Allow("2001:db8::2") {
		t.Fatal("Drossel nicht je /64")
	}
}

// Sitzungen außerhalb des Tarpits enden nach maxSessionDur, auch wenn der Angreifer
// regelmäßig etwas schickt.
func TestSessionMaxDuration(t *testing.T) {
	old := maxSessionDur
	maxSessionDur = 300 * time.Millisecond
	t.Cleanup(func() { maxSessionDur = old })
	m := testManager()
	c, done := run(t, m, "redis", "emulate")
	go io.Copy(io.Discard, c)
	stop := time.After(3 * time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-stop:
			t.Fatal("Sitzung läuft über die Gesamtfrist hinaus")
		case <-tick.C:
			c.Write([]byte("PING\r\n"))
		}
	}
}
