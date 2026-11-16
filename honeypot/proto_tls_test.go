package main

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// clientHello liefert den ersten TLS-Record eines echten Go-Clients (ClientHello).
func clientHello(t *testing.T, sni string) []byte {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Handshake()
		a.Close()
	}()
	b.SetReadDeadline(time.Now().Add(3 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(b, hdr); err != nil {
		t.Fatal(err)
	}
	rec := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(b, rec); err != nil {
		t.Fatal(err)
	}
	b.Close()
	return append(hdr, rec...)
}

// Ein TLS-ClientHello auf einem Klartext-Port ist kein Befehl, sondern ein Ereignis
// "tls" mit plain=true und den Rohdaten.
func TestTLSOnPlainPorts(t *testing.T) {
	hello := clientHello(t, "nas.example")
	telnetDelay = func() time.Duration { return 0 }
	for _, svc := range []string{"ftp", "redis", "smtp", "telnet", "http", "dockerapi", "mysql", "raw"} {
		m := testManager()
		c, done := run(t, m, svc, "emulate")
		go io.Copy(io.Discard, c)
		c.Write(hello)
		waitDone(t, done, 5*time.Second)
		c.Close()
		raw := rawEvents(m)
		var tlsEv *Event
		for _, b := range raw {
			if len(b) > maxEventBytes {
				t.Errorf("%s: Ereignis %d Bytes", svc, len(b))
			}
			var e Event
			json.Unmarshal(b, &e)
			switch e.Type {
			case "command", "payload", "login", "request":
				t.Errorf("%s: TLS-Handshake als %s gemeldet: %v", svc, e.Type, e.Data)
			case "tls":
				tlsEv = &e
			}
		}
		if tlsEv == nil {
			t.Errorf("%s: kein tls-Ereignis", svc)
			continue
		}
		h, _ := tlsEv.Data["client_hello"].(string)
		if tlsEv.Data["plain"] != true || h != hex.EncodeToString(hello) {
			t.Errorf("%s: Rohdaten fehlen oder falsch: plain=%v, %d Zeichen", svc, tlsEv.Data["plain"], len(h))
		}
	}
}

// Ein übergroßer Record wird gekürzt; das Ereignis bleibt im Budget.
func TestTLSOnPlainTruncated(t *testing.T) {
	m := testManager()
	c, done := run(t, m, "redis", "emulate")
	go io.Copy(io.Discard, c)
	big := append([]byte{0x16, 0x03, 0x01, 0x40, 0x00}, make([]byte, 0x4000)...)
	c.Write(big)
	waitDone(t, done, 5*time.Second)
	seen := false
	for _, b := range rawEvents(m) {
		if len(b) > maxEventBytes {
			t.Fatalf("Ereignis %d Bytes", len(b))
		}
		if strings.Contains(string(b), `"type":"tls"`) {
			seen = true
			if !strings.Contains(string(b), `"truncated":true`) {
				t.Fatalf("Kürzung nicht vermerkt: %s", b[:200])
			}
		}
	}
	if !seen {
		t.Fatal("kein tls-Ereignis")
	}
}

// Normale Eingaben laufen unverändert (kein Warten auf mehr Bytes, kein Fehlalarm).
func TestNoTLSFalsePositive(t *testing.T) {
	m := testManager()
	c, done := run(t, m, "redis", "emulate")
	go func() { c.Write([]byte("PING\r\n")) }()
	if got := readUntil(t, c, "PONG"); !strings.Contains(got, "+PONG") {
		t.Fatal(got)
	}
	c.Close()
	waitDone(t, done, 5*time.Second)
	if find(events(m), "tls") != nil {
		t.Fatal("PING als TLS erkannt")
	}
}

// HTTPS: Der ClientHello wird vor dem Handshake mitgelesen; der Handshake gelingt trotzdem.
func TestHTTPSClientHelloCaptured(t *testing.T) {
	m := testManager()
	c := DefaultConfig()
	m.Apply(c)
	defer m.StopAll()
	cl, done := run(t, m, "https", "emulate")
	tc := tls.Client(cl, &tls.Config{ServerName: "nas.example", InsecureSkipVerify: true})
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	tc.Write([]byte("GET / HTTP/1.1\r\nHost: nas.example\r\nUser-Agent: test\r\nAccept: */*\r\nConnection: close\r\n\r\n"))
	io.Copy(io.Discard, tc)
	tc.Close()
	waitDone(t, done, 5*time.Second)
	evs := events(m)
	ev := find(evs, "tls")
	if ev == nil || ev.Data["sni"] != "nas.example" || !strings.HasPrefix(ev.Data["client_hello"].(string), "1603") {
		t.Fatalf("tls-Ereignis: %+v", ev)
	}
	if r := find(evs, "request"); r == nil || r.Data["header_order"] != "Host,User-Agent,Accept,Connection" {
		t.Fatalf("Reihenfolge der Kopfzeilen: %+v", r)
	}
}
