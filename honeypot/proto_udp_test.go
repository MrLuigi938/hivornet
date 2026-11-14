package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// Tests für die UDP-Dienste SIP, SNMP und DNS (proto_udp.go).

func crlf(s string) []byte { return []byte(strings.ReplaceAll(s, "\n", "\r\n")) }

func TestSIPEvent(t *testing.T) {
	e := sipEvent(crlf(`OPTIONS sip:100@203.0.113.1 SIP/2.0
Via: SIP/2.0/UDP 198.51.100.7:5060
From: "sipvicious"<sip:100@1.1.1.1>;tag=1
User-Agent: friendly-scanner
Content-Length: 0

`))
	if e.Type != "request" || e.Data["method"] != "OPTIONS" || e.Data["user_agent"] != "friendly-scanner" || e.Data["path"] != "sip:100@203.0.113.1" {
		t.Fatalf("%+v", e)
	}
	if e := sipEvent([]byte{0, 1, 'x'}); e.Type != "payload" {
		t.Fatalf("Unsinn: %+v", e)
	}
}

// snmpGet baut ein SNMP-v2c-GetRequest mit der angegebenen Community.
func snmpGet(community string) []byte {
	pdu := []byte{0xa0, 0x0e, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x03, 0x30, 0x01, 0x05}
	body := append([]byte{0x02, 0x01, 0x01, 0x04, byte(len(community))}, community...)
	body = append(body, pdu...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

func TestSNMPEvent(t *testing.T) {
	e := snmpEvent(snmpGet("public"))
	if e.Type != "login" || e.Password != "public" || e.Data["snmp_version"] != "v2c" || e.Data["pdu"] != "get" {
		t.Fatalf("%+v", e)
	}
	if e := snmpEvent([]byte{0x30, 0x82, 0xff, 0xff, 0x02}); e.Type != "payload" {
		t.Fatalf("kaputte Länge: %+v", e)
	}
}

func dnsQuery(name string, qtype uint16) []byte {
	p := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		p = append(p, byte(len(l)))
		p = append(p, l...)
	}
	return append(p, 0, byte(qtype>>8), byte(qtype), 0, 1)
}

func TestDNSEvent(t *testing.T) {
	e := dnsEvent(dnsQuery("example.com", 255))
	if e.Type != "request" || e.Data["method"] != "DNS ANY" || e.Data["path"] != "example.com." || e.Data["recursion"] != true {
		t.Fatalf("%+v", e)
	}
	bad := dnsQuery("example.com", 1)
	bad[12] = 0xc0 // Zeiger in der Frage
	if e := dnsEvent(bad); e.Type != "payload" {
		t.Fatalf("Zeiger: %+v", e)
	}
}

// Ein UDP-Dienst zeichnet auf und schickt nie etwas zurück (keine Reflexion).
func TestUDPListenerNeverReplies(t *testing.T) {
	m := testManager()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	if !m.Apply(Config{Listeners: []ListenerConfig{{"snmp", port, "emulate", true}}}) {
		t.Fatal("Konfiguration nicht übernommen")
	}
	defer m.StopAll()
	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(snmpGet("private"))
	c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	if n, err := c.Read(make([]byte, 100)); err == nil || n > 0 {
		t.Fatalf("UDP-Dienst hat geantwortet (%d Bytes)", n)
	}
	var got *Event
	for i := 0; i < 20 && got == nil; i++ {
		got = find(events(m), "login")
		time.Sleep(50 * time.Millisecond)
	}
	if got == nil || got.Password != "private" || got.Service != "snmp" || got.DstPort != port {
		t.Fatalf("Ereignis: %+v", got)
	}
	_, st := m.Status()
	if len(st) != 1 || !st[0].Running || st[0].Total != 1 {
		t.Fatalf("Status: %+v", st)
	}
}

func FuzzUDPParsers(f *testing.F) {
	f.Add(snmpGet("public"))
	f.Add(dnsQuery("a.b", 1))
	f.Add(crlf("REGISTER sip:x SIP/2.0\n\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, p := range udpHandlers {
			if out, _ := json.Marshal(p(b)); len(out) > maxEventBytes {
				t.Fatalf("Ereignis zu groß: %d", len(out))
			}
		}
	})
}
