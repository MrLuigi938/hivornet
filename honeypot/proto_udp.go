package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// ---------------- UDP: SIP, SNMP, DNS ----------------
//
// Diese Dienste zeichnen nur auf und ANTWORTEN NIE. Bei UDP lässt sich die
// Absenderadresse fälschen; jede Antwort könnte ein Angreifer nutzen, um Dritte mit
// unseren Paketen zu überfluten (Reflexion/Verstärkung, typisch bei DNS und SNMP).
// Scanner verraten trotzdem, was sie suchen: SIP-Scanner ihren User-Agent und ihre
// Zielnummer, SNMP-Scanner den Community-String, DNS-Scanner die Abfrage.
//
// Grenzen: höchstens udpMaxPacket Bytes je Paket werden gelesen, die Drossel je IP
// gilt wie bei TCP. Modi (tarpit/hybrid) haben bei UDP keine Bedeutung.
// Die Absender-IP kann gefälscht sein; das steht auch in der README.

const udpMaxPacket = 2048

// udpHandlers wertet ein Paket aus und liefert das Ereignis (ohne Absenderfelder).
// Wie "handlers" (manager.go) die einzige Liste der UDP-Dienste.
var udpHandlers = map[string]func(p []byte) Event{
	"sip":  sipEvent,
	"snmp": snmpEvent,
	"dns":  dnsEvent,
}

func isUDP(service string) bool { return udpHandlers[service] != nil }

func rawEvent(p []byte) Event {
	return Event{Type: "payload", Data: map[string]any{"text": printable(p, budgetText), "bytes": len(p)}}
}

// ---- SIP ----

func sipEvent(p []byte) Event {
	head, _, _ := bytes.Cut(p, []byte("\r\n\r\n"))
	lines := strings.Split(string(head), "\r\n")
	f := strings.Fields(lines[0])
	if len(f) != 3 || !strings.HasPrefix(f[2], "SIP/") {
		return rawEvent(p)
	}
	data := map[string]any{"method": pr(f[0], 16), "path": pr(f[1], budgetPath), "version": pr(f[2], 16)}
	var hdr strings.Builder
	for _, l := range lines[1:] {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "user-agent":
			data["user_agent"] = pr(strings.TrimSpace(v), budgetShort)
		case "from", "f":
			data["from"] = pr(strings.TrimSpace(v), budgetShort)
		case "to", "t":
			data["to"] = pr(strings.TrimSpace(v), budgetShort)
		}
		hdr.WriteString(l + "\n")
	}
	data["headers"] = pr(hdr.String(), 1536)
	return Event{Type: "request", Data: data}
}

// ---- SNMP (v1/v2c; v3 nur als Rohdaten) ----

// berTLV liest Typ und Länge an Position i; liefert den Inhalt und die Position danach.
func berTLV(b []byte, i int) (tag byte, val []byte, next int, err error) {
	if i+2 > len(b) {
		return 0, nil, 0, errors.New("zu kurz")
	}
	tag = b[i]
	n := int(b[i+1])
	i += 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 2 || i+k > len(b) {
			return 0, nil, 0, errors.New("Länge ungültig")
		}
		n = 0
		for j := 0; j < k; j++ {
			n = n<<8 | int(b[i+j])
		}
		i += k
	}
	if n > len(b)-i {
		return 0, nil, 0, errors.New("Länge zu groß")
	}
	return tag, b[i : i+n], i + n, nil
}

var snmpPDU = map[byte]string{0xa0: "get", 0xa1: "getnext", 0xa2: "response", 0xa3: "set", 0xa5: "getbulk", 0xa6: "inform", 0xa7: "trap", 0xa4: "trap-v1"}

func snmpEvent(p []byte) Event {
	tag, seq, _, err := berTLV(p, 0)
	if err != nil || tag != 0x30 {
		return rawEvent(p)
	}
	tag, ver, i, err := berTLV(seq, 0)
	if err != nil || tag != 0x02 || len(ver) != 1 {
		return rawEvent(p)
	}
	version := map[byte]string{0: "v1", 1: "v2c", 3: "v3"}[ver[0]]
	if version == "" || version == "v3" {
		e := rawEvent(p)
		e.Data["snmp_version"] = version
		return e
	}
	tag, comm, i, err := berTLV(seq, i)
	if err != nil || tag != 0x04 {
		return rawEvent(p)
	}
	pdu := "unbekannt"
	if i < len(seq) {
		if n, ok := snmpPDU[seq[i]]; ok {
			pdu = n
		}
	}
	// Der Community-String ist bei SNMP v1/v2c das Passwort; er geht im Klartext übers Netz.
	return Event{Type: "login", Username: "community", Password: pr(string(comm), 256),
		Data: map[string]any{"snmp_version": version, "pdu": pdu}}
}

// ---- DNS ----

var dnsTypes = map[uint16]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 43: "DS", 48: "DNSKEY", 255: "ANY", 252: "AXFR", 65: "HTTPS", 46: "RRSIG"}

func dnsEvent(p []byte) Event {
	if len(p) < 17 {
		return rawEvent(p)
	}
	flags := binary.BigEndian.Uint16(p[2:4])
	qd := binary.BigEndian.Uint16(p[4:6])
	if flags&0x8000 != 0 || qd == 0 { // Antwort statt Anfrage oder keine Frage
		return rawEvent(p)
	}
	var labels []string
	i, total := 12, 0
	for {
		if i >= len(p) {
			return rawEvent(p)
		}
		n := int(p[i])
		i++
		if n == 0 {
			break
		}
		if n&0xc0 != 0 || i+n > len(p) || total+n > 253 { // Zeiger gibt es in der Frage nicht
			return rawEvent(p)
		}
		labels = append(labels, string(p[i:i+n]))
		total += n + 1
		i += n
	}
	if i+4 > len(p) {
		return rawEvent(p)
	}
	qt := binary.BigEndian.Uint16(p[i : i+2])
	typ, ok := dnsTypes[qt]
	if !ok {
		typ = fmt.Sprintf("TYPE%d", qt)
	}
	name := strings.Join(labels, ".") + "."
	return Event{Type: "request", Data: map[string]any{
		"method": "DNS " + typ, "path": pr(name, budgetShort), "recursion": flags&0x0100 != 0, "edns": len(p) > i+4,
	}}
}

// ---- Empfang ----

func (m *Manager) serveUDP(rl *runListener) {
	buf := make([]byte, udpMaxPacket)
	for {
		n, addr, err := rl.pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		rl.total.Add(1)
		cfg := *rl.cfg.Load()
		ip, sport := splitAddr(addr)
		if pip := net.ParseIP(ip); pip != nil && m.fromOwnNet(pip) {
			m.proxied.Add(1)
		}
		if n == 0 || !m.rate.Allow(ip) {
			m.em.throttled.Add(1)
			continue
		}
		ev := m.parseUDP(cfg.Service, buf[:n])
		ev.Service, ev.SrcIP, ev.SrcPort, ev.DstPort = cfg.Service, ip, sport, cfg.Port
		m.em.Emit(ev)
	}
}

// parseUDP ruft den Parser des Dienstes auf, abgesichert gegen Fehler in den Parsern.
func (m *Manager) parseUDP(service string, p []byte) (ev Event) {
	defer func() {
		if recover() != nil {
			ev = rawEvent(p)
		}
	}()
	if h := udpHandlers[service]; h != nil {
		return h(p)
	}
	return rawEvent(p)
}
