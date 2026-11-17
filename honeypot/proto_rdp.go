package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"strings"
	"time"
	"unicode/utf16"
)

// ---------------- RDP ----------------
//
// Wertet die erste Nachricht aus (X.224 Connection Request): das Cookie
// "mstshash=<Benutzer>" und die gewünschten Sicherheitsprotokolle. Danach wird
// wie ein Windows-Server ohne NLA geantwortet: TLS, wenn der Client es anbietet,
// sonst klassische RDP-Sicherheit. Aus dem folgenden "MCS Connect Initial" werden
// Rechnername, Build und Tastaturlayout des Clients gelesen. Dort endet die Emulation.
//
// Grenze: kein CredSSP/NLA. Clients, die NLA verlangen, bekommen TLS angeboten und
// brechen meist ab; Benutzername und Passwort aus NLA werden nicht erfasst.

const (
	rdpProtoSSL    = 1
	rdpProtoHybrid = 2
	rdpMaxPDU      = 16 << 10
)

type rdpRequest struct {
	Cookie    string // Wert hinter "mstshash=" (Benutzername, vom Client oft gekürzt)
	Token     string // sonstige Routing-Zeile
	Protocols uint32
	HasNeg    bool
}

var errNotTPKT = errors.New("kein TPKT")

// readTPKT liest ein TPKT-Paket (Kopf 03 00 Länge) und liefert den Inhalt ohne Kopf.
// Bei errNotTPKT enthält das Ergebnis die vier gelesenen Bytes.
func readTPKT(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[2:]))
	if hdr[0] != 3 || n < 5 || n > rdpMaxPDU {
		return hdr, errNotTPKT
	}
	p := make([]byte, n-4)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	return p, nil
}

// parseRDPRequest wertet ein X.224 Connection Request aus (ohne TPKT-Kopf).
func parseRDPRequest(p []byte) (rdpRequest, bool) {
	var r rdpRequest
	if len(p) < 7 || p[1]&0xf0 != 0xe0 {
		return r, false
	}
	rest := p[7:]
	if i := bytes.Index(rest, []byte("\r\n")); i >= 0 {
		line := string(rest[:i])
		if v, ok := strings.CutPrefix(line, "Cookie: mstshash="); ok {
			r.Cookie = v
		} else {
			r.Token = line
		}
		rest = rest[i+2:]
	}
	if len(rest) >= 8 && rest[0] == 1 && binary.LittleEndian.Uint16(rest[2:4]) == 8 {
		r.HasNeg = true
		r.Protocols = binary.LittleEndian.Uint32(rest[4:8])
	}
	return r, true
}

// rdpConfirm baut das X.224 Connection Confirm; neg=false für Clients ohne Verhandlung.
func rdpConfirm(neg bool, selected uint32) []byte {
	if !neg {
		return []byte{3, 0, 0, 11, 6, 0xd0, 0, 0, 0x12, 0x34, 0}
	}
	out := []byte{3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, 2, 0, 8, 0}
	return binary.LittleEndian.AppendUint32(out, selected)
}

// rdpClientInfo sucht im MCS Connect Initial den Block CS_CORE (Typ 0xC001) und
// liest Build, Tastaturlayout und Rechnername (UTF-16, höchstens 16 Zeichen).
func rdpClientInfo(p []byte) (name string, build, layout uint32, ok bool) {
	i := bytes.Index(p, []byte("Duca"))
	if i < 0 {
		return
	}
	j := bytes.Index(p[i:], []byte{0x01, 0xc0})
	if j < 0 {
		return
	}
	b := p[i+j:]
	if len(b) < 24+32 {
		return
	}
	layout = binary.LittleEndian.Uint32(b[16:20])
	build = binary.LittleEndian.Uint32(b[20:24])
	u := make([]uint16, 0, 16)
	for k := 24; k < 56; k += 2 {
		c := binary.LittleEndian.Uint16(b[k:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u)), build, layout, true
}

func rdpProtoNames(p uint32) string {
	var n []string
	for _, x := range []struct {
		bit  uint32
		name string
	}{{1, "TLS"}, {2, "NLA"}, {4, "RDSTLS"}, {8, "NLA-EX"}} {
		if p&x.bit != 0 {
			n = append(n, x.name)
		}
	}
	if len(n) == 0 {
		return "RDP"
	}
	return strings.Join(n, "+")
}

func handleRDP(s *Session) {
	drip := func() []byte { return []byte{byte(rand.IntN(256))} }
	if s.Mode == "tarpit" {
		s.Tarpit(nil, drip)
		return
	}
	raw := func(p []byte) {
		if len(p) > 0 {
			s.Emit(Event{Type: "payload", Data: map[string]any{"text": printable(p, budgetText), "bytes": len(p)}})
		}
	}
	s.ReadDeadline(15 * time.Second)
	p, err := readTPKT(s.Conn)
	if err != nil {
		raw(p) // kein RDP: Anfang festhalten
		return
	}
	req, ok := parseRDPRequest(p)
	if !ok {
		raw(p)
		return
	}
	protos := rdpProtoNames(req.Protocols)
	if req.Cookie != "" {
		data := map[string]any{"cookie": true, "protocols": protos} // nur ein Name, kein Passwort
		s.Login(pr(req.Cookie, 256), "", data)
	} else {
		data := map[string]any{"method": "RDP", "path": "Verbindungsanfrage (" + protos + ")"}
		if req.Token != "" {
			data["token"] = pr(req.Token, budgetShort)
		}
		s.Emit(Event{Type: "request", Data: data})
	}
	if s.Mode == "hybrid" {
		s.Tarpit(nil, drip)
		return
	}
	useTLS := req.HasNeg && req.Protocols&(rdpProtoSSL|rdpProtoHybrid) != 0
	sel := uint32(0)
	if useTLS {
		sel = rdpProtoSSL
	}
	if s.Write(rdpConfirm(req.HasNeg, sel)) != nil {
		return
	}
	if useTLS {
		tc := s.m.tlsConf.Load()
		if tc == nil {
			return
		}
		conn := tls.Server(s.Conn, tc)
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if conn.Handshake() != nil {
			return
		}
		conn.SetDeadline(time.Time{})
		s.Conn = conn
	}
	s.ReadDeadline(15 * time.Second)
	mcs, err := readTPKT(s.Conn)
	if err != nil {
		return
	}
	if name, build, layout, ok := rdpClientInfo(mcs); ok {
		s.Emit(Event{Type: "client_version", Data: map[string]any{
			"version":     fmt.Sprintf("RDP-Client Build %d", build),
			"client_name": pr(name, 64), "keyboard_layout": fmt.Sprintf("0x%04x", layout),
		}})
	}
}
