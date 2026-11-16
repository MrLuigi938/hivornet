package main

// Fingerabdrücke von Clients:
//   - JA3 und JA4 aus dem TLS-ClientHello (HTTPS und TLS-Handshakes an Klartext-Ports;
//     der Honeypot schickt die Rohdaten als data.client_hello, Hex),
//   - Reihenfolge der HTTP-Kopfzeilen (data.header_order), als kurzer Hash,
//   - HASSH liefert Cowrie selbst (Ereignis fingerprint).
// Gleiche Fingerabdrücke bei verschiedenen IPs deuten auf dasselbe Werkzeug hin
// (Kampagnen, campaigns.go).
//
// JA3: Salesforce, BSD-3-Clause. JA4 (nur der TLS-Client-Teil): FoxIO, BSD-3-Clause;
// die übrigen JA4+-Verfahren stehen unter einer anderen Lizenz und werden nicht genutzt.

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type clientHello struct {
	Version    uint16
	Ciphers    []uint16
	Exts       []uint16
	Groups     []uint16
	PointFmts  []uint8
	SigAlgs    []uint16
	Versions   []uint16
	ALPN       []string
	SNI        string
	HasSNI     bool
	recordSize int
}

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

var errHello = errors.New("kein vollständiger ClientHello")

// parseClientHello liest einen TLS-Record mit ClientHello (wie vom Honeypot geliefert).
func parseClientHello(b []byte) (*clientHello, error) {
	if len(b) < 9 || b[0] != 0x16 || b[5] != 0x01 {
		return nil, errHello
	}
	h := &clientHello{recordSize: len(b)}
	p := b[9:]
	if hl := int(b[6])<<16 | int(b[7])<<8 | int(b[8]); hl < len(p) {
		p = p[:hl]
	}
	need := func(n int) bool { return len(p) >= n }
	if !need(2 + 32 + 1) {
		return nil, errHello
	}
	h.Version = binary.BigEndian.Uint16(p)
	p = p[34:]
	sid := int(p[0])
	if !need(1 + sid + 2) {
		return nil, errHello
	}
	p = p[1+sid:]
	cl := int(binary.BigEndian.Uint16(p))
	if !need(2+cl+1) || cl%2 != 0 {
		return nil, errHello
	}
	for i := 0; i < cl; i += 2 {
		h.Ciphers = append(h.Ciphers, binary.BigEndian.Uint16(p[2+i:]))
	}
	p = p[2+cl:]
	comp := int(p[0])
	if !need(1 + comp) {
		return nil, errHello
	}
	p = p[1+comp:]
	if len(p) < 2 {
		return h, nil // ohne Erweiterungen
	}
	el := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if el > len(p) {
		return nil, errHello
	}
	p = p[:el]
	for len(p) >= 4 {
		t, l := binary.BigEndian.Uint16(p), int(binary.BigEndian.Uint16(p[2:]))
		if 4+l > len(p) {
			return nil, errHello
		}
		d := p[4 : 4+l]
		h.Exts = append(h.Exts, t)
		switch t {
		case 0x0000: // server_name
			h.HasSNI = true
			if len(d) >= 5 {
				if n := int(binary.BigEndian.Uint16(d[3:])); 5+n <= len(d) {
					h.SNI = string(d[5 : 5+n])
				}
			}
		case 0x000a: // supported_groups
			h.Groups = u16list(d, 2)
		case 0x000b: // ec_point_formats
			if len(d) >= 1 && int(d[0])+1 <= len(d) {
				h.PointFmts = append(h.PointFmts, d[1:1+int(d[0])]...)
			}
		case 0x000d: // signature_algorithms
			h.SigAlgs = u16list(d, 2)
		case 0x002b: // supported_versions
			if len(d) >= 1 {
				h.Versions = u16list(d[1:], 0)
			}
		case 0x0010: // ALPN
			if len(d) >= 2 {
				q := d[2:]
				for len(q) >= 1 && int(q[0])+1 <= len(q) {
					h.ALPN = append(h.ALPN, string(q[1:1+int(q[0])]))
					q = q[1+int(q[0]):]
				}
			}
		}
		p = p[4+l:]
	}
	return h, nil
}

// u16list: Liste von 16-Bit-Werten nach einem Längenfeld von skip Bytes.
func u16list(d []byte, skip int) []uint16 {
	if len(d) < skip {
		return nil
	}
	d = d[skip:]
	var out []uint16
	for i := 0; i+1 < len(d); i += 2 {
		out = append(out, binary.BigEndian.Uint16(d[i:]))
	}
	return out
}

func joinU16(v []uint16, sep string, f func(uint16) string) string {
	var s []string
	for _, x := range v {
		if !isGREASE(x) {
			s = append(s, f(x))
		}
	}
	return strings.Join(s, sep)
}

func dec(x uint16) string  { return strconv.Itoa(int(x)) }
func hex4(x uint16) string { return fmt.Sprintf("%04x", x) }

// JA3 liefert die JA3-Zeichenkette und ihren MD5-Hash.
func (h *clientHello) JA3() (string, string) {
	var pf []string
	for _, x := range h.PointFmts {
		pf = append(pf, strconv.Itoa(int(x)))
	}
	s := strings.Join([]string{dec(h.Version), joinU16(h.Ciphers, "-", dec), joinU16(h.Exts, "-", dec),
		joinU16(h.Groups, "-", dec), strings.Join(pf, "-")}, ",")
	sum := md5.Sum([]byte(s))
	return s, hex.EncodeToString(sum[:])
}

func sha12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

var ja4Versions = map[uint16]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2", 0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3"}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// JA4 liefert den JA4-Fingerabdruck (TLS über TCP).
func (h *clientHello) JA4() string {
	ver, best := h.Version, uint16(0) // supported_versions hat Vorrang (höchster Wert ohne GREASE)
	for _, v := range h.Versions {
		if !isGREASE(v) && v > best {
			best = v
		}
	}
	if best != 0 {
		ver = best
	}
	vs, ok := ja4Versions[ver]
	if !ok {
		vs = "00"
	}
	sni := "i"
	if h.HasSNI {
		sni = "d"
	}
	var ciphers, exts []string
	for _, c := range h.Ciphers {
		if !isGREASE(c) {
			ciphers = append(ciphers, hex4(c))
		}
	}
	nExt := 0
	for _, e := range h.Exts {
		if isGREASE(e) {
			continue
		}
		nExt++
		if e != 0x0000 && e != 0x0010 {
			exts = append(exts, hex4(e))
		}
	}
	alpn := "00"
	if len(h.ALPN) > 0 && h.ALPN[0] != "" {
		a := h.ALPN[0]
		f, l := a[0], a[len(a)-1]
		if isAlnum(f) && isAlnum(l) {
			alpn = string([]byte{f, l})
		} else {
			hx := hex.EncodeToString([]byte(a))
			alpn = string([]byte{hx[0], hx[len(hx)-1]})
		}
	}
	sort.Strings(ciphers)
	sort.Strings(exts)
	c := strings.Join(exts, ",")
	if sig := joinU16(h.SigAlgs, ",", hex4); sig != "" && c != "" {
		c += "_" + sig
	}
	return fmt.Sprintf("t%s%s%02d%02d%s_%s_%s", vs, sni, min(len(ciphers), 99), min(nExt, 99), alpn, sha12(strings.Join(ciphers, ",")), sha12(c))
}

// tlsFingerprints wertet data.client_hello eines tls-Ereignisses aus.
func tlsFingerprints(e *Event) (ja3, ja3hash, ja4 string, ok bool) {
	if e.Type != "tls" {
		return
	}
	raw, err := hex.DecodeString(dataString(e.Data, "client_hello"))
	if err != nil || len(raw) == 0 {
		return
	}
	h, err := parseClientHello(raw)
	if err != nil {
		return
	}
	ja3, ja3hash = h.JA3()
	return ja3, ja3hash, h.JA4(), true
}

// headerFingerprint: kurzer Hash der Reihenfolge der HTTP-Kopfzeilen (klein geschrieben).
func headerFingerprint(e *Event) (hash, order string) {
	order = dataString(e.Data, "header_order")
	if e.Type != "request" || order == "" {
		return "", ""
	}
	return sha12(strings.ToLower(order)), order
}

// eventFingerprints: alle Fingerabdrücke eines Ereignisses als "Art Wert".
func eventFingerprints(e *Event) []string {
	var out []string
	if _, j3, j4, ok := tlsFingerprints(e); ok {
		out = append(out, "JA4 "+j4, "JA3 "+j3)
	}
	if e.Type == "fingerprint" {
		if h := dataString(e.Data, "hassh"); h != "" {
			out = append(out, "HASSH "+h)
		}
	}
	if h, _ := headerFingerprint(e); h != "" {
		out = append(out, "HTTP "+h)
	}
	return out
}
