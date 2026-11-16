package main

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func ext(t uint16, data []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, t)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func u16s(prefixLen int, v ...uint16) []byte {
	var d []byte
	for _, x := range v {
		d = binary.BigEndian.AppendUint16(d, x)
	}
	if prefixLen == 1 {
		return append([]byte{byte(len(d))}, d...)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(d))), d...)
}

// testHello baut einen ClientHello mit bekannten Werten (mit GREASE).
func testHello() []byte {
	sni := append(append([]byte{0, 0x0e, 0}, binary.BigEndian.AppendUint16(nil, 11)...), "example.org"...)
	var exts []byte
	exts = append(exts, ext(0x0a0a, nil)...) // GREASE
	exts = append(exts, ext(0x0000, sni)...)
	exts = append(exts, ext(0x000a, u16s(2, 0x2a2a, 0x001d, 0x0017))...)
	exts = append(exts, ext(0x000b, []byte{1, 0})...)
	exts = append(exts, ext(0x0010, []byte{0, 3, 2, 'h', '2'})...)
	exts = append(exts, ext(0x000d, u16s(2, 0x0403, 0x0804))...)
	exts = append(exts, ext(0x002b, u16s(1, 0x3a3a, 0x0304, 0x0303))...)
	body := binary.BigEndian.AppendUint16(nil, 0x0303)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0) // keine Session-ID
	body = append(body, u16s(2, 0x0a0a, 0x1301, 0xc02f)...)
	body = append(body, 1, 0) // Kompression: null
	body = append(body, binary.BigEndian.AppendUint16(nil, uint16(len(exts)))...)
	body = append(body, exts...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func TestJA3JA4(t *testing.T) {
	h, err := parseClientHello(testHello())
	if err != nil {
		t.Fatal(err)
	}
	s, hash := h.JA3()
	if s != "771,4865-49199,0-10-11-16-13-43,29-23,0" {
		t.Fatalf("JA3 %q", s)
	}
	if m := md5.Sum([]byte(s)); hash != hex.EncodeToString(m[:]) {
		t.Fatal("JA3-Hash")
	}
	sh := func(x string) string { s := sha256.Sum256([]byte(x)); return hex.EncodeToString(s[:])[:12] }
	want := "t13d0206h2_" + sh("1301,c02f") + "_" + sh("000a,000b,000d,002b_0403,0804")
	if got := h.JA4(); got != want || h.SNI != "example.org" {
		t.Fatalf("JA4 %q, erwartet %q (SNI %q)", got, want, h.SNI)
	}
	if _, err := parseClientHello(testHello()[:40]); err == nil {
		t.Fatal("abgeschnittener ClientHello angenommen")
	}
}

// Ein echter Go-Client: Fingerabdrücke entstehen, JA4 beginnt mit t13d.
func TestTLSFingerprintRealClient(t *testing.T) {
	a, b := net.Pipe()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: "nas.example", InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Handshake()
		a.Close()
	}()
	hdr := make([]byte, 5)
	io.ReadFull(b, hdr)
	rec := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	io.ReadFull(b, rec)
	b.Close()
	e := evAt(time.Time{}, "tls", "https", "", 443, map[string]any{"client_hello": hex.EncodeToString(append(hdr, rec...))})
	_, j3, j4, ok := tlsFingerprints(e)
	if !ok || len(j3) != 32 || !strings.HasPrefix(j4, "t13d") || !strings.Contains(j4, "h2_") {
		t.Fatalf("JA3 %q JA4 %q", j3, j4)
	}
	found := map[string]bool{}
	for _, k := range topKeys(e) {
		found[k[0]] = true
	}
	if !found["ja3"] || !found["ja4"] {
		t.Fatalf("Zähltabelle: %v", topKeys(e))
	}
	a2 := attackOf(e, evAt(time.Time{}, "request", "https", "", 443, map[string]any{"path": "/", "header_order": "Host,User-Agent,Accept"}))
	if len(a2.Fingerprints) != 3 {
		t.Fatalf("Fingerabdrücke am Angriff: %v", a2.Fingerprints)
	}
}
