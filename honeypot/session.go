package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"math/rand/v2"
	"net"
	"strings"
	"time"
	"unicode/utf8"
)

// Größenbudget für Inhalte in Ereignissen (Zeichen nach printable/clip).
const (
	budgetText    = 2048 // Body, Payload, Header-Block
	budgetPath    = 1024
	budgetShort   = 256 // Host, SNI, Pfad im Login usw.
	budgetCommand = 2048
)

// Session ist eine einzelne Verbindung eines Angreifers.
type Session struct {
	m       *Manager
	rl      *runListener
	Conn    net.Conn
	Service string
	Mode    string
	ID      string
	SrcIP   string
	SrcPort int
	DstPort int
	Start   time.Time

	tarpitted   bool
	tarpitStart time.Time
	bytesOut    int64
}

func (s *Session) Emit(ev Event) {
	ev.Service = s.Service
	ev.SrcIP, ev.SrcPort, ev.DstPort, ev.Session = s.SrcIP, s.SrcPort, s.DstPort, s.ID
	// Drossel pro IP; das Verbindungsende eines Tarpits zählt immer (für die Statistik).
	if !(ev.Type == "disconnect" && ev.Tarpit) && !s.m.rate.Allow(s.SrcIP) {
		s.m.em.throttled.Add(1)
		return
	}
	s.m.em.Emit(ev)
}

func (s *Session) Login(user, pass string, data map[string]any) {
	s.Emit(Event{Type: "login", Username: clip(user, 256), Password: clip(pass, 256), Data: data})
}

func (s *Session) Command(input string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["input"] = clip(input, budgetCommand)
	s.Emit(Event{Type: "command", Data: data})
}

func (s *Session) Write(b []byte) error {
	s.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	n, err := s.Conn.Write(b)
	s.bytesOut += int64(n)
	return err
}

func (s *Session) WriteString(str string) error { return s.Write([]byte(str)) }

func (s *Session) ReadDeadline(d time.Duration) { s.Conn.SetReadDeadline(time.Now().Add(d)) }

// Tarpit hält die Verbindung fest: erst prefix, dann in jedem Intervall ein
// kleines Stück aus next(). Blockiert, bis der Angreifer aufgibt, das Limit
// greift oder die maximale Dauer erreicht ist.
func (s *Session) Tarpit(prefix []byte, next func() []byte) {
	if !s.m.limits.AcquireTarpit(s.SrcIP) {
		return // zu viele festgehaltene Verbindungen: einfach schließen
	}
	defer s.m.limits.ReleaseTarpit(s.SrcIP)
	s.rl.tarpitting.Add(1)
	defer s.rl.tarpitting.Add(-1)
	s.tarpitted = true
	s.tarpitStart = time.Now()

	// Eingaben des Angreifers verwerfen und erkennen, wann er auflegt.
	gone := make(chan struct{})
	go func() {
		s.Conn.SetReadDeadline(time.Time{})
		buf := make([]byte, 512)
		for {
			if _, err := s.Conn.Read(buf); err != nil {
				close(gone)
				return
			}
		}
	}()

	if len(prefix) > 0 && s.Write(prefix) != nil {
		return
	}
	var until time.Time
	if mx := s.m.TarpitCfg().MaxDurationMin; mx > 0 {
		until = s.tarpitStart.Add(time.Duration(mx) * time.Minute)
	}
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		iv := s.m.TarpitCfg().IntervalMs
		// +-20 % Zufall, damit es nicht maschinell aussieht
		d := time.Duration(iv)*time.Millisecond*8/10 + time.Duration(rand.Int64N(int64(iv)*4/10+1))*time.Millisecond
		timer.Reset(d)
		select {
		case <-gone:
			return
		case <-timer.C:
		}
		if !until.IsZero() && time.Now().After(until) {
			return
		}
		if s.Write(next()) != nil {
			return
		}
	}
}

// ---- Hilfsfunktionen ----

func randHex(n int) string {
	b := make([]byte, n)
	crand.Read(b)
	return hex.EncodeToString(b)
}

const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randWord(min, max int) string {
	n := min + rand.IntN(max-min+1)
	b := make([]byte, n)
	for i := range b {
		b[i] = alnum[rand.IntN(len(alnum))]
	}
	return string(b)
}

// clip kürzt auf höchstens n Bytes. Am Schnitt wird höchstens ein angeschnittenes
// UTF-8-Zeichen entfernt; ungültige Bytes im Text werden ersetzt statt den Text abzuschneiden.
func clip(s string, n int) string {
	if len(s) > n {
		s = s[:n]
		for k := 0; k < 3 && len(s) > 0; k++ {
			r, size := utf8.DecodeLastRuneInString(s)
			if r != utf8.RuneError || size != 1 {
				break
			}
			s = s[:len(s)-1]
		}
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return s
}

// printable macht beliebige Bytes anzeigbar (nicht druckbare Zeichen als \xNN).
// maxOut begrenzt die LÄNGE DER AUSGABE, nicht der Eingabe; gekürzt wird mit "…".
func printable(b []byte, maxOut int) string {
	var sb strings.Builder
	for _, c := range b {
		if sb.Len() >= maxOut-4 {
			sb.WriteString("…")
			break
		}
		switch {
		case c == '\n':
			sb.WriteString("\\n")
		case c == '\r':
			sb.WriteString("\\r")
		case c == '\t':
			sb.WriteString("\\t")
		case c == '\\':
			sb.WriteString("\\\\")
		case c >= 32 && c < 127:
			sb.WriteByte(c)
		default:
			sb.WriteString("\\x")
			sb.WriteString(hex.EncodeToString([]byte{c}))
		}
	}
	return sb.String()
}

var errLineTooLong = errors.New("Zeile zu lang")

func readLine(br *bufio.Reader, max int) (string, error) {
	var sb strings.Builder
	for {
		frag, isPrefix, err := br.ReadLine()
		if err != nil {
			if err == io.EOF && sb.Len() > 0 {
				return sb.String(), nil
			}
			return "", err
		}
		sb.Write(frag)
		if sb.Len() > max {
			return "", errLineTooLong
		}
		if !isPrefix {
			return sb.String(), nil
		}
	}
}

// capReader begrenzt, wie viele Bytes insgesamt gelesen werden dürfen (pro Anfrage
// neu gesetzt). Ist das Budget erschöpft, liefert er EOF statt weiter zu puffern.
type capReader struct {
	r io.Reader
	n int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > c.n {
		p = p[:c.n]
	}
	n, err := c.r.Read(p)
	c.n -= int64(n)
	return n, err
}

func selfSignedTLS(host string) (*tls.Config, time.Time, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return nil, time.Time{}, err
	}
	serial, _ := crand.Int(crand.Reader, big.NewInt(1<<62))
	notAfter := time.Now().Add(365 * 24 * time.Hour)
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{host}},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-30 * 24 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(crand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, time.Time{}, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS10,
	}, notAfter, nil
}
