package main

// PostgreSQL (Port 5432): Anmeldung mit Klartext-Passwort, danach einfache Abfragen.
// Typisch sind Brute-Force auf "postgres" und anschließend COPY … FROM PROGRAM, um einen
// Miner nachzuladen. Schwache Standardpasswörter werden angenommen, damit diese Befehle
// sichtbar werden; ausgeführt wird nichts.

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	pgMaxStartup = 10000
	pgMaxMessage = 64 << 10
	pgSSLRequest = 80877103
	pgGSSRequest = 80877104
	pgCancel     = 80877102
)

// Passwörter, mit denen die Nachbildung eine Anmeldung annimmt.
var pgWeak = map[string]bool{"": true, "postgres": true, "password": true, "123456": true, "admin": true, "root": true, "postgres123": true, "12345678": true}

func pgMsg(t byte, body []byte) []byte {
	b := make([]byte, 5+len(body))
	b[0] = t
	binary.BigEndian.PutUint32(b[1:], uint32(4+len(body)))
	copy(b[5:], body)
	return b
}

func pgCStr(parts ...string) []byte {
	var b []byte
	for _, p := range parts {
		b = append(append(b, p...), 0)
	}
	return b
}

func pgError(code, msg string) []byte {
	return pgMsg('E', append(pgCStr("SFATAL", "VFATAL", "C"+code, "M"+msg), 0))
}

func pgReady() []byte { return pgMsg('Z', []byte{'I'}) }

// pgRow: eine Spalte vom Typ text mit einem Wert.
func pgRow(col, val string) []byte {
	desc := []byte{0, 1}
	desc = append(desc, pgCStr(col)...)
	desc = append(desc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0)
	row := []byte{0, 1, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(row[2:], uint32(len(val)))
	row = append(row, val...)
	return append(pgMsg('T', desc), pgMsg('D', row)...)
}

// pgVersion: Antwort auf version(), passend zur Architektur des Geräteprofils (Debian-Paket wie im offiziellen Docker-Abbild).
func pgVersion(p deviceProfile) string {
	return fmt.Sprintf("PostgreSQL 14.9 (Debian 14.9-1.pgdg120+1) on %s, compiled by gcc (Debian 12.2.0-14) 12.2.0, %d-bit", p.gnuTriple(), p.archBits())
}

func pgQueryReply(q string, p deviceProfile) []byte {
	u := strings.ToUpper(strings.TrimSpace(q))
	switch {
	case u == "":
		return append(pgMsg('I', nil), pgReady()...)
	case strings.Contains(u, "VERSION()"):
		return append(append(pgRow("version", pgVersion(p)), pgMsg('C', pgCStr("SELECT 1"))...), pgReady()...)
	case strings.HasPrefix(u, "SELECT"):
		return append(append(pgRow("?column?", "1"), pgMsg('C', pgCStr("SELECT 1"))...), pgReady()...)
	}
	tag := strings.Fields(u)[0]
	switch tag {
	case "CREATE", "DROP", "ALTER":
		if f := strings.Fields(u); len(f) > 1 {
			tag += " " + f[1]
		}
	case "COPY":
		tag = "COPY 0"
	case "INSERT":
		tag = "INSERT 0 1"
	case "UPDATE", "DELETE":
		tag += " 0"
	}
	return append(pgMsg('C', pgCStr(tag)), pgReady()...)
}

func handlePostgres(s *Session) {
	drip := func() []byte { return pgMsg('N', pgCStr("SNOTICE", "M"+randWord(4, 12))) }
	if s.Mode == "tarpit" {
		s.Tarpit(nil, drip)
		return
	}
	br := bufio.NewReader(s.Conn)
	var params map[string]string
	for tries := 0; tries < 3 && params == nil; tries++ {
		s.ReadDeadline(30 * time.Second)
		if tries == 0 && s.sniffTLS(br) {
			return
		}
		var hdr [8]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint32(hdr[:4]))
		code := binary.BigEndian.Uint32(hdr[4:])
		if n < 8 || n > pgMaxStartup {
			s.Emit(Event{Type: "payload", Data: map[string]any{"text": printable(hdr[:], budgetText)}})
			return
		}
		rest, err := readN(br, n-8)
		if err != nil {
			return
		}
		switch code {
		case pgSSLRequest, pgGSSRequest: // kein TLS: der Client fährt im Klartext fort
			s.Write([]byte{'N'})
			continue
		case pgCancel:
			return
		}
		params = map[string]string{}
		kv := strings.Split(string(rest), "\x00")
		for i := 0; i+1 < len(kv) && len(params) < 32; i += 2 {
			if kv[i] != "" {
				params[kv[i]] = kv[i+1]
			}
		}
	}
	if params == nil {
		return
	}
	user := params["user"]
	info := map[string]any{"database": printable([]byte(params["database"]), budgetShort)}
	if app := params["application_name"]; app != "" {
		info["application"] = printable([]byte(app), budgetShort)
		s.Emit(Event{Type: "client_version", Data: map[string]any{"version": printable([]byte("PostgreSQL client "+app), budgetShort)}})
	}
	// Klartext-Passwort anfordern
	s.Write(pgMsg('R', []byte{0, 0, 0, 3}))
	s.ReadDeadline(30 * time.Second)
	t, err := br.ReadByte()
	if err != nil || t != 'p' {
		return
	}
	var lenb [4]byte
	if _, err := io.ReadFull(br, lenb[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint32(lenb[:]))
	if n < 4 || n > 4096 {
		return
	}
	pw, err := readN(br, n-4)
	if err != nil {
		return
	}
	pass := strings.TrimRight(string(pw), "\x00")
	ok := pgWeak[pass] || pass == user
	info["success"] = ok
	s.Login(user, pass, info)
	if s.Mode == "hybrid" {
		s.Tarpit(nil, drip)
		return
	}
	if !ok {
		s.Write(pgError("28P01", `password authentication failed for user "`+clip(user, 64)+`"`))
		return
	}
	var out []byte
	out = append(out, pgMsg('R', []byte{0, 0, 0, 0})...)
	for _, kv := range [][2]string{{"server_version", "14.9 (Debian 14.9-1.pgdg120+1)"}, {"server_encoding", "UTF8"}, {"client_encoding", "UTF8"},
		{"DateStyle", "ISO, MDY"}, {"TimeZone", "Etc/UTC"}, {"integer_datetimes", "on"}, {"standard_conforming_strings", "on"}} {
		out = append(out, pgMsg('S', pgCStr(kv[0], kv[1]))...)
	}
	key := make([]byte, 8)
	copy(key, randHex(4))
	out = append(append(out, pgMsg('K', key)...), pgReady()...)
	if s.Write(out) != nil {
		return
	}
	for i := 0; i < 200; i++ {
		s.ReadDeadline(120 * time.Second)
		t, err := br.ReadByte()
		if err != nil {
			return
		}
		if _, err := io.ReadFull(br, lenb[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint32(lenb[:]))
		if n < 4 || n > pgMaxMessage {
			return
		}
		body, err := readN(br, n-4)
		if err != nil {
			return
		}
		switch t {
		case 'Q':
			q := strings.TrimRight(string(body), "\x00")
			s.Command(printable([]byte(q), budgetCommand), nil)
			if s.Write(pgQueryReply(q, s.m.prof())) != nil {
				return
			}
		case 'P': // erweitertes Protokoll: nur die Abfrage aufzeichnen, dann ablehnen
			parts := strings.SplitN(string(body), "\x00", 3)
			if len(parts) > 1 {
				s.Command(printable([]byte(parts[1]), budgetCommand), map[string]any{"extended": true})
			}
			s.Write(append(pgError("0A000", "extended query protocol not supported"), pgReady()...))
			return
		case 'X':
			return
		default:
			return
		}
	}
}
