package main

import (
	"bufio"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/rand/v2"
	"strings"
	"time"
)

// ---------------- VNC (RFB) ----------------
//
// Spielt den Anfang des RFB-Protokolls bis zur VNC-Authentifizierung nach:
// Der Client schickt seine DES-Antwort auf unsere 16-Byte-Challenge. Das Passwort
// selbst wird bei VNC nie übertragen; Challenge und Antwort werden gespeichert
// (damit lässt sich offline prüfen, welches Passwort versucht wurde).
// Clients, die keinen Typ 2 wählen, erscheinen nur mit ihrer Protokollversion.

func handleVNC(s *Session) {
	drip := func() []byte { return []byte{byte(rand.IntN(256))} }
	if s.Mode == "tarpit" {
		s.Tarpit(nil, drip)
		return
	}
	if s.WriteString("RFB 003.008\n") != nil {
		return
	}
	s.ReadDeadline(20 * time.Second)
	br := bufio.NewReaderSize(s.Conn, 256)
	ver := make([]byte, 12)
	if n, err := io.ReadFull(br, ver); err != nil {
		if n > 0 {
			s.Emit(Event{Type: "payload", Data: map[string]any{"text": printable(ver[:n], budgetText), "bytes": n}})
		}
		return
	}
	if !strings.HasPrefix(string(ver), "RFB ") {
		s.Emit(Event{Type: "payload", Data: map[string]any{"text": printable(ver, budgetText), "bytes": len(ver)}})
		return
	}
	s.Emit(Event{Type: "client_version", Data: map[string]any{"version": printable(ver[:11], 32)}})
	old := string(ver[4:11]) == "003.003" // RFB 3.3: der Server bestimmt den Typ
	if old {
		if s.Write([]byte{0, 0, 0, 2}) != nil {
			return
		}
	} else {
		if s.Write([]byte{1, 2}) != nil { // ein Sicherheitstyp: 2 = VNC-Authentifizierung
			return
		}
		sel, err := br.ReadByte()
		if err != nil || sel != 2 {
			return
		}
	}
	challenge := make([]byte, 16)
	crand.Read(challenge)
	if s.Write(challenge) != nil {
		return
	}
	resp := make([]byte, 16)
	if _, err := io.ReadFull(br, resp); err != nil {
		return
	}
	s.Login("", "", map[string]any{
		"password_hashed": true, "challenge": hex.EncodeToString(challenge), "response": hex.EncodeToString(resp),
	})
	if s.Mode == "hybrid" {
		s.Tarpit(nil, drip)
		return
	}
	const reason = "Authentication failed"
	out := []byte{0, 0, 0, 1} // SecurityResult: fehlgeschlagen
	if !old {
		out = binary.BigEndian.AppendUint32(out, uint32(len(reason)))
		out = append(out, reason...)
	}
	s.Write(out)
}
