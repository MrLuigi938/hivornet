package main

// Fremde Protokolle an Zeilendiensten: Scanner schicken HTTP-Anfragen, TLS-Handshakes oder
// Binärdaten an jeden offenen Port (Redis 6379, FTP, SMTP, Telnet …). Früher landete dort
// jede Kopfzeile einer HTTP-Anfrage ("Host: …", "User-Agent: …") als eigener "Befehl" in
// den Listen, samt der öffentlichen Adresse des Honeypots im Host-Kopf. sniffForeign
// erkennt solche Eingaben, bevor der Dienst sie als Befehl liest, und meldet sie als EIN
// Ereignis: "tls" (wie bisher, siehe sniffTLS) oder "payload" mit foreign=http bzw. binary.
// Der Hive stuft beides als Abtasten ein (Muster tls_on_plain, http_on_raw).

import (
	"bufio"
	"bytes"
	"regexp"
	"time"
)

// httpRequestRe: Anfragezeile einer HTTP-Anfrage (ohne Zeilenende).
var httpRequestRe = regexp.MustCompile(`^(GET|POST|HEAD|PUT|DELETE|OPTIONS|CONNECT|PATCH|TRACE|PRI) \S+ HTTP/\d(\.\d)?$`)

// foreignMax: so viele Bytes einer fremden Eingabe werden höchstens gelesen und gemeldet.
const foreignMax = 4096

// isHTTPRequestLine: line ist die erste Zeile einer HTTP-Anfrage.
func isHTTPRequestLine(line string) bool {
	return httpRequestRe.MatchString(string(bytes.TrimRight([]byte(line), "\r")))
}

// binaryStart: ein Zeilenprotokoll beginnt nie mit diesem Byte (Steuerzeichen außer
// Tab/CR/LF, DEL und alles ab 0x80).
func binaryStart(c byte) bool {
	return c < 0x20 && c != '\t' && c != '\r' && c != '\n' || c >= 0x7f
}

// sniffForeign prüft die nächste Eingabe, ohne sie zu verbrauchen, solange sie zum Dienst
// passt. Erkennt es einen TLS-Handshake, eine HTTP-Anfrage oder (binary=true, nur für
// Textprotokolle) Binärdaten, liest es diese (höchstens foreignMax Bytes), meldet sie als
// ein Ereignis und liefert die Art ("tls", "http", "binary") sowie die gelesenen Bytes.
// Der Aufrufer antwortet dann höchstens noch einmal und beendet die Verbindung. Die
// Lesefrist setzt der Aufrufer vorher. HTTP erkennt es nur, wenn die Anfragezeile schon
// vollständig angekommen ist (Scanner schicken die Anfrage in einem Stück).
func (s *Session) sniffForeign(br *bufio.Reader, binary bool) (string, []byte) {
	b, err := br.Peek(1)
	if err != nil {
		return "", nil
	}
	if b[0] == 0x16 && s.sniffTLS(br) {
		return "tls", nil
	}
	buf, _ := br.Peek(min(br.Buffered(), foreignMax))
	if i := bytes.IndexByte(buf, '\n'); i > 0 && isHTTPRequestLine(string(buf[:i])) {
		return "http", s.recordForeign(br, "http")
	}
	if binary && binaryStart(b[0]) {
		return "binary", s.recordForeign(br, "binary")
	}
	return "", nil
}

// recordForeign liest eine fremde Eingabe (HTTP: bis zum Ende der Kopfzeilen samt schon
// angekommenem Rumpf; Binärdaten: was gerade vorliegt) und meldet sie als "payload".
func (s *Session) recordForeign(br *bufio.Reader, kind string) []byte {
	s.ReadDeadline(2 * time.Second)
	data := make([]byte, 0, 1024)
	tmp := make([]byte, 1024)
	for len(data) < foreignMax {
		if len(data) > 0 && br.Buffered() == 0 &&
			(kind != "http" || bytes.Contains(data, []byte("\r\n\r\n")) || bytes.Contains(data, []byte("\n\n"))) {
			break
		}
		n, err := br.Read(tmp[:min(len(tmp), foreignMax-len(data))])
		data = append(data, tmp[:n]...)
		if err != nil {
			break
		}
	}
	ev := map[string]any{"text": printable(data, budgetText), "bytes": len(data), "foreign": kind}
	if len(data) >= foreignMax {
		ev["truncated"] = true
	}
	s.Emit(Event{Type: "payload", Data: ev})
	return data
}

// httpMethod: erstes Wort der Anfrage.
func httpMethod(req []byte) string {
	m, _, _ := bytes.Cut(req, []byte(" "))
	return string(m)
}
