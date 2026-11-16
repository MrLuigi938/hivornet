package main

import (
	"bufio"
	"encoding/base64"
	"strings"
	"time"
)

// ---------------- SMTP ----------------
//
// Gibt sich als Postfix aus, der Anmeldung (AUTH PLAIN/LOGIN) anbietet und
// scheinbar jede Mail annimmt. Es wird NIE etwas weitergeleitet: Die Mail wird
// gelesen (höchstens smtpMaxData), der Anfang als Ereignis gespeichert und der
// Rest verworfen. So zeigen Spam-Bots Zugangsdaten, Absender und Inhalte.

const (
	smtpMaxCommands = 40
	smtpMaxLine     = 2048
	smtpMaxData     = 64 << 10 // so viel einer Mail wird höchstens gelesen
)

func b64(s string) string {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return s // nicht dekodierbar: roh festhalten
	}
	return string(b)
}

// smtpPlain zerlegt die AUTH-PLAIN-Antwort "authzid\0user\0pass".
func smtpPlain(arg string) (string, string) {
	p := strings.Split(b64(arg), "\x00")
	switch len(p) {
	case 0, 1:
		return "", strings.Join(p, "")
	case 2:
		return p[0], p[1]
	}
	return p[len(p)-2], p[len(p)-1]
}

// smtpReadData liest den Mailtext bis zur Zeile "." und behält höchstens keep Bytes.
// ok=false, wenn die Verbindung endet oder die Mail größer als smtpMaxData ist.
func smtpReadData(br *bufio.Reader, keep int) (head []byte, total int, ok bool) {
	for total < smtpMaxData {
		line, err := br.ReadSlice('\n')
		total += len(line)
		if err == nil && (string(line) == ".\r\n" || string(line) == ".\n") {
			return head, total, true
		}
		if room := keep - len(head); room > 0 {
			head = append(head, line[:min(len(line), room)]...)
		}
		if err != nil && err != bufio.ErrBufferFull {
			return head, total, false
		}
	}
	return head, total, false
}

func handleSMTP(s *Session) {
	host := s.m.Hostname()
	if s.Mode == "tarpit" {
		s.Tarpit(nil, func() []byte { return []byte("220-" + randWord(10, 40) + "\r\n") })
		return
	}
	if s.WriteString("220 "+host+" ESMTP Postfix (Ubuntu)\r\n") != nil {
		return
	}
	hold := func() { // hybrid: nach dem ersten Login oder Absender festhalten
		s.Tarpit(nil, func() []byte { return []byte("250-" + randWord(10, 40) + "\r\n") })
	}
	br := bufio.NewReaderSize(s.Conn, 4096)
	read := func() (string, bool) {
		s.ReadDeadline(60 * time.Second)
		line, err := readLine(br, smtpMaxLine)
		return line, err == nil
	}
	s.ReadDeadline(60 * time.Second)
	if s.sniffTLS(br) {
		return
	}
	for i := 0; i < smtpMaxCommands; i++ {
		line, ok := read()
		if !ok {
			return
		}
		cmd, arg, _ := strings.Cut(strings.TrimSpace(line), " ")
		cmd = strings.ToUpper(cmd)
		reply := "502 5.5.2 Error: command not recognized\r\n"
		switch cmd {
		case "":
			continue
		case "EHLO":
			s.Command(pr(line, 512), nil)
			reply = "250-" + host + "\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250 8BITMIME\r\n"
		case "HELO":
			s.Command(pr(line, 512), nil)
			reply = "250 " + host + "\r\n"
		case "AUTH":
			mech, rest, _ := strings.Cut(strings.TrimSpace(arg), " ")
			var user, pass string
			switch strings.ToUpper(mech) {
			case "PLAIN":
				if rest == "" {
					if s.WriteString("334 \r\n") != nil {
						return
					}
					if rest, ok = read(); !ok {
						return
					}
				}
				user, pass = smtpPlain(rest)
			case "LOGIN":
				if rest == "" {
					if s.WriteString("334 VXNlcm5hbWU6\r\n") != nil { // "Username:"
						return
					}
					if rest, ok = read(); !ok {
						return
					}
				}
				user = b64(rest)
				if s.WriteString("334 UGFzc3dvcmQ6\r\n") != nil { // "Password:"
					return
				}
				p, ok := read()
				if !ok {
					return
				}
				pass = b64(p)
			default:
				s.Command(pr(line, 512), nil)
				reply = "504 5.5.4 Unrecognized authentication type\r\n"
				if s.WriteString(reply) != nil {
					return
				}
				continue
			}
			s.Login(pr(user, 256), pr(pass, 256), nil)
			if s.Mode == "hybrid" {
				hold()
				return
			}
			reply = "535 5.7.8 Error: authentication failed: UGFzc3dvcmQ6\r\n"
		case "MAIL":
			s.Command(pr(line, 512), nil)
			if s.Mode == "hybrid" {
				hold()
				return
			}
			reply = "250 2.1.0 Ok\r\n"
		case "RCPT":
			s.Command(pr(line, 512), nil)
			reply = "250 2.1.5 Ok\r\n"
		case "DATA":
			if s.WriteString("354 End data with <CR><LF>.<CR><LF>\r\n") != nil {
				return
			}
			s.ReadDeadline(60 * time.Second)
			head, total, ok := smtpReadData(br, 4096)
			if len(head) > 0 {
				s.Emit(Event{Type: "payload", Data: map[string]any{"text": printable(head, budgetText), "bytes": total, "mail": true}})
			}
			if !ok {
				return
			}
			reply = "250 2.0.0 Ok: queued as " + strings.ToUpper(randHex(5)) + "\r\n"
		case "RSET", "NOOP":
			reply = "250 2.0.0 Ok\r\n"
		case "STARTTLS":
			s.Command(pr(line, 512), nil)
			reply = "454 4.7.0 TLS not available due to local problem\r\n"
		case "VRFY", "EXPN":
			s.Command(pr(line, 512), nil)
			reply = "252 2.0.0 " + clip(pr(arg, 64), 64) + "\r\n"
		case "QUIT":
			s.WriteString("221 2.0.0 Bye\r\n")
			return
		default:
			s.Command(pr(line, 512), nil)
		}
		if s.WriteString(reply) != nil {
			return
		}
	}
}
