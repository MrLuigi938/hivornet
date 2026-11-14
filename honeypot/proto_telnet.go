package main

import (
	"bufio"
	"strings"
	"time"
)

// ---------------- Telnet ----------------
//
// Einfache Telnet-Emulation für Ports wie 2323 (Port 23 übernimmt Cowrie).
// Ablauf im Modus emulate: Login-Abfrage, jede Kombination wird angenommen,
// danach eine BusyBox-artige Shell mit festen Antworten. Bots wie Mirai prüfen
// mit "/bin/busybox <WORT>" auf die Antwort "<WORT>: applet not found"; die
// liefern wir, damit sie ihre nächsten Befehle (Download des Laders) zeigen.
// Es wird nichts ausgeführt und nichts gespeichert außer den Ereignissen.

const (
	telnetMaxLine     = 1024
	telnetMaxCommands = 40
)

// telnetReadLine liest eine Zeile und entfernt Telnet-Verhandlungen (IAC ...).
// Liefert errLineTooLong, wenn die Zeile max überschreitet.
func telnetReadLine(br *bufio.Reader, max int) (string, error) {
	var sb strings.Builder
	for {
		c, err := br.ReadByte()
		if err != nil {
			if sb.Len() > 0 {
				return sb.String(), nil
			}
			return "", err
		}
		switch c {
		case 255: // IAC
			cmd, err := br.ReadByte()
			if err != nil {
				return "", err
			}
			switch {
			case cmd == 255: // maskiertes 0xFF
				sb.WriteByte(255)
			case cmd >= 251 && cmd <= 254: // WILL, WONT, DO, DONT + Option
				if _, err := br.ReadByte(); err != nil {
					return "", err
				}
			case cmd == 250: // Subnegotiation bis IAC SE, höchstens 512 Bytes
				prev := byte(0)
				for i := 0; i < 512; i++ {
					b, err := br.ReadByte()
					if err != nil {
						return "", err
					}
					if prev == 255 && b == 240 {
						break
					}
					prev = b
				}
			}
		case '\n':
			return sb.String(), nil
		case '\r':
			// \r\n und \r\0 gelten als ein Zeilenende
			if nx, err := br.Peek(1); err == nil && (nx[0] == '\n' || nx[0] == 0) {
				br.ReadByte()
			}
			return sb.String(), nil
		case 0:
		default:
			sb.WriteByte(c)
			if sb.Len() > max {
				return "", errLineTooLong
			}
		}
	}
}

// telnetReply liefert die Antwort der Schein-Shell auf eine Eingabezeile.
func telnetReply(line string) string {
	var out strings.Builder
	for _, part := range strings.FieldsFunc(line, func(r rune) bool { return r == ';' || r == '&' || r == '|' }) {
		f := strings.Fields(part)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "enable", "system", "shell", "sh", "linuxshell", "cd", "export", "rm", "chmod", "cp", "mv", "kill", "echo", ">":
			if f[0] == "echo" && len(f) > 1 {
				out.WriteString(clip(strings.Join(f[1:], " "), 256) + "\r\n")
			}
		case "/bin/busybox", "busybox":
			if len(f) > 1 {
				switch f[1] {
				case "cat", "wget", "tftp", "echo", "chmod", "cp", "rm", "ps", "mount", "dd":
				default:
					out.WriteString(clip(f[1], 64) + ": applet not found\r\n")
				}
			}
		case "uname":
			out.WriteString("Linux\r\n")
		case "id", "whoami":
			out.WriteString("uid=0(root) gid=0(root)\r\n")
		case "cat", "ps", "mount", "ls", "dd", "wget", "curl", "tftp", "ftpget":
		default:
			out.WriteString("sh: " + clip(f[0], 64) + ": not found\r\n")
		}
	}
	return out.String()
}

func handleTelnet(s *Session) {
	drip := func() []byte { return []byte(randWord(1, 2)) }
	if s.Mode == "tarpit" {
		s.Tarpit([]byte("\r\n"), drip)
		return
	}
	host := s.m.Hostname()
	// IAC WILL ECHO, IAC WILL SUPPRESS-GO-AHEAD: wie ein gewöhnlicher telnetd
	if s.Write([]byte{255, 251, 1, 255, 251, 3}) != nil {
		return
	}
	br := bufio.NewReaderSize(s.Conn, 1024)
	ask := func(prompt string) (string, bool) {
		if s.WriteString(prompt) != nil {
			return "", false
		}
		s.ReadDeadline(60 * time.Second)
		line, err := telnetReadLine(br, telnetMaxLine)
		return line, err == nil
	}
	user := ""
	for i := 0; i < 5 && user == ""; i++ {
		u, ok := ask("\r\n" + host + " login: ")
		if !ok {
			return
		}
		user = strings.TrimSpace(u)
	}
	if user == "" {
		return
	}
	pass, ok := ask("Password: ")
	if !ok {
		return
	}
	s.Login(pr(user, 256), pr(pass, 256), map[string]any{"accepted": true})
	if s.Mode == "hybrid" {
		s.Tarpit([]byte("\r\n"), drip)
		return
	}
	if s.WriteString("\r\n\r\nBusyBox v1.30.1 (2021-04-19 13:01:22 UTC) built-in shell (ash)\r\n\r\n") != nil {
		return
	}
	for i := 0; i < telnetMaxCommands; i++ {
		line, ok := ask("# ")
		if !ok {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		s.Command(pr(line, budgetCommand), nil)
		if line == "exit" || line == "quit" || line == "logout" {
			return
		}
		if s.WriteString("\r\n"+telnetReply(line)) != nil {
			return
		}
	}
}
