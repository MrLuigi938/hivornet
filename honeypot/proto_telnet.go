package main

import (
	"bufio"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------- Telnet ----------------
//
// Telnet-Emulation für Ports wie 2323 (Port 23 übernimmt Cowrie): ein kleines
// Gerät mit BusyBox, wie Kameras und Router sie haben.
//
// Anmeldung: Wie ein echtes Gerät hat der Honeypot je Konto genau EIN Passwort aus
// der Liste bekannter Werkspasswörter (telnetAccounts). Welches, legt jeder Angreifer
// selbst fest: Je Angreifer-IP gilt das dritte verschiedene Werkspasswort, das sie für
// ein Konto ausprobiert, und danach bleibt es für diese IP dasselbe (telnetAccept).
// So sieht das Gerät für jeden einzelnen Angreifer echt aus (erst Fehlschläge, dann
// ein fester Treffer), statt dass ein Bot je nach Gerät nie oder sofort hineinkommt.
// Passwörter außerhalb der Liste werden immer abgelehnt; Honeypot-Erkenner, die
// zufällige Zugangsdaten probieren, kommen nicht hinein. Die Köder-Zugangsdaten aus
// den Köderdateien des HTTP-Honeypots (bait.go) gelten immer.
// Nach drei Fehlversuchen endet eine Verbindung.
//
// Nach dem Login folgt eine Schein-Shell mit festen Antworten. Bots wie Mirai
// prüfen mit "/bin/busybox <WORT>" auf "<WORT>: applet not found" und mit
// "echo -e '\x..'" auf die dekodierte Ausgabe; beides liefern wir, damit sie
// ihre nächsten Befehle (Download des Laders) zeigen.
// Es wird nichts ausgeführt und nichts gespeichert außer den Ereignissen.

const (
	telnetMaxLine     = 1024
	telnetMaxCommands = 40
	telnetMaxLogins   = 3
)

// Werkspasswörter verbreiteter Geräte (aus den Listen gängiger IoT-Botnetze).
// Je Konto und Angreifer-IP gilt genau eines davon, siehe telnetAccept.
var telnetAccounts = map[string][]string{
	"root":  {"xc3511", "vizxv", "admin", "888888", "xmhdipc", "default", "juantech", "123456", "54321", "root", "12345", "pass", "1111", "666666", "password", "1234", "klv123", "hi3518", "jvbzd", "anko", "system", "realtek", "00000000", "Zte521"},
	"admin": {"admin", "password", "1234", "12345", "123456", "admin1234", "smcadmin", "1111", "54321", "pass", "4321", "1111111"},
}

const (
	telnetAcceptNth  = 3     // das wievielte verschiedene Werkspasswort gilt
	telnetMemoMax    = 20000 // so viele Angreifer-IPs merkt sich der Honeypot
	telnetMemoMaxAge = 7 * 24 * time.Hour
)

// telnetMemo: was eine Angreifer-IP je Konto probiert hat und welches Passwort gilt.
type telnetMemo struct {
	tried map[string][]string
	ok    map[string]string
	seen  time.Time
}

type telnetMemos struct {
	mu sync.Mutex
	m  map[string]*telnetMemo
}

// telnetAccept entscheidet über einen Login (siehe Kommentar oben).
func (m *Manager) telnetAccept(ip, user, pass string) bool {
	if b := bait(); user == b.User && pass == b.Pass {
		return true
	}
	if !slices.Contains(telnetAccounts[user], pass) {
		return false
	}
	t := &m.telnet
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]*telnetMemo{}
	}
	st := t.m[ip]
	if st == nil {
		if len(t.m) >= telnetMemoMax { // Älteste verwerfen, damit der Speicher begrenzt bleibt
			cut := time.Now().Add(-telnetMemoMaxAge)
			for k, v := range t.m {
				if v.seen.Before(cut) || len(t.m) >= telnetMemoMax {
					delete(t.m, k)
				}
				if len(t.m) < telnetMemoMax*9/10 {
					break
				}
			}
		}
		st = &telnetMemo{tried: map[string][]string{}, ok: map[string]string{}}
		t.m[ip] = st
	}
	st.seen = time.Now()
	if want, ok := st.ok[user]; ok {
		return pass == want
	}
	if !slices.Contains(st.tried[user], pass) && len(st.ok) < 4 {
		st.tried[user] = append(st.tried[user], pass)
	}
	if len(st.tried[user]) >= telnetAcceptNth {
		st.ok[user] = pass
		delete(st.tried, user)
		return true
	}
	return false
}

// telnetDelay ist die Pause nach einem falschen Passwort (in Tests verkürzt).
var telnetDelay = func() time.Duration { return 1500*time.Millisecond + time.Duration(rand.IntN(1200))*time.Millisecond }

// echoArgs bildet "echo" nach: -e wertet \xNN, \n und \r aus, -n unterdrückt den Zeilenumbruch.
func echoArgs(f []string) string {
	esc, nl := false, true
	for len(f) > 0 && len(f[0]) > 1 && f[0][0] == '-' && strings.Trim(f[0][1:], "en") == "" {
		esc = esc || strings.Contains(f[0], "e")
		nl = nl && !strings.Contains(f[0], "n")
		f = f[1:]
	}
	s := strings.Trim(strings.Join(f, " "), `"'`)
	if esc {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) {
				switch s[i+1] {
				case 'x':
					if i+3 < len(s) {
						if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
							b.WriteByte(byte(v))
							i += 3
							continue
						}
					}
				case 'n':
					b.WriteByte('\n')
					i++
					continue
				case 'r':
					b.WriteByte('\r')
					i++
					continue
				}
			}
			b.WriteByte(s[i])
		}
		s = b.String()
	}
	s = clip(s, 512)
	if nl {
		s += "\r\n"
	}
	return s
}

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
			case cmd == 255: // maskiertes 0xFF zählt wie jedes andere Zeichen zur Länge
				sb.WriteByte(255)
				if sb.Len() > max {
					return "", errLineTooLong
				}
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

// telnetReply liefert die Antwort der Schein-Shell auf eine Eingabezeile. uname, /proc/cpuinfo
// und /proc/mounts kommen aus dem Geräteprofil, damit sie zu Redis und Docker passen.
func telnetReply(p deviceProfile, host, line string) string {
	var out strings.Builder
	for _, part := range strings.FieldsFunc(line, func(r rune) bool { return r == ';' || r == '&' || r == '|' }) {
		f := strings.Fields(part)
		if len(f) == 0 {
			continue
		}
		if (f[0] == "/bin/busybox" || f[0] == "busybox") && len(f) > 1 {
			switch f[1] {
			case "cat", "wget", "tftp", "echo", "chmod", "cp", "rm", "ps", "mount", "dd", "ls", "uname", "id", "sh":
				f = f[1:] // eingebautes Programm: wie direkt aufgerufen
			default:
				out.WriteString(clip(f[1], 64) + ": applet not found\r\n")
				continue
			}
		}
		switch f[0] {
		case "enable", "system", "shell", "sh", "linuxshell", "cd", "export", "rm", "chmod", "cp", "mv", "kill", ">", "dd":
		case "echo":
			out.WriteString(echoArgs(f[1:]))
		case "uname":
			out.WriteString(p.uname(host, f[1:]) + "\r\n")
		case "id":
			out.WriteString("uid=0(root) gid=0(root)\r\n")
		case "whoami":
			out.WriteString("root\r\n")
		case "cat":
			switch {
			case len(f) > 1 && f[1] == "/proc/cpuinfo":
				out.WriteString(telnetLines(p.CPUInfo))
			case len(f) > 1 && f[1] == "/proc/mounts":
				out.WriteString(telnetLines(p.Mounts))
			case len(f) > 1:
				out.WriteString("cat: can't open '" + clip(f[1], 64) + "': No such file or directory\r\n")
			}
		case "mount":
			out.WriteString(telnetLines(p.Mounts))
		case "ps":
			out.WriteString("  PID USER       VSZ STAT COMMAND\r\n    1 root      1484 S    init\r\n  312 root      1488 S    /sbin/syslogd -n\r\n  401 root      1492 S    telnetd\r\n  987 root      1496 S    -sh\r\n")
		case "ls":
			out.WriteString("bin   dev   etc   lib   mnt   proc  sbin  sys   tmp   usr   var\r\n")
		case "wget", "curl", "tftp", "ftpget":
			// Das Gerät hat scheinbar keine Route nach draußen (wie hinter einer Firewall).
			out.WriteString(f[0] + ": can't connect to remote host: Network is unreachable\r\n")
		default:
			out.WriteString("sh: " + clip(f[0], 64) + ": not found\r\n")
		}
	}
	return out.String()
}

// telnetLines: Zeilenenden für Telnet.
func telnetLines(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }

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
	first := true
	ask := func(prompt string) (string, bool) {
		if s.WriteString(prompt) != nil {
			return "", false
		}
		s.ReadDeadline(60 * time.Second)
		if first { // TLS-Client am Telnet-Port: erst nach der ersten Abfrage prüfen, Bots warten auf sie
			first = false
			if kind, _ := s.sniffForeign(br, false); kind != "" { // auch HTTP: Kopfzeilen sind keine Zugangsdaten
				return "", false
			}
		}
		line, err := telnetReadLine(br, telnetMaxLine)
		return line, err == nil
	}
	loggedIn := false
	for try, empty := 0, 0; try < telnetMaxLogins && !loggedIn; {
		u, ok := ask("\r\n" + host + " login: ")
		if !ok {
			return
		}
		user := strings.TrimSpace(u)
		if user == "" {
			if empty++; empty > 5 {
				return
			}
			continue
		}
		try++
		pass, ok := ask("Password: ")
		if !ok {
			return
		}
		loggedIn = s.m.telnetAccept(s.SrcIP, user, pass)
		s.Login(pr(user, 256), pr(pass, 256), map[string]any{"accepted": loggedIn})
		if s.Mode == "hybrid" {
			s.Tarpit([]byte("\r\n"), drip)
			return
		}
		if !loggedIn {
			time.Sleep(telnetDelay())
			if s.WriteString("\r\nLogin incorrect") != nil {
				return
			}
		}
	}
	if !loggedIn {
		return
	}
	if s.WriteString("\r\n\r\n"+s.m.prof().TelnetShell+"\r\n\r\n") != nil {
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
		if s.WriteString("\r\n"+s.mimicShell(host, line)) != nil { // Unbekanntes ggf. vom Sprachmodell (mimic.go)
			return
		}
	}
}
