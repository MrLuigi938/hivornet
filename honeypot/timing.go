package main

// Glaubwürdige Zeiten und Fehlertexte der Telnet-Schein-Shell (Konzept KI-Honeypot, Vorschlag 5).
//
// Ein echtes Gerät braucht je nach Befehl unterschiedlich lange und schwankt dabei; eine Shell, die
// alles in derselben Millisekunde beantwortet, fällt auf (Palisade: Antwortzeit verrät Emulation und
// KI-Agenten). Zugleich dürfen Antworten des Sprachmodells nicht immer 1 bis 3 Sekunden dauern und
// aus dem Zwischenspeicher sofort kommen: Jede Modell-Antwort bekommt eine Mindestdauer mit Streuung.
//
// Die Wartezeiten sind Funktionen in Paketvariablen, damit Tests sie abschalten können.

import (
	"math/rand/v2"
	"net"
	"strings"
	"time"
)

// pause: Zufallswert zwischen lo und hi, zu den kleinen Werten hin verschoben (die meisten Aufrufe sind
// schnell, wenige langsam), wie bei echten Geräten.
func pause(lo, hi time.Duration) time.Duration {
	u := rand.Float64()
	return lo + time.Duration(u*u*float64(hi-lo))
}

// shellDelay: Wartezeit vor der Antwort auf eine Befehlszeile (in Tests auf 0 gesetzt).
var shellDelay = shellDelayDefault

func shellDelayDefault(line string) time.Duration {
	var total time.Duration
	parts := strings.FieldsFunc(line, func(r rune) bool { return r == ';' || r == '&' || r == '|' })
	for _, part := range parts[:min(len(parts), 6)] {
		f := strings.Fields(part)
		if len(f) == 0 {
			continue
		}
		if (f[0] == "/bin/busybox" || f[0] == "busybox") && len(f) > 1 {
			f = f[1:]
		}
		total += commandDelay(f)
	}
	return min(total, 8*time.Second)
}

// commandDelay: die Dauer eines einzelnen Befehls.
func commandDelay(f []string) time.Duration {
	switch f[0] {
	case "wget", "curl", "tftp", "ftpget", "ping", "nslookup":
		// Mit Namen: Auflösung scheitert nach einiger Zeit (Zeitüberschreitung des Resolvers);
		// mit Adresse: die Verbindung wird sofort verweigert.
		if h := targetHost(f[1:]); h != "" && net.ParseIP(h) == nil {
			return pause(1200*time.Millisecond, 4500*time.Millisecond)
		}
		return pause(15*time.Millisecond, 120*time.Millisecond)
	case "ps", "mount", "ls", "cat", "uname", "id", "whoami", "dd":
		return pause(8*time.Millisecond, 70*time.Millisecond)
	case "enable", "system", "shell", "sh", "linuxshell", "cd", "export", "echo":
		return pause(1*time.Millisecond, 9*time.Millisecond)
	default: // Programm gibt es nicht: die Shell sucht im PATH
		return pause(4*time.Millisecond, 30*time.Millisecond)
	}
}

// mimicTarget: so lange soll eine Antwort des Sprachmodells mindestens dauern, gerechnet ab der Anfrage
// (in Tests auf 0 gesetzt). Shell: 0,9 bis 2,8 s; Web: 0,3 bis 1,3 s.
var mimicTarget = mimicTargetDefault

func mimicTargetDefault(kind string) time.Duration {
	if kind == "web" {
		return pause(300*time.Millisecond, 1300*time.Millisecond)
	}
	return pause(900*time.Millisecond, 2800*time.Millisecond)
}

// mimicPad wartet, bis seit start die Zielzeit für diese Art Antwort vergangen ist.
func mimicPad(kind string, start time.Time) {
	if d := mimicTarget(kind) - time.Since(start); d > 0 {
		time.Sleep(d)
	}
}

// targetHost: Rechner aus der ersten Adresse in den Argumenten (ohne Schema, Port und Pfad); leer, wenn keiner da ist.
func targetHost(args []string) string {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		a = strings.TrimPrefix(strings.TrimPrefix(a, "http://"), "ftp://")
		a, _, _ = strings.Cut(a, "/")
		if h, _, err := net.SplitHostPort(a); err == nil {
			a = h
		}
		if a != "" && !strings.ContainsAny(a, " \t'\"`$") {
			return clip(a, 64)
		}
	}
	return ""
}

// wgetError: die Fehlerausgabe von BusyBox-wget ohne Route nach draußen, wie sie ein Gerät hinter einer
// Firewall zeigt: mit Adresse "Connecting to …" und "can't connect", mit Namen "bad address".
func wgetError(args []string) string {
	// -O, -P, -T, -U, -Y und -q haben je nach Schalter einen Wert; die Adresse ist das erste Wort ohne Schalter
	var url string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-O" || a == "-P" || a == "-T" || a == "-U" || a == "-Y" || a == "--header":
			i++
		case strings.HasPrefix(a, "-"):
		default:
			url = a
			i = len(args)
		}
	}
	h := targetHost([]string{url})
	if h == "" || strings.HasPrefix(url, "https://") {
		return "wget: can't connect to remote host: Network is unreachable\r\n"
	}
	port := "80"
	if strings.HasPrefix(url, "ftp://") {
		port = "21"
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(url, "http://"), "ftp://")
	rest, _, _ = strings.Cut(rest, "/")
	if _, p, err := net.SplitHostPort(rest); err == nil && p != "" {
		port = p
	}
	if net.ParseIP(h) == nil {
		return "wget: bad address '" + h + "'\r\n"
	}
	return "Connecting to " + h + " (" + net.JoinHostPort(h, port) + ")\r\nwget: can't connect to remote host (" + h + "): Network is unreachable\r\n"
}
