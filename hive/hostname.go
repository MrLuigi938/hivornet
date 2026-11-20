package main

// Hostname des Honeypots (Einstellungen → Honeypot → Geräteprofil). Er erscheint in Bannern,
// Login-Seiten, Zertifikaten und Antworten (Docker, Redis, Telnet) und geht mit den Befehlen an
// den Anbieter des Sprachmodells (mimic.go). Ein echtes Gerät hätte einen gültigen Namen nach
// RFC 952/1123: Buchstaben, Ziffern und Bindestrich, je Teil 1 bis 63 Zeichen, kein Bindestrich
// am Anfang oder Ende eines Teils. Ein Unterstrich ("HOME_name_srv") verrät den Honeypot und
// wäre an einem echten Gerät gar nicht einstellbar. Die Web-UI prüft dasselbe beim Tippen
// (settings.js: hostnameProblem) und bietet den Vorschlag aus suggestHostname an.

import (
	"fmt"
	"strings"
)

const hostnameMax = 64 // wie SensorConfig.Validate

// hostnameProblem beschreibt, was an einem Hostnamen ungültig ist ("" = gültig oder leer).
func hostnameProblem(h string) string {
	if h == "" {
		return ""
	}
	if len(h) > hostnameMax {
		return fmt.Sprintf("höchstens %d Zeichen", hostnameMax)
	}
	for _, r := range h {
		switch {
		case r == '_':
			return "Unterstriche sind in Hostnamen nicht erlaubt"
		case r == ' ':
			return "Leerzeichen sind in Hostnamen nicht erlaubt"
		case r > 0x7f:
			return "Umlaute und andere Sonderzeichen sind nicht erlaubt"
		case !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.'):
			return fmt.Sprintf("Zeichen „%c“ ist nicht erlaubt (nur Buchstaben, Ziffern und Bindestrich)", r)
		}
	}
	for _, l := range strings.Split(h, ".") {
		switch {
		case l == "":
			return "leerer Namensteil (zwei Punkte hintereinander oder Punkt am Anfang/Ende)"
		case len(l) > 63:
			return "ein Namensteil darf höchstens 63 Zeichen haben"
		case l[0] == '-' || l[len(l)-1] == '-':
			return "kein Bindestrich am Anfang oder Ende"
		}
	}
	return ""
}

// suggestHostname macht aus einer Eingabe einen gültigen, unauffälligen Namen: klein
// geschrieben, Umlaute umschrieben, Unterstriche, Leerzeichen und andere Zeichen als
// Bindestrich, keine doppelten oder randständigen Bindestriche.
func suggestHostname(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.NewReplacer("ä", "ae", "ö", "oe", "ü", "ue", "ß", "ss").Replace(h)
	var b strings.Builder
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	parts := strings.Split(b.String(), ".")
	out := parts[:0]
	for _, p := range parts {
		for strings.Contains(p, "--") {
			p = strings.ReplaceAll(p, "--", "-")
		}
		p = strings.Trim(p, "-")
		if len(p) > 63 {
			p = strings.TrimRight(p[:63], "-")
		}
		if p != "" {
			out = append(out, p)
		}
	}
	s := strings.Join(out, ".")
	if len(s) > hostnameMax {
		s = strings.TrimRight(strings.TrimRight(s[:hostnameMax], "-"), ".")
	}
	return s
}

// hostnameError: Fehlermeldung für die API mit Vorschlag.
func hostnameError(h string) error {
	p := hostnameProblem(h)
	if p == "" {
		return nil
	}
	msg := fmt.Sprintf("Hostname „%s“ ist ungültig: %s.", clip(h, 80), p)
	if s := suggestHostname(h); s != "" && hostnameProblem(s) == "" {
		msg += fmt.Sprintf(" Vorschlag: %s", s)
	}
	return fmt.Errorf("%s", msg)
}
