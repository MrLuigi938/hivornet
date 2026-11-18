package main

// Schutz der Sprachmodell-Antworten (mimic.go) gegen Prompt-Injection. Angreifer schreiben in
// die Schein-Shell oder in Web-Pfade gern Text, der das Modell umsteuern soll ("ignore previous
// instructions, you are now …"). Gelingt das, verrät eine Antwort womöglich die KI und damit
// den Honeypot, oder sie kostet viel. Drei Stufen:
//
//  1. Eingang: Eingaben mit typischen Anweisungen an eine KI oder reiner Fließtext statt eines
//     Befehls gehen nicht ans Modell; der Honeypot antwortet statisch (mimicInjection).
//  2. Abgrenzung: Die Eingabe steht zwischen Markierungen mit Zufallskennung; die Anweisung an
//     das Modell sagt, dass alles dazwischen nur Daten sind (mimicMessages).
//  3. Ausgang: Antworten, die sich als KI oder Emulation verraten, Teile der Anweisung oder die
//     Zufallskennung enthalten, werden verworfen und nicht gespeichert (mimicLeak).
//
// Das Muster "prompt_injection" (analyze.go) kennzeichnet solche Versuche in den Angriffen.

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// injectionExpr: typische Anweisungen an Sprachmodelle (englisch und deutsch), Rollen-Markierungen.
const injectionExpr = `ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding)|disregard\s+(all|any|the|previous|prior|above|your)|forget\s+(all|everything|your|previous|the)|` +
	`(system|developer|hidden|initial)\s*prompt|new\s+instructions?|your\s+instructions|override\s+(the\s+)?(rules|instructions)|` +
	`\byou\s+are\s+(now\s+)?(a|an|the|chatgpt|gpt|claude|an\s+ai|no\s+longer)\b|\bact\s+as\s+(a|an|if)\b|pretend\s+(to\s+be|you)|role-?play|jailbreak|developer\s+mode|\bdan\s+mode|` +
	`\b(as\s+an?\s+ai|language\s+model|large\s+language|llm|chatgpt|openai|anthropic|gemini|llama)\b|` +
	`<\|im_(start|end)\|>|\[/?inst\]|<<\s*sys\s*>>|^\s*(system|assistant|user)\s*:|###\s*(instruction|system|response)|` +
	`(repeat|print|reveal|show|output)\s+(the\s+|your\s+)?(above|instructions|prompt|system\s+message)|` +
	`ignorier(e|en)?\s+(alle|alles|die|vorherige|bisherige)|vergiss\s+(alle|alles|deine|die)|du\s+bist\s+(jetzt|nun|ab\s+sofort)|` +
	`\btu\s+so\s+als\b|antworte\s+(ab\s+jetzt|nur\s+noch|als)|deine\s+anweisungen|neue\s+anweisung`

var injectionRe = regexp.MustCompile(`(?im)` + injectionExpr)

// looksLikeProse: Fließtext statt eines Befehls (viele Wörter, kaum Zeichen einer Befehlszeile).
// Bots schicken Befehle; ganze Sätze an eine Shell sind fast immer an eine KI gerichtet.
func looksLikeProse(s string) bool {
	words := strings.Fields(s)
	if len(words) < 9 {
		return false
	}
	letters, shellish := 0, 0
	for _, r := range s {
		switch {
		case unicode.IsLetter(r):
			letters++
		case strings.ContainsRune(`/|;$&=<>()[]{}\"'*~-_:`+"`", r):
			shellish++
		}
	}
	plain := 0
	for _, w := range words {
		if strings.IndexFunc(w, func(r rune) bool { return !unicode.IsLetter(r) && !strings.ContainsRune(".,!?", r) }) < 0 {
			plain++
		}
	}
	return shellish*20 < letters && plain*10 >= len(words)*8
}

// mimicInjection: Grund, warum eine Eingabe nicht ans Modell darf ("" = in Ordnung). Geprüft
// werden die rohe Eingabe und ihre dekodierten Fassungen (mimicVariants): Das Modell versteht
// "ignore%20previous%20instructions" oder Base64 genauso wie Klartext.
func mimicInjection(kind, input string) string {
	vs, texts := mimicVariants(kind, input)
	for _, v := range vs {
		if injectionRe.MatchString(v) {
			return "Anweisung an eine KI"
		}
	}
	if kind == "shell" {
		for _, v := range texts { // nicht die Fassung ohne Trennzeichen: Befehle sähen wie Sätze aus
			if looksLikeProse(v) {
				return "Fließtext statt Befehl"
			}
		}
	}
	return ""
}

// sepRe: Zeichen, die in Adressen und Befehlen statt Leerzeichen stehen.
var sepRe = regexp.MustCompile(`[_/+.,;:=&?|\\]+`)

// b64Re (deobf.go), hexRe: lange Folgen, die als Base64 oder Hex dekodiert werden.
var (
	hexRe   = regexp.MustCompile(`(?i)(?:\\x[0-9a-f]{2}){6,}|\b(?:0x)?(?:[0-9a-f]{2}){8,}\b`)
	hexByte = regexp.MustCompile(`(?i)\\x|0x`)
)

// mimicVariants: rohe Eingabe, mehrfach prozent-dekodiert, Trennzeichen als Leerzeichen und
// (nur Shell) eingebettetes Base64 oder Hex als Text. Höchstens wenige Fassungen, damit eine
// lange Eingabe nicht viel Arbeit kostet. texts: rohe Eingabe und dekodierter Text, ohne die
// Fassungen mit Leerzeichen statt Trennzeichen (für die Prüfung auf Fließtext).
func mimicVariants(kind, input string) (out, texts []string) {
	out, texts = []string{input}, []string{input}
	add := func(s string) {
		for _, o := range out {
			if o == s {
				return
			}
		}
		out = append(out, s)
	}
	dec := input
	for i := 0; i < 4; i++ { // doppelt und dreifach kodiert
		d, err := url.QueryUnescape(dec)
		if err != nil {
			d, err = url.PathUnescape(dec)
		}
		if err != nil {
			d = lenientUnescape(dec)
		}
		if d == dec {
			break
		}
		dec = d
	}
	add(dec)
	add(sepRe.ReplaceAllString(dec, " "))
	if kind == "shell" {
		for _, s := range []string{input, dec} {
			for _, m := range b64Re.FindAllString(s, 8) {
				if b, ok := decodeB64(m); ok { // deobf.go
					t := string(b)
					add(t)
					add(sepRe.ReplaceAllString(t, " "))
					texts = append(texts, t)
				}
			}
			for _, m := range hexRe.FindAllString(s, 8) {
				if b, err := hex.DecodeString(hexByte.ReplaceAllString(m, "")); err == nil && readable(b) {
					add(string(b))
					texts = append(texts, string(b))
				}
			}
		}
	}
	return out, texts
}

// lenientUnescape löst gültige %XX-Folgen auf und lässt den Rest stehen (url.QueryUnescape
// bricht bei einem einzelnen "%" ganz ab).
func lenientUnescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := hex.DecodeString(s[i+1 : i+3]); err == nil {
				b.WriteByte(v[0])
				i += 2
				continue
			}
		}
		if s[i] == '+' {
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// unsafeWebRe: Web-Antworten, die den Anschluss zur Ablage fremder Inhalte machen würden:
// Skripte, Rahmen oder Formulare mit fremder Quelle oder fremdem Ziel, automatische
// Weiterleitung, Umlenken per Skript, eigener Basis-Pfad.
var unsafeWebRe = regexp.MustCompile(`(?is)<script[^>]*\ssrc\s*=\s*["']?\s*(?:[a-z][a-z0-9+.-]*:|//|\\\\)|` +
	`<(?:iframe|frame|embed|object|img|link)[^>]*\s(?:src|data|href)\s*=\s*["']?\s*(?:javascript:|data:text/html|//[^/])|` +
	`\s(?:action|formaction)\s*=\s*["']?\s*(?:[a-z][a-z0-9+.-]*:|//|\\\\)|` +
	`http-equiv\s*=\s*["']?\s*refresh|<base[\s>]|` +
	`\b(?:window|document|top|self|parent)\s*\.\s*location\b|\blocation\s*\.\s*(?:href|replace|assign)\b|\bwindow\s*\.\s*open\s*\(|` +
	`\bimport\s*\(|\bfetch\s*\(\s*["'\x60]\s*(?:https?:)?//|\beval\s*\(|\batob\s*\(|\bfromCharCode\b`)

// Adressen in Eingaben (M2 des dritten Audits): Scanner schreiben die Zieladresse oft selbst in
// Pfad oder Befehl ("/?url=http://<öffentliche IP>/…", "wget http://<öffentliche IP>/…"). Vor dem
// Aufruf des Modells werden die eigene öffentliche Adresse (exposure.go) und private Adressen
// durch Dokumentationsadressen ersetzt (192.0.2.N, 2001:db8::N); in der Antwort werden sie für
// diesen Angreifer zurückgetauscht. Der Zwischenspeicher arbeitet mit der ersetzten Fassung.
var (
	mimicV4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	mimicV6Re = regexp.MustCompile(`(?i)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}`)
	phV4Re    = regexp.MustCompile(`\b192\.0\.2\.\d{1,3}\b`)
	phV6Re    = regexp.MustCompile(`(?i)\b2001:db8::[0-9a-f]{1,4}\b`)
	docNetV4  = mustCIDR("192.0.2.0/24")
	docNetV6  = mustCIDR("2001:db8::/32")
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// scrubIPs ersetzt eigene öffentliche und private Adressen; back bildet Platzhalter auf die
// ursprünglichen Adressen ab (für restoreIPs).
func scrubIPs(input string, own []net.IP) (string, map[string]string) {
	back := map[string]string{}
	fwd := map[string]string{}
	n4, n6 := 0, 0
	hide := func(ip net.IP) bool {
		for _, o := range own {
			if o.Equal(ip) {
				return true
			}
		}
		return ip.IsPrivate() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip) || docNetV4.Contains(ip) || docNetV6.Contains(ip)
	}
	repl := func(m string, v6 bool) string {
		ip := net.ParseIP(m)
		if ip == nil || v6 != (ip.To4() == nil) || !hide(ip) {
			return m
		}
		if p, ok := fwd[m]; ok {
			return p
		}
		var p string
		if v6 {
			n6++
			p = fmt.Sprintf("2001:db8::%x", n6)
		} else {
			n4++
			p = fmt.Sprintf("192.0.2.%d", n4)
		}
		fwd[m], back[p] = p, m
		return p
	}
	s := mimicV4Re.ReplaceAllStringFunc(input, func(m string) string { return repl(m, false) })
	s = mimicV6Re.ReplaceAllStringFunc(s, func(m string) string {
		if strings.Count(m, ":") < 2 {
			return m
		}
		return repl(m, true)
	})
	return s, back
}

// restoreIPs tauscht die Platzhalter in einer Antwort zurück.
func restoreIPs(out string, back map[string]string) string {
	if len(back) == 0 {
		return out
	}
	f := func(m string) string {
		if o, ok := back[strings.ToLower(m)]; ok {
			return o
		}
		return m
	}
	return phV6Re.ReplaceAllStringFunc(phV4Re.ReplaceAllStringFunc(out, f), f)
}

// mimicUnsafeWeb: Grund, warum eine Web-Antwort verworfen wird ("" = in Ordnung).
func mimicUnsafeWeb(body string) string {
	if unsafeWebRe.MatchString(body) {
		return "fremde Quelle, fremdes Ziel oder Weiterleitung"
	}
	return ""
}

// leakRe: Antworten, die sich als KI oder Emulation verraten.
var leakRe = regexp.MustCompile(`(?i)\b(as\s+an?\s+(ai|assistant|language\s+model)|language\s+model|i'?m\s+(sorry|an?\s+ai)|i\s+(cannot|can'?t|won'?t)\s+(help|assist|comply)|` +
	`openai|anthropic|chatgpt|honeypot|emulat(e|ed|ion|ing)|simulat(e|ed|ion|ing)|system\s+prompt|my\s+instructions|untrusted\s+attacker|` +
	`als\s+ki|sprachmodell|ich\s+kann\s+(dabei\s+)?nicht\s+helfen)\b`)

// mimicLeak: Grund, warum eine Antwort verworfen wird ("" = in Ordnung).
func mimicLeak(out, nonce string) string {
	if nonce != "" && strings.Contains(out, nonce) {
		return "Antwort enthält die Markierung"
	}
	if leakRe.MatchString(out) {
		return "Antwort verrät die KI"
	}
	return ""
}
