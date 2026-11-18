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

// mimicInjection: Grund, warum eine Eingabe nicht ans Modell darf ("" = in Ordnung).
func mimicInjection(kind, input string) string {
	if injectionRe.MatchString(input) {
		return "Anweisung an eine KI"
	}
	if kind == "shell" && looksLikeProse(input) {
		return "Fließtext statt Befehl"
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
