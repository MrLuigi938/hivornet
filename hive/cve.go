package main

// Bekannte Lücken (CVE), Produkte und MITRE-ATT&CK-Techniken.
//
// cveRules (cverules.go) ordnen Web-Anfragen (Pfad, Body, Kopfzeilen) und Rohdaten einem
// Produkt und, wo es eine gibt, einer Lücke zu. Jede Regel hat eine Art:
//   - "exploit": die Anfrage trägt die Nutzlast der Lücke (Befehl, Pfad-Traversal, Umgehung)
//     oder nutzt eine Fehlkonfiguration aus (offene Docker-API, Standardpasswort);
//   - "probe": die Anfrage prüft nur, ob das Produkt da ist (Versions- oder Anmeldeseite).
// Trifft eine Ausnutzung eines Produkts, fällt dessen Probe weg. Ein Treffer heißt "jemand hat
// es versucht", nicht "das Gerät wäre verwundbar".
//
// Regeln ohne CVE erkennen Produkte und Fehlkonfigurationen. Eigene Regeln (aus KI-Vorschlägen,
// cvesuggest.go) gelten wie die eingebauten.
//
// eventCVEs liefert nur Ausnutzungen mit CVE: Sie stehen am Angriff (Feld cves), im Bericht, in
// der Angriffskette und in der Zähltabelle (Feld "cve"). eventRules liefert alle Treffer.
//
// patternMitre ordnet die Angriffsmuster aus analyze.go Techniken aus MITRE ATT&CK
// (Enterprise) zu: https://attack.mitre.org/techniques/<ID>/

import (
	"regexp"
	"sort"
	"sync/atomic"
)

const (
	kindExploit = "exploit"
	kindProbeR  = "probe"
)

type cveRule struct {
	ID      string // stabil, für Suche und Tabelle ("regel:<ID>")
	Kind    string // kindExploit oder kindProbeR
	Product string
	CVE     string // "" = Produkt oder Fehlkonfiguration ohne Lücke
	Name    string // kurz, ohne Produkt
	over    string // ID einer allgemeineren Regel, die bei einem Treffer dieser wegfällt
	custom  bool
	re      *regexp.Regexp
}

// Label: Produkt und Name, z. B. "Hikvision IP-Kamera: Befehlsausführung über webLanguage".
func (r cveRule) Label() string { return r.Product + ": " + r.Name }

func rule(id, kind, product, cveID, name, expr string) cveRule {
	return cveRule{ID: id, Kind: kind, Product: product, CVE: cveID, Name: name, re: regexp.MustCompile(`(?i)` + expr)}
}

// overrides: Diese Regel ersetzt die allgemeinere Regel id, wenn beide passen.
func (r cveRule) overrides(id string) cveRule { r.over = id; return r }

// customRules: angenommene Regelvorschläge (cvesuggest.go); werden atomar ausgetauscht.
var customRules atomic.Pointer[[]cveRule]

func allRules() []cveRule {
	if c := customRules.Load(); c != nil && len(*c) > 0 {
		return append(cveRules[:len(cveRules):len(cveRules)], *c...)
	}
	return cveRules
}

// matchRules prüft den Text gegen alle Regeln und räumt auf: Spezielle Regeln verdrängen
// allgemeinere (over), eine Ausnutzung verdrängt die Probe desselben Produkts.
func matchRules(text, on string) []cveRule {
	if text == "" || on != "web" && on != "raw" {
		return nil
	}
	var hits []cveRule
	for _, r := range allRules() {
		if r.re.MatchString(text) {
			hits = append(hits, r)
		}
	}
	if len(hits) < 2 {
		return hits
	}
	drop, exploited := map[string]bool{}, map[string]bool{}
	for _, r := range hits {
		if r.over != "" {
			drop[r.over] = true
		}
		if r.Kind == kindExploit {
			exploited[r.Product] = true
		}
	}
	out := hits[:0]
	for _, r := range hits {
		if !drop[r.ID] && !(r.Kind == kindProbeR && exploited[r.Product]) {
			out = append(out, r)
		}
	}
	return out
}

// eventRules: alle Regeltreffer eines Ereignisses (über den Zwischenspeicher, analysiscache.go).
func eventRules(text, on string) []cveRule {
	if text == "" || on != "web" && on != "raw" {
		return nil
	}
	return analyzeText(text, on).rules
}

// eventCVEs: Ausnutzungen bekannter Lücken (nur Regeln mit CVE und Art "exploit").
func eventCVEs(text, on string) []cveRule {
	if text == "" || on != "web" && on != "raw" {
		return nil
	}
	return analyzeText(text, on).cves
}

// exploitsOnly filtert Treffer auf Ausnutzungen mit CVE.
func exploitsOnly(hits []cveRule) []cveRule {
	var out []cveRule
	for _, r := range hits {
		if r.Kind == kindExploit && r.CVE != "" {
			out = append(out, r)
		}
	}
	return out
}

// firstExploit: erste Ausnutzung unter den Treffern.
func firstExploit(hits []cveRule) (cveRule, bool) {
	for _, r := range hits {
		if r.Kind == kindExploit {
			return r, true
		}
	}
	return cveRule{}, false
}

// ruleTags: Muster aus den Regeltreffern (analyze.go: known_exploit, product_probe).
func ruleTags(hits []cveRule) []string {
	var ex, pr bool
	for _, r := range hits {
		ex = ex || r.Kind == kindExploit
		pr = pr || r.Kind == kindProbeR
	}
	var out []string
	if ex {
		out = append(out, "known_exploit")
	}
	if pr {
		out = append(out, "product_probe")
	}
	return out
}

// cveByID: Regel je CVE (Ausnutzung bevorzugt) für Beschriftungen.
var cveByID = func() map[string]cveRule {
	m := map[string]cveRule{}
	for _, r := range cveRules {
		if r.CVE == "" {
			continue
		}
		if old, ok := m[r.CVE]; !ok || old.Kind != kindExploit && r.Kind == kindExploit {
			m[r.CVE] = r
		}
	}
	return m
}()

var ruleByIDMap = func() map[string]cveRule {
	m := map[string]cveRule{}
	for _, r := range cveRules {
		if _, dup := m[r.ID]; dup {
			panic("doppelte Regel-ID " + r.ID)
		}
		m[r.ID] = r
	}
	return m
}()

// ruleByID findet eingebaute und eigene Regeln.
func ruleByID(id string) (cveRule, bool) {
	if r, ok := ruleByIDMap[id]; ok {
		return r, true
	}
	if c := customRules.Load(); c != nil {
		for _, r := range *c {
			if r.ID == id {
				return r, true
			}
		}
	}
	return cveRule{}, false
}

// cveLabel: Beschriftung einer CVE (eingebaute Regeln, sonst eigene).
func cveLabel(id string) string {
	if r, ok := cveByID[id]; ok {
		return r.Label()
	}
	if c := customRules.Load(); c != nil {
		for _, r := range *c {
			if r.CVE == id {
				return r.Label()
			}
		}
	}
	return ""
}

// ExploitHit: Regeltreffer an einem Angriff oder im Bericht.
type ExploitHit struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"` // exploit oder probe
	Product string `json:"product"`
	CVE     string `json:"cve,omitempty"`
	Name    string `json:"name"`
	N       int    `json:"n"`
	Path    string `json:"path,omitempty"` // erste passende Anfrage
	Custom  bool   `json:"custom,omitempty"`
	Last    int64  `json:"last,omitempty"`
}

// ruleHits sammelt Treffer (Angriff, Bericht).
type ruleHits map[string]*ExploitHit

func (m ruleHits) add(r cveRule, path string, ms int64) {
	x := m[r.ID]
	if x == nil {
		x = &ExploitHit{ID: r.ID, Kind: r.Kind, Product: r.Product, CVE: r.CVE, Name: r.Name, Path: clip(path, 200), Custom: r.custom}
		m[r.ID] = x
	}
	x.N++
	x.Last = max(x.Last, ms)
}

// list: Ausnutzungen zuerst, dann nach Häufigkeit; höchstens n.
func (m ruleHits) list(n int) []ExploitHit {
	out := make([]ExploitHit, 0, len(m))
	for _, x := range m {
		out = append(out, *x)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind == kindExploit
		}
		return out[i].N > out[j].N || out[i].N == out[j].N && out[i].ID < out[j].ID
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

var patternMitre = map[string][]string{
	"download_exec":    {"T1105", "T1059.004"},
	"miner":            {"T1496"},
	"iot_botnet":       {"T1059.004"}, // Nachladen (T1105) erst mit download_exec oder Download
	"file_upload":      {"T1105"},
	"ssh_tunnel":       {"T1090"},
	"persist_ssh":      {"T1098.004"},
	"persist_cron":     {"T1053.003"},
	"docker_escape":    {"T1610", "T1611"},
	"redis_takeover":   {"T1190", "T1053.003"},
	"account":          {"T1136.001", "T1098"},
	"cover_tracks":     {"T1070.003", "T1070.002"},
	"kill_rivals":      {"T1489"},
	"obfuscation":      {"T1027", "T1140"},
	"recon":            {"T1082", "T1033"},
	"honeypot_check":   {"T1497.001"},
	"prompt_injection": {"AML.T0051"},
	"data_theft":       {"T1552.001", "T1005"},
	"log4shell":        {"T1190"},
	"java4shell":       {"T1190"},
	"web_rce":          {"T1190"},
	"secret_hunt":      {"T1595.003"},
	"iot_exploit":      {"T1190"},
	"traversal":        {"T1190", "T1083"},
	"sqli":             {"T1190"},
	"cms_login":        {"T1110"},
	"api_probe":        {"T1595"},
	"known_exploit":    {"T1190"},
	"product_probe":    {"T1595.002"},
	"bait_used":        {"T1078"},
	"tls_on_plain":     {"T1595"},
	"smb_probe":        {"T1595"},
	"http_on_raw":      {"T1595"},
}

// mitreNames: Namen der Techniken (für Anzeige und Bericht).
var mitreNames = map[string]string{
	"T1105": "Ingress Tool Transfer", "T1059.004": "Unix Shell", "T1496": "Resource Hijacking",
	"T1098.004": "SSH Authorized Keys", "T1053.003": "Cron", "T1610": "Deploy Container", "T1611": "Escape to Host",
	"T1190": "Exploit Public-Facing Application", "T1136.001": "Create Local Account", "T1098": "Account Manipulation",
	"T1070.003": "Clear Command History", "T1070.002": "Clear Linux or Mac System Logs", "T1489": "Service Stop",
	"T1027": "Obfuscated Files or Information", "T1140": "Deobfuscate/Decode Files or Information",
	"T1082": "System Information Discovery", "T1033": "System Owner/User Discovery", "T1552.001": "Credentials In Files",
	"T1005": "Data from Local System", "T1595.003": "Wordlist Scanning", "T1083": "File and Directory Discovery",
	"T1497.001": "System Checks", "AML.T0051": "LLM Prompt Injection (MITRE ATLAS)", "T1110": "Brute Force", "T1595": "Active Scanning", "T1078": "Valid Accounts",
	"T1595.002": "Vulnerability Scanning", "T1090": "Proxy",
}
