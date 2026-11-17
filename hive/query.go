package main

// Suchsprache für die Seite Angriffe (Parameter q). Freier Text sucht wie bisher überall;
// dazu kommen Felder, Vergleiche und Verneinung. Alle Teile müssen zutreffen (UND).
//
//   service:ssh  stufe>=3  country:CN  cmd:*wget*  -tag:miner  user:root  "two words"
//
// Felder:  ip, country/land, asn, org, service/dienst, port, stufe, events, user, pass, cred,
//          cmd/befehl, path/pfad, url, tag/muster, cve, client, fp, wallet, art/profile,
//          scanner (ja/nein), login (ja/nein)
// Werte:   ohne * = enthält (Groß-/Kleinschreibung egal), mit * = Platzhalter über den ganzen Wert
// Zahlen:  stufe, port, events, asn mit = < > <= >=; Stufe auch als Name (befehle, download …)
//
// Gespeicherte Suchen: GET/POST /api/searches, DELETE /api/searches/{name}

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type qTerm struct {
	neg   bool
	field string // "" = freier Text
	op    string // ":" "=" "<" ">" "<=" ">="
	val   string
	re    *regexp.Regexp
}

var qTokenRe = regexp.MustCompile(`(?i)-?(?:[a-zäöü]+(?:>=|<=|:|=|<|>))?(?:"[^"]*"|\S+)`)
var qFieldRe = regexp.MustCompile(`^(-?)([a-zäöü]+)(>=|<=|:|=|<|>)(.*)$`)

var qAliases = map[string]string{
	"land": "country", "dienst": "service", "svc": "service", "befehl": "cmd", "command": "cmd", "pfad": "path",
	"muster": "tag", "pattern": "tag", "profile": "art", "benutzer": "user", "passwort": "pass", "password": "pass",
	"fingerprint": "fp", "organisation": "org", "as": "asn",
}

var qFields = map[string]bool{"ip": true, "country": true, "asn": true, "org": true, "service": true, "port": true, "stufe": true,
	"events": true, "user": true, "pass": true, "cred": true, "cmd": true, "path": true, "url": true, "tag": true, "cve": true,
	"client": true, "fp": true, "wallet": true, "art": true, "scanner": true, "login": true}

var stufeNames = map[string]int{"abtasten": 0, "scan": 0, "versuche": 1, "login": 2, "befehle": 3, "download": 4, "datei": 4}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func parseQuery(q string) []qTerm {
	var out []qTerm
	for _, tok := range qTokenRe.FindAllString(strings.TrimSpace(q), 30) {
		t := qTerm{}
		if m := qFieldRe.FindStringSubmatch(strings.ToLower(tok)); m != nil {
			f := m[2]
			if a, ok := qAliases[f]; ok {
				f = a
			}
			if qFields[f] {
				t.neg, t.field, t.op = m[1] == "-", f, m[3]
				// Wert in Originalschreibung (für Länder egal, für Glob unwichtig)
				t.val = strings.ToLower(unquote(tok[len(m[1])+len(m[2])+len(m[3]):]))
			}
		}
		if t.field == "" {
			if strings.HasPrefix(tok, "-") && len(tok) > 1 {
				t.neg, tok = true, tok[1:]
			}
			t.val = strings.ToLower(unquote(tok))
		}
		if t.val == "" {
			continue
		}
		// Grenzen gegen teure Muster (zweites Audit, N8)
		if len(t.val) > 200 {
			t.val = t.val[:200]
		}
		if strings.Count(t.val, "*") > 8 {
			t.val = strings.ReplaceAll(t.val, "*", "")
		}
		// Platzhalter nur bei Feldern: Freier Text kommt oft per Klick aus Befehlen, in denen * wörtlich steht.
		if t.field != "" && strings.Contains(t.val, "*") {
			t.re = regexp.MustCompile("^" + strings.ReplaceAll(regexp.QuoteMeta(t.val), `\*`, ".*") + "$")
		}
		out = append(out, t)
	}
	return out
}

func (t qTerm) str(vals ...string) bool {
	for _, v := range vals {
		v = strings.ToLower(v)
		if t.re != nil && t.re.MatchString(v) || t.re == nil && (t.op == "=" && v == t.val || t.op != "=" && strings.Contains(v, t.val)) {
			return true
		}
	}
	return false
}

func (t qTerm) num(n int) bool {
	want, err := strconv.Atoi(t.val)
	if err != nil {
		if s, ok := stufeNames[t.val]; ok && t.field == "stufe" {
			want = s
		} else {
			return false
		}
	}
	switch t.op {
	case "<":
		return n < want
	case ">":
		return n > want
	case "<=":
		return n <= want
	case ">=":
		return n >= want
	}
	return n == want
}

func yes(v string) bool { return v == "ja" || v == "yes" || v == "1" || v == "true" }

func (a *Attack) matchTerm(t qTerm) bool {
	keys := func(m map[string]int) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		return out
	}
	switch t.field {
	case "":
		return a.matches(t.val)
	case "ip":
		return t.str(a.IP)
	case "country":
		if len(t.val) == 2 && t.re == nil { // Ländercode: genau, sonst träfe "de" auch "Bangladesh"
			return strings.EqualFold(a.Country, t.val) == (t.op != "!=")
		}
		return t.str(a.Country, a.CountryName)
	case "asn":
		if _, err := strconv.Atoi(strings.TrimPrefix(t.val, "as")); err == nil && t.re == nil {
			t.val = strings.TrimPrefix(t.val, "as")
			return t.num(a.ASN)
		}
		return t.str("AS"+strconv.Itoa(a.ASN), a.ASOrg)
	case "org":
		return t.str(a.ASOrg)
	case "service":
		return t.str(a.Services...)
	case "port":
		for _, p := range a.Ports {
			if t.num(p) {
				return true
			}
		}
		return false
	case "stufe":
		return t.num(a.Stufe)
	case "events":
		return t.num(a.Events)
	case "cred":
		return t.str(keys(a.creds)...)
	case "user", "pass":
		for k := range a.creds {
			u, p, _ := strings.Cut(k, " / ")
			if t.field == "user" && t.str(u) || t.field == "pass" && t.str(p) {
				return true
			}
		}
		return false
	case "cmd":
		return t.str(a.Commands...) || t.str(a.ProtoCommands...) || t.str(a.Decoded...)
	case "path":
		return t.str(keys(a.paths)...)
	case "url":
		return t.str(a.URLs...)
	case "tag":
		for _, x := range a.Tags {
			if t.str(x.Key, x.Label) {
				return true
			}
		}
		return false
	case "cve":
		for _, x := range a.CVEs {
			if t.str(x.Key, x.Label) {
				return true
			}
		}
		return false
	case "client":
		return t.str(a.Clients...)
	case "fp":
		return t.str(a.Fingerprints...)
	case "wallet":
		return t.str(a.Wallets...) || t.str(a.Pools...)
	case "art":
		return t.str(a.Profile)
	case "scanner":
		return (a.Scanner != "") == yes(t.val)
	case "login":
		return a.Success == yes(t.val)
	}
	return false
}

// matchQuery: alle Teile müssen zutreffen; "-" kehrt einen Teil um.
func (a *Attack) matchQuery(terms []qTerm) bool {
	for _, t := range terms {
		if a.matchTerm(t) == t.neg {
			return false
		}
	}
	return true
}

// ---------- Gespeicherte Suchen ----------

type savedSearch struct {
	Name  string `json:"name"`
	Query string `json:"q"`
}

func (h *Hive) loadSearches() []savedSearch {
	var list []savedSearch
	if v, ok := h.st.GetKV("saved_searches"); ok {
		json.Unmarshal([]byte(v), &list)
	}
	if list == nil {
		list = []savedSearch{}
	}
	return list
}

// searchesMu: Lesen, Ändern und Schreiben der gespeicherten Suchen am Stück (zweites Audit, N8).
var searchesMu sync.Mutex

func (h *Hive) searches(w http.ResponseWriter, r *http.Request) {
	searchesMu.Lock()
	defer searchesMu.Unlock()
	list := h.loadSearches()
	switch r.Method {
	case "POST":
		var in savedSearch
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil {
			httpErr(w, 400, "ungültige Eingabe")
			return
		}
		in.Name, in.Query = clip(strings.TrimSpace(in.Name), 60), clip(strings.TrimSpace(in.Query), 500)
		if in.Name == "" || in.Query == "" {
			httpErr(w, 400, "Name und Suche angeben")
			return
		}
		kept := []savedSearch{in}
		for _, s := range list {
			if s.Name != in.Name {
				kept = append(kept, s)
			}
		}
		list = kept[:min(len(kept), 30)]
	case "DELETE":
		name := r.PathValue("name")
		kept := []savedSearch{}
		for _, s := range list {
			if s.Name != name {
				kept = append(kept, s)
			}
		}
		list = kept
	default:
		writeJSON(w, list)
		return
	}
	sort.SliceStable(list, func(i, j int) bool { return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name) })
	b, _ := json.Marshal(list)
	if err := h.st.SetKV("saved_searches", string(b)); err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	writeJSON(w, list)
}
