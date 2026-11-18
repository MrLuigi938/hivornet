package main

// Angriffe: Ereignisse einer IP gehören zu einem Angriff, solange zwischen zwei
// Ereignissen weniger als attackGap liegt. Die Web-UI zeigt Angriffe statt einzelner
// Ereignisse (Seite "Angriffe", Dashboard "Gerade aktiv"); jeder Angriff trägt eine
// Zusammenfassung, eine Stufe (wie weit der Angreifer kam) und eine vermutete Art.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	attackGap     = 15 * time.Minute
	attackScanMax = 500000 // höchstens so viele Ereignisse je Abfrage lesen (die neuesten)
)

// Stufen: was der Angreifer höchstens erreicht hat.
const (
	stufeScan     = 0 // nur Verbindungen, Banner, Client-Version
	stufeVersuch  = 1 // Login-Versuche, Web-Anfragen, Daten
	stufeLogin    = 2 // Login (zum Schein) angenommen
	stufeBefehle  = 3 // Befehle ausgeführt
	stufeDownload = 4 // Datei nachgeladen
)

type Attack struct {
	ID            string         `json:"id"`
	IP            string         `json:"ip"`
	Country       string         `json:"country,omitempty"`
	CountryName   string         `json:"country_name,omitempty"`
	City          string         `json:"city,omitempty"`
	Lat           float64        `json:"lat,omitempty"`
	Lon           float64        `json:"lon,omitempty"`
	ASN           int            `json:"asn,omitempty"`
	ASOrg         string         `json:"as_org,omitempty"`
	First         int64          `json:"first"`
	Last          int64          `json:"last"`
	Events        int            `json:"events"`
	Counts        map[string]int `json:"counts"`
	Services      []string       `json:"services"`
	Ports         []int          `json:"ports"`
	Creds         []Count        `json:"creds,omitempty"`
	CredsDistinct int            `json:"creds_distinct,omitempty"`
	Paths         []Count        `json:"paths,omitempty"`
	PathsDistinct int            `json:"paths_distinct,omitempty"`
	Commands      []string       `json:"commands,omitempty"`       // ausgeführte Befehle (einstufung.go)
	ProtoCommands []string       `json:"proto_commands,omitempty"` // Protokoll-Befehle vor der Anmeldung, Eingaben an der Login-Abfrage
	URLs          []string       `json:"urls,omitempty"`
	Wallets       []string       `json:"wallets,omitempty"`    // Krypto-Wallets aus Miner-Befehlen (indicators.go)
	Pools         []string       `json:"pools,omitempty"`      // Mining-Pools
	Sensors       []string       `json:"sensors,omitempty"`    // meldende Sensoren (feed.go: Vertrauen)
	AIReplies     []AIReply      `json:"ai_replies,omitempty"` // Antworten des Sprachmodells (mimic.go)
	Decoded       []string       `json:"decoded,omitempty"`    // entschlüsselte Inhalte (Base64, Hex …)
	Clients       []string       `json:"clients,omitempty"`
	Fingerprints  []string       `json:"fingerprints,omitempty"` // JA4, JA3, HASSH, HTTP-Kopfzeilen (tlsfp.go)
	Tags          []Count        `json:"tags,omitempty"`         // erkannte Muster (Key = ID, Label = Name)
	CVEs          []Count        `json:"cves,omitempty"`         // bekannte Lücken (cve.go; Key = CVE, Label = Name)
	Mitre         []string       `json:"mitre,omitempty"`        // MITRE-ATT&CK-Techniken der Muster
	Success       bool           `json:"success,omitempty"`
	SuccessCred   string         `json:"success_cred,omitempty"`
	Stufe         int            `json:"stufe"`
	Own           bool           `json:"own,omitempty"`     // eigener Test (ownnet.go)
	Scanner       string         `json:"scanner,omitempty"` // Forschungsscanner (scanner.go) oder geprüfter Suchmaschinen-Bot
	Bot           string         `json:"bot,omitempty"`     // angeblicher Suchmaschinen-Bot und Prüfergebnis (botverify.go)
	userAgents    []string
	Profile       string       `json:"profile"`
	TarpitMs      int64        `json:"tarpit_ms,omitempty"`
	Sessions      []string     `json:"sessions,omitempty"`
	Strip         []stripEvent `json:"strip,omitempty"` // Zeitstreifen: höchstens stripMax Ereignisse
	// nur zum Aufbau
	creds, paths, tags, loginSvc map[string]int
	cves                         map[string]int
	svc                          map[string]bool
	port                         map[int]bool
	seenCmd, seenSess, seenCli   map[string]bool
	okSess                       map[string]bool // Sitzungen mit angenommenem Login
	stripStride, stripSeen       int             // Ausdünnung des Zeitstreifens (addStrip)
}

type stripEvent struct {
	T    int64  `json:"t"`
	Type string `json:"type"`
}

const stripMax = 400

// stripRare: Arten, die im Zeitstreifen immer einen Strich bekommen (sonst gehen die
// wenigen Befehle zwischen Hunderten Logins unter).
var stripRare = map[string]bool{"command": true, "download": true, "tty": true, "ai_reply": true, "payload": true}

// addStrip: Der Streifen hält höchstens stripMax Striche. Ist er voll, wird jeder zweite
// häufige Strich gestrichen und von da an nur noch jedes zweite (vierte, achte …) häufige
// Ereignis aufgenommen. So deckt der Streifen auch lange Angriffe bis zum Ende ab; vorher
// endete er nach den ersten 400 Ereignissen.
func (a *Attack) addStrip(ms int64, typ string) {
	if a.stripStride == 0 {
		a.stripStride = 1
	}
	if !stripRare[typ] {
		a.stripSeen++
		if a.stripSeen%a.stripStride != 0 {
			return
		}
	}
	a.Strip = append(a.Strip, stripEvent{ms, typ})
	for len(a.Strip) >= stripMax {
		kept := a.Strip[:0]
		n, common := 0, 0
		for _, x := range a.Strip {
			if !stripRare[x.Type] {
				common++
			}
		}
		for _, x := range a.Strip {
			if stripRare[x.Type] && common > 0 { // nur seltene übrig: dann auch diese ausdünnen
				kept = append(kept, x)
				continue
			}
			if n%2 == 0 {
				kept = append(kept, x)
			}
			n++
		}
		a.Strip = kept
		a.stripStride *= 2
	}
}

func newAttack(e *Event) *Attack {
	ms := e.TS.UnixMilli()
	return &Attack{ID: e.SrcIP + "@" + strconv.FormatInt(ms, 10), IP: e.SrcIP, First: ms, Last: ms, Counts: map[string]int{},
		creds: map[string]int{}, paths: map[string]int{}, tags: map[string]int{}, loginSvc: map[string]int{}, cves: map[string]int{},
		svc: map[string]bool{}, port: map[int]bool{}, seenCmd: map[string]bool{}, seenSess: map[string]bool{}, seenCli: map[string]bool{},
		okSess: map[string]bool{}}
}

// kindCount: Zähler in Attack.Counts für die Arten aus einstufung.go. Befehle zählen nur
// als "command", wenn sie ausgeführt wurden; sonst unter "proto_command" bzw. "prompt".
var kindCount = map[evKind]string{kindTLSPlain: "tls_plain", kindPrompt: "prompt", kindProbe: "probe_command", kindProto: "proto_command", kindExec: "command"}

func (a *Attack) addCommand(list *[]string, c string) {
	c = clip(c, 500)
	if c != "" && !a.seenCmd[c] && len(*list) < 30 {
		a.seenCmd[c] = true
		*list = append(*list, c)
	}
}

func dataBool(d json.RawMessage, key string) bool {
	if len(d) == 0 {
		return false
	}
	var m map[string]any
	if json.Unmarshal(d, &m) != nil {
		return false
	}
	b, _ := m[key].(bool)
	return b
}

func (a *Attack) add(e *Event) {
	ms := e.TS.UnixMilli()
	a.Last = ms
	a.Events++
	kind := eventKind(e, a.okSess[e.Session])
	if k, ok := kindCount[kind]; ok {
		a.Counts[k]++
	} else {
		a.Counts[e.Type]++
	}
	if a.Country == "" && e.Country != "" {
		a.Country, a.CountryName, a.City, a.Lat, a.Lon, a.ASN, a.ASOrg = e.Country, e.CountryName, e.City, e.Lat, e.Lon, e.ASN, e.ASOrg
	}
	if e.Service != "" {
		a.svc[e.Service] = true
	}
	if e.Sensor != "" && len(a.Sensors) < 8 && !slices.Contains(a.Sensors, e.Sensor) {
		a.Sensors = append(a.Sensors, e.Sensor)
	}
	if e.DstPort > 0 {
		a.port[e.DstPort] = true
	}
	if e.Session != "" && !a.seenSess[e.Session] && len(a.seenSess) < 50 {
		a.seenSess[e.Session] = true
		a.Sessions = append(a.Sessions, e.Session)
	}
	a.TarpitMs += e.TarpitMs
	if e.Type != "disconnect" {
		a.addStrip(ms, e.Type)
	}
	if e.Type == "connect" || e.Type == "disconnect" {
		return // häufigste Ereignisse: nichts weiter auszuwerten
	}
	for _, f := range eventFingerprints(e) {
		if len(a.Fingerprints) < 8 && !slices.Contains(a.Fingerprints, f) {
			a.Fingerprints = append(a.Fingerprints, f)
		}
	}
	var d map[string]any // Daten nur einmal lesen
	if len(e.Data) > 0 {
		json.Unmarshal(e.Data, &d)
	}
	str := func(k string) string { s, _ := d[k].(string); return s }
	flag := func(k string) bool { b, _ := d[k].(bool); return b }
	switch {
	case kind == kindPrompt:
		lines, _ := promptLines(e)
		for _, l := range lines {
			a.addCommand(&a.ProtoCommands, "an der Login-Abfrage: "+l)
		}
	case kind == kindTLSPlain && e.Type == "command":
		// kein Befehl; das Merkmal tls_on_plain setzt die Musterprüfung unten
	case e.Type == "command":
		if kind == kindExec {
			a.addCommand(&a.Commands, str("input"))
		} else {
			a.addCommand(&a.ProtoCommands, str("input"))
		}
	}
	switch e.Type {
	case "login":
		if kind == kindPrompt {
			break
		}
		a.loginSvc[e.Service]++
		var k string
		switch {
		case e.Service == "snmp":
			k = "SNMP-Community " + e.Password
		case str("cookie") != "":
			k = e.Username + " (RDP-Cookie)"
		case flag("password_hashed"):
			k = e.Username + " / (gehasht)"
		default:
			k = e.Username + " / " + e.Password
		}
		a.creds[clip(k, 200)]++
		if baitUsed(e) {
			a.tags["bait_used"]++
		}
		if flag("success") || flag("accepted") {
			a.Success, a.SuccessCred = true, clip(k, 200)
			if e.Session != "" {
				a.okSess[e.Session] = true
			}
		}
		return
	case "request":
		a.paths[clip(requestKey(e), 300)]++
		if ua := str("user_agent"); ua != "" && len(a.userAgents) < 5 && !slices.Contains(a.userAgents, ua) {
			a.userAgents = append(a.userAgents, clip(ua, 200))
		}
	case "download":
		if u := str("url"); u != "" && len(a.URLs) < 10 && !slices.Contains(a.URLs, u) {
			a.URLs = append(a.URLs, clip(u, 300))
		}
	case "ai_reply":
		// Text des Modells: keine Muster- oder Adressprüfung (stammt nicht vom Angreifer)
		if len(a.AIReplies) < 10 {
			a.AIReplies = append(a.AIReplies, aiReplyFrom(e))
		}
		return
	case "client_version":
		if v := str("version"); v != "" && !a.seenCli[v] && len(a.Clients) < 5 {
			a.seenCli[v] = true
			a.Clients = append(a.Clients, clip(v, 120))
		}
		return
	}
	text, on, revealed := analysisText(e)
	for _, id := range eventPatterns(e, text, on, revealed) {
		a.tags[id]++
	}
	for _, r := range eventCVEs(text, on) {
		a.cves[r.CVE]++
	}
	for _, d := range revealed {
		if len(a.Decoded) < 10 && !slices.Contains(a.Decoded, clip(d, 500)) {
			a.Decoded = append(a.Decoded, clip(d, 500))
		}
	}
	// Nachlade-Adressen auch aus Befehlen (wget, curl …) und aus entschlüsselten Inhalten
	src := text
	if e.Type == "request" {
		src = "" // Pfade sind oft nur Proben; nur entschlüsselte Adressen zählen
	}
	if e.Type == "command" || e.Type == "payload" || e.Type == "request" {
		for _, u := range allURLs(src, revealed, 6) {
			if len(a.URLs) < 10 && !slices.Contains(a.URLs, clip(u, 300)) {
				a.URLs = append(a.URLs, clip(u, 300))
			}
		}
	}
	// Wallets und Mining-Pools (indicators.go)
	if e.Type == "command" || e.Type == "payload" {
		for _, t := range append([]string{src}, revealed...) {
			ws, ps := cryptoIndicators(t)
			for _, w := range ws {
				if len(a.Wallets) < 6 && !slices.Contains(a.Wallets, w) {
					a.Wallets = append(a.Wallets, w)
				}
			}
			for _, p := range ps {
				if len(a.Pools) < 6 && !slices.Contains(a.Pools, p) {
					a.Pools = append(a.Pools, p)
				}
			}
		}
	}
}

func topCounts(m map[string]int, max int) []Count {
	out := make([]Count, 0, len(m))
	for k, n := range m {
		out = append(out, Count{Key: k, N: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].N > out[j].N || out[i].N == out[j].N && out[i].Key < out[j].Key })
	if len(out) > max {
		out = out[:max]
	}
	return out
}

var loginProfile = map[string]string{
	"ssh": "SSH-Brute-Force", "telnet": "Telnet-Brute-Force", "ftp": "FTP-Brute-Force", "mysql": "MySQL-Brute-Force",
	"vnc": "VNC-Brute-Force", "rdp": "RDP-Abtastung", "smtp": "SMTP-Anmeldeversuche", "http": "Web-Anmeldeversuche", "https": "Web-Anmeldeversuche",
}

// finish berechnet Listen, Stufe und vermutete Art.
func (a *Attack) finish() {
	for s := range a.svc {
		a.Services = append(a.Services, s)
	}
	sort.Strings(a.Services)
	for p := range a.port {
		a.Ports = append(a.Ports, p)
	}
	sort.Ints(a.Ports)
	a.Creds, a.CredsDistinct = topCounts(a.creds, 12), len(a.creds)
	a.Paths, a.PathsDistinct = topCounts(a.paths, 12), len(a.paths)
	a.Tags = topCounts(a.tags, 8)
	for i := range a.Tags {
		if p := patternByID[a.Tags[i].Key]; p != nil {
			a.Tags[i].Label = p.Name
		}
		for _, m := range patternMitre[a.Tags[i].Key] {
			if !slices.Contains(a.Mitre, m) {
				a.Mitre = append(a.Mitre, m)
			}
		}
	}
	a.CVEs = topCounts(a.cves, 8)
	for i := range a.CVEs {
		a.CVEs[i].Label = cveByID[a.CVEs[i].Key].Name
	}
	a.Stufe = a.stufe()
	a.Own = ownHidden(a.IP) // eigener Test, der aus Kennzahlen herausgehalten wird
	a.Scanner = researchScanner(a.ASOrg, a.userAgents...)
	if label, real := botLabel(a.IP, a.userAgents); label != "" {
		a.Bot = label
		if real && a.Scanner == "" {
			a.Scanner = strings.Fields(label)[0]
		}
	}
	a.Profile = a.classify()
}

// stufe: höchste erreichte Stufe. Was als ausgeführter Befehl zählt, regelt einstufung.go;
// TLS-Handshakes und reine Protokoll-Abfragen (PING, INFO, EHLO …) bleiben Abtasten.
func (a *Attack) stufe() int {
	c := a.Counts
	switch {
	case c["download"] > 0:
		return stufeDownload
	case c["command"] > 0:
		return stufeBefehle
	case a.Success || a.tags["bait_used"] > 0: // Köder-Zugangsdaten: wusste, was er tut
		return stufeLogin
	case c["login"] > 0 || c["request"] > 0 || c["payload"] > 0 || c["proto_command"] > 0 || c["prompt"] > 0:
		return stufeVersuch
	}
	return stufeScan
}

func (a *Attack) classify() string {
	has := func(id string) bool { return a.tags[id] > 0 }
	c := a.Counts
	switch {
	case has("bait_used"):
		return "Köder benutzt"
	case has("iot_botnet"):
		return "IoT-Botnetz (Mirai-Art)"
	case has("miner"):
		return "Krypto-Miner"
	case has("redis_takeover") || a.svc["redis"] && c["command"] > 0:
		return "Redis-Übernahme"
	case has("docker_escape") || a.svc["dockerapi"] && c["command"] > 0:
		return "Docker-API-Angriff"
	case c["command"] > 0 || c["download"] > 0:
		best, n := "", 0
		for s, k := range a.loginSvc {
			if k > n || k == n && s < best {
				best, n = s, k
			}
		}
		if best == "" && len(a.Services) > 0 {
			best = a.Services[0]
		}
		return strings.ToUpper(svcShort(best)) + "-Einbruch"
	case a.svc["snmp"] && len(a.svc) == 1:
		return "SNMP-Abtastung"
	case a.svc["sip"] && len(a.svc) == 1:
		return "SIP-Scan"
	case a.svc["dns"] && len(a.svc) == 1:
		return "DNS-Abfragen"
	case c["login"] > 0:
		best, n := "", 0
		for s, k := range a.loginSvc {
			if k > n || k == n && s < best {
				best, n = s, k
			}
		}
		if p, ok := loginProfile[best]; ok {
			return p
		}
		return "Anmeldeversuche"
	case c["request"] > 0:
		if a.svc["dockerapi"] && len(a.svc) == 1 {
			return "Docker-API-Abfrage"
		}
		if has("web_rce") || has("iot_exploit") || has("log4shell") || has("traversal") || has("sqli") {
			return "Web-Exploit"
		}
		return "Web-Scanner"
	case c["payload"] > 0 || c["proto_command"] > 0 || c["prompt"] > 0 || c["probe_command"] > 0:
		return "Protokoll-Probe"
	case c["tls_plain"] > 0:
		return "TLS-Scan"
	case len(a.port) >= 3:
		return "Port-Scan"
	}
	return "Verbindungsversuch"
}

// svcShort: Dienstname für "XY-Einbruch".
func svcShort(s string) string {
	switch s {
	case "dockerapi":
		return "Docker"
	case "":
		return "Dienst"
	}
	return s
}

// loadAttacks liest die Ereignisse ab since (optional nur für bestimmte IPs) und
// bündelt sie zu Angriffen, neueste Aktivität zuerst. truncated: es gab mehr Ereignisse,
// als gelesen wurden.
func (h *Hive) loadAttacks(ctx context.Context, since time.Time, ips []string) ([]*Attack, bool, error) {
	truncated := false
	if len(ips) == 0 {
		// Mehr Ereignisse als lesbar? Dann erst ab dem Zeitpunkt lesen, ab dem es die neuesten
		// attackScanMax sind. So fehlen nur die ältesten Angriffe, nicht beliebige IPs.
		var ts int64
		err := h.st.db.QueryRowContext(ctx, `SELECT ts FROM events WHERE ts >= ? ORDER BY ts DESC LIMIT 1 OFFSET ?`, since.UnixMilli(), attackScanMax).Scan(&ts)
		if err == nil {
			since, truncated = time.UnixMilli(ts+1), true
		}
	}
	where, args := "ts >= ?", []any{since.UnixMilli()}
	if len(ips) > 0 {
		where += " AND src_ip IN (" + strings.TrimSuffix(strings.Repeat("?,", len(ips)), ",") + ")"
		for _, ip := range ips {
			args = append(args, ip)
		}
	}
	args = append(args, attackScanMax+1)
	rs, err := h.st.db.QueryContext(ctx, `SELECT ts, sensor, service, type, src_ip, dst_port, session, username, password, data, tarpit_ms,
		country, country_name, city, lat, lon, asn, as_org FROM events WHERE `+where+` ORDER BY src_ip, ts LIMIT ?`, args...)
	if err != nil {
		return nil, false, err
	}
	defer rs.Close()
	var out []*Attack
	var cur *Attack
	n := 0
	for rs.Next() {
		n++
		if n > attackScanMax {
			break
		}
		var e Event
		var ms int64
		var data []byte
		if err := rs.Scan(&ms, &e.Sensor, &e.Service, &e.Type, &e.SrcIP, &e.DstPort, &e.Session, &e.Username, &e.Password, &data, &e.TarpitMs,
			&e.Country, &e.CountryName, &e.City, &e.Lat, &e.Lon, &e.ASN, &e.ASOrg); err != nil {
			return nil, false, err
		}
		e.TS, e.Data = time.UnixMilli(ms), data
		if cur == nil || cur.IP != e.SrcIP || ms-cur.Last > attackGap.Milliseconds() {
			cur = newAttack(&e)
			out = append(out, cur)
		}
		cur.add(&e)
	}
	if err := rs.Err(); err != nil {
		return nil, false, err
	}
	for _, a := range out {
		a.finish()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last > out[j].Last })
	return out, truncated || n > attackScanMax, nil
}

func (a *Attack) matches(q string) bool {
	if q == "" {
		return true
	}
	parts := []string{a.IP, a.Country, a.CountryName, a.City, a.ASOrg, "AS" + strconv.Itoa(a.ASN), a.Profile, a.SuccessCred, a.Scanner, a.Bot}
	for k := range a.creds { // alle, nicht nur die angezeigten
		parts = append(parts, k)
	}
	for k := range a.paths {
		parts = append(parts, k)
	}
	for k := range a.seenCmd {
		parts = append(parts, k)
	}
	parts = append(parts, a.Commands...)
	parts = append(parts, a.ProtoCommands...)
	parts = append(parts, a.URLs...)
	parts = append(parts, a.Decoded...)
	parts = append(parts, a.Clients...)
	parts = append(parts, a.Fingerprints...)
	for _, t := range a.Tags {
		parts = append(parts, t.Label)
	}
	for _, c := range a.CVEs {
		parts = append(parts, c.Key, c.Label)
	}
	return strings.Contains(strings.ToLower(strings.Join(parts, "\n")), q)
}

// attacks: GET /api/attacks
//
//	range=1h|24h|7d     Zeitraum (Standard 24h)
//	active=1            nur Angriffe mit Aktivität in den letzten 15 Minuten
//	ip=a,b,c            nur diese IPs (für Live-Aktualisierung)
//	stufe=2,3 service=ssh success=1 q=text before=<ms> limit=50
func (h *Hive) attacks(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	q := r.URL.Query()
	since := time.Now().Add(-24 * time.Hour)
	if rng := q.Get("range"); rng == "all" { // alles, was die Aufbewahrung hält
		since = time.Now().AddDate(0, 0, -max(h.retentionDays(), 1))
	} else if _, ok := parseRange(rng); ok {
		since, _ = rangeSince(r)
	}
	active := q.Get("active") == "1"
	if active {
		since = time.Now().Add(-6 * time.Hour) // Beginn laufender Angriffe mitnehmen
	}
	var ips []string
	if v := q.Get("ip"); v != "" {
		for _, s := range strings.Split(v, ",") {
			if net.ParseIP(strings.TrimSpace(s)) != nil && len(ips) < 50 {
				ips = append(ips, strings.TrimSpace(s))
			}
		}
		if len(ips) == 0 {
			httpErr(w, 400, "ungültige IP")
			return
		}
	}
	list, truncated, err := h.loadAttacks(ctx, since, ips)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	if active {
		cut := time.Now().Add(-attackGap).UnixMilli()
		n := 0
		for _, a := range list {
			if a.Last >= cut {
				list[n] = a
				n++
			}
		}
		list = list[:n]
	}
	// Eigene Tests ausblenden, außer own=1 (Filter, Angreifer-Profil)
	showOwn, nOwn := q.Get("own") == "1", 0
	{
		n := 0
		for _, a := range list {
			hidden := a.Own
			if hidden {
				nOwn++
			}
			if hidden && !showOwn {
				continue
			}
			list[n] = a
			n++
		}
		list = list[:n]
	}
	// Zähler je Stufe vor den Filtern (für die Filter-Schaltflächen)
	stufen := make([]int, 5)
	for _, a := range list {
		stufen[a.Stufe]++
	}
	var want map[int]bool
	if v := q.Get("stufe"); v != "" {
		want = map[int]bool{}
		for _, s := range strings.Split(v, ",") {
			if n, err := strconv.Atoi(s); err == nil {
				want[n] = true
			}
		}
	}
	svc, terms := q.Get("service"), parseQuery(q.Get("q")) // Suchsprache (query.go)
	onlyOK := q.Get("success") == "1"                      // nur Angriffe mit angenommenem Login
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	limit := qInt(r, "limit", 50, 500)
	out := make([]*Attack, 0, limit)
	matched := 0
	for _, a := range list {
		if want != nil && !want[a.Stufe] || svc != "" && !a.svc[svc] || onlyOK && !a.Success || !a.matchQuery(terms) {
			continue
		}
		matched++
		if before > 0 && a.Last >= before || len(out) >= limit {
			continue
		}
		out = append(out, a)
	}
	writeJSON(w, map[string]any{"attacks": out, "total": len(list), "matched": matched, "stufen": stufen, "truncated": truncated, "own": nOwn,
		"gap_ms": attackGap.Milliseconds(), "retention_days": h.retentionDays()})
}

// series: Verläufe für die Kennzahlen des Dashboards und Vergleich zum Zeitraum davor.
func (h *Hive) series(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := qctx(r)
	defer cancel()
	since, d := rangeSince(r)
	bucket := int64(1)
	switch {
	case d > 8*24*time.Hour:
		bucket = 24
	case d > 2*24*time.Hour:
		bucket = 6
	}
	from := since.UnixMilli() / 3600000
	hours := int64(d / time.Hour)
	nb := int((hours + bucket - 1) / bucket)
	if nb < 1 {
		nb = 1
	}
	idx := func(hr int64) int {
		i := int((hr - from) / bucket)
		return min(max(i, 0), nb-1)
	}
	series := map[string][]int64{}
	get := func(k string) []int64 {
		if series[k] == nil {
			series[k] = make([]int64, nb)
		}
		return series[k]
	}
	for _, k := range []string{"connect", "login", "request", "command", "download", "ips", "success"} {
		get(k)
	}
	rs, err := h.rows(ctx, `SELECT hour, type, SUM(cnt) AS n FROM hourly WHERE hour >= ? GROUP BY hour, type`, from)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	for _, row := range rs {
		hr, _ := row["hour"].(int64)
		n, _ := row["n"].(int64)
		get(fmt.Sprint(row["type"]))[idx(hr)] += n
	}
	rs, _ = h.rows(ctx, `SELECT hour, COUNT(*) AS n FROM top_hourly WHERE field = 'ip' AND hour >= ? GROUP BY hour`, from)
	for _, row := range rs {
		hr, _ := row["hour"].(int64)
		n, _ := row["n"].(int64)
		get("ips")[idx(hr)] += n // Summe je Stunde: eine IP über mehrere Stunden zählt mehrfach, als Verlauf genügt das
	}
	succ := `type = 'login' AND (json_extract(data, '$.success') = 1 OR json_extract(data, '$.accepted') = 1)`
	// Summen jetzt und im Zeitraum davor
	totals, prev := map[string]int64{}, map[string]int64{}
	pfrom := since.Add(-d)
	// angenommene Logins: selten, darum je Ereignis gelesen (eigene Tests heraus, ownnet.go)
	var okNow, okPrev int64
	rs, _ = h.rows(ctx, `SELECT ts, src_ip FROM events WHERE ts >= ? AND `+succ+` LIMIT 100000`, pfrom.UnixMilli())
	for _, row := range rs {
		ts, _ := row["ts"].(int64)
		if ownHidden(fmt.Sprint(row["src_ip"])) {
			continue
		}
		if ts < since.UnixMilli() {
			okPrev++
			continue
		}
		okNow++
		get("success")[idx(ts/3600000)]++
	}
	rs, _ = h.rows(ctx, `SELECT type, SUM(CASE WHEN hour >= ? THEN cnt ELSE 0 END) AS cur, SUM(CASE WHEN hour < ? THEN cnt ELSE 0 END) AS prev
		FROM hourly WHERE hour >= ? GROUP BY type`, from, from, pfrom.UnixMilli()/3600000)
	for _, row := range rs {
		t := fmt.Sprint(row["type"])
		totals[t], _ = row["cur"].(int64)
		prev[t], _ = row["prev"].(int64)
	}
	var ipsNow, ipsPrev int64
	h.st.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT key) FROM top_hourly WHERE field = 'ip' AND hour >= ?`, from).Scan(&ipsNow)
	h.st.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT key) FROM top_hourly WHERE field = 'ip' AND hour >= ? AND hour < ?`, pfrom.UnixMilli()/3600000, from).Scan(&ipsPrev)
	totals["ips"], prev["ips"], totals["success"], prev["success"] = ipsNow, ipsPrev, okNow, okPrev
	writeJSON(w, map[string]any{"from": from * 3600000, "bucket_hours": bucket, "series": series, "totals": totals, "prev": prev,
		"active_tarpits": h.sensors.ActiveTarpits()})
}

// liveStatus: Zahlen für die Live-Anzeige in der Kopfleiste (jede Seite fragt regelmäßig):
// Angreifer mit Aktivität in den letzten 15 Minuten und gerade festgehaltene Verbindungen.
func (h *Hive) liveStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := qctx(r)
	defer cancel()
	var n int64
	if rs, err := h.st.db.QueryContext(ctx, `SELECT DISTINCT src_ip FROM events WHERE ts >= ?`, time.Now().Add(-attackGap).UnixMilli()); err == nil {
		for rs.Next() {
			var ip string
			if rs.Scan(&ip) == nil && !ownHidden(ip) {
				n++
			}
		}
		rs.Close()
	}
	writeJSON(w, map[string]any{"active": n, "tarpits": h.sensors.ActiveTarpits()})
}
