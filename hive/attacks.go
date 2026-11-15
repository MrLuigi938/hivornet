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
	attackScanMax = 300000 // höchstens so viele Ereignisse je Abfrage lesen
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
	Commands      []string       `json:"commands,omitempty"`
	URLs          []string       `json:"urls,omitempty"`
	Clients       []string       `json:"clients,omitempty"`
	Tags          []Count        `json:"tags,omitempty"` // erkannte Muster (Key = ID, Label = Name)
	Success       bool           `json:"success,omitempty"`
	SuccessCred   string         `json:"success_cred,omitempty"`
	Stufe         int            `json:"stufe"`
	Profile       string         `json:"profile"`
	TarpitMs      int64          `json:"tarpit_ms,omitempty"`
	Sessions      []string       `json:"sessions,omitempty"`
	Strip         []stripEvent   `json:"strip,omitempty"` // Zeitstreifen: höchstens stripMax Ereignisse
	// nur zum Aufbau
	creds, paths, tags, loginSvc map[string]int
	svc                          map[string]bool
	port                         map[int]bool
	seenCmd, seenSess, seenCli   map[string]bool
}

type stripEvent struct {
	T    int64  `json:"t"`
	Type string `json:"type"`
}

const stripMax = 400

func newAttack(e *Event) *Attack {
	ms := e.TS.UnixMilli()
	return &Attack{ID: e.SrcIP + "@" + strconv.FormatInt(ms, 10), IP: e.SrcIP, First: ms, Last: ms, Counts: map[string]int{},
		creds: map[string]int{}, paths: map[string]int{}, tags: map[string]int{}, loginSvc: map[string]int{},
		svc: map[string]bool{}, port: map[int]bool{}, seenCmd: map[string]bool{}, seenSess: map[string]bool{}, seenCli: map[string]bool{}}
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
	a.Counts[e.Type]++
	if a.Country == "" && e.Country != "" {
		a.Country, a.CountryName, a.City, a.Lat, a.Lon, a.ASN, a.ASOrg = e.Country, e.CountryName, e.City, e.Lat, e.Lon, e.ASN, e.ASOrg
	}
	if e.Service != "" {
		a.svc[e.Service] = true
	}
	if e.DstPort > 0 {
		a.port[e.DstPort] = true
	}
	if e.Session != "" && !a.seenSess[e.Session] && len(a.seenSess) < 50 {
		a.seenSess[e.Session] = true
		a.Sessions = append(a.Sessions, e.Session)
	}
	a.TarpitMs += e.TarpitMs
	if e.Type != "disconnect" && len(a.Strip) < stripMax {
		a.Strip = append(a.Strip, stripEvent{ms, e.Type})
	}
	switch e.Type {
	case "login":
		a.loginSvc[e.Service]++
		var k string
		switch {
		case dataString(e.Data, "cookie") != "":
			k = e.Username + " (RDP-Cookie)"
		case dataBool(e.Data, "password_hashed"):
			k = e.Username + " / (gehasht)"
		default:
			k = e.Username + " / " + e.Password
		}
		a.creds[clip(k, 200)]++
		if dataBool(e.Data, "success") || dataBool(e.Data, "accepted") {
			a.Success, a.SuccessCred = true, clip(k, 200)
		}
	case "request":
		p := dataString(e.Data, "path")
		if m := dataString(e.Data, "method"); m != "" && m != "GET" {
			p = m + " " + p
		}
		a.paths[clip(p, 300)]++
	case "command":
		c := clip(dataString(e.Data, "input"), 500)
		if c != "" && !a.seenCmd[c] && len(a.Commands) < 30 {
			a.seenCmd[c] = true
			a.Commands = append(a.Commands, c)
		}
	case "download":
		if u := dataString(e.Data, "url"); u != "" && len(a.URLs) < 10 && !slices.Contains(a.URLs, u) {
			a.URLs = append(a.URLs, clip(u, 300))
		}
	case "client_version":
		if v := dataString(e.Data, "version"); v != "" && !a.seenCli[v] && len(a.Clients) < 5 {
			a.seenCli[v] = true
			a.Clients = append(a.Clients, clip(v, 120))
		}
	}
	text, on := eventText(e)
	for _, id := range matchPatterns(text, on) {
		a.tags[id]++
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
	}
	c := a.Counts
	switch {
	case c["download"] > 0:
		a.Stufe = stufeDownload
	case c["command"] > 0:
		a.Stufe = stufeBefehle
	case a.Success:
		a.Stufe = stufeLogin
	case c["login"] > 0 || c["request"] > 0 || c["payload"] > 0:
		a.Stufe = stufeVersuch
	}
	a.Profile = a.classify()
}

func (a *Attack) classify() string {
	has := func(id string) bool { return a.tags[id] > 0 }
	c := a.Counts
	switch {
	case has("iot_botnet"):
		return "IoT-Botnetz (Mirai-Art)"
	case has("miner"):
		return "Krypto-Miner"
	case has("redis_takeover") || a.svc["redis"] && c["command"] > 0:
		return "Redis-Übernahme"
	case has("docker_escape") || a.svc["dockerapi"] && (c["command"] > 0 || c["request"] > 0):
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
		if has("web_rce") || has("iot_exploit") || has("log4shell") || has("traversal") || has("sqli") {
			return "Web-Exploit"
		}
		return "Web-Scanner"
	case c["payload"] > 0:
		return "Protokoll-Probe"
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
	where, args := "ts >= ?", []any{since.UnixMilli()}
	if len(ips) > 0 {
		where += " AND src_ip IN (" + strings.TrimSuffix(strings.Repeat("?,", len(ips)), ",") + ")"
		for _, ip := range ips {
			args = append(args, ip)
		}
	}
	args = append(args, attackScanMax+1)
	rs, err := h.st.db.QueryContext(ctx, `SELECT ts, service, type, src_ip, dst_port, session, username, password, data, tarpit_ms,
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
		if err := rs.Scan(&ms, &e.Service, &e.Type, &e.SrcIP, &e.DstPort, &e.Session, &e.Username, &e.Password, &data, &e.TarpitMs,
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
	return out, n > attackScanMax, nil
}

func (a *Attack) matches(q string) bool {
	if q == "" {
		return true
	}
	parts := []string{a.IP, a.Country, a.CountryName, a.City, a.ASOrg, "AS" + strconv.Itoa(a.ASN), a.Profile, a.SuccessCred}
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
	parts = append(parts, a.URLs...)
	parts = append(parts, a.Clients...)
	for _, t := range a.Tags {
		parts = append(parts, t.Label)
	}
	return strings.Contains(strings.ToLower(strings.Join(parts, "\n")), q)
}

// attacks: GET /api/attacks
//
//	range=1h|24h|7d     Zeitraum (Standard 24h)
//	active=1            nur Angriffe mit Aktivität in den letzten 15 Minuten
//	ip=a,b,c            nur diese IPs (für Live-Aktualisierung)
//	stufe=2,3 service=ssh q=text before=<ms> limit=50
func (h *Hive) attacks(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	q := r.URL.Query()
	since, _ := rangeSince(r)
	if rng := q.Get("range"); rng != "1h" && rng != "24h" && rng != "7d" {
		since = time.Now().Add(-24 * time.Hour)
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
	svc, text := q.Get("service"), strings.ToLower(strings.TrimSpace(q.Get("q")))
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	limit := qInt(r, "limit", 50, 500)
	out := make([]*Attack, 0, limit)
	matched := 0
	for _, a := range list {
		if want != nil && !want[a.Stufe] || svc != "" && !a.svc[svc] || !a.matches(text) {
			continue
		}
		matched++
		if before > 0 && a.Last >= before || len(out) >= limit {
			continue
		}
		out = append(out, a)
	}
	writeJSON(w, map[string]any{"attacks": out, "total": len(list), "matched": matched, "stufen": stufen, "truncated": truncated,
		"gap_ms": attackGap.Milliseconds()})
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
	rs, _ = h.rows(ctx, `SELECT ts / 3600000 AS hour, COUNT(*) AS n FROM events WHERE ts >= ? AND `+succ+` GROUP BY hour`, since.UnixMilli())
	for _, row := range rs {
		hr, _ := row["hour"].(int64)
		n, _ := row["n"].(int64)
		get("success")[idx(hr)] += n
	}
	// Summen jetzt und im Zeitraum davor
	totals, prev := map[string]int64{}, map[string]int64{}
	pfrom := since.Add(-d)
	rs, _ = h.rows(ctx, `SELECT type, SUM(CASE WHEN hour >= ? THEN cnt ELSE 0 END) AS cur, SUM(CASE WHEN hour < ? THEN cnt ELSE 0 END) AS prev
		FROM hourly WHERE hour >= ? GROUP BY type`, from, from, pfrom.UnixMilli()/3600000)
	for _, row := range rs {
		t := fmt.Sprint(row["type"])
		totals[t], _ = row["cur"].(int64)
		prev[t], _ = row["prev"].(int64)
	}
	var ipsNow, ipsPrev, okNow, okPrev int64
	h.st.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT key) FROM top_hourly WHERE field = 'ip' AND hour >= ?`, from).Scan(&ipsNow)
	h.st.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT key) FROM top_hourly WHERE field = 'ip' AND hour >= ? AND hour < ?`, pfrom.UnixMilli()/3600000, from).Scan(&ipsPrev)
	h.st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE ts >= ? AND `+succ, since.UnixMilli()).Scan(&okNow)
	h.st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE ts >= ? AND ts < ? AND `+succ, pfrom.UnixMilli(), since.UnixMilli()).Scan(&okPrev)
	totals["ips"], prev["ips"], totals["success"], prev["success"] = ipsNow, ipsPrev, okNow, okPrev
	writeJSON(w, map[string]any{"from": from * 3600000, "bucket_hours": bucket, "series": series, "totals": totals, "prev": prev,
		"active_tarpits": h.sensors.ActiveTarpits()})
}
