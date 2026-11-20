package main

// Dauer-Brute-Force: Eine IP meldet sich über Stunden alle paar Sekunden mit neuen
// Zugangsdaten an, jede Kombination in einer eigenen Verbindung, meist mit demselben Client.
// Solche Bots überfluten Angriffsliste, Kette und Bericht, ohne dass sie Neues zeigen.
//
// Erkennen: Ein Angriff (attacks.go) gilt als Dauer-Brute-Force, wenn er mindestens
// MinLogins Logins über mindestens MinMinutes Minuten zählt und dabei höchstens MaxClients
// verschiedene Clients und HASSH benutzt, oder wenn für ihn schon verdichtet wurde.
// Angriffskarte und Angreiferseite zeigen das Merkmal; Suche "dauer:ja", Filter "brute=0".
//
// Verdichten (Writer, store.go): Ist eine IP als Dauer-Brute-Forcer erkannt, speichert der Hive
// fehlgeschlagene Logins und die Verbindungsereignisse drumherum (connect, disconnect, Client,
// HASSH) nicht mehr einzeln. Sie zählen weiter vollständig in Kennzahlen, Angreiferliste und
// Top-Listen (jede Kombination); dazu kommt höchstens alle fünf Minuten je IP und Dienst eine
// Sammelzeile vom Typ "condensed" mit Zeitraum, Anzahl je Art, den Kombinationen samt Zähler,
// Clients und HASSH. Immer vollständig bleiben: angenommene Logins und alles danach in derselben
// Sitzung, Befehle, Downloads, Anfragen, Köder-Zugangsdaten, Tarpit-Verbindungen, eigene Netze
// und die Liste "Nie sperren".
//
// Die Top-Zähler der verdichteten Ereignisse stehen zusätzlich unter dem Feld "bf:<feld>" in
// top_hourly. Das Neuzählen der Top-Listen (setup.go, recountUpTo) liest nur gespeicherte
// Ereignisse und zählt diese Zähler danach wieder hinzu.
//
// Drosseln an der Quelle übernimmt die Firewall (pi/…/hivornet-firewall, tools/firewall.sh);
// hier stehen nur ihre Einstellungen (bruteLimitRequest, Raspberry Pi über hivornet-cowrie-config).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BruteConfig: Einstellungen (Extras.Brute).
type BruteConfig struct {
	Condense   bool `json:"condense"`    // fehlgeschlagene Logins erkannter Dauer-Brute-Forcer verdichten
	MinLogins  int  `json:"min_logins"`  // so viele Logins …
	MinMinutes int  `json:"min_minutes"` // … über mindestens so viele Minuten
	MaxClients int  `json:"max_clients"` // höchstens so viele verschiedene Clients bzw. HASSH
	// Drossel in der Firewall (Cowrie-Ports 22 und 23 bzw. im Container 2222 und 2223)
	Limit      bool `json:"limit"`
	Rate       int  `json:"rate"`        // neue Verbindungen je Minute und Quell-IP
	Burst      int  `json:"burst"`       // so viele auf einmal, bevor die Rate greift
	BanMinutes int  `json:"ban_minutes"` // danach so lange gesperrt (0 = nur drosseln)
}

func defaultBrute() BruteConfig {
	return BruteConfig{Condense: true, MinLogins: 200, MinMinutes: 30, MaxClients: 3,
		Limit: false, Rate: 6, Burst: 20, BanMinutes: 15}
}

func (b *BruteConfig) validate() error {
	switch {
	case b.MinLogins < 20 || b.MinLogins > 100000:
		return fmt.Errorf("Dauer-Brute-Force: Logins von 20 bis 100000")
	case b.MinMinutes < 5 || b.MinMinutes > 1440:
		return fmt.Errorf("Dauer-Brute-Force: Dauer von 5 bis 1440 Minuten")
	case b.MaxClients < 1 || b.MaxClients > 20:
		return fmt.Errorf("Dauer-Brute-Force: Clients von 1 bis 20")
	case b.Rate < 2 || b.Rate > 120:
		return fmt.Errorf("Drossel: 2 bis 120 neue Verbindungen je Minute")
	case b.Burst < 5 || b.Burst > 1000:
		return fmt.Errorf("Drossel: Spitze von 5 bis 1000 Verbindungen")
	case b.BanMinutes < 0 || b.BanMinutes > 1440:
		return fmt.Errorf("Drossel: Sperre von 0 bis 1440 Minuten")
	}
	return nil
}

var bruteCur atomic.Pointer[BruteConfig]

func setBrute(b BruteConfig) { bruteCur.Store(&b) }

func bruteCfg() BruteConfig {
	if b := bruteCur.Load(); b != nil {
		return *b
	}
	return defaultBrute()
}

// ---------- Erkennen (Angriffe) ----------

// bruteAttack: Merkmal für einen fertig aufgebauten Angriff (Attack.finish).
func bruteAttack(a *Attack) bool {
	if a.Condensed > 0 {
		return true
	}
	c := bruteCfg()
	if a.Counts["login"] < c.MinLogins || a.Last-a.First < int64(c.MinMinutes)*60000 {
		return false
	}
	hassh := 0
	for _, f := range a.Fingerprints {
		if strings.HasPrefix(f, "HASSH ") {
			hassh++
		}
	}
	return len(a.Clients) <= c.MaxClients && hassh <= c.MaxClients
}

// condensedData: Inhalt einer Sammelzeile.
type condensedData struct {
	From    int64          `json:"from"`
	To      int64          `json:"to"`
	N       int            `json:"n"`
	Types   map[string]int `json:"types"`
	Creds   map[string]int `json:"creds,omitempty"`
	Clients []string       `json:"clients,omitempty"`
	HASSH   []string       `json:"hassh,omitempty"`
}

func readCondensed(e *Event) (condensedData, bool) {
	var d condensedData
	if e.Type != "condensed" || json.Unmarshal(e.Data, &d) != nil {
		return d, false
	}
	return d, true
}

// addCondensed: Sammelzeile in einen Angriff übernehmen (statt Attack.add).
func (a *Attack) addCondensed(e *Event) {
	d, ok := readCondensed(e)
	if !ok {
		return
	}
	if a.Country == "" && e.Country != "" {
		a.Country, a.CountryName, a.City, a.Lat, a.Lon, a.ASN, a.ASOrg = e.Country, e.CountryName, e.City, e.Lat, e.Lon, e.ASN, e.ASOrg
	}
	if d.From > 0 && d.From < a.First {
		a.First = d.From
	}
	a.Last = max(a.Last, e.TS.UnixMilli())
	a.Events += d.N
	a.Condensed += d.N
	for t, n := range d.Types {
		if n > 0 && n < 1e7 {
			a.Counts[t] += n
		}
	}
	if e.Service != "" {
		a.svc[e.Service] = true
		a.loginSvc[e.Service] += d.Types["login"]
	}
	if e.DstPort > 0 {
		a.port[e.DstPort] = true
	}
	if e.Sensor != "" && len(a.Sensors) < 8 && !contains(a.Sensors, e.Sensor) {
		a.Sensors = append(a.Sensors, e.Sensor)
	}
	for k, n := range d.Creds {
		if n > 0 {
			a.creds[clip(k, 200)] += n
		}
	}
	for _, v := range d.Clients {
		if v != "" && !a.seenCli[v] && len(a.Clients) < 5 {
			a.seenCli[v] = true
			a.Clients = append(a.Clients, clip(v, 120))
		}
	}
	for _, v := range d.HASSH {
		if f := "HASSH " + v; v != "" && len(a.Fingerprints) < 8 && !contains(a.Fingerprints, f) {
			a.Fingerprints = append(a.Fingerprints, f)
		}
	}
	a.addStrip(e.TS.UnixMilli(), "condensed")
}

// condensedLine: Zeile für Zeitleiste und Bericht (analyze.go).
func condensedLine(d condensedData) string {
	keys := make([]string, 0, len(d.Types))
	for k := range d.Types {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", map[string]string{"login": "Logins", "connect": "Verbindungen", "disconnect": "Verbindungsenden",
			"client_version": "Client-Kennungen", "fingerprint": "HASSH"}[k], d.Types[k]))
	}
	s := fmt.Sprintf("Dauer-Brute-Force verdichtet: %d Ereignisse (%s), %d Kombinationen", d.N, strings.Join(parts, ", "), len(d.Creds))
	if len(d.Clients) > 0 {
		s += ", Client " + strings.Join(d.Clients, ", ")
	}
	return s
}

// mergeCondensed ergänzt Ports und Zugangsdaten der Angreiferseite (api.go) um die Sammelzeilen
// der IP und liefert die Zahl der verdichteten Ereignisse.
func (h *Hive) mergeCondensed(ctx context.Context, ip string, ports, creds []map[string]any) ([]map[string]any, []map[string]any, int) {
	rs, err := h.st.db.QueryContext(ctx, `SELECT service, dst_port, data FROM events WHERE src_ip = ? AND type = 'condensed' ORDER BY id DESC LIMIT 5000`, ip)
	if err != nil {
		return ports, creds, 0
	}
	defer rs.Close()
	total := 0
	type pk struct {
		port int64
		svc  string
	}
	portN, credN := map[pk]int64{}, map[[2]string]int64{}
	for rs.Next() {
		var e Event
		var port int64
		var data []byte
		if rs.Scan(&e.Service, &port, &data) != nil {
			continue
		}
		e.Type, e.Data = "condensed", data
		d, ok := readCondensed(&e)
		if !ok {
			continue
		}
		total += d.N
		portN[pk{port, e.Service}] += int64(d.Types["connect"])
		for k, n := range d.Creds {
			u, p, _ := strings.Cut(k, " / ")
			credN[[2]string{u, p}] += int64(n)
		}
	}
	if total == 0 {
		return ports, creds, 0
	}
	num := func(v any) int64 { n, _ := v.(int64); return n }
	for _, p := range ports {
		k := pk{num(p["dst_port"]), fmt.Sprint(p["service"])}
		if n, ok := portN[k]; ok {
			p["n"] = num(p["n"]) + n
			delete(portN, k)
		}
	}
	for k, n := range portN {
		if n > 0 {
			ports = append(ports, map[string]any{"dst_port": k.port, "service": k.svc, "n": n})
		}
	}
	for _, c := range creds {
		k := [2]string{fmt.Sprint(c["username"]), fmt.Sprint(c["password"])}
		if n, ok := credN[k]; ok {
			c["n"] = num(c["n"]) + n
			delete(credN, k)
		}
	}
	for k, n := range credN {
		creds = append(creds, map[string]any{"username": k[0], "password": k[1], "n": n})
	}
	for _, l := range [][]map[string]any{ports, creds} {
		sort.SliceStable(l, func(i, j int) bool { return num(l[i]["n"]) > num(l[j]["n"]) })
	}
	if len(creds) > 50 {
		creds = creds[:50]
	}
	return ports, creds, total
}

// ---------- Verdichten (Writer) ----------

const (
	bruteSumAge     = 5 * time.Minute // Sammelzeile spätestens nach dieser Zeit schreiben (< attackGap)
	bruteSumCreds   = 100             // höchstens so viele Kombinationen je Sammelzeile
	bruteSumEvents  = 5000
	bruteMaxIPs     = 50000 // so viele IPs merkt sich der Hive höchstens
	bruteDueEvery   = 10 * time.Second
	bruteSeedWindow = time.Hour
)

type bruteIP struct {
	exempt        bool
	first, last   time.Time // laufende Serie (Lücken unter attackGap)
	lastLogin     time.Time
	logins        int
	clients, hash map[string]bool
	okSess        map[string]bool // Sitzungen mit angenommenem Login: bleiben vollständig
	seeded        bool            // Stand aus der Datenbank geholt (nach einem Neustart)
	sums          map[string]*bruteSum
}

type bruteSum struct {
	tmpl    Event
	from    time.Time
	to      time.Time
	d       condensedData
	clients map[string]bool
	hassh   map[string]bool
}

type bruteTracker struct {
	mu      sync.Mutex
	ips     map[string]*bruteIP
	cfg     func() BruteConfig
	exempt  func(ip string) bool                            // eigene Netze, "Nie sperren"
	seed    func(ip string, now time.Time) (int, time.Time) // Logins seit … aus der Datenbank (nach Neustart)
	lastDue time.Time
}

func newBruteTracker() *bruteTracker {
	return &bruteTracker{ips: map[string]*bruteIP{}, cfg: bruteCfg, exempt: isOwnIP}
}

// active: IP ist als Dauer-Brute-Forcer erkannt.
func (t *bruteTracker) active(s *bruteIP, c BruteConfig) bool {
	return !s.exempt && s.logins >= c.MinLogins && s.lastLogin.Sub(s.first) >= time.Duration(c.MinMinutes)*time.Minute &&
		len(s.clients) <= c.MaxClients && len(s.hash) <= c.MaxClients
}

func (t *bruteTracker) state(e *Event) *bruteIP {
	s := t.ips[e.SrcIP]
	if s != nil {
		if e.TS.Sub(s.last) > attackGap { // neue Serie
			s.first, s.logins, s.okSess = e.TS, 0, map[string]bool{}
			s.clients, s.hash = map[string]bool{}, map[string]bool{}
		}
		return s
	}
	if len(t.ips) >= bruteMaxIPs {
		return nil
	}
	s = &bruteIP{first: e.TS, last: e.TS, clients: map[string]bool{}, hash: map[string]bool{}, okSess: map[string]bool{}, sums: map[string]*bruteSum{}}
	s.exempt = t.exempt != nil && t.exempt(e.SrcIP)
	s.seeded = s.exempt || t.seed == nil
	t.ips[e.SrcIP] = s
	return s
}

func credKey(e *Event) string {
	switch {
	case e.Service == "snmp":
		return "SNMP-Community " + e.Password
	case dataString(e.Data, "cookie") != "":
		return e.Username + " (RDP-Cookie)"
	case dataBool(e.Data, "password_hashed"):
		return e.Username + " / (gehasht)"
	}
	return e.Username + " / " + e.Password
}

// failedLogin: echter, abgelehnter Anmeldeversuch (keine Köder, keine Befehle an der Login-Abfrage).
func failedLogin(e *Event) bool {
	if e.Type != "login" || dataBool(e.Data, "success") || dataBool(e.Data, "accepted") || foreignEvent(e) || baitUsed(e) {
		return false
	}
	_, prompt := promptLines(e)
	return !prompt
}

// process markiert verdichtbare Ereignisse (e.condensed) und hängt fällige Sammelzeilen an.
// Läuft im Writer vor dem Schreiben (nicht bei Wiederholungen eines fehlgeschlagenen Schreibens).
func (t *bruteTracker) process(batch []*Event) []*Event {
	c := t.cfg()
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []*Event
	for _, e := range batch {
		if e.Type == "condensed" {
			continue
		}
		s := t.state(e)
		if s == nil {
			continue
		}
		s.last = maxTime(s.last, e.TS)
		ok := e.Session != "" && s.okSess[e.Session]
		switch e.Type {
		case "login":
			if dataBool(e.Data, "success") || dataBool(e.Data, "accepted") {
				if e.Session != "" && len(s.okSess) < 1000 {
					s.okSess[e.Session] = true
				}
				ok = true
			} else if failedLogin(e) {
				if !s.seeded { // nach einem Neustart nicht wieder bei null anfangen
					s.seeded = true
					if n, first := t.seed(e.SrcIP, e.TS); n > s.logins && first.Before(s.first) {
						s.logins, s.first = n, first
					}
				}
				s.logins++
				s.lastLogin = e.TS
			}
		case "client_version":
			if v := dataString(e.Data, "version"); v != "" && len(s.clients) <= 20 {
				s.clients[clip(v, 120)] = true
			}
		case "fingerprint":
			if v := dataString(e.Data, "hassh"); v != "" && len(s.hash) <= 20 {
				s.hash[clip(v, 64)] = true
			}
		}
		if !c.Condense || ok || !t.active(s, c) || !condensable(e) {
			continue
		}
		e.condensed = true
		out = append(out, t.add(s, e)...)
	}
	return append(out, t.dueLocked(time.Now(), false)...)
}

func condensable(e *Event) bool {
	switch e.Type {
	case "login":
		return failedLogin(e)
	case "connect", "client_version", "fingerprint":
		return true
	case "disconnect":
		return !e.Tarpit && e.TarpitMs == 0 // Tarpit-Verbindungen zählt die Tarpit-Seite einzeln
	}
	return false
}

// add zählt e in die Sammelzeile seiner IP und seines Dienstes; liefert sie, wenn sie voll oder
// (nach Ereigniszeit) älter als bruteSumAge ist.
func (t *bruteTracker) add(s *bruteIP, e *Event) []*Event {
	key := e.Service + "|" + strconv.Itoa(e.DstPort) + "|" + e.Sensor
	sum := s.sums[key]
	var out []*Event
	if sum != nil && e.TS.Sub(sum.from) >= bruteSumAge { // nach Ereigniszeit (auch beim Nachlesen alter Logs)
		out = append(out, sum.event())
		sum = nil
	}
	if sum == nil {
		sum = &bruteSum{tmpl: *e, from: e.TS, to: e.TS, d: condensedData{Types: map[string]int{}, Creds: map[string]int{}},
			clients: map[string]bool{}, hassh: map[string]bool{}}
		sum.tmpl.Data, sum.tmpl.Session, sum.tmpl.Username, sum.tmpl.Password, sum.tmpl.condensed = nil, "", "", "", false
		s.sums[key] = sum
	}
	if e.TS.Before(sum.from) {
		sum.from = e.TS
	}
	sum.to = maxTime(sum.to, e.TS)
	sum.d.N++
	sum.d.Types[e.Type]++
	switch e.Type {
	case "login":
		sum.d.Creds[clip(credKey(e), 100)]++
	case "client_version":
		sum.clients[clip(dataString(e.Data, "version"), 120)] = true
	case "fingerprint":
		sum.hassh[clip(dataString(e.Data, "hassh"), 64)] = true
	}
	if e.Country != "" && sum.tmpl.Country == "" {
		sum.tmpl.Country, sum.tmpl.CountryName, sum.tmpl.City, sum.tmpl.Lat, sum.tmpl.Lon, sum.tmpl.ASN, sum.tmpl.ASOrg =
			e.Country, e.CountryName, e.City, e.Lat, e.Lon, e.ASN, e.ASOrg
	}
	if len(sum.d.Creds) >= bruteSumCreds || sum.d.N >= bruteSumEvents {
		delete(s.sums, key)
		return append(out, sum.event())
	}
	return out
}

func (sum *bruteSum) event() *Event {
	e := sum.tmpl
	e.ID, e.Type, e.TS, e.Tarpit, e.TarpitMs, e.DurationMs, e.SrcPort = 0, "condensed", sum.to, false, 0, 0, 0
	e.EID = clip("bf-"+e.SrcIP+"-"+strconv.FormatInt(sum.from.UnixMilli(), 36)+"-"+strconv.FormatInt(sum.to.UnixMilli(), 36), 64)
	sum.d.From, sum.d.To = sum.from.UnixMilli(), sum.to.UnixMilli()
	for _, m := range []struct {
		set map[string]bool
		out *[]string
	}{{sum.clients, &sum.d.Clients}, {sum.hassh, &sum.d.HASSH}} {
		for k := range m.set {
			if k != "" && len(*m.out) < 10 {
				*m.out = append(*m.out, k)
			}
		}
		sort.Strings(*m.out)
	}
	b, _ := json.Marshal(sum.d)
	for len(b) > maxDataBytes && len(sum.d.Creds) > 0 { // Sicherheitsnetz: Zähler bleiben in top_hourly
		for k := range sum.d.Creds {
			delete(sum.d.Creds, k)
			break
		}
		b, _ = json.Marshal(sum.d)
	}
	e.Data = b
	return &e
}

// due liefert Sammelzeilen, die älter als bruteSumAge sind (force: alle), und vergisst ruhige IPs.
func (t *bruteTracker) due(now time.Time, force bool) []*Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dueLocked(now, force)
}

func (t *bruteTracker) dueLocked(now time.Time, force bool) []*Event {
	if !force && now.Sub(t.lastDue) < bruteDueEvery {
		return nil
	}
	t.lastDue = now
	var out []*Event
	for ip, s := range t.ips {
		for k, sum := range s.sums {
			if force || now.Sub(sum.from) >= bruteSumAge || sum.to.Sub(sum.from) >= bruteSumAge {
				out = append(out, sum.event())
				delete(s.sums, k)
			}
		}
		if len(s.sums) == 0 && now.Sub(s.last) > 2*attackGap {
			delete(t.ips, ip)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TS.Before(out[j].TS) })
	return out
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// bruteSeed: fehlgeschlagene Logins einer IP seit now-bruteSeedWindow (auch verdichtete), wenn
// sie in den letzten attackGap aktiv war. Nur beim ersten Ereignis einer IP nach dem Start.
func (s *Store) bruteSeed(ip string, now time.Time) (int, time.Time) {
	var n, first, last int64
	err := s.db.QueryRow(`SELECT COALESCE(SUM(CASE WHEN type = 'login' THEN 1 ELSE COALESCE(json_extract(data, '$.types.login'), 0) END), 0),
		COALESCE(MIN(CASE WHEN type = 'condensed' THEN COALESCE(json_extract(data, '$.from'), ts) ELSE ts END), 0), COALESCE(MAX(ts), 0)
		FROM events WHERE src_ip = ? AND ts >= ? AND (type = 'condensed' OR type = 'login' AND COALESCE(json_extract(data, '$.success'), 0) = 0)`,
		ip, now.Add(-bruteSeedWindow).UnixMilli()).Scan(&n, &first, &last)
	if err != nil || n == 0 || now.UnixMilli()-last > attackGap.Milliseconds() {
		return 0, time.Time{}
	}
	return int(n), time.UnixMilli(first)
}

// condensedTopField: Felder, deren Zähler für verdichtete Ereignisse zusätzlich unter "bf:<feld>"
// stehen. Das sind die Felder, die das Neuzählen löscht (setup.go); Land, Port, IP … bleiben dort.
var condensedTopField = func() map[string]bool {
	m := map[string]bool{}
	for _, f := range recountFields {
		m[f] = true
	}
	return m
}()

// restoreCondensedTop zählt nach dem Löschen der Felder fields die Zähler verdichteter Ereignisse
// wieder hinzu. Muss im selben Schritt wie das Löschen laufen (vor dem Neuzählen bis maxID): Was
// der Writer danach verdichtet, trägt er in beide Felder selbst ein.
func restoreCondensedTop(db interface {
	Exec(string, ...any) (sql.Result, error)
}, fields []string) error {
	for _, f := range fields {
		if _, err := db.Exec(`INSERT INTO top_hourly(hour, field, key, label, n)
			SELECT hour, ?, key, label, n FROM top_hourly WHERE field = ?
			ON CONFLICT(hour, field, key) DO UPDATE SET n = n + excluded.n`, f, "bf:"+f); err != nil {
			return err
		}
	}
	return nil
}

// ---------- Drossel in der Firewall ----------

// Raspberry Pi: Der Hive legt die gewünschte Drossel in einer Datei ab, die hivornet-cowrie-config
// (root, per .path gestartet) streng prüft, nach /etc/hivornet/brute.conf übernimmt und mit
// hivornet-firewall anwendet. Docker: Die Firewall läuft auf dem Host (tools/firewall.sh); die UI
// zeigt den passenden Aufruf.
func bruteRequestPath() string {
	if p := os.Getenv("HIVE_BRUTE_REQUEST"); p != "" {
		return p
	}
	if logsEnabled() {
		return "/var/lib/hivornet/brute-request"
	}
	return ""
}

func bruteStatusPath() string {
	if p := os.Getenv("HIVE_BRUTE_STATUS"); p != "" {
		return p
	}
	return "/var/lib/hivornet-status/brute"
}

const bruteMaxAllow = 200

// bruteRequest: Inhalt der Anforderung. Erste Zeile "brute off" oder "brute RATE BURST BAN",
// danach höchstens bruteMaxAllow Zeilen "allow NETZ" (eigene Netze, "Nie sperren"; private Netze nimmt die
// Firewall ohnehin aus).
func bruteRequest(b BruteConfig, allow []string) string {
	var sb strings.Builder
	if !b.Limit {
		sb.WriteString("brute off\n")
	} else {
		fmt.Fprintf(&sb, "brute %d %d %d\n", b.Rate, b.Burst, b.BanMinutes)
	}
	seen := map[string]bool{}
	n := 0
	for _, s := range allow {
		ipn, err := parseNet(s)
		if err != nil || n >= bruteMaxAllow {
			continue
		}
		v := ipn.String()
		if !seen[v] {
			seen[v] = true
			n++
			sb.WriteString("allow " + v + "\n")
		}
	}
	return sb.String()
}

// bruteAllow: Netze, die nie gedrosselt werden (eigene Netze und Liste "Nie sperren").
func (h *Hive) bruteAllow() []string {
	x := h.Extras()
	return append(append([]string{}, x.Own.Nets...), h.feedConfig().NeverBlock...)
}

// syncBruteLimit legt die Anforderung ab, wenn sie sich seit der letzten geändert hat (nur
// Raspberry Pi; beim Start, nach dem Speichern der Einstellungen und von "Nie sperren").
// Solange die Drossel nie eingeschaltet war, bleibt die Firewall unberührt.
func (h *Hive) syncBruteLimit() error {
	req := bruteRequestPath()
	if req == "" {
		return nil
	}
	body := bruteRequest(h.Extras().Brute, h.bruteAllow())
	last, known := h.st.GetKV("brute_request_sent")
	if last == body || !known && !h.Extras().Brute.Limit {
		return nil
	}
	tmp := req + ".neu"
	if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, req); err != nil {
		return err
	}
	return h.st.SetKV("brute_request_sent", body)
}

// dockerBruteCommand: Aufruf von tools/firewall.sh mit den Werten aus den Einstellungen.
func dockerBruteCommand(b BruteConfig, allow []string) string {
	if !b.Limit {
		return "BRUTE_LIMIT=0 sudo -E sh tools/firewall.sh"
	}
	var nets []string
	for _, s := range allow {
		if n, err := parseNet(s); err == nil && len(nets) < bruteMaxAllow {
			nets = append(nets, n.String())
		}
	}
	cmd := fmt.Sprintf("BRUTE_LIMIT=1 BRUTE_RATE=%d BRUTE_BURST=%d BRUTE_BAN=%d", b.Rate, b.Burst, b.BanMinutes)
	if len(nets) > 0 {
		cmd += ` BRUTE_ALLOW="` + strings.Join(nets, " ") + `"`
	}
	return cmd + " sudo -E sh tools/firewall.sh"
}

// bruteStatus: GET /api/brute — Plattform, Stand der Drossel, Verdichtung seit dem Start.
func (h *Hive) bruteStatus(w http.ResponseWriter, r *http.Request) {
	b := h.Extras().Brute
	out := map[string]any{"platform": "none", "condensed": h.writer.condensedN.Load(), "summaries": h.writer.summaries.Load()}
	switch {
	case bruteRequestPath() != "":
		out["platform"] = "pi"
		if st := readStatusFile(bruteStatusPath()); st != nil {
			out["status"] = st
		}
		_, err := os.Stat(bruteRequestPath())
		out["pending"] = err == nil
	case h.cowrie != nil:
		out["platform"] = "docker"
		out["command"] = dockerBruteCommand(b, h.bruteAllow())
	}
	writeJSON(w, out)
}
