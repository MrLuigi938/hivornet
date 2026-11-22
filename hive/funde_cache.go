package main

// Zwischenspeicher für den Tab „Funde“ (funde.go).
//
// Gemessen (November 2026, 40.000 Befehle in 25 Tagen): Ohne Zwischenspeicher brauchte
// /api/funde?range=30d auf einem Desktop 0,8–1,4 s, davon gut drei Viertel für das Lesen aller
// Befehle aus der Datenbank, der Rest für tausende Einzelabfragen (Stand je Adresse, je IP,
// Herkunft je Angreifer). Auf einem Raspberry Pi wäre das ein Vielfaches gewesen, und die
// Fallakte rechnete bei jedem Öffnen 30 Tage neu.
//
// Jetzt:
//   - sightCache merkt sich die Nachlade-Adressen aller Befehle und Downloads der letzten
//     30 Tage (Rohform, Absender, Zeit) und liest bei jedem Aufruf nur neue Ereignisse nach.
//     Ob eine Adresse zulässig ist, wird bei jedem Aufruf neu entschieden (eigene Adresse,
//     Sensoren und Scanner können sich ändern), aber je Absender und je Adresse nur einmal.
//   - fundeState lädt die Meldestände (lookups) mit einer Abfrage je Quelle und die
//     Protokolle und Wartelisten einmal je Aufruf.

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"time"
)

// sighting: eine Nachlade-Adresse aus einem Ereignis (Strings geteilt, siehe intern).
type sighting struct {
	id      int64
	ts      int64
	ip      string
	sensor  string
	asOrg   string
	country string
	service string
	session string
	kind    string // command | download
	raw     string
	sha     string
}

// sightCacheMax: Obergrenze der gemerkten Adressen (etwa 100 Byte je Eintrag plus geteilte
// Strings). Darüber fallen die ältesten weg; der Tab zeigt dann nicht mehr alle 30 Tage.
const sightCacheMax = 300000

type sightCache struct {
	mu     sync.Mutex
	lastID int64
	list   []sighting
	strs   map[string]string
}

func (c *sightCache) intern(s string) string {
	if v, ok := c.strs[s]; ok {
		return v
	}
	if len(c.strs) > 4*sightCacheMax { // sehr viele verschiedene Werte: neu anfangen
		c.strs = map[string]string{}
	}
	c.strs[s] = s
	return s
}

// fundeSightings liefert die Adressen der letzten 30 Tage in der Reihenfolge des Eintreffens;
// der Aufrufer filtert nach Zeit. Die Liste ist geteilt und darf nicht verändert werden.
func (h *Hive) fundeSightings(ctx context.Context) ([]sighting, error) {
	c := &h.fundeCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.strs == nil {
		c.strs = map[string]string{}
	}
	// Datenbank zurückgesetzt oder aus einer Sicherung geladen: neu aufbauen
	var maxID int64
	h.st.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM events`).Scan(&maxID)
	if maxID < c.lastID {
		c.lastID, c.list, c.strs = 0, nil, map[string]string{}
	}
	horizon := time.Now().Add(-fundeMaxRange).UnixMilli()
	for {
		n, err := h.fundeCacheFill(ctx, c, horizon, c.lastID == 0)
		if err != nil {
			return nil, err
		}
		if n < 20000 {
			break
		}
	}
	// Älteres als 30 Tage und Überzähliges abschneiden. Die Liste ist nach id geordnet, die Zeit
	// nicht ganz (Sensoren liefern verspätet nach): darum je Eintrag prüfen, nicht nur den Anfang.
	old := 0
	for _, s := range c.list {
		if s.ts < horizon {
			old++
		}
	}
	if over := len(c.list) - sightCacheMax; old > 0 && (old > len(c.list)/10 || over > 0) || over > 0 {
		keep := make([]sighting, 0, len(c.list)-old)
		for _, s := range c.list {
			if s.ts >= horizon {
				keep = append(keep, s)
			}
		}
		if len(keep) > sightCacheMax {
			keep = keep[len(keep)-sightCacheMax:]
		}
		c.list = keep
	}
	// Kapazität = Länge, damit spätere Anhänge die Liste des Aufrufers nicht berühren
	return c.list[:len(c.list):len(c.list)], nil
}

// fundeCacheFill liest bis zu 20.000 neue Ereignisse; liefert, wie viele es waren. Beim ersten
// Mal (cold) alle Befehle und Downloads der letzten 30 Tage auf einmal über den Index nach Typ,
// statt die ganze Tabelle samt aller Verbindungen nach id zu durchlaufen.
func (h *Hive) fundeCacheFill(ctx context.Context, c *sightCache, horizon int64, cold bool) (int, error) {
	q, args := `SELECT id, ts, sensor, service, type, src_ip, session, data, as_org, country FROM events
		WHERE id > ? AND ts >= ? AND type IN ('command','download') ORDER BY id LIMIT 20000`, []any{c.lastID, horizon}
	if cold {
		q, args = `SELECT id, ts, sensor, service, type, src_ip, session, data, as_org, country FROM events
		WHERE type IN ('command','download') AND ts >= ? ORDER BY id`, []any{horizon}
	}
	rs, err := h.st.db.QueryContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	defer rs.Close()
	n := 0
	for rs.Next() {
		var e Event
		var data []byte
		var asOrg, session, country sql.NullString
		var ts int64
		if rs.Scan(&e.ID, &ts, &e.Sensor, &e.Service, &e.Type, &e.SrcIP, &session, &data, &asOrg, &country) != nil {
			continue
		}
		n++
		c.lastID = max(c.lastID, e.ID)
		if cold && len(c.list) >= 2*sightCacheMax {
			continue // Obergrenze; abgeschnitten wird unten
		}
		e.Data = data
		for _, raw := range eventURLs(&e) {
			s := sighting{id: e.ID, ts: ts, ip: c.intern(e.SrcIP), sensor: c.intern(e.Sensor), asOrg: c.intern(asOrg.String), country: c.intern(country.String),
				service: c.intern(e.Service), session: session.String, kind: c.intern(e.Type), raw: c.intern(clip(raw, 2048))}
			if e.Type == "download" {
				s.sha = c.intern(strings.ToLower(dataString(e.Data, "sha256")))
			}
			c.list = append(c.list, s)
		}
	}
	if cold && n > 0 {
		return min(n, 19999), rs.Err() // alles gelesen; danach nur noch Neues
	}
	return n, rs.Err()
}

// warmFunde füllt den Zwischenspeicher im Hintergrund (beim Start und alle 5 Minuten mit der
// Weitergabe), damit der erste Aufruf des Tabs nicht alle Befehle lesen muss.
func (h *Hive) warmFunde(ctx context.Context) {
	h.fundeSightings(ctx)
}

// ---- Meldestände, einmal je Aufruf geladen ----

type fundeState struct {
	lk     map[string]map[string]string // Quelle -> Betreff -> Daten
	uhWait map[string]string            // Adresse -> „wartet bis …“
	abWait map[string]string            // IP -> „wartet bis …“
	uhLast map[string]shareLogEntry     // jüngster URLhaus-Eintrag je Adresse
	bzLast map[string]shareLogEntry     // jüngster MalwareBazaar-Eintrag je Hash
	abLast map[string]abuseLogEntry     // jüngster AbuseIPDB-Eintrag je IP
}

var fundeSources = []string{"sample_fetch", "urlhaus_report", "urlhaus_report_dry", "bazaar_upload", "bazaar_wait", "abuse_report", "abuse_report_dry", "sample"}

func (h *Hive) fundeState(ctx context.Context) *fundeState {
	st := &fundeState{lk: map[string]map[string]string{}, uhWait: map[string]string{}, abWait: map[string]string{},
		uhLast: map[string]shareLogEntry{}, bzLast: map[string]shareLogEntry{}, abLast: map[string]abuseLogEntry{}}
	for _, src := range fundeSources {
		m := map[string]string{}
		if rs, err := h.st.db.QueryContext(ctx, `SELECT subject, data FROM lookups WHERE source = ?`, src); err == nil {
			for rs.Next() {
				var subj, data string
				if rs.Scan(&subj, &data) == nil {
					m[subj] = data
				}
			}
			rs.Close()
		}
		st.lk[src] = m
	}
	for _, w := range h.share.waitList("urlhaus") {
		st.uhWait[w.Subject] = w.Detail
	}
	for _, w := range h.share.waitList("abuseipdb") {
		st.abWait[w.Subject] = w.Detail
	}
	h.share.mu.Lock()
	for _, e := range h.share.channel("urlhaus").Log { // neueste zuerst
		if _, ok := st.uhLast[e.Subject]; !ok {
			st.uhLast[e.Subject] = e
		}
	}
	for _, e := range h.share.channel("bazaar").Log {
		if _, ok := st.bzLast[e.SHA256]; !ok && e.SHA256 != "" {
			st.bzLast[e.SHA256] = e
		}
	}
	h.share.mu.Unlock()
	h.abuse.mu.Lock()
	for _, e := range h.abuse.log {
		if _, ok := st.abLast[e.IP]; !ok {
			st.abLast[e.IP] = e
		}
	}
	h.abuse.mu.Unlock()
	return st
}

func (st *fundeState) has(src, subj string) bool { _, ok := st.lk[src][subj]; return ok }

// urlhaus: Meldestand einer Adresse bei URLhaus.
func (st *fundeState) urlhaus(u string) (string, string) {
	subj := urlSubject(u)
	switch {
	case st.has("urlhaus_report", subj):
		return "ok", ""
	case st.uhWait[u] != "":
		return "wait", st.uhWait[u]
	}
	if e, ok := st.uhLast[u]; ok && e.Status == "error" {
		return "error", e.Error
	}
	if st.has("urlhaus_report_dry", subj) {
		return "dry", ""
	}
	return "", ""
}

// bazaar: Stand einer Datei bei MalwareBazaar.
func (st *fundeState) bazaar(sha string) string {
	if v, ok := st.lk["bazaar_upload"]["hash:"+sha]; ok {
		return v
	}
	if st.has("bazaar_wait", "hash:"+sha) {
		return "wait"
	}
	if e, ok := st.bzLast[sha]; ok && e.Status == "error" {
		return "error"
	}
	return ""
}

// abuse: Stand einer IP bei AbuseIPDB.
func (st *fundeState) abuse(ip string) (string, string) {
	switch {
	case st.has("abuse_report", "ip:"+ip):
		return "ok", ""
	case st.abWait[ip] != "":
		return "wait", st.abWait[ip]
	}
	if e, ok := st.abLast[ip]; ok && e.Status == "error" {
		return "error", e.Error
	}
	if st.has("abuse_report_dry", "ip:"+ip) {
		return "dry", ""
	}
	return "", ""
}
