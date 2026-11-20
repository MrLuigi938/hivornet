package main

// Top-Listen ohne Dauer-Brute-Force (GET /api/stats/top?...&nobrute=1).
//
// Bis 0.9.0 zog "ohne" nur die verdichteten Versuche ab (Zähler unter "bf:<feld>"). Was ein
// Brute-Forcer bis zur Erkennung versuchte, und alles von Läufen vor dem Update blieb in den
// Listen; auf einer Instanz ohne neue Brute-Forcer änderte der Schalter nichts (Live-Check 0.9.0).
//
// Jetzt fallen alle Beiträge markierter IPs heraus:
//   - verdichtete Versuche wie bisher über "bf:<feld>",
//   - dazu alle gespeicherten Ereignisse dieser IPs im Zeitraum, mit denselben Schlüsseln
//     gezählt wie beim Schreiben (topKeys, store.go).
//
// Markiert sind IPs, deren Angriff in den letzten sieben Tagen als Dauer-Brute-Force gilt
// (Angriffs-Schnappschuss, attacksnap.go), und IPs mit Sammelzeilen im Zeitraum. Für längere
// Zeiträume zählen ältere Läufe also nur, wenn sie verdichtet wurden; die Rohdaten jenseits der
// Aufbewahrung sind ohnehin nicht mehr da. Das Ergebnis wird zwischengespeichert und im Hintergrund erneuert (bruteTopCache),
// weil das Dashboard mehrere Listen auf einmal holt.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	bruteTopTTL       = 2 * time.Minute // danach im Hintergrund neu rechnen
	bruteTopMaxIPs    = 500             // so viele markierte IPs werden höchstens abgezogen
	bruteTopMaxEvents = 1000000         // Sicherheitsnetz für den Speicher
)

// bruteTopCache: je Startstunde ein Ergebnis. Liegt eines vor, bekommt die Anfrage es sofort,
// auch wenn es älter als bruteTopTTL ist; neu gerechnet wird dann im Hintergrund. Gewartet wird
// nur beim allerersten Mal. Vorher (0.9.2) rechnete jede Aktualisierung des Dashboards nach einer
// Minute synchron neu, belegte dabei einen der beiden Plätze für aufwendige Abfragen (heavySem)
// und hielt so "Gerade aktiv" auf einem Pi mehrere Sekunden auf.
type bruteTopCache struct {
	mu    sync.Mutex
	build sync.Mutex // ein Aufbau zur Zeit
	m     map[int64]*bruteTopEntry
}

type bruteTopEntry struct {
	at   time.Time
	sub  map[string]map[string]int64 // Feld -> Schlüssel -> Anzahl
	busy bool                        // wird gerade im Hintergrund neu gerechnet
}

// bruteIPsSince: IPs, die im Zeitraum als Dauer-Brute-Force gelten.
func (h *Hive) bruteIPsSince(ctx context.Context, since time.Time) ([]string, error) {
	set := map[string]bool{}
	from := since
	if time.Since(from) > snapWindow {
		from = time.Now().Add(-snapWindow)
	}
	list, _, err := h.attacksSince(ctx, from)
	if err != nil {
		return nil, err
	}
	for _, a := range list {
		if a.Brute && !a.Own {
			set[a.IP] = true
		}
	}
	rs, err := h.st.db.QueryContext(ctx, `SELECT DISTINCT src_ip FROM events WHERE type = 'condensed' AND ts >= ? LIMIT ?`,
		since.UnixMilli(), bruteTopMaxIPs)
	if err != nil {
		return nil, err
	}
	for rs.Next() {
		var ip string
		if rs.Scan(&ip) == nil {
			set[ip] = true
		}
	}
	rs.Close()
	out := make([]string, 0, len(set))
	for ip := range set {
		if !ownHidden(ip) {
			out = append(out, ip)
		}
	}
	sort.Strings(out)
	if len(out) > bruteTopMaxIPs {
		out = out[:bruteTopMaxIPs]
	}
	return out, nil
}

// bruteTopSub liefert je Feld und Schlüssel, was die markierten IPs ab der Stunde hour mit
// gespeicherten Ereignissen zu den Top-Listen beigetragen haben.
func (h *Hive) bruteTopSub(ctx context.Context, hour int64) (map[string]map[string]int64, error) {
	c := &h.bruteTop
	c.mu.Lock()
	if c.m == nil {
		c.m = map[int64]*bruteTopEntry{}
	}
	e := c.m[hour]
	if e == nil { // "24 Std" rückt jede Stunde vor: das Ergebnis der Vorstunde taugt bis zum Neurechnen
		e = c.m[hour-1]
	}
	if e != nil {
		if time.Since(e.at) > bruteTopTTL && !e.busy {
			e.busy = true
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				h.bruteTopRefresh(ctx, hour)
				c.mu.Lock()
				e.busy = false
				c.mu.Unlock()
			}()
		}
		sub := e.sub
		c.mu.Unlock()
		return sub, nil
	}
	c.mu.Unlock()
	return h.bruteTopRefresh(ctx, hour)
}

// bruteTopRefresh rechnet das Ergebnis für hour neu und legt es ab.
func (h *Hive) bruteTopRefresh(ctx context.Context, hour int64) (map[string]map[string]int64, error) {
	c := &h.bruteTop
	c.build.Lock()
	defer c.build.Unlock()
	c.mu.Lock()
	if e := c.m[hour]; e != nil && time.Since(e.at) < bruteTopTTL { // inzwischen erledigt
		c.mu.Unlock()
		return e.sub, nil
	}
	c.mu.Unlock()
	since := time.UnixMilli(hour * 3600000)
	ips, err := h.bruteIPsSince(ctx, since)
	if err != nil {
		return nil, err
	}
	sub := map[string]map[string]int64{}
	n := 0
	for _, ip := range ips {
		rs, err := h.st.db.QueryContext(ctx, `SELECT ts, service, type, src_ip, dst_port, username, password, data, country, country_name, asn, as_org
			FROM events WHERE src_ip = ? AND ts >= ? AND type != 'condensed'`, ip, since.UnixMilli())
		if err != nil {
			return nil, err
		}
		for rs.Next() && n < bruteTopMaxEvents {
			e := &Event{}
			var ms int64
			var data sql.NullString
			if rs.Scan(&ms, &e.Service, &e.Type, &e.SrcIP, &e.DstPort, &e.Username, &e.Password, &data, &e.Country, &e.CountryName, &e.ASN, &e.ASOrg) != nil {
				continue
			}
			n++
			e.TS = time.UnixMilli(ms)
			if data.Valid {
				e.Data = json.RawMessage(data.String)
			}
			for _, k := range topKeys(e) {
				if !bruteTopField(k[0]) {
					continue
				}
				m := sub[k[0]]
				if m == nil {
					m = map[string]int64{}
					sub[k[0]] = m
				}
				m[k[1]]++
			}
		}
		err = rs.Err()
		rs.Close()
		if err != nil {
			return nil, err
		}
	}
	c.mu.Lock()
	c.m[hour] = &bruteTopEntry{at: time.Now(), sub: sub}
	for k, old := range c.m { // lange nicht Neugerechnetes vergessen (vorgerückte Startstunden)
		if time.Since(old.at) > 30*time.Minute && !old.busy {
			delete(c.m, k)
		}
	}
	c.mu.Unlock()
	return sub, nil
}

// topNoBrute: Top-Liste eines Feldes ohne Dauer-Brute-Force.
func (h *Hive) topNoBrute(ctx context.Context, field string, hour int64, limit int) ([]map[string]any, error) {
	sub, err := h.bruteTopSub(ctx, hour)
	if err != nil {
		return nil, err
	}
	// Verdichtete Versuche wie bisher abziehen; mehr Zeilen holen, weil nach dem Abziehen der
	// Rohereignisse Einträge wegfallen oder nach hinten rutschen.
	rows, err := h.rows(ctx, `SELECT key, MAX(label) AS label, SUM(CASE WHEN field = ?1 THEN n ELSE -n END) AS n FROM top_hourly
		WHERE field IN (?1, 'bf:' || ?1) AND hour >= ?2 GROUP BY key HAVING SUM(CASE WHEN field = ?1 THEN n ELSE -n END) > 0
		ORDER BY n DESC LIMIT ?3`, field, hour, limit*4+200)
	if err != nil {
		return nil, err
	}
	minus := sub[field]
	out := rows[:0]
	for _, row := range rows {
		n := toInt64(row["n"]) - minus[fmt.Sprint(row["key"])]
		if n <= 0 {
			continue
		}
		row["n"] = n
		out = append(out, row)
	}
	sort.SliceStable(out, func(i, j int) bool { return toInt64(out[i]["n"]) > toInt64(out[j]["n"]) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
