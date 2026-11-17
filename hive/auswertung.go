package main

// Zusatzdaten für die Seiten Zugangsdaten und Tarpit (Konzept A, konzepte/d-auswertung.html).

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// ---- Zugangsdaten ----

// miraiCreds: kennzeichnende Einträge der öffentlich bekannten Mirai-Liste. Allerweltspaare
// (admin/admin, root/123456 …) fehlen bewusst: Sie stehen in jeder Liste und sagten nichts.
var miraiCreds = map[string]bool{
	"root/xc3511": true, "root/vizxv": true, "root/xmhdipc": true, "root/juantech": true, "admin/smcadmin": true,
	"root/klv123": true, "root/klv1234": true, "root/zte521": true, "root/hi3518": true, "root/jvbzd": true,
	"root/anko": true, "root/zlxx.": true, "root/7ujmko0vizxv": true, "root/7ujmko0admin": true, "admin/7ujmko0admin": true,
	"root/ikwb": true, "root/dreambox": true, "root/realtek": true, "admin/meinsm": true, "ubnt/ubnt": true,
	"admin/1111111": true, "supervisor/supervisor": true, "mother/fucker": true, "tech/tech": true,
}

var miraiPasswords = func() map[string]bool {
	m := map[string]bool{}
	for k := range miraiCreds {
		if _, p, ok := strings.Cut(k, "/"); ok && len(p) > 4 {
			m[p] = true
		}
	}
	return m
}()

// botnetList nennt die bekannte Botnetz-Liste, aus der ein Eintrag stammt ("" = keine).
func botnetList(field, key string) string {
	switch field {
	case "cred":
		u, p, ok := strings.Cut(key, " / ")
		if ok && miraiCreds[strings.ToLower(u)+"/"+strings.ToLower(p)] {
			return "Mirai"
		}
	case "password":
		if miraiPasswords[strings.ToLower(key)] {
			return "Mirai"
		}
	}
	return ""
}

// credSummary: GET /api/creds/summary?range=7d – Anzahl und Vielfalt der Zugangsdaten.
func (h *Hive) credSummary(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := qctx(r)
	defer cancel()
	since, _ := rangeSince(r)
	hour := since.UnixMilli() / 3600000
	out := map[string]any{}
	// Fehler (z. B. Zeitüberschreitung) melden statt Nullen zu liefern (zweites Audit, N9)
	fail := func(err error) { httpErr(w, 500, "Zugangsdaten-Übersicht: "+err.Error()) }
	for _, f := range []string{"username", "password", "cred"} {
		var distinct, total int64
		if err := h.st.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(n),0) FROM (SELECT SUM(n) AS n FROM top_hourly WHERE field = ? AND hour >= ? GROUP BY key)`, f, hour).Scan(&distinct, &total); err != nil {
			fail(err)
			return
		}
		out[f+"_distinct"], out[f+"_total"] = distinct, total
	}
	var once int64
	if err := h.st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT SUM(n) AS n FROM top_hourly WHERE field = 'password' AND hour >= ? GROUP BY key) WHERE n = 1`, hour).Scan(&once); err != nil {
		fail(err)
		return
	}
	out["password_once"] = once
	// Anteil der Versuche aus der Mirai-Liste (über alle Kombinationen des Zeitraums)
	var botnet int64
	rows, err := h.st.db.QueryContext(ctx, `SELECT key, SUM(n) FROM top_hourly WHERE field = 'cred' AND hour >= ? GROUP BY key`, hour)
	if err != nil {
		fail(err)
		return
	}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			fail(err)
			return
		}
		if botnetList("cred", k) != "" {
			botnet += n
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		fail(err)
		return
	}
	out["botnet"] = botnet
	writeJSON(w, out)
}

// ---- Tarpit ----

// tarpitExtras ergänzt die Tarpit-Antwort um Verlauf, Verteilung der Haltedauer und
// die Zeitleiste der zehn Angreifer mit der längsten Gesamtzeit.
func (h *Hive) tarpitExtras(ctx context.Context, since time.Time, d time.Duration, byIP []map[string]any) map[string]any {
	ms := since.UnixMilli()
	from, hours := ms/3600000, max(int64(d.Hours()), 1)
	series := make([]int64, seriesBuckets)
	if rows, err := h.st.db.QueryContext(ctx, `SELECT hour, SUM(tarpit_ms) FROM hourly WHERE hour >= ? AND tarpit_ms > 0 GROUP BY hour`, from); err == nil {
		for rows.Next() {
			var hr, n int64
			if rows.Scan(&hr, &n) == nil {
				series[min(max((hr-from)*seriesBuckets/hours, 0), seriesBuckets-1)] += n
			}
		}
		rows.Close()
	}
	hist, _ := h.rows(ctx, `SELECT CASE WHEN tarpit_ms < 10000 THEN 0 WHEN tarpit_ms < 60000 THEN 1 WHEN tarpit_ms < 600000 THEN 2
		WHEN tarpit_ms < 3600000 THEN 3 WHEN tarpit_ms < 21600000 THEN 4 ELSE 5 END AS b, COUNT(*) AS n
		FROM events WHERE type='disconnect' AND tarpit=1 AND ts >= ? GROUP BY b ORDER BY b`, ms)
	counts := make([]int64, 6)
	for _, row := range hist {
		if b := toInt64(row["b"]); b >= 0 && b < 6 {
			counts[b] = toInt64(row["n"])
		}
	}
	// Zeitleiste: je IP die einzelnen Verbindungen (Beginn = Ende minus Haltedauer)
	var ips []any
	for i, row := range byIP {
		if i >= 10 {
			break
		}
		ips = append(ips, row["src_ip"])
	}
	segs := []map[string]any{}
	if len(ips) > 0 {
		segs, _ = h.rows(ctx, `SELECT src_ip, service, dst_port, ts, tarpit_ms FROM events WHERE type='disconnect' AND tarpit=1 AND ts >= ?
			AND src_ip IN (`+strings.TrimSuffix(strings.Repeat("?,", len(ips)), ",")+`) ORDER BY tarpit_ms DESC LIMIT 1500`, append([]any{ms}, ips...)...)
		if segs == nil {
			segs = []map[string]any{}
		}
	}
	return map[string]any{
		"series": series, "series_from": ms, "series_to": time.Now().UnixMilli(),
		"hist":     counts,
		"timeline": map[string]any{"from": ms, "to": time.Now().UnixMilli(), "segments": segs},
	}
}
