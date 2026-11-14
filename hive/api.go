package main

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ---- Hilfsfunktionen ----

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// readJSON liest einen kleinen JSON-Body mit Größen- und Zeitgrenze.
func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	http.NewResponseController(w).SetReadDeadline(time.Now().Add(15 * time.Second))
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v)
}

func qctx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 20*time.Second)
}

// rows liefert Ergebniszeilen als Liste von Maps (Spaltenname -> Wert).
func (h *Hive) rows(ctx context.Context, q string, args ...any) ([]map[string]any, error) {
	rs, err := h.st.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	cols, _ := rs.Columns()
	out := []map[string]any{}
	for rs.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rs.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			v := vals[i]
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			if c == "data" {
				if s, ok := v.(string); ok && s != "" && json.Valid([]byte(s)) {
					v = json.RawMessage(s)
				}
			}
			m[c] = v
		}
		out = append(out, m)
	}
	return out, rs.Err()
}

func (h *Hive) sendRows(w http.ResponseWriter, r *http.Request, q string, args ...any) {
	ctx, cancel := qctx(r)
	defer cancel()
	res, err := h.rows(ctx, q, args...)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	writeJSON(w, res)
}

func rangeDur(v string, def time.Duration) time.Duration {
	switch v {
	case "1h":
		return time.Hour
	case "24h":
		return 24 * time.Hour
	case "7d":
		return 7 * 24 * time.Hour
	case "30d":
		return 30 * 24 * time.Hour
	case "90d":
		return 90 * 24 * time.Hour
	}
	return def
}

func rangeSince(r *http.Request) (time.Time, time.Duration) {
	d := rangeDur(r.URL.Query().Get("range"), 24*time.Hour)
	return time.Now().Add(-d), d
}

func qInt(r *http.Request, k string, def, max int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(k))
	if err != nil || v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

const evCols = `id, ts, sensor, service, type, src_ip, src_port, dst_port, session, username, password, data,
	duration_ms, tarpit, tarpit_ms, country, country_name, city, asn, as_org`

// ---- Sensor-Endpunkte ----

func (h *Hive) ingest(w http.ResponseWriter, r *http.Request) {
	http.NewResponseController(w).SetReadDeadline(time.Now().Add(60 * time.Second))
	r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
	var req struct {
		Sensor string  `json:"sensor"`
		Events []Event `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, 400, "ungültiges JSON")
		return
	}
	if len(req.Events) > 10000 {
		httpErr(w, 413, "zu viele Ereignisse auf einmal")
		return
	}
	n := 0
	for i := range req.Events {
		e := &req.Events[i]
		if e.Sensor == "" {
			e.Sensor = req.Sensor
		}
		e.ID, e.Country, e.CountryName, e.City, e.Lat, e.Lon, e.ASN, e.ASOrg = 0, "", "", "", 0, 0, 0, ""
		if e.Sanitize() != nil {
			continue
		}
		h.geo.Enrich(e)
		if !h.writer.Submit(e) {
			// Bereits angenommene Ereignisse erkennt der Hive beim erneuten Senden an der eid.
			httpErr(w, 503, "Warteschlange voll")
			return
		}
		n++
	}
	writeJSON(w, map[string]int{"accepted": n})
}

func (h *Hive) heartbeat(w http.ResponseWriter, r *http.Request) {
	var hb Heartbeat
	if err := readJSON(w, r, &hb); err != nil || hb.Sensor == "" {
		httpErr(w, 400, "ungültiges Lebenszeichen")
		return
	}
	hb.Sensor = clip(hb.Sensor, 64)
	// Erste Konfiguration übernehmen, damit die UI sie bearbeiten kann.
	if _, ok := h.st.GetKV(configKey("")); !ok && hb.Config != nil && hb.Config.Validate() == nil {
		b, _ := json.Marshal(hb.Config)
		h.st.SetKV(configKey(""), string(b))
	}
	h.sensors.Put(hb)
	writeJSON(w, map[string]bool{"ok": true})
}

func (h *Hive) sensorConfig(w http.ResponseWriter, r *http.Request) {
	cfg, _ := h.SensorConfigFor(clip(r.Header.Get("X-Sensor"), 64))
	if cfg == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(cfg)
}

// ---- UI-Endpunkte ----

func (h *Hive) me(w http.ResponseWriter, r *http.Request) {
	u := h.auth.User(r)
	if u == "" {
		httpErr(w, 401, "nicht angemeldet")
		return
	}
	writeJSON(w, map[string]string{"username": u, "version": version})
}

func (h *Hive) summary(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := qctx(r)
	defer cancel()
	since, _ := rangeSince(r)
	hour := since.UnixMilli() / 3600000
	res := map[string]any{"events": 0, "connect": 0, "login": 0, "command": 0, "download": 0, "request": 0, "tarpit_ms": 0}
	rs, err := h.rows(ctx, `SELECT type, SUM(cnt) AS n, SUM(tarpit_ms) AS t FROM hourly WHERE hour >= ? GROUP BY type`, hour)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	var total, tms int64
	for _, row := range rs {
		n, _ := row["n"].(int64)
		t, _ := row["t"].(int64)
		res[row["type"].(string)] = n
		total += n
		tms += t
	}
	res["events"], res["tarpit_ms"] = total, tms
	var ips, countries int64
	h.st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM attackers WHERE last_seen >= ?`, since.UnixMilli()).Scan(&ips)
	h.st.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT country) FROM hourly WHERE hour >= ? AND country NOT IN ('', 'LAN')`, hour).Scan(&countries)
	res["unique_ips"], res["countries"], res["active_tarpits"] = ips, countries, h.sensors.ActiveTarpits()
	writeJSON(w, res)
}

func (h *Hive) timeline(w http.ResponseWriter, r *http.Request) {
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
	rs, err := h.rows(ctx, `SELECT (hour / ?) * ? AS b, service, SUM(cnt) AS n FROM hourly
		WHERE hour >= ? AND type = 'connect' GROUP BY b, service ORDER BY b`, bucket, bucket, since.UnixMilli()/3600000)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"bucket_hours": bucket, "from": since.UnixMilli(), "to": time.Now().UnixMilli(), "rows": rs})
}

var topFields = map[string]bool{
	"country": true, "port": true, "ip": true, "asn": true, "service": true, "username": true, "password": true,
	"cred": true, "command": true, "path": true, "useragent": true, "client": true,
}

// top liest aus der beim Schreiben gepflegten Zähltabelle (schnell auch bei Millionen Ereignissen).
func (h *Hive) top(w http.ResponseWriter, r *http.Request) {
	field := r.URL.Query().Get("field")
	if !topFields[field] {
		httpErr(w, 400, "unbekanntes Feld")
		return
	}
	since, _ := rangeSince(r)
	h.sendRows(w, r, `SELECT key, MAX(label) AS label, SUM(n) AS n FROM top_hourly WHERE field = ? AND hour >= ?
		GROUP BY key ORDER BY n DESC LIMIT ?`, field, since.UnixMilli()/3600000, qInt(r, "limit", 10, 100))
}

func (h *Hive) mapPoints(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := qctx(r)
	defer cancel()
	since, _ := rangeSince(r)
	rs, err := h.rows(ctx, `SELECT key, MAX(label) AS label, SUM(n) AS n FROM top_hourly WHERE field = 'geo' AND hour >= ?
		GROUP BY key ORDER BY n DESC LIMIT 600`, since.UnixMilli()/3600000)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(rs))
	for _, row := range rs {
		k, _ := row["key"].(string)
		lat, lon, ok := strings.Cut(k, ",")
		if !ok {
			continue
		}
		la, _ := strconv.ParseFloat(lat, 64)
		lo, _ := strconv.ParseFloat(lon, 64)
		label, _ := row["label"].(string)
		cc, city, _ := strings.Cut(label, "|")
		out = append(out, map[string]any{"lat": la, "lon": lo, "n": row["n"], "country": cc, "city": city})
	}
	writeJSON(w, out)
}

// eventFilter baut die WHERE-Bedingung für Liste und Export.
func eventFilter(r *http.Request) (string, []any) {
	q := r.URL.Query()
	where := []string{"1=1"}
	var args []any
	if v, err := strconv.ParseInt(q.Get("before"), 10, 64); err == nil && v > 0 {
		where = append(where, "id < ?")
		args = append(args, v)
	}
	for _, f := range []string{"service", "type", "country", "session", "src_ip"} {
		if v := q.Get(f); v != "" {
			where = append(where, f+" = ?")
			args = append(args, v)
		}
	}
	search := strings.TrimSpace(q.Get("q"))
	if q.Get("range") != "" || search != "" {
		// Volltextsuche nur über einen Zeitraum (Standard 7 Tage), sonst liest sie die ganze Tabelle
		where = append(where, "ts >= ?")
		args = append(args, time.Now().Add(-rangeDur(q.Get("range"), 7*24*time.Hour)).UnixMilli())
	}
	if search != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(search) + "%"
		where = append(where, `(src_ip LIKE ? ESCAPE '\' OR username LIKE ? ESCAPE '\' OR password LIKE ? ESCAPE '\' OR data LIKE ? ESCAPE '\')`)
		args = append(args, like, like, like, like)
	}
	if q.Get("hide_noise") == "1" {
		where = append(where, "type NOT IN ('connect','disconnect')")
	}
	return strings.Join(where, " AND "), args
}

func (h *Hive) events(w http.ResponseWriter, r *http.Request) {
	where, args := eventFilter(r)
	args = append(args, qInt(r, "limit", 100, 500))
	h.sendRows(w, r, `SELECT `+evCols+` FROM events WHERE `+where+` ORDER BY id DESC LIMIT ?`, args...)
}

func (h *Hive) attacker(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := qctx(r)
	defer cancel()
	ip := r.PathValue("ip")
	info, err := h.rows(ctx, `SELECT * FROM attackers WHERE ip = ?`, ip)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	if len(info) == 0 {
		httpErr(w, 404, "unbekannte IP")
		return
	}
	ports, _ := h.rows(ctx, `SELECT dst_port, service, COUNT(*) AS n FROM events WHERE src_ip = ? AND type='connect' GROUP BY dst_port, service ORDER BY n DESC`, ip)
	creds, _ := h.rows(ctx, `SELECT username, password, COUNT(*) AS n FROM events WHERE src_ip = ? AND type='login' GROUP BY username, password ORDER BY n DESC LIMIT 50`, ip)
	evs, _ := h.rows(ctx, `SELECT `+evCols+` FROM events WHERE src_ip = ? ORDER BY id DESC LIMIT 300`, ip)
	writeJSON(w, map[string]any{"info": info[0], "ports": ports, "creds": creds, "events": evs})
}

func (h *Hive) sessionsList(w http.ResponseWriter, r *http.Request) {
	since, _ := rangeSince(r)
	h.sendRows(w, r, `SELECT session, MIN(ts) AS start, MAX(ts) AS last, MAX(src_ip) AS src_ip, MAX(service) AS service,
		MAX(dst_port) AS dst_port, MAX(country) AS country,
		SUM(type='login') AS logins, SUM(type='command') AS commands, SUM(type='download') AS downloads,
		MAX(CASE WHEN type='login' AND json_extract(data,'$.success') = 1 THEN 1 ELSE 0 END) AS success,
		MAX(tarpit) AS tarpit
		FROM events WHERE session IN (SELECT DISTINCT session FROM events WHERE ts >= ? AND session != '' AND type IN ('login','command','download'))
		GROUP BY session ORDER BY last DESC LIMIT ?`, since.UnixMilli(), qInt(r, "limit", 200, 1000))
}

func (h *Hive) sessionDetail(w http.ResponseWriter, r *http.Request) {
	h.sendRows(w, r, `SELECT `+evCols+` FROM events WHERE session = ? ORDER BY id LIMIT 2000`, r.PathValue("id"))
}

func (h *Hive) tarpit(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := qctx(r)
	defer cancel()
	since, _ := rangeSince(r)
	ms := since.UnixMilli()
	var total, count int64
	h.st.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(tarpit_ms),0) FROM hourly WHERE hour >= ?`, ms/3600000).Scan(&total)
	h.st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE type='disconnect' AND tarpit=1 AND ts >= ?`, ms).Scan(&count)
	longest, _ := h.rows(ctx, `SELECT ts, src_ip, service, dst_port, tarpit_ms, country FROM events
		WHERE type='disconnect' AND tarpit=1 AND ts >= ? ORDER BY tarpit_ms DESC LIMIT 15`, ms)
	byIP, _ := h.rows(ctx, `SELECT src_ip, MAX(country) AS country, SUM(tarpit_ms) AS tarpit_ms, COUNT(*) AS n FROM events
		WHERE type='disconnect' AND tarpit=1 AND ts >= ? GROUP BY src_ip ORDER BY tarpit_ms DESC LIMIT 15`, ms)
	byPort, _ := h.rows(ctx, `SELECT service, dst_port, SUM(tarpit_ms) AS tarpit_ms, COUNT(*) AS n FROM events
		WHERE type='disconnect' AND tarpit=1 AND ts >= ? GROUP BY service, dst_port ORDER BY tarpit_ms DESC`, ms)
	writeJSON(w, map[string]any{
		"total_ms": total, "connections": count, "active": h.sensors.ActiveTarpits(),
		"longest": longest, "by_ip": byIP, "by_port": byPort, "sensors": h.sensors.All(),
	})
}

// ---- Export ----

func (h *Hive) exportEvents(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	where, args := eventFilter(r)
	if r.URL.Query().Get("range") == "" && r.URL.Query().Get("q") == "" {
		where += " AND ts >= ?"
		args = append(args, time.Now().Add(-7*24*time.Hour).UnixMilli())
	}
	rs, err := h.st.db.QueryContext(ctx, `SELECT `+evCols+` FROM events WHERE `+where+` ORDER BY id LIMIT 200000`, args...)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer rs.Close()
	cols, _ := rs.Columns()
	format := r.URL.Query().Get("format")
	stamp := time.Now().Format("20060102-1504")
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	str := func(v any) string {
		switch t := v.(type) {
		case nil:
			return ""
		case []byte:
			return string(t)
		case int64:
			return strconv.FormatInt(t, 10)
		case float64:
			return strconv.FormatFloat(t, 'f', -1, 64)
		}
		return fmt.Sprint(v)
	}
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="hivornet-events-`+stamp+`.csv"`)
		cw := csv.NewWriter(w)
		cw.Write(cols)
		for rs.Next() {
			rs.Scan(ptrs...)
			rec := make([]string, len(cols))
			for i, v := range vals {
				s := str(v)
				if cols[i] == "ts" {
					if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
						s = time.UnixMilli(ms).UTC().Format(time.RFC3339Nano)
					}
				}
				// Schutz gegen Formel-Injection beim Öffnen in Excel/LibreOffice
				if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
					s = "'" + s
				}
				rec[i] = s
			}
			cw.Write(rec)
		}
		cw.Flush()
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="hivornet-events-`+stamp+`.jsonl"`)
	enc := json.NewEncoder(w)
	for rs.Next() {
		rs.Scan(ptrs...)
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			v := vals[i]
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			if c == "data" {
				if s, ok := v.(string); ok && json.Valid([]byte(s)) {
					v = json.RawMessage(s)
				}
			}
			if c == "ts" {
				if ms, ok := v.(int64); ok {
					v = time.UnixMilli(ms).UTC().Format(time.RFC3339Nano)
				}
			}
			m[c] = v
		}
		enc.Encode(m)
	}
}

// blocklist liefert Angreifer-IPs als Textliste (eine pro Zeile), z. B. für Firewall-Regeln.
func (h *Hive) blocklist(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := qctx(r)
	defer cancel()
	since, _ := rangeSince(r)
	minEvents := qInt(r, "min", 1, 1000000)
	rs, err := h.st.db.QueryContext(ctx, `SELECT ip FROM attackers WHERE last_seen >= ? AND events >= ? ORDER BY events DESC LIMIT 100000`,
		since.UnixMilli(), minEvents)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer rs.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="hivornet-blocklist.txt"`)
	fmt.Fprintf(w, "# Hivornet Blockliste, %s, Zeitraum %s, mindestens %d Ereignisse\n", time.Now().Format(time.RFC3339), r.URL.Query().Get("range"), minEvents)
	for rs.Next() {
		var ip string
		rs.Scan(&ip)
		if p := net.ParseIP(ip); p == nil || p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast() {
			continue
		}
		io.WriteString(w, ip+"\n")
	}
}

// ---- Einstellungen ----

// Öffentliche Ports laut .env: Container-Port -> Variable
var publishedPorts = map[int]string{
	21: "PORT_FTP", 80: "PORT_HTTP", 443: "PORT_HTTPS", 2375: "PORT_DOCKER", 2222: "PORT_SSH_TARPIT",
	3306: "PORT_MYSQL", 6379: "PORT_REDIS", 5900: "PORT_RAW", 8080: "PORT_HTTP_ALT",
	25: "PORT_SMTP", 2323: "PORT_TELNET_ALT", 3389: "PORT_RDP",
}

func (h *Hive) getSettings(w http.ResponseWriter, r *http.Request) {
	sensor := r.URL.Query().Get("sensor")
	cfg, own := h.SensorConfigFor(sensor)
	pub := map[string]any{}
	for p, envName := range publishedPorts {
		pub[strconv.Itoa(p)] = map[string]string{"env": envName, "host": os.Getenv(envName)}
	}
	var names []string
	for _, s := range h.sensors.All() {
		names = append(names, s.Sensor)
	}
	writeJSON(w, map[string]any{
		"sensor": sensor, "sensors": names, "own_config": own,
		"sensor_config": cfg, "retention_days": h.retentionDays(), "published": pub,
		"services": knownServices, "modes": knownModes, "max_tarpit_conns": maxTarpitConns,
		"cowrie": map[string]string{"ssh": os.Getenv("PORT_SSH"), "telnet": os.Getenv("PORT_TELNET")},
	})
}

func (h *Hive) putSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Sensor        string        `json:"sensor"`
		SensorConfig  *SensorConfig `json:"sensor_config"`
		ResetOwn      bool          `json:"reset_own"`
		RetentionDays int           `json:"retention_days"`
	}
	if err := readJSON(w, r, &req); err != nil {
		httpErr(w, 400, "ungültige Anfrage")
		return
	}
	req.Sensor = clip(req.Sensor, 64)
	switch {
	case req.ResetOwn && req.Sensor != "":
		h.st.DelKV(configKey(req.Sensor))
	case req.SensorConfig != nil:
		if err := req.SensorConfig.Validate(); err != nil {
			httpErr(w, 400, err.Error())
			return
		}
		b, _ := json.Marshal(req.SensorConfig)
		h.st.SetKV(configKey(req.Sensor), string(b))
	}
	if req.RetentionDays != 0 {
		if req.RetentionDays < 1 || req.RetentionDays > 3650 {
			httpErr(w, 400, "Aufbewahrung muss zwischen 1 und 3650 Tagen liegen")
			return
		}
		h.st.SetKV("retention_days", strconv.Itoa(req.RetentionDays))
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (h *Hive) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct{ Current, New string }
	if readJSON(w, r, &req) != nil {
		httpErr(w, 400, "ungültige Anfrage")
		return
	}
	user := h.auth.User(r)
	if len(req.Current) > maxPasswordLen || !h.auth.Check(user, req.Current) {
		httpErr(w, 403, "aktuelles Passwort ist falsch")
		return
	}
	if err := h.auth.SetPassword(user, req.New); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	h.auth.DropOtherSessions(r)
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- System, Warnungen, Metriken ----

type warning struct {
	Level string `json:"level"` // warn | critical
	Text  string `json:"text"`
}

func (h *Hive) warnings() []warning {
	var out []warning
	add := func(level, f string, a ...any) { out = append(out, warning{level, fmt.Sprintf(f, a...)}) }
	sensors := h.sensors.All()
	if len(sensors) == 0 && time.Since(h.started) > 2*time.Minute {
		add("critical", "Kein Sensor hat sich gemeldet. Läuft der Honeypot-Container?")
	}
	for _, s := range sensors {
		if time.Since(s.Seen) > 2*time.Minute {
			add("critical", "Sensor %s meldet sich seit %s nicht mehr.", s.Sensor, time.Since(s.Seen).Round(time.Minute))
		}
		if s.Egress == "offen" {
			add("critical", "Sensor %s kann ins Internet verbinden: Die Netzsperre fehlt (tools/firewall.sh, siehe README).", s.Sensor)
		}
		if s.ProxiedConns > 0 {
			add("warn", "Sensor %s: %d Verbindungen kamen scheinbar aus dem eigenen Docker-Netz. Vermutlich gehen die echten Angreifer-IPs verloren (Userland-Proxy, siehe README).", s.Sensor, s.ProxiedConns)
		}
		if s.EventsDropped > 0 {
			add("warn", "Sensor %s hat %d Ereignisse verworfen (Warteschlange voll oder vom Hive abgelehnt).", s.Sensor, s.EventsDropped)
		}
	}
	if n := h.writer.dropped.Load(); n > 0 {
		add("critical", "Der Hive konnte %d Ereignisse nicht speichern: %s", n, h.writer.lastErr.Load())
	}
	if p := h.retention().Pressure; p != "" {
		add("warn", "Speicher knapp (%s): älteste Ereignisse wurden vorzeitig gelöscht.", p)
	}
	if free := diskFree(h.dbPath); free >= 0 && free < 1<<30 {
		add("warn", "Nur noch %d MB frei auf dem Datenträger.", free>>20)
	}
	if st, _ := h.geo.Status(); strings.HasPrefix(st, "Download fehlgeschlagen") {
		add("warn", "GeoIP: %s", st)
	}
	if h.cowrie != nil {
		if found, last := h.cowrie.Status(); !found && time.Since(h.started) > 2*time.Minute {
			add("warn", "Cowrie-Log nicht gefunden. Läuft der Cowrie-Container (COMPOSE_PROFILES=cowrie)?")
		} else if found && !last.IsZero() && time.Since(last) > 48*time.Hour {
			add("warn", "Seit %s kein Cowrie-Ereignis. Ist Port 22 im Router weitergeleitet?", time.Since(last).Round(time.Hour))
		}
	}
	return out
}

func (h *Hive) system(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := qctx(r)
	defer cancel()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	file, used := h.st.Size()
	var evMax, evMin sql.NullInt64
	h.st.db.QueryRowContext(ctx, `SELECT MIN(id), MAX(id) FROM events`).Scan(&evMin, &evMax)
	var attackers int64
	h.st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM attackers`).Scan(&attackers)
	geoStatus, geoUpdated := h.geo.Status()
	cow := map[string]any{"enabled": h.cowrie != nil}
	if h.cowrie != nil {
		found, last := h.cowrie.Status()
		cow["found"], cow["last_event"] = found, last
		cow["volumes"] = h.cowrieVolumes()
	}
	evStored := int64(0)
	if evMax.Valid {
		evStored = evMax.Int64 - evMin.Int64 + 1
	}
	writeJSON(w, map[string]any{
		"warnings": h.warnings(),
		"hive": map[string]any{
			"version": version, "uptime_s": int64(time.Since(h.started).Seconds()), "mem_bytes": ms.Sys,
			"goroutines": runtime.NumGoroutine(), "db_bytes": file, "db_used_bytes": used, "disk_free": diskFree(h.dbPath),
			"events_stored": evStored, "attackers": attackers, "queue": h.writer.QueueLen(), "retention_days": h.retentionDays(),
			"max_db_bytes": h.policy().MaxDBBytes, "written": h.writer.written.Load(), "dropped": h.writer.dropped.Load(),
			"duplicates": h.writer.dupes.Load(), "retention": h.retention(),
		},
		"geoip":   map[string]any{"status": geoStatus, "updated": geoUpdated},
		"cowrie":  cow,
		"sensors": h.sensors.All(),
	})
}

// metrics liefert Kennzahlen im Prometheus-Textformat (nur mit HIVE_METRICS_TOKEN).
func (h *Hive) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	ctx, cancel := qctx(r)
	defer cancel()
	p := func(name, help, typ string, v any, labels string) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s%s %v\n", name, help, name, typ, name, labels, v)
	}
	rs, _ := h.rows(ctx, `SELECT type, SUM(cnt) AS n FROM hourly GROUP BY type ORDER BY type`)
	fmt.Fprintf(w, "# HELP hivornet_events_total Gespeicherte Ereignisse nach Typ\n# TYPE hivornet_events_total counter\n")
	for _, row := range rs {
		fmt.Fprintf(w, "hivornet_events_total{type=%q} %v\n", row["type"], row["n"])
	}
	file, used := h.st.Size()
	p("hivornet_db_file_bytes", "Größe der Datenbankdateien", "gauge", file, "")
	p("hivornet_db_used_bytes", "Belegter Platz in der Datenbank", "gauge", used, "")
	p("hivornet_disk_free_bytes", "Freier Speicher", "gauge", diskFree(h.dbPath), "")
	p("hivornet_events_dropped_total", "Vom Hive verworfene Ereignisse", "counter", h.writer.dropped.Load(), "")
	p("hivornet_events_written_total", "Seit Start geschriebene Ereignisse", "counter", h.writer.written.Load(), "")
	p("hivornet_tarpits_active", "Gerade festgehaltene Verbindungen", "gauge", h.sensors.ActiveTarpits(), "")
	p("hivornet_warnings", "Anzahl aktueller Warnungen", "gauge", len(h.warnings()), "")
	fmt.Fprintf(w, "# HELP hivornet_sensor_last_seen_seconds Sekunden seit dem letzten Lebenszeichen\n# TYPE hivornet_sensor_last_seen_seconds gauge\n")
	for _, s := range h.sensors.All() {
		fmt.Fprintf(w, "hivornet_sensor_last_seen_seconds{sensor=%q} %d\n", s.Sensor, int64(time.Since(s.Seen).Seconds()))
	}
}

func (h *Hive) retentionDays() int {
	if v, ok := h.st.GetKV("retention_days"); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return h.defaultRetention
}

func (h *Hive) policy() RetentionPolicy {
	return RetentionPolicy{Days: h.retentionDays(), MaxDBBytes: h.maxDBBytes, MinFreeBytes: h.minFreeBytes}
}

// cowrieVolumes zählt den Platz in den Cowrie-Volumes (zwischengespeichert, alle 10 Minuten neu).
func (h *Hive) cowrieVolumes() map[string]int64 {
	h.volMu.Lock()
	defer h.volMu.Unlock()
	if time.Since(h.volAt) < 10*time.Minute && h.vol != nil {
		return h.vol
	}
	h.vol = map[string]int64{}
	for name, dir := range map[string]string{"log": h.cowrieLogDir, "lib": h.cowrieLibDir} {
		if dir != "" {
			h.vol[name] = dirSize(dir, 200000)
		}
	}
	h.volAt = time.Now()
	return h.vol
}
