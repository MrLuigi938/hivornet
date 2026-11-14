package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ---- GreyNoise (Community-API) ----
//
// GreyNoise sagt, ob eine IP als Massen-Scanner bekannt ist ("noise"), zu einem
// harmlosen, bekannten Dienst gehört ("riot", z. B. Suchmaschinen-Crawler) und
// wie sie eingestuft wird (benign, malicious, unknown). Die Community-API geht
// ohne Schlüssel (mit knappem Tageskontingent); ein kostenloser Schlüssel erhöht es.
// Abfrage nur auf Knopfdruck, Ergebnis 24 Stunden in "lookups".

// greynoiseBase ist die Adresse der API; in Tests überschrieben.
var greynoiseBase = "https://api.greynoise.io"

func (h *Hive) greynoise(w http.ResponseWriter, r *http.Request) {
	ip := net.ParseIP(r.PathValue("ip"))
	if ip == nil {
		httpErr(w, 400, "ungültige IP")
		return
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		httpErr(w, 400, "Private Adressen werden nicht abgefragt.")
		return
	}
	subject := "ip:" + ip.String()
	if data, at, ok := h.st.lookupGet(subject, "greynoise", 24*time.Hour); ok {
		writeJSON(w, map[string]any{"data": json.RawMessage(data), "at": at, "cached": true})
		return
	}
	ctx, cancel := qctx(r)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", greynoiseBase+"/v3/community/"+ip.String(), nil)
	req.Header.Set("Accept", "application/json")
	if k := h.Extras().GreyNoiseKey; k != "" {
		req.Header.Set("key", k)
	}
	resp, err := intelHTTP.Do(req)
	if err != nil {
		httpErr(w, 502, "GreyNoise nicht erreichbar")
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var out map[string]any
	// 404 heißt hier: Die IP ist GreyNoise nicht als Scanner bekannt. Das ist eine gültige Antwort.
	if (resp.StatusCode != 200 && resp.StatusCode != 404) || json.Unmarshal(raw, &out) != nil {
		msg := "GreyNoise antwortet " + resp.Status
		if resp.StatusCode == 429 {
			msg = "Tageskontingent von GreyNoise erschöpft; mit kostenlosem Schlüssel (Einstellungen) gibt es mehr."
		}
		httpErr(w, 502, msg)
		return
	}
	keep := map[string]any{"found": resp.StatusCode == 200}
	for _, k := range []string{"noise", "riot", "classification", "name", "last_seen", "message"} {
		if v, ok := out[k]; ok {
			keep[k] = v
		}
	}
	b, _ := json.Marshal(keep)
	h.st.lookupPut(subject, "greynoise", string(b))
	writeJSON(w, map[string]any{"data": json.RawMessage(b), "at": time.Now(), "cached": false})
}

// ---- STIX-2.1-Export ----
//
// Liefert Angreifer-IPs, Nachlade-Adressen und SHA-256 der Downloads als STIX-2.1-
// Bundle mit Indikatoren. MISP, OpenCTI und viele Firewalls lesen das ein.
// Achtung: Das sind personenbezogene Daten (README, Recht und Datenschutz).

func stixID(typ string) string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40 // UUID Version 4
	b[8] = b[8]&0x3f | 0x80
	x := hex.EncodeToString(b)
	return fmt.Sprintf("%s--%s-%s-%s-%s-%s", typ, x[0:8], x[8:12], x[12:16], x[16:20], x[20:32])
}

// stixString maskiert einen Wert für ein STIX-Muster (in einfachen Anführungszeichen).
func stixString(s string) string {
	return strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s)
}

func (h *Hive) exportSTIX(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	since, _ := rangeSince(r)
	minEvents := qInt(r, "min", 1, 1000000)
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	identity := stixID("identity")
	objects := []map[string]any{{
		"type": "identity", "spec_version": "2.1", "id": identity, "created": now, "modified": now,
		"name": "HoneyLite " + version, "identity_class": "system",
	}}
	add := func(name, pattern, desc string, first time.Time, types []string) {
		objects = append(objects, map[string]any{
			"type": "indicator", "spec_version": "2.1", "id": stixID("indicator"), "created": now, "modified": now,
			"created_by_ref": identity, "name": name, "description": desc, "indicator_types": types,
			"pattern": pattern, "pattern_type": "stix", "valid_from": first.UTC().Format("2006-01-02T15:04:05.000Z"),
		})
	}

	rs, err := h.st.db.QueryContext(ctx, `SELECT ip, first_seen, events, logins, commands, country FROM attackers
		WHERE last_seen >= ? AND events >= ? ORDER BY events DESC LIMIT 10000`, since.UnixMilli(), minEvents)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	for rs.Next() {
		var ip, country string
		var first, events, logins, commands int64
		if rs.Scan(&ip, &first, &events, &logins, &commands, &country) != nil {
			continue
		}
		p := net.ParseIP(ip)
		if p == nil || p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast() {
			continue
		}
		kind := "ipv4-addr"
		if p.To4() == nil {
			kind = "ipv6-addr"
		}
		add("Angreifer "+ip, fmt.Sprintf("[%s:value = '%s']", kind, stixString(ip)),
			fmt.Sprintf("Vom Honeypot beobachtet: %d Ereignisse, %d Login-Versuche, %d Befehle, Herkunft %s", events, logins, commands, country),
			time.UnixMilli(first), []string{"malicious-activity"})
	}
	rs.Close()

	urls, _ := h.rows(ctx, `SELECT key, MIN(hour) AS first FROM top_hourly WHERE field = 'url' AND hour >= ? GROUP BY key LIMIT 5000`, since.UnixMilli()/3600000)
	for _, u := range urls {
		k, _ := u["key"].(string)
		hr, _ := u["first"].(int64)
		if k != "" {
			add("Nachlade-Adresse", fmt.Sprintf("[url:value = '%s']", stixString(k)), "Angreifer wollten von dieser Adresse Dateien laden.",
				time.UnixMilli(hr*3600000), []string{"malicious-activity"})
		}
	}
	hashes, _ := h.rows(ctx, `SELECT json_extract(data, '$.sha256') AS h, MIN(ts) AS first FROM events
		WHERE type = 'download' AND ts >= ? AND json_extract(data, '$.sha256') != '' GROUP BY h LIMIT 5000`, since.UnixMilli())
	for _, x := range hashes {
		k, _ := x["h"].(string)
		first, _ := x["first"].(int64)
		if sha256Re.MatchString(k) {
			add("Heruntergeladene Datei", fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", k), "Von Angreifern auf den Honeypot geladene Datei.",
				time.UnixMilli(first), []string{"malicious-activity"})
		}
	}
	w.Header().Set("Content-Disposition", `attachment; filename="honeylite-stix-`+time.Now().Format("20060102-1504")+`.json"`)
	writeJSON(w, map[string]any{"type": "bundle", "id": stixID("bundle"), "objects": objects})
}
