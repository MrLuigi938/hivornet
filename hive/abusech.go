package main

// Nachschlagen bei abuse.ch auf Knopfdruck (wie AbuseIPDB): Nachlade-Adressen bei URLhaus,
// SHA-256 von Downloads bei MalwareBazaar. Nur Abfragen, nie ein Upload.
//
// API (Stand November 2026, urlhaus-api.abuse.ch und bazaar.abuse.ch/api): beide
// verlangen einen kostenlosen Schlüssel im Kopf "Auth-Key"; URLhaus POST /v1/url/ mit
// Formularfeld url, MalwareBazaar POST /api/v1/ mit query=get_info und hash.
//
// Abgefragt werden nur Adressen und Hashes, die in den eigenen Daten vorkommen, damit der
// Hive nicht als allgemeiner Abfragedienst dient. Ergebnisse bleiben 24 Stunden in lookups.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	urlhausBase = "https://urlhaus-api.abuse.ch"
	bazaarBase  = "https://mb-api.abuse.ch"
	sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func (h *Hive) abuseChPost(r *http.Request, endpoint string, form url.Values) (map[string]any, error) {
	ctx, cancel := qctx(r)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Auth-Key", h.Extras().AbuseChKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := intelHTTP.Do(req)
	if err != nil {
		return nil, errString("abuse.ch nicht erreichbar")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	var out map[string]any
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, errString("abuse.ch lehnt den Schlüssel ab (" + resp.Status + ")")
	}
	if resp.StatusCode != 200 || json.Unmarshal(raw, &out) != nil {
		return nil, errString("abuse.ch antwortet " + resp.Status)
	}
	return out, nil
}

type errString string

func (e errString) Error() string { return string(e) }

func pickKeys(m map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			out[k] = v
		}
	}
	return out
}

// lookupURLhaus: GET /api/lookup/urlhaus?url=…
func (h *Hive) lookupURLhaus(w http.ResponseWriter, r *http.Request) {
	u := strings.TrimSpace(r.URL.Query().Get("url"))
	if u == "" || len(u) > 2048 {
		httpErr(w, 400, "Adresse fehlt")
		return
	}
	if h.Extras().AbuseChKey == "" {
		httpErr(w, 400, "Kein abuse.ch-Schlüssel hinterlegt (Einstellungen).")
		return
	}
	var n int
	h.st.db.QueryRow(`SELECT COUNT(*) FROM top_hourly WHERE field = 'url' AND key = ?`, clip(u, 300)).Scan(&n)
	if n == 0 {
		httpErr(w, 400, "Diese Adresse kommt in den eigenen Daten nicht vor.")
		return
	}
	sum := sha256.Sum256([]byte(u))
	subject := "url:" + hex.EncodeToString(sum[:])
	if data, at, ok := h.st.lookupGet(subject, "urlhaus", 24*time.Hour); ok {
		writeJSON(w, map[string]any{"data": json.RawMessage(data), "at": at, "cached": true})
		return
	}
	out, err := h.abuseChPost(r, urlhausBase+"/v1/url/", url.Values{"url": {u}})
	if err != nil {
		httpErr(w, 502, err.Error())
		return
	}
	keep := pickKeys(out, "query_status", "url_status", "threat", "tags", "date_added", "urlhaus_reference", "host", "last_online")
	if p, ok := out["payloads"].([]any); ok {
		keep["payloads"] = len(p)
		var sigs []string
		for _, x := range p {
			if m, ok := x.(map[string]any); ok {
				if s, _ := m["signature"].(string); s != "" && !contains(sigs, s) && len(sigs) < 5 {
					sigs = append(sigs, s)
				}
			}
		}
		keep["signatures"] = sigs
	}
	b, _ := json.Marshal(keep)
	h.st.lookupPut(subject, "urlhaus", string(b))
	writeJSON(w, map[string]any{"data": json.RawMessage(b), "at": time.Now(), "cached": false})
}

// lookupBazaar: GET /api/lookup/malwarebazaar?hash=<sha256>
func (h *Hive) lookupBazaar(w http.ResponseWriter, r *http.Request) {
	hash := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("hash")))
	if !sha256HexRe.MatchString(hash) {
		httpErr(w, 400, "SHA-256 erwartet")
		return
	}
	if h.Extras().AbuseChKey == "" {
		httpErr(w, 400, "Kein abuse.ch-Schlüssel hinterlegt (Einstellungen).")
		return
	}
	var n int
	h.st.db.QueryRow(`SELECT COUNT(*) FROM events WHERE type = 'download' AND json_extract(data, '$.sha256') = ?`, hash).Scan(&n)
	if n == 0 {
		httpErr(w, 400, "Dieser Hash kommt in den eigenen Daten nicht vor.")
		return
	}
	subject := "hash:" + hash
	if data, at, ok := h.st.lookupGet(subject, "malwarebazaar", 24*time.Hour); ok {
		writeJSON(w, map[string]any{"data": json.RawMessage(data), "at": at, "cached": true})
		return
	}
	out, err := h.abuseChPost(r, bazaarBase+"/api/v1/", url.Values{"query": {"get_info"}, "hash": {hash}})
	if err != nil {
		httpErr(w, 502, err.Error())
		return
	}
	keep := pickKeys(out, "query_status")
	if d, ok := out["data"].([]any); ok && len(d) > 0 {
		if m, ok := d[0].(map[string]any); ok {
			for k, v := range pickKeys(m, "signature", "file_type", "file_name", "file_size", "tags", "first_seen", "last_seen", "delivery_method") {
				keep[k] = v
			}
		}
	}
	b, _ := json.Marshal(keep)
	h.st.lookupPut(subject, "malwarebazaar", string(b))
	writeJSON(w, map[string]any{"data": json.RawMessage(b), "at": time.Now(), "cached": false})
}
