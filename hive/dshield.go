package main

// Daten an DShield (SANS Internet Storm Center) senden, stündlich.
//
// Format wie beim DShield-Sensor (github.com/DShield-ISC/dshield, DShield.py, fwlogparser.py,
// isc_agent) und dem DShield-Ausgang von Cowrie (Stand November 2026):
//   POST https://www.dshield.org/submitapi/, JSON {"type": …, "logs": […], "authheader": …},
//   Kopf X-ISC-Authorization: "ISC-HMAC-SHA256 Credentials=<b64> Userid=<id> Nonce=<b64>"
//   mit Credentials = Base64(HMAC-SHA256(Schlüssel = Nonce + Benutzernummer, Nachricht =
//   API-Schlüssel)), Nonce = Base64 von 8 Zufallsbytes; dazu X-ISC-LogType: <type>.
//   Erfolg ist jede Antwort 2xx. Der API-Schlüssel geht als Text in die HMAC, nicht
//   Base64-dekodiert (so auch Cowrie seit 2026). Userid ist die numerische ISC-Benutzer-ID.
//
// Zugang prüfen wie das Installationsprogramm des DShield-Sensors (bin/install.sh):
//   GET https://isc.sans.edu/api/checkapikey/<E-Mail>/<Nonce>/<Hash>/<Version>/<piid>
//   mit Hash = hex(HMAC-SHA512(Schlüssel = Nonce, Nachricht = "<E-Mail>:<API-Schlüssel>")),
//   Nonce = 10 Zufallsbytes hex. Antwort XML mit <result>ok</result> und <id>…</id>: das ist
//   die Benutzer-ID für die Einreichung. Bis 0.9.4 musste man sie selbst finden, und oft
//   stand dort der Anmeldename.
//   - "firewall": je Verbindungsversuch {time (Unix-Sekunden), sip, dip, sport, dport,
//     proto (6/17), flags, version}.
//   - "webhoneypot": je Web-Anfrage {time, sip, dip, method, url, useragent, version, headers}.
//   - "cowrie": je SSH-/Telnet-Anmeldeversuch {timestamp, source_ip, user, password}.
//
// Datenschutz: Die eigene Adresse (dip) wird nie gesendet, sondern 0.0.0.0, wie es der
// DShield-Sensor mit anonymizemask 0.0.0.0 tut. Absender aus dem eigenen Netz, mit der
// eigenen öffentlichen IP, von nicht vertrauenswürdigen Sensoren oder aus "nie sperren"
// werden ausgelassen. In Pfaden und Kopfzeilen werden die eigene IP und die Hostnamen der
// Sensoren ersetzt; der Host-Kopf entfällt.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	dshieldSubmitURL = "https://www.dshield.org/submitapi/"
	dshieldCheckURL  = "https://isc.sans.edu/api/checkapikey/"
	dshieldKeyRe     = regexp.MustCompile(`^[A-Za-z0-9=+/]{1,200}$`)
)

const dshieldMaxEvents = 20000

func dshieldAuth(userID int, key string, nonce []byte) string {
	n := base64.StdEncoding.EncodeToString(nonce)
	m := hmac.New(sha256.New, []byte(n+strconv.Itoa(userID)))
	m.Write([]byte(key))
	return fmt.Sprintf("ISC-HMAC-SHA256 Credentials=%s Userid=%d Nonce=%s", base64.StdEncoding.EncodeToString(m.Sum(nil)), userID, n)
}

// publicPort: Der Honeypot lauscht für Ports unter 1024 auf Port+10000 (docker-compose.yml).
func publicPort(p int) int {
	if p >= 10000 && p < 11024 {
		return p - 10000
	}
	return p
}

type dshieldBatch struct {
	firewall, web, logins []map[string]any
	lastID                int64
	truncated             bool
	webSkipped            bool // eigene öffentliche Adresse unbekannt
}

// dshieldCollect liest die Ereignisse nach lastID und baut die Einträge.
func (h *Hive) dshieldCollect(ctx context.Context, cfg DShieldConfig, lastID int64) (*dshieldBatch, error) {
	var types []string
	if cfg.Firewall {
		types = append(types, "'connect'")
	}
	if cfg.Web {
		types = append(types, "'request'")
	}
	if cfg.Logins {
		types = append(types, "'login'")
	}
	b := &dshieldBatch{lastID: lastID}
	if len(types) == 0 {
		return b, nil
	}
	evs, err := h.loadEvents(ctx, "id > ? AND ts < ? AND type IN ("+strings.Join(types, ",")+")",
		[]any{lastID, time.Now().Add(-time.Minute).UnixMilli()}, "ASC", dshieldMaxEvents)
	if err != nil {
		return nil, err
	}
	b.truncated = len(evs) >= dshieldMaxEvents
	own := h.ownPublicIP()
	untrusted := h.untrustedSensors()
	scrub := h.honeypotNames()
	scrub = append(scrub, h.knownOwnIPs()...) // auch frühere Adressen (ownip.go)
	// Ohne bekannte eigene Adresse lässt sie sich aus Pfaden und Kopfzeilen nicht entfernen:
	// dann keine Web-Anfragen (Verbindungen und Anmeldungen tragen sie nicht, dip ist 0.0.0.0).
	webOK := own != ""
	if !webOK && cfg.Web {
		b.webSkipped = true
	}
	clean := func(s string, n int) string {
		for _, x := range scrub {
			if len(x) >= 3 {
				s = strings.ReplaceAll(s, x, "[host]")
			}
		}
		return clip(strings.ToValidUTF8(s, "?"), n)
	}
	for _, e := range evs {
		b.lastID = e.ID
		ip, err := netip.ParseAddr(e.SrcIP)
		if err != nil || specialIP(ip, own) != "" || untrusted[e.Sensor] || h.neverBlock(e.SrcIP) {
			continue
		}
		ver := 4
		if ip.Unmap().Is6() {
			ver = 6
		}
		switch e.Type {
		case "connect":
			proto, flags := 6, "S"
			if udpServices[e.Service] {
				proto, flags = 17, ""
			}
			b.firewall = append(b.firewall, map[string]any{"time": e.TS.Unix(), "sip": e.SrcIP, "dip": "0.0.0.0",
				"sport": strconv.Itoa(e.SrcPort), "dport": strconv.Itoa(publicPort(e.DstPort)), "proto": proto, "flags": flags, "version": ver})
		case "request":
			method := dataString(e.Data, "method")
			if !webOK || method == "" || udpServices[e.Service] || e.Service == "rdp" || strings.Contains(method, " ") {
				continue
			}
			ua := clean(dataString(e.Data, "user_agent"), 300)
			hdr := map[string]string{}
			for _, line := range strings.Split(dataString(e.Data, "headers"), "\n") {
				k, v, ok := strings.Cut(line, ": ")
				// Host, Referer, Origin, Weiterleitungs-Köpfe und Cookies tragen eigene Namen,
				// Adressen oder vom Honeypot vergebene Sitzungen (dropHeaders, cvesuggest.go).
				if !ok || dropHeaders[strings.ToLower(strings.TrimSpace(k))] || len(hdr) >= 30 {
					continue
				}
				hdr[clip(k, 60)] = clean(v, 300)
			}
			b.web = append(b.web, map[string]any{"time": float64(e.TS.UnixMilli()) / 1000, "sip": e.SrcIP, "dip": "0.0.0.0",
				"method": clip(method, 16), "url": clean(dataString(e.Data, "path"), 1000), "useragent": ua,
				"version": clip(dataString(e.Data, "version"), 16), "headers": hdr})
		case "login":
			if e.Service != "ssh" && e.Service != "telnet" || e.Username == "" && e.Password == "" {
				continue
			}
			b.logins = append(b.logins, map[string]any{"timestamp": e.TS.UTC().Format(time.RFC3339), "source_ip": e.SrcIP,
				"user": clip(e.Username, 100), "password": clip(e.Password, 100)})
		}
	}
	return b, nil
}

func (h *Hive) dshieldRound(ctx context.Context) {
	cfg := h.Extras().DShield
	if !cfg.Enabled || cfg.UserID == 0 || cfg.APIKey == "" {
		return
	}
	h.share.mu.Lock()
	c := h.share.channel("dshield")
	due := time.Since(c.LastRun) >= 55*time.Minute || c.LastErr == "" && len(c.Log) > 0 && c.Log[0].Detail == "mehr folgt"
	h.share.mu.Unlock()
	if !due || !h.share.begin("dshield") {
		return
	}
	var lastID int64
	if v, ok := h.st.GetKV("dshield_last_id"); ok {
		lastID, _ = strconv.ParseInt(v, 10, 64)
	} else {
		// Erster Lauf: nur die letzte Stunde, keine alten Daten
		h.st.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM events WHERE ts < ?`, time.Now().Add(-time.Hour).UnixMilli()).Scan(&lastID)
	}
	b, err := h.dshieldCollect(ctx, cfg, lastID)
	if err != nil {
		return
	}
	summary := fmt.Sprintf("%d Verbindungen, %d Web-Anfragen, %d Anmeldungen", len(b.firewall), len(b.web), len(b.logins))
	e := shareLogEntry{Time: time.Now(), Subject: summary}
	if b.truncated {
		e.Detail = "mehr folgt"
	} else if b.webSkipped {
		e.Detail = "Web-Anfragen ausgelassen: eigene öffentliche Adresse unbekannt (Einstellungen → Zugang und Sicherheit → Eigene öffentliche Adresse)"
	}
	if len(b.firewall)+len(b.web)+len(b.logins) == 0 {
		h.st.SetKV("dshield_last_id", strconv.FormatInt(b.lastID, 10))
		return
	}
	if cfg.DryRun {
		e.Status = "dry"
		h.share.add("dshield", e)
		h.st.SetKV("dshield_last_id", strconv.FormatInt(b.lastID, 10))
		return
	}
	for _, part := range []struct {
		typ  string
		logs []map[string]any
	}{{"firewall", b.firewall}, {"webhoneypot", b.web}, {"cowrie", b.logins}} {
		for i := 0; i < len(part.logs); i += 1000 {
			if code, err := dshieldPost(ctx, cfg, part.typ, part.logs[i:min(i+1000, len(part.logs))]); err != nil {
				e.Status, e.Error = "error", err.Error()
				h.share.setErr("dshield", err.Error(), pauseFor(code))
				h.share.add("dshield", e)
				return // lastID bleibt: beim nächsten Lauf noch einmal (DShield erkennt Doppeltes)
			}
		}
	}
	h.share.setErr("dshield", "", 0)
	e.Status = "ok"
	h.share.add("dshield", e)
	h.st.SetKV("dshield_last_id", strconv.FormatInt(b.lastID, 10))
}

func dshieldPost(ctx context.Context, cfg DShieldConfig, typ string, logs []map[string]any) (int, error) {
	nonce := make([]byte, 8)
	rand.Read(nonce)
	auth := dshieldAuth(cfg.UserID, cfg.APIKey, nonce)
	body, _ := json.Marshal(map[string]any{"type": typ, "logs": logs, "authheader": auth})
	req, _ := http.NewRequestWithContext(ctx, "POST", dshieldSubmitURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Hivornet")
	req.Header.Set("X-ISC-Authorization", auth)
	req.Header.Set("X-ISC-LogType", typ)
	resp, err := shareHTTP.Do(req)
	if err != nil {
		return 0, fmt.Errorf("DShield nicht erreichbar")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, dshieldError(resp.StatusCode, resp.Status, raw)
	}
	return resp.StatusCode, nil
}

// dshieldError: verständliche Meldung zu einer Ablehnung durch DShield.
func dshieldError(code int, status string, raw []byte) error {
	answer := clip(strings.Join(strings.Fields(htmlTagRe.ReplaceAllString(strings.ToValidUTF8(string(raw), "?"), " ")), " "), 150)
	if answer != "" {
		answer = " (Antwort: " + answer + ")"
	}
	if code == 401 || code == 403 {
		return fmt.Errorf("DShield lehnt Benutzer-ID oder API-Schlüssel ab: %s. Die Benutzer-ID ist die Zahl unter isc.sans.edu → My Account, nicht der Anmeldename; „Zugang prüfen“ trägt sie selbst ein%s", status, answer)
	}
	return fmt.Errorf("DShield antwortet %s%s", status, answer)
}

var (
	htmlTagRe    = regexp.MustCompile(`<[^>]*>`)
	iscResultRe  = regexp.MustCompile(`<result>\s*([^<]*?)\s*</result>`)
	iscIDRe      = regexp.MustCompile(`<id>\s*([0-9]{1,9})\s*</id>`)
	dshieldEmail = regexp.MustCompile(`^[^\s/@]{1,100}@[^\s/@]{1,100}$`)
)

// dshieldCheck fragt bei isc.sans.edu, ob E-Mail-Adresse und API-Schlüssel zusammenpassen,
// und liefert die numerische Benutzer-ID.
func dshieldCheck(ctx context.Context, email, key string) (int, error) {
	if !dshieldEmail.MatchString(email) {
		return 0, fmt.Errorf("Bitte die E-Mail-Adresse angeben, mit der du dich bei isc.sans.edu anmeldest")
	}
	if !dshieldKeyRe.MatchString(key) {
		return 0, fmt.Errorf("API-Schlüssel fehlt oder enthält unerlaubte Zeichen (erlaubt: Buchstaben, Ziffern, + / =)")
	}
	nb := make([]byte, 10)
	rand.Read(nb)
	nonce := hex.EncodeToString(nb)
	m := hmac.New(sha512.New, []byte(nonce))
	m.Write([]byte(email + ":" + key))
	pb := make([]byte, 10)
	rand.Read(pb)
	// Pfad wie install.sh: Version 102 des Sensors, piid eine Zufallskennung
	u := dshieldCheckURL + url.PathEscape(email) + "/" + nonce + "/" + hex.EncodeToString(m.Sum(nil)) + "/102/" + hex.EncodeToString(pb)
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	req.Header.Set("User-Agent", "Hivornet")
	resp, err := shareHTTP.Do(req)
	if err != nil {
		return 0, fmt.Errorf("isc.sans.edu nicht erreichbar")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != 200 {
		return 0, dshieldError(resp.StatusCode, resp.Status, raw)
	}
	res := iscResultRe.FindSubmatch(raw)
	if res == nil || !strings.EqualFold(string(res[1]), "ok") {
		why := "keine Antwort"
		if res != nil {
			why = clip(string(res[1]), 80)
		}
		return 0, fmt.Errorf("isc.sans.edu kennt diese Kombination aus E-Mail-Adresse und API-Schlüssel nicht (%s). Schlüssel unter isc.sans.edu → My Account → API Key neu kopieren", why)
	}
	id := iscIDRe.FindSubmatch(raw)
	if id == nil {
		return 0, fmt.Errorf("isc.sans.edu bestätigt den Schlüssel, nennt aber keine Benutzer-ID. Bitte die Zahl unter My Account selbst eintragen")
	}
	n, _ := strconv.Atoi(string(id[1]))
	return n, nil
}

// dshieldCheckAPI: POST /api/share/dshield/check {email, api_key} – prüft den Zugang und
// trägt E-Mail-Adresse, Benutzer-ID und Schlüssel ein. Ohne api_key gilt der gespeicherte.
func (h *Hive) dshieldCheckAPI(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email  string `json:"email"`
		APIKey string `json:"api_key"`
	}
	if err := readJSON(w, r, &in); err != nil {
		httpErr(w, 400, "ungültige Anfrage")
		return
	}
	in.Email, in.APIKey = strings.TrimSpace(in.Email), strings.TrimSpace(in.APIKey)
	key := in.APIKey
	if key == "" {
		key = h.Extras().DShield.APIKey
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	id, err := dshieldCheck(ctx, in.Email, key)
	if err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	h.extras.mu.Lock()
	x := h.extras.x
	x.DShield.UserID, x.DShield.Email, x.DShield.APIKey = id, in.Email, key
	err = x.Validate()
	if err == nil {
		b, _ := json.Marshal(x)
		if err = h.st.SetKV("extras", string(b)); err == nil {
			h.extras.x = x
		}
	}
	h.extras.mu.Unlock()
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	h.share.mu.Lock()
	c := h.share.channel("dshield")
	c.LastErr, c.PauseUntil = "", time.Time{}
	h.share.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true, "user_id": id})
}
