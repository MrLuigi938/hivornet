package main

// Automatische Meldung an AbuseIPDB (POST /api/v2/report).
//
// Regeln (Stand der API-Dokumentation docs.abuseipdb.com, November 2026):
//   - Gemeldet wird erst ein echter Angriffsversuch: Login-Versuche (auch Befehle an der
//     Login-Abfrage), Exploit-Muster bei Web-Anfragen, ausgeführte Befehle, Downloads.
//     Reines Abtasten, Protokoll-Abfragen und TLS-Handshakes nicht.
//   - Nie: private oder eigene Adressen (ownnet.go), Angriffe, die nur über UDP kamen
//     (Absender fälschbar), und, wenn eingestellt, Forschungsscanner (scanner.go).
//   - Kategorie nach Art (abuseCategories), Kommentar auf Englisch ohne Passwörter, ohne
//     IP-Adressen und ohne Hostnamen des Honeypots (abuseComment, scrubComment).
//   - AbuseIPDB nimmt dieselbe IP höchstens alle 15 Minuten an; Hivornet meldet eine IP
//     höchstens einmal je eingestelltem Abstand (Standard 24 h, mindestens 1 h) und nur so
//     viele Meldungen am Tag wie eingestellt (Standard 50; das Kontingent ist 1.000).
//   - Standardmäßig aus; der Probemodus schreibt nur ins Protokoll ("würde melden").
//   - Kontingent aus den Kopfzeilen X-RateLimit-Limit/-Remaining; bei 429 Pause bis
//     Retry-After. Fehler und Kontingent zeigt die UI.
//
// Der Hive prüft alle 5 Minuten die Angriffe der letzten 30 Minuten.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type AbuseReportConfig struct {
	Enabled         bool `json:"enabled"`
	DryRun          bool `json:"dry_run"`           // nur protokollieren, nichts senden
	DailyLimit      int  `json:"daily_limit"`       // Meldungen je 24 h
	IntervalHours   int  `json:"interval_hours"`    // Abstand je IP
	SkipScanners    bool `json:"skip_scanners"`     // Forschungsscanner nicht melden
	IncludeWebProbe bool `json:"include_web_probe"` // auch Geheimnis-Suche (.env, .git) als Web-Angriff melden
}

func defaultAbuseReport() AbuseReportConfig {
	return AbuseReportConfig{DryRun: true, DailyLimit: 50, IntervalHours: 24, SkipScanners: true}
}

func (c *AbuseReportConfig) validate() error {
	if c.DailyLimit < 1 || c.DailyLimit > 1000 {
		return fmt.Errorf("AbuseIPDB: Meldungen pro Tag 1 bis 1000")
	}
	if c.IntervalHours < 1 || c.IntervalHours > 24*30 {
		return fmt.Errorf("AbuseIPDB: Abstand je IP 1 bis 720 Stunden")
	}
	return nil
}

// AbuseIPDB-Kategorien (www.abuseipdb.com/categories)
const (
	catFTPBrute  = 5
	catPortScan  = 14
	catHacking   = 15
	catSQLi      = 16
	catBrute     = 18
	catExploited = 20
	catWebApp    = 21
	catSSH       = 22
	catIoT       = 23
	catEmailSpam = 11
)

var udpServices = map[string]bool{"sip": true, "snmp": true, "dns": true}

// webExploitTags: Muster, die bei Web-Anfragen als Angriff gelten (nicht nur Erkundung).
var webExploitTags = map[string]bool{"web_rce": true, "log4shell": true, "java4shell": true, "iot_exploit": true, "traversal": true, "sqli": true}

// abuseVerdict: Soll der Angriff gemeldet werden? Liefert Kategorien oder den Grund dagegen.
func abuseVerdict(a *Attack, cfg AbuseReportConfig) (cats []int, why string) {
	ip := net.ParseIP(a.IP)
	switch {
	case ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || isOwnIP(a.IP) || cgnat.Contains(ip):
		return nil, "eigene oder private Adresse"
	case cfg.SkipScanners && a.Scanner != "" && a.scannerExempt(): // scanner.go
		return nil, "Forschungsscanner (" + a.Scanner + ")"
	}
	tcp := false
	for _, s := range a.Services {
		if !udpServices[s] {
			tcp = true
		}
	}
	if !tcp {
		return nil, "nur UDP (Absender fälschbar)"
	}
	set := map[int]bool{}
	c := a.Counts
	logins := c["login"] - a.loginSvc["snmp"]
	if logins > 0 || c["prompt"] > 0 {
		set[catBrute] = true
		for s := range a.loginSvc {
			switch s {
			case "ssh":
				set[catSSH] = true
			case "ftp":
				set[catFTPBrute] = true
			case "telnet":
				set[catIoT] = true
			}
		}
		if c["prompt"] > 0 {
			set[catIoT] = true
		}
	}
	if len(a.CVEs) > 0 {
		set[catWebApp] = true
	}
	for _, t := range a.Tags {
		if webExploitTags[t.Key] || cfg.IncludeWebProbe && (t.Key == "secret_hunt" || t.Key == "cms_login") {
			set[catWebApp] = true
		}
		switch t.Key {
		case "sqli":
			set[catSQLi] = true
		case "iot_exploit", "iot_botnet":
			set[catIoT] = true
		}
	}
	if c["command"] > 0 || c["download"] > 0 {
		set[catHacking] = true
		if a.svc["ssh"] {
			set[catSSH] = true
		}
	}
	if len(set) == 0 {
		return nil, "kein Angriffsversuch (nur Abtasten oder Abfragen)"
	}
	for k := range set {
		cats = append(cats, k)
	}
	sort.Ints(cats)
	return cats, ""
}

var abuseSvcName = map[string]string{"ssh": "SSH", "telnet": "Telnet", "ftp": "FTP", "mysql": "MySQL", "redis": "Redis",
	"smtp": "SMTP", "vnc": "VNC", "rdp": "RDP", "http": "HTTP", "https": "HTTPS", "dockerapi": "Docker API"}

var safeUser = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,24}$`)

// abuseComment: kurze Beschreibung ohne Passwörter, IPs und Hostnamen.
func abuseComment(a *Attack, scrub []string) string {
	var parts []string
	var svcs []string
	for _, s := range a.Services {
		if n, ok := abuseSvcName[s]; ok {
			svcs = append(svcs, n)
		}
	}
	// Englische Plattform: keine deutschen Bezeichnungen (Art, Musternamen), sondern die Kennungen der Muster.
	head := "Honeypot"
	if len(svcs) > 0 {
		head += " (" + strings.Join(svcs, ", ") + ")"
	}
	parts = append(parts, head)
	if n := a.Counts["login"]; n > 0 {
		users := map[string]bool{}
		var list []string
		for _, cr := range a.Creds {
			u, _, _ := strings.Cut(cr.Key, " / ")
			u = strings.TrimSuffix(u, " (RDP-Cookie)")
			if safeUser.MatchString(u) && !users[u] && len(list) < 6 {
				users[u] = true
				list = append(list, u)
			}
		}
		t := fmt.Sprintf("%d login attempts", n)
		if len(list) > 0 {
			t += ", usernames: " + strings.Join(list, ", ")
		}
		parts = append(parts, t)
	}
	if a.Counts["prompt"] > 0 {
		parts = append(parts, "shell commands typed at the telnet login prompt")
	}
	var tags []string
	for _, t := range a.Tags {
		if t.Key == "tls_on_plain" || t.Key == "recon" {
			continue
		}
		tags = append(tags, strings.ReplaceAll(t.Key, "_", " "))
	}
	if len(tags) > 0 {
		parts = append(parts, "detected: "+strings.Join(tags, ", "))
	}
	if len(a.CVEs) > 0 {
		var ids []string
		for _, c := range a.CVEs {
			ids = append(ids, c.Key)
		}
		parts = append(parts, "exploit attempt "+strings.Join(ids, ", "))
	}
	if n := a.Counts["command"]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d commands", n))
	}
	if a.Counts["download"] > 0 {
		parts = append(parts, "tried to download malware")
	}
	if len(a.Ports) > 0 && len(a.Ports) <= 8 {
		var ps []string
		for _, p := range a.Ports {
			ps = append(ps, strconv.Itoa(p))
		}
		parts = append(parts, "ports "+strings.Join(ps, ","))
	}
	return scrubComment(strings.Join(parts, "; "), scrub)
}

var (
	ipv4Re = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	ipv6Re = regexp.MustCompile(`(?i)\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b`)
)

// scrubComment entfernt IP-Adressen und die Namen des Honeypots, kürzt auf 1.000 Zeichen.
func scrubComment(s string, names []string) string {
	s = ipv4Re.ReplaceAllString(s, "[ip]")
	s = ipv6Re.ReplaceAllString(s, "[ip]")
	for _, n := range names {
		if len(n) >= 3 {
			s = regexp.MustCompile(`(?i)`+regexp.QuoteMeta(n)).ReplaceAllString(s, "[host]")
		}
	}
	// Deutsche Umlaute der Art-Namen für die englische Plattform umschreiben
	s = strings.NewReplacer("ä", "ae", "ö", "oe", "ü", "ue", "Ä", "Ae", "Ö", "Oe", "Ü", "Ue", "ß", "ss").Replace(s)
	return clip(s, 1000)
}

// ---- Protokoll und Zustand ----

type abuseLogEntry struct {
	Time       time.Time `json:"time"`
	IP         string    `json:"ip"`
	Categories []int     `json:"categories"`
	Comment    string    `json:"comment"`
	Status     string    `json:"status"` // dry | ok | error
	Error      string    `json:"error,omitempty"`
	Score      int       `json:"score,omitempty"`
}

type abuseReporter struct {
	mu         sync.Mutex
	st         *Store
	log        []abuseLogEntry
	limit      int // X-RateLimit-Limit
	remaining  int // X-RateLimit-Remaining (-1 = unbekannt)
	pauseUntil time.Time
	lastErr    string
	lastRun    time.Time
}

const abuseLogMax = 200

func (r *abuseReporter) add(e abuseLogEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log = append([]abuseLogEntry{e}, r.log...)
	if len(r.log) > abuseLogMax {
		r.log = r.log[:abuseLogMax]
	}
	if r.st != nil { // überlebt Neustarts (Tageslimit)
		b, _ := json.Marshal(r.log)
		r.st.SetKV("abuse_report_log", string(b))
	}
}

func (r *abuseReporter) load(st *Store) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.st, r.remaining = st, -1
	if v, ok := st.GetKV("abuse_report_log"); ok {
		json.Unmarshal([]byte(v), &r.log)
	}
}

// sentSince: echte (bzw. im Probemodus angenommene) Meldungen seit t.
func (r *abuseReporter) sentSince(t time.Time, dry bool) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.log {
		if e.Time.After(t) && (e.Status == "ok" || dry && e.Status == "dry") {
			n++
		}
	}
	return n
}

var abuseReportHTTP = &http.Client{Timeout: 20 * time.Second}

// honeypotNames: Hostnamen der Sensoren und des Hive, die nie in Kommentaren stehen dürfen.
func (h *Hive) honeypotNames() []string {
	var out []string
	if rs, err := h.st.db.Query(`SELECT v FROM kv WHERE k = 'sensor_config' OR k LIKE 'sensor_config:%'`); err == nil {
		for rs.Next() {
			var v string
			var c struct {
				Hostname string `json:"hostname"`
			}
			if rs.Scan(&v) == nil && json.Unmarshal([]byte(v), &c) == nil && c.Hostname != "" {
				out = append(out, c.Hostname)
			}
		}
		rs.Close()
	}
	if n, err := os.Hostname(); err == nil {
		out = append(out, n)
	}
	for _, s := range h.sensors.All() {
		out = append(out, s.Sensor)
	}
	return out
}

// abuseRound prüft die Angriffe der letzten 30 Minuten und meldet, was die Regeln erlauben.
func (h *Hive) abuseRound(ctx context.Context) {
	x := h.Extras()
	cfg := x.AbuseReport
	if !cfg.Enabled || x.AbuseIPDBKey == "" {
		return
	}
	r := &h.abuse
	r.mu.Lock()
	paused := time.Now().Before(r.pauseUntil)
	r.lastRun = time.Now()
	r.mu.Unlock()
	if paused {
		return
	}
	untrusted := h.untrustedSensors() // protect.go: gefälschte Ereignisse sollen niemanden melden
	list, _, err := h.loadAttacksSkip(ctx, time.Now().Add(-30*time.Minute), nil, untrusted)
	if err != nil {
		return
	}
	names := h.honeypotNames()
	interval := time.Duration(cfg.IntervalHours) * time.Hour
	source := "abuse_report"
	if cfg.DryRun {
		source = "abuse_report_dry"
	}
	for _, a := range list {
		if r.sentSince(time.Now().Add(-24*time.Hour), cfg.DryRun) >= cfg.DailyLimit {
			return
		}
		cats, why := abuseVerdict(a, cfg)
		if why != "" || !trustedAttack(a, untrusted) || h.neverBlock(a.IP) {
			continue
		}
		if _, _, seen := h.st.lookupGet("ip:"+a.IP, source, interval); seen {
			continue
		}
		e := abuseLogEntry{Time: time.Now(), IP: a.IP, Categories: cats, Comment: abuseComment(a, names)}
		if cfg.DryRun {
			e.Status = "dry"
		} else {
			e.Score, err = h.sendAbuseReport(ctx, x.AbuseIPDBKey, a, e)
			e.Status = "ok"
			if err != nil {
				e.Status, e.Error = "error", err.Error()
			}
		}
		r.add(e)
		if e.Status != "error" {
			h.st.lookupPut("ip:"+a.IP, source, e.Status)
		}
		r.mu.Lock()
		stop := time.Now().Before(r.pauseUntil)
		r.mu.Unlock()
		if stop {
			return
		}
	}
}

func (h *Hive) sendAbuseReport(ctx context.Context, key string, a *Attack, e abuseLogEntry) (int, error) {
	var cats []string
	for _, c := range e.Categories {
		cats = append(cats, strconv.Itoa(c))
	}
	form := url.Values{"ip": {a.IP}, "categories": {strings.Join(cats, ",")}, "comment": {e.Comment},
		"timestamp": {time.UnixMilli(a.First).UTC().Format(time.RFC3339)}}
	req, _ := http.NewRequestWithContext(ctx, "POST", abuseBase+"/api/v2/report", strings.NewReader(form.Encode()))
	req.Header.Set("Key", key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := abuseReportHTTP.Do(req)
	if err != nil {
		h.abuseErr("AbuseIPDB nicht erreichbar")
		return 0, fmt.Errorf("AbuseIPDB nicht erreichbar")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	r := &h.abuse
	r.mu.Lock()
	if v, err := strconv.Atoi(resp.Header.Get("X-RateLimit-Limit")); err == nil {
		r.limit = v
	}
	if v, err := strconv.Atoi(resp.Header.Get("X-RateLimit-Remaining")); err == nil {
		r.remaining = v
	}
	if resp.StatusCode == 429 {
		wait := time.Hour
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			wait = time.Duration(min(s, 86400)) * time.Second
		}
		// "same IP once in 15 minutes" betrifft nur diese IP, nicht alle Meldungen
		if !strings.Contains(string(raw), "once in 15 minutes") {
			r.pauseUntil = time.Now().Add(wait)
		}
	}
	// Schlüssel abgelehnt oder Störung bei AbuseIPDB: nicht jede weitere IP dagegen schicken,
	// sondern warten (sonst füllt ein falscher Schlüssel das Protokoll alle 5 Minuten neu).
	switch {
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		r.pauseUntil = time.Now().Add(time.Hour)
	case resp.StatusCode >= 500:
		r.pauseUntil = time.Now().Add(15 * time.Minute)
	}
	r.mu.Unlock()
	var out struct {
		Data struct {
			Score int `json:"abuseConfidenceScore"`
		} `json:"data"`
		Errors []struct {
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	json.Unmarshal(raw, &out)
	if resp.StatusCode != 200 {
		msg := "AbuseIPDB antwortet " + resp.Status
		if len(out.Errors) > 0 {
			msg += ": " + clip(out.Errors[0].Detail, 200)
		}
		h.abuseErr(msg)
		return 0, fmt.Errorf("%s", msg)
	}
	h.abuseErr("")
	return out.Data.Score, nil
}

func (h *Hive) abuseErr(s string) {
	h.abuse.mu.Lock()
	h.abuse.lastErr = s
	h.abuse.mu.Unlock()
	if s != "" {
		log.Printf("AbuseIPDB-Meldung: %s", s)
	}
}

func (h *Hive) runAbuseReports(stop <-chan struct{}) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		h.abuseRound(ctx)
		cancel()
	}
}

// abuseLog: GET /api/abuse/log – Protokoll, Kontingent, letzter Fehler.
func (h *Hive) abuseLog(w http.ResponseWriter, r *http.Request) {
	a := &h.abuse
	a.mu.Lock()
	defer a.mu.Unlock()
	log := a.log
	if log == nil {
		log = []abuseLogEntry{}
	}
	var pause any
	if time.Now().Before(a.pauseUntil) {
		pause = a.pauseUntil
	}
	var last any
	if !a.lastRun.IsZero() {
		last = a.lastRun
	}
	day := 0
	for _, e := range a.log {
		if e.Time.After(time.Now().Add(-24*time.Hour)) && e.Status == "ok" {
			day++
		}
	}
	writeJSON(w, map[string]any{"log": log, "limit": a.limit, "remaining": a.remaining, "pause_until": pause,
		"last_error": a.lastErr, "last_run": last, "sent_24h": day})
}
