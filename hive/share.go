package main

// Weitergabe an die Sicherheits-Community: Nachlade-Adressen an URLhaus melden, Dateien
// selbst holen (samplecollect.go), bei MalwareBazaar nachschlagen und hochladen, Daten an
// DShield (SANS ISC) senden (dshield.go). Alles ist standardmäßig aus.
//
// URLhaus (Stand der API-Dokumentation urlhaus.abuse.ch/api, November 2026):
//   POST https://urlhaus.abuse.ch/api/ mit Kopf "Auth-Key" (derselbe abuse.ch-Schlüssel wie
//   für die Abfragen) und JSON {"anonymous":"0","submission":[{"url","threat","tags"}]}.
//   threat ist immer "malware_download"; Tags nur aus [A-Za-z0-9.- ].
//   Regeln von URLhaus: nur Adressen, die gerade Schadsoftware ausliefern (online, HTTP 200),
//   keine privaten oder besonderen IP-Adressen, keine Kurz-URLs, kein Phishing, keine Adware.
//   Verstöße können zur Sperre des Kontos führen. Deshalb meldet Hivornet standardmäßig nur
//   Adressen, deren Datei der Hive selbst geholt hat ("nur bestätigte").
//
// Gemeldet werden nur Adressen aus ausgeführten Befehlen (wget, curl, tftp …, auch
// entschlüsselt) und aus Download-Ereignissen; nie Pfade von Web-Anfragen, nie eigene oder
// private Adressen, nie Rückruf-Adressen von Scannern (safefetch.go), nie Funde von
// Forschungsscannern, eigenen Tests oder nicht vertrauenswürdigen Sensoren.
//
// Der Hive prüft alle 5 Minuten die Ereignisse der letzten 30 Minuten.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type URLhausReportConfig struct {
	Enabled      bool `json:"enabled"`
	DryRun       bool `json:"dry_run"`
	DailyLimit   int  `json:"daily_limit"`
	VerifiedOnly bool `json:"verified_only"` // nur Adressen, deren Datei der Hive geholt hat
}

type SampleCollectConfig struct {
	Enabled      bool   `json:"enabled"`
	DailyLimit   int    `json:"daily_limit"`    // Downloads je 24 h
	PerHostDaily int    `json:"per_host_daily"` // Downloads je Host und 24 h
	MaxMB        int    `json:"max_mb"`         // je Datei
	KeepDays     int    `json:"keep_days"`
	MaxTotalMB   int    `json:"max_total_mb"` // Quarantäne insgesamt
	UserAgent    string `json:"user_agent"`
}

type BazaarConfig struct {
	Lookup bool `json:"lookup"` // Hash geholter Dateien nachschlagen
	Upload bool `json:"upload"` // unbekannte Schadprogramme hochladen
	DryRun bool `json:"dry_run"`
}

type DShieldConfig struct {
	Enabled  bool   `json:"enabled"`
	DryRun   bool   `json:"dry_run"`
	UserID   int    `json:"user_id"`
	APIKey   string `json:"api_key"`
	Firewall bool   `json:"firewall"` // Verbindungsversuche
	Web      bool   `json:"web"`      // Web-Anfragen
	Logins   bool   `json:"logins"`   // SSH- und Telnet-Anmeldungen
}

func defaultShare(x *Extras) {
	x.URLhausReport = URLhausReportConfig{DryRun: true, DailyLimit: 30, VerifiedOnly: true}
	x.Samples = SampleCollectConfig{DailyLimit: 20, PerHostDaily: 3, MaxMB: 10, KeepDays: 14, MaxTotalMB: 500, UserAgent: "Wget/1.21.4"}
	x.Bazaar = BazaarConfig{Lookup: true, DryRun: true}
	x.DShield = DShieldConfig{DryRun: true, Firewall: true, Web: true, Logins: true}
}

var userAgentRe = regexp.MustCompile(`^[\x20-\x7e]{1,120}$`)

func (x *Extras) validateShare() error {
	u, s, d := &x.URLhausReport, &x.Samples, &x.DShield
	switch {
	case u.DailyLimit < 1 || u.DailyLimit > 150:
		return fmt.Errorf("URLhaus: Meldungen pro Tag 1 bis 150")
	case s.DailyLimit < 1 || s.DailyLimit > 100:
		return fmt.Errorf("Dateien sammeln: Downloads pro Tag 1 bis 100")
	case s.PerHostDaily < 1 || s.PerHostDaily > 20:
		return fmt.Errorf("Dateien sammeln: je Server und Tag 1 bis 20")
	case s.MaxMB < 1 || s.MaxMB > 32:
		return fmt.Errorf("Dateien sammeln: Größe je Datei 1 bis 32 MB")
	case s.KeepDays < 1 || s.KeepDays > 365:
		return fmt.Errorf("Dateien sammeln: Aufbewahrung 1 bis 365 Tage")
	case s.MaxTotalMB < 10 || s.MaxTotalMB > 10000:
		return fmt.Errorf("Dateien sammeln: Platz insgesamt 10 bis 10000 MB")
	case !userAgentRe.MatchString(s.UserAgent):
		return fmt.Errorf("Dateien sammeln: User-Agent 1 bis 120 druckbare Zeichen")
	case d.UserID < 0 || d.UserID > 999999999:
		return fmt.Errorf("DShield: Benutzernummer ungültig")
	case d.Enabled && (d.UserID == 0 || d.APIKey == ""):
		return fmt.Errorf("DShield braucht Benutzernummer und API-Schlüssel")
	case d.APIKey != "" && !dshieldKeyRe.MatchString(d.APIKey):
		return fmt.Errorf("DShield: API-Schlüssel enthält unerlaubte Zeichen")
	}
	return nil
}

// ---- Protokoll und Zustand ----

type shareLogEntry struct {
	Time    time.Time `json:"time"`
	Status  string    `json:"status"`  // ok | dry | error | known | skipped
	Subject string    `json:"subject"` // Adresse, Hash oder Zusammenfassung
	Host    string    `json:"host,omitempty"`
	SHA256  string    `json:"sha256,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	Error   string    `json:"error,omitempty"`
}

type shareChannel struct {
	Log        []shareLogEntry `json:"log"`
	LastErr    string          `json:"last_error"`
	PauseUntil time.Time       `json:"pause_until"`
	LastRun    time.Time       `json:"last_run"`
}

const shareLogMax = 300

var shareKinds = []string{"urlhaus", "sample", "bazaar", "dshield"}

type shareState struct {
	mu      sync.Mutex
	st      *Store
	ch      map[string]*shareChannel
	dir     string // Quarantäne; leer = neben der Datenbank
	cleaned time.Time
}

func (s *shareState) load(st *Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st = st
	s.ch = map[string]*shareChannel{}
	for _, k := range shareKinds {
		c := &shareChannel{}
		if v, ok := st.GetKV("share_log_" + k); ok {
			json.Unmarshal([]byte(v), &c.Log)
		}
		s.ch[k] = c
	}
}

func (s *shareState) channel(kind string) *shareChannel {
	if s.ch == nil {
		s.ch = map[string]*shareChannel{}
	}
	c := s.ch[kind]
	if c == nil {
		c = &shareChannel{}
		s.ch[kind] = c
	}
	return c
}

func (s *shareState) add(kind string, e shareLogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.channel(kind)
	e.Subject, e.Detail, e.Error = clip(e.Subject, 300), clip(e.Detail, 300), clip(e.Error, 300)
	c.Log = append([]shareLogEntry{e}, c.Log...)
	if len(c.Log) > shareLogMax {
		c.Log = c.Log[:shareLogMax]
	}
	if s.st != nil {
		b, _ := json.Marshal(c.Log)
		s.st.SetKV("share_log_"+kind, string(b))
	}
}

// count: Einträge seit t, die match erfüllen.
func (s *shareState) count(kind string, t time.Time, match func(shareLogEntry) bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.channel(kind).Log {
		if e.Time.After(t) && match(e) {
			n++
		}
	}
	return n
}

func (s *shareState) setErr(kind, msg string, pause time.Duration) {
	s.mu.Lock()
	c := s.channel(kind)
	c.LastErr = msg
	if pause > 0 {
		c.PauseUntil = time.Now().Add(pause)
	}
	s.mu.Unlock()
	if msg != "" {
		log.Printf("Weitergabe (%s): %s", kind, msg)
	}
}

// begin markiert einen Lauf; false, wenn der Kanal pausiert.
func (s *shareState) begin(kind string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.channel(kind)
	c.LastRun = time.Now()
	return !time.Now().Before(c.PauseUntil)
}

// pauseFor: Wartezeit nach einer Antwort (Schlüssel abgelehnt, Kontingent, Störung).
func pauseFor(code int) time.Duration {
	switch {
	case code == 401 || code == 403 || code == 429:
		return time.Hour
	case code >= 500:
		return 15 * time.Minute
	}
	return 0
}

// ownPublicIP: zuletzt ermittelte öffentliche Adresse (System → "Wie Shodan dich sieht").
func (h *Hive) ownPublicIP() string {
	data, _, ok := h.st.lookupGet("self", "internetdb", 0)
	if !ok {
		return ""
	}
	var e Exposure
	json.Unmarshal([]byte(data), &e)
	return e.IP
}

func urlSubject(u string) string {
	sum := sha256.Sum256([]byte(u))
	return "url:" + hex.EncodeToString(sum[:])
}

// ---- Funde: Nachlade-Adressen aus Befehlen und Downloads ----

type urlFinding struct {
	URL     string
	Service string
}

// urlFindings: zulässige Nachlade-Adressen seit since, je Adresse einmal.
func (h *Hive) urlFindings(ctx context.Context, since time.Time) ([]urlFinding, error) {
	rs, err := h.st.db.QueryContext(ctx, `SELECT sensor, service, type, src_ip, data, as_org FROM events
		WHERE ts >= ? AND type IN ('command','download') ORDER BY id LIMIT 20000`, since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	untrusted := h.untrustedSensors()
	own := h.ownPublicIP()
	seen := map[string]bool{}
	var out []urlFinding
	for rs.Next() {
		var e Event
		var data []byte
		var asOrg string
		if rs.Scan(&e.Sensor, &e.Service, &e.Type, &e.SrcIP, &data, &asOrg) != nil {
			continue
		}
		e.Data = data
		// Eigene Tests, nicht vertrauenswürdige Sensoren und Forschungsscanner liefern keine Funde
		if isOwnIP(e.SrcIP) || e.SrcIP == own || untrusted[e.Sensor] || researchScanner(asOrg) != "" {
			continue
		}
		var urls []string
		if e.Type == "download" {
			urls = []string{dataString(e.Data, "url")}
		} else if text, on := eventText(&e); on == "cmd" {
			urls = analyzeText(text, on).urls
		}
		for _, raw := range urls {
			u, why := shareURLProblem(strings.ReplaceAll(raw, `\`, ""), own)
			if why != "" || seen[u] {
				continue
			}
			seen[u] = true
			out = append(out, urlFinding{URL: u, Service: e.Service})
		}
	}
	return out, rs.Err()
}

// ---- Ablauf ----

func (h *Hive) runSharing(stop <-chan struct{}) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		h.shareRound(ctx)
		h.dshieldRound(ctx)
		cancel()
	}
}

func (h *Hive) shareRound(ctx context.Context) {
	x := h.Extras()
	uh := x.URLhausReport.Enabled && x.AbuseChKey != ""
	if x.Samples.Enabled || uh {
		finds, err := h.urlFindings(ctx, time.Now().Add(-30*time.Minute))
		if err == nil {
			if x.Samples.Enabled && h.share.begin("sample") {
				for _, f := range finds {
					if ctx.Err() != nil || !h.collectSample(ctx, x, f) {
						break
					}
				}
			}
			if uh && h.share.begin("urlhaus") {
				h.urlhausSubmit(ctx, x, finds)
			}
		}
	}
	h.cleanupQuarantine(x.Samples, false)
}

// ---- URLhaus ----

var urlhausSubmitURL = "https://urlhaus.abuse.ch/api/"

var tagCleanRe = regexp.MustCompile(`[^A-Za-z0-9. -]`)

func cleanTag(s string) string { return clip(tagCleanRe.ReplaceAllString(s, ""), 40) }

func (h *Hive) urlhausSubmit(ctx context.Context, x Extras, finds []urlFinding) {
	cfg := x.URLhausReport
	source := "urlhaus_report"
	if cfg.DryRun {
		source = "urlhaus_report_dry"
	}
	sent := h.share.count("urlhaus", time.Now().Add(-24*time.Hour), func(e shareLogEntry) bool {
		return e.Status == "ok" || cfg.DryRun && e.Status == "dry"
	})
	type item struct {
		URL    string   `json:"url"`
		Threat string   `json:"threat"`
		Tags   []string `json:"tags"`
	}
	var batch []item
	var subjects []string
	for _, f := range finds {
		if sent+len(batch) >= cfg.DailyLimit || len(batch) >= 20 {
			break
		}
		subj := urlSubject(f.URL)
		if _, _, done := h.st.lookupGet(subj, source, 0); done {
			continue
		}
		tags := []string{"honeypot"}
		if svc := cleanTag(f.Service); svc != "" {
			tags = append(tags, svc)
		}
		if v, _, ok := h.st.lookupGet(subj, "sample_fetch", 24*time.Hour); ok {
			var r sampleFetchResult
			json.Unmarshal([]byte(v), &r)
			if r.Status != "ok" && cfg.VerifiedOnly {
				continue
			}
			if r.FileTag != "" {
				tags = append(tags, r.FileTag)
			}
		} else if cfg.VerifiedOnly {
			continue
		}
		batch = append(batch, item{URL: f.URL, Threat: "malware_download", Tags: tags})
		subjects = append(subjects, subj)
	}
	if len(batch) == 0 {
		return
	}
	logAll := func(status, detail, errText string) {
		for i, it := range batch {
			u, _ := url.Parse(it.URL)
			e := shareLogEntry{Time: time.Now(), Status: status, Subject: it.URL, Detail: detail, Error: errText}
			if u != nil {
				e.Host = u.Hostname()
			}
			h.share.add("urlhaus", e)
			if status != "error" {
				h.st.lookupPut(subjects[i], source, status)
			}
		}
	}
	if cfg.DryRun {
		logAll("dry", "Tags: "+strings.Join(batch[0].Tags, ", "), "")
		return
	}
	body, _ := json.Marshal(map[string]any{"anonymous": "0", "submission": batch})
	req, _ := http.NewRequestWithContext(ctx, "POST", urlhausSubmitURL, bytes.NewReader(body))
	req.Header.Set("Auth-Key", x.AbuseChKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := shareHTTP.Do(req)
	if err != nil {
		h.share.setErr("urlhaus", "URLhaus nicht erreichbar", 0)
		logAll("error", "", "URLhaus nicht erreichbar")
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	answer := strings.Join(strings.Fields(strings.ToValidUTF8(string(raw), "?")), " ")
	if resp.StatusCode != 200 {
		msg := "URLhaus antwortet " + resp.Status
		h.share.setErr("urlhaus", msg, pauseFor(resp.StatusCode))
		logAll("error", "", msg+" "+clip(answer, 150))
		return
	}
	h.share.setErr("urlhaus", "", 0)
	logAll("ok", clip(answer, 200), "")
}

// shareHTTP: Verbindungen zu den Diensten selbst (URLhaus, MalwareBazaar, DShield).
var shareHTTP = &http.Client{Timeout: 60 * time.Second}

// ---- Stand für die Einstellungen ----

// shareStatus: GET /api/share/status – Protokolle, Fehler, Quarantäne.
func (h *Hive) shareStatus(w http.ResponseWriter, r *http.Request) {
	x := h.Extras()
	out := map[string]any{}
	h.share.mu.Lock()
	for _, k := range shareKinds {
		c := h.share.channel(k)
		lg := c.Log
		if len(lg) > 100 {
			lg = lg[:100]
		}
		if lg == nil {
			lg = []shareLogEntry{}
		}
		day := 0
		for _, e := range c.Log {
			if e.Time.After(time.Now().Add(-24*time.Hour)) && (e.Status == "ok" || e.Status == "known") {
				day++
			}
		}
		m := map[string]any{"log": lg, "last_error": c.LastErr, "ok_24h": day}
		if time.Now().Before(c.PauseUntil) {
			m["pause_until"] = c.PauseUntil
		}
		if !c.LastRun.IsZero() {
			m["last_run"] = c.LastRun
		}
		out[k] = m
	}
	h.share.mu.Unlock()
	files, total := h.quarantineList()
	out["quarantine"] = map[string]any{"files": files, "bytes": total, "max_bytes": int64(x.Samples.MaxTotalMB) << 20}
	out["own_ip_known"] = h.ownPublicIP() != ""
	out["abusech_key"] = x.AbuseChKey != ""
	writeJSON(w, out)
}
