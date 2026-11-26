package main

// Weitergabe an die Sicherheits-Community: Nachlade-Adressen an URLhaus melden, Dateien
// selbst holen (samplecollect.go), bei MalwareBazaar nachschlagen und hochladen, Daten an
// DShield (SANS ISC) senden (dshield.go). Alles ist standardmäßig aus.
//
// URLhaus (Stand der API-Dokumentation urlhaus.abuse.ch/api, November 2026):
//   POST https://urlhaus.abuse.ch/api/ mit JSON {"Auth-Key","anonymous":"0","submission":
//   [{"url","threat","tags"}]} und zusätzlich Kopf "Auth-Key" (derselbe abuse.ch-Schlüssel wie
//   für die Abfragen; die Doku nennt ein Feld, das Beispielskript den Kopf).
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
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
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
	UserID   int64  `json:"user_id"` // numerische ISC-Benutzer-ID, nicht der Anmeldename (heute 10 Stellen, z. B. 3000012345)
	Email    string `json:"email"`   // Anmeldung bei isc.sans.edu; nur für "Zugang prüfen"
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
	// Eingefügte Schlüssel tragen oft Leerzeichen oder Zeilenumbrüche am Rand
	d.APIKey, d.Email = strings.TrimSpace(d.APIKey), strings.TrimSpace(d.Email)
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
	case d.UserID < 0 || d.UserID > 999999999999:
		return fmt.Errorf("DShield: Benutzer-ID ist eine Zahl (isc.sans.edu → My Account), nicht der Anmeldename")
	case d.Enabled && (d.UserID == 0 || d.APIKey == ""):
		return fmt.Errorf("DShield braucht die ISC-Benutzer-ID (Zahl) und den API-Schlüssel. „Zugang prüfen“ ermittelt die ID aus E-Mail-Adresse und Schlüssel")
	case d.APIKey != "" && !dshieldKeyRe.MatchString(d.APIKey):
		return fmt.Errorf("DShield: API-Schlüssel enthält unerlaubte Zeichen (erlaubt: Buchstaben, Ziffern, + / =)")
	case len(d.Email) > 200 || d.Email != "" && !strings.Contains(d.Email, "@"):
		return fmt.Errorf("DShield: E-Mail-Adresse ungültig")
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
	// Sent: was den Hive verließ, wörtlich (ohne Schlüssel), für das Prüfprotokoll im Tab
	// „Funde“ (funde.go). Neu seit 0.9.5; ältere Einträge haben es nicht.
	Sent string `json:"sent,omitempty"`
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
	skips   []sampleSkip            // zuletzt nicht geholte Adressen mit Grund (nur im Speicher)
	later   bool                    // in dieser Runde aufgeschoben: Suchfenster nicht vorrücken
	waits   map[string][]reportWait // wartet auf die Verzögerung (delay.go)
}

// sampleSkip: eine Nachlade-Adresse, die der Hive nicht geholt hat, und warum.
type sampleSkip struct {
	Time   time.Time `json:"time"`
	URL    string    `json:"url"`
	Reason string    `json:"reason"`
}

const sampleSkipMax = 30

// skipLater: wie skip, die Adresse kommt aber in einer späteren Runde wieder dran.
func (s *shareState) skipLater(u, reason string) {
	s.mu.Lock()
	s.later = true
	s.mu.Unlock()
	s.skip(u, reason)
}

// skip merkt sich den Grund (je Adresse nur der jüngste Eintrag).
func (s *shareState) skip(u, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u = clip(u, 300)
	out := []sampleSkip{{Time: time.Now(), URL: u, Reason: reason}}
	for _, k := range s.skips {
		if k.URL != u && len(out) < sampleSkipMax {
			out = append(out, k)
		}
	}
	s.skips = out
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
	e.Subject, e.Detail, e.Error, e.Sent = clip(e.Subject, 300), clip(e.Detail, 300), clip(e.Error, 300), clip(e.Sent, 1500)
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

// pausedUntil: Ende der Pause eines Kanals (Nullzeit, wenn er nicht pausiert).
func (s *shareState) pausedUntil(kind string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.channel(kind); time.Now().Before(c.PauseUntil) {
		return c.PauseUntil
	}
	return time.Time{}
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

// ownPublicIP: aktuelle eigene öffentliche Adresse (ownip.go), sonst die zuletzt bei Shodan
// abgefragte (System → "Wie Shodan dich sieht"); leer, wenn unbekannt.
func (h *Hive) ownPublicIP() string {
	if l := h.knownOwnIPs(); len(l) > 0 {
		return l[0]
	}
	return ""
}

// ownMarkers: Zeichenfolgen, die nie nach außen gehen: die eigene öffentliche Adresse und die
// Hostnamen der Honeypots und des Hive (klein geschrieben, mindestens 4 Zeichen).
func (h *Hive) ownMarkers() []string {
	var out []string
	for _, s := range append(h.honeypotNames(), h.knownOwnIPs()...) {
		if s = strings.ToLower(strings.TrimSpace(s)); len(s) >= 4 && !contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// containsMarker: Kommt eine der Marken (ownMarkers) in s vor (ohne Groß/Klein)?
func containsMarker(s string, marks []string) bool {
	ls := strings.ToLower(s)
	for _, m := range marks {
		if strings.Contains(ls, m) {
			return true
		}
	}
	return false
}

func urlSubject(u string) string {
	sum := sha256.Sum256([]byte(u))
	return "url:" + hex.EncodeToString(sum[:])
}

// ---- Funde: Nachlade-Adressen aus Befehlen und Downloads ----

type urlFinding struct {
	URL     string
	Service string
	Last    time.Time // zuletzt benutzt (Verzögerung der Meldung, delay.go)
}

// urlSighting: eine Nachlade-Adresse in einem Befehl oder Download (scanURLs).
type urlSighting struct {
	TS      time.Time
	IP      string
	Service string
	Session string
	Kind    string // command | download
	Raw     string // wie gesehen ("(ausgeblendet)", wenn sie eigene Marken enthält)
	URL     string // bereinigt; leer, wenn nicht zulässig
	Why     string // Grund, warum sie nicht geholt und nicht gemeldet wird; leer = zulässig
	SHA256  string // nur Downloads von Cowrie
}

// urlRules: Regeln, nach denen Nachlade-Adressen geholt und gemeldet werden dürfen
// (Stand der Einstellungen beim Aufruf). Gemeinsam für scanURLs und den Tab „Funde“.
type urlRules struct {
	untrusted map[string]bool
	own       string
	marks     []string
}

func (h *Hive) urlRules() urlRules {
	return urlRules{untrusted: h.untrustedSensors(), own: h.ownPublicIP(), marks: h.ownMarkers()}
}

// source: Eigene Tests, nicht vertrauenswürdige Sensoren und Forschungsscanner liefern keine
// Funde; leer, wenn der Absender zählt.
func (r urlRules) source(ip, sensor, asOrg string) string {
	switch {
	case isOwnIP(ip) || ip == r.own:
		return "stammt von einer eigenen Adresse (Test)"
	case r.untrusted[sensor]:
		return "stammt von einem nicht vertrauenswürdigen Sensor"
	case researchScanner(asOrg) != "":
		return "stammt von einem Forschungsscanner"
	}
	return ""
}

// check: bereinigte Adresse, angezeigte Form und Grund dagegen (leer = zulässig).
func (r urlRules) check(raw string) (u, shown, why string) {
	u, why = shareURLProblem(strings.ReplaceAll(raw, `\`, ""), r.own)
	switch {
	case why != "":
		return "", raw, "Adresse nicht zulässig: " + why
	// Eigene Adresse oder Name des Honeypots irgendwo in der Adresse (Pfad, Parameter):
	// nie öffentlich melden und nicht holen.
	case containsMarker(u, r.marks):
		return "", "(ausgeblendet)", "enthält die eigene Adresse oder den Namen des Honeypots"
	}
	return u, raw, ""
}

// eventURLs: Nachlade-Adressen eines Befehls oder Downloads.
func eventURLs(e *Event) []string {
	if e.Type == "download" {
		// Hochgeladene Dateien (SFTP/scp, data.upload) haben keine Adresse: nichts zu holen
		if u := dataString(e.Data, "url"); u != "" {
			return []string{u}
		}
		return nil
	}
	if text, on := eventText(e); on == "cmd" {
		return analyzeText(text, on).urls
	}
	return nil
}

// scanURLs ruft fn für jede Nachlade-Adresse in Befehlen und Downloads seit since auf, in
// zeitlicher Reihenfolge, höchstens aus limit Ereignissen. Grundlage für die Weitergabe
// (urlFindings); der Tab „Funde“ nutzt dieselben Regeln über einen Zwischenspeicher (funde_cache.go).
func (h *Hive) scanURLs(ctx context.Context, since time.Time, limit int, fn func(urlSighting)) error {
	rs, err := h.st.db.QueryContext(ctx, `SELECT ts, sensor, service, type, src_ip, session, data, as_org FROM events
		WHERE ts >= ? AND type IN ('command','download') ORDER BY id LIMIT ?`, since.UnixMilli(), limit)
	if err != nil {
		return err
	}
	defer rs.Close()
	rules := h.urlRules()
	for rs.Next() {
		var e Event
		var data []byte
		var asOrg, session sql.NullString
		var ts int64
		if rs.Scan(&ts, &e.Sensor, &e.Service, &e.Type, &e.SrcIP, &session, &data, &asOrg) != nil {
			continue
		}
		e.Data = data
		from := rules.source(e.SrcIP, e.Sensor, asOrg.String)
		for _, raw := range eventURLs(&e) {
			s := urlSighting{TS: time.UnixMilli(ts), IP: e.SrcIP, Service: e.Service, Session: session.String, Kind: e.Type, Raw: raw}
			if e.Type == "download" {
				s.SHA256 = strings.ToLower(dataString(e.Data, "sha256"))
			}
			if from != "" {
				s.Why = from
			} else {
				s.URL, s.Raw, s.Why = rules.check(raw)
			}
			fn(s)
		}
	}
	return rs.Err()
}

// urlFindings: zulässige Nachlade-Adressen seit since, je Adresse einmal. skip (darf nil sein)
// erfährt verworfene Adressen mit Grund.
func (h *Hive) urlFindings(ctx context.Context, since time.Time, skip func(u, why string)) ([]urlFinding, error) {
	if skip == nil {
		skip = func(string, string) {}
	}
	seen := map[string]int{} // Adresse -> Index in out
	var out []urlFinding
	err := h.scanURLs(ctx, since, 20000, func(s urlSighting) {
		if s.Why != "" {
			skip(s.Raw, s.Why)
			return
		}
		if i, ok := seen[s.URL]; ok {
			out[i].Last = s.TS // jüngste Benutzung
			return
		}
		seen[s.URL] = len(out)
		out = append(out, urlFinding{URL: s.URL, Service: s.Service, Last: s.TS})
	})
	return out, err
}

// ---- Ablauf ----

// shareSince: ab wann eine Runde nach Nachlade-Adressen sucht. Bis 0.8.0 waren es feste
// 30 Minuten: Adressen von vor dem Einschalten, aus einem Neustart oder Update oder einer
// abgebrochenen Runde wurden nie geholt (Live-Check). Jetzt: ab der letzten vollständigen
// Runde (5 Minuten Überlappung), beim ersten Mal die letzten 24 Stunden, höchstens 48 Stunden.
func (h *Hive) shareSince(now time.Time) time.Time {
	since := now.Add(-24 * time.Hour)
	if v, ok := h.st.GetKV("share_since"); ok {
		if ms, err := strconv.ParseInt(v, 10, 64); err == nil && ms > 0 && ms <= now.UnixMilli() {
			since = time.UnixMilli(ms).Add(-5 * time.Minute)
		}
	}
	if oldest := now.Add(-48 * time.Hour); since.Before(oldest) {
		since = oldest
	}
	return since
}

func (h *Hive) runSharing(stop <-chan struct{}) {
	if !waitStartupQuiet(stop, 2*time.Hour) { // erst nach der Neuzählung (setup.go)
		return
	}
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	warm, cancelWarm := context.WithTimeout(context.Background(), 4*time.Minute)
	h.warmFunde(warm) // Tab „Funde“ (funde_cache.go)
	cancelWarm()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		h.shareRound(ctx)
		h.dshieldRound(ctx)
		h.warmFunde(ctx)
		cancel()
	}
}

func (h *Hive) shareRound(ctx context.Context) {
	x := h.Extras()
	uh := x.URLhausReport.Enabled && x.AbuseChKey != ""
	if x.Samples.Enabled || uh {
		start := time.Now()
		// URLhaus meldet erst nach der Verzögerung (delay.go): so weit zurück suchen
		since := h.shareSince(start).Add(-x.reportDelay())
		var skip func(u, why string)
		if x.Samples.Enabled {
			skip = h.share.skip
		}
		finds, err := h.urlFindings(ctx, since, skip)
		if err == nil {
			done := true
			h.share.mu.Lock()
			h.share.later = false
			h.share.mu.Unlock()
			if x.Samples.Enabled && h.share.begin("sample") {
				for _, f := range finds {
					if ctx.Err() != nil || !h.collectSample(ctx, x, f) {
						done = false
						break
					}
				}
			}
			// Erst wenn alles abgearbeitet ist, rückt das Fenster vor; sonst kommen die übrigen
			// Adressen in der nächsten Runde dran (geholte und versuchte merkt sich lookups).
			h.share.mu.Lock()
			done = done && !h.share.later
			h.share.mu.Unlock()
			if done && ctx.Err() == nil {
				h.st.SetKV("share_since", strconv.FormatInt(start.UnixMilli(), 10))
			}
			if uh && h.share.begin("urlhaus") {
				h.urlhausSubmit(ctx, x, finds)
			}
		}
	}
	if x.AbuseChKey != "" && (x.Bazaar.Lookup || x.Bazaar.Upload) {
		h.bazaarDue(ctx, x) // geholte Dateien nach der Wartezeit melden (delay.go)
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
	var waits []reportWait
	defer func() { h.share.setWaits("urlhaus", waits) }()
	delay := x.reportDelay()
	for _, f := range finds {
		if sent+len(batch) >= cfg.DailyLimit || len(batch) >= 20 {
			break
		}
		subj := urlSubject(f.URL)
		if _, _, done := h.st.lookupGet(subj, source, 0); done {
			continue
		}
		// Erst prüfen, ob die Adresse überhaupt gemeldet würde; sonst stand sie als „wartet“ da und
		// fiel nach der Wartezeit still heraus (Live-Check 0.9.6).
		fetched, fr := false, sampleFetchResult{}
		if v, _, ok := h.st.lookupGet(subj, "sample_fetch", 24*time.Hour); ok {
			json.Unmarshal([]byte(v), &fr)
			fetched = true
		}
		// Audit 4: Geholt allein heißt nicht Schadsoftware. Vorher genügte jede Antwort ohne
		// HTML (JSON, PDF, die eigene Docker-API über den Router), und die Adresse eines Dritten
		// stand bei URLhaus als malware_download.
		if cfg.VerifiedOnly && (!fetched || fr.Status != "ok" || !fr.Malware) {
			continue
		}
		if until := f.Last.Add(delay); time.Now().Before(until) {
			waits = append(waits, reportWait{Subject: f.URL, Until: until, Detail: waitText(until)})
			continue
		}
		tags := []string{"honeypot"}
		if svc := cleanTag(f.Service); svc != "" {
			tags = append(tags, svc)
		}
		if fetched && fr.FileTag != "" {
			tags = append(tags, fr.FileTag)
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
			one, _ := json.MarshalIndent(map[string]any{"anonymous": "0", "submission": []item{it}}, "", "  ")
			e := shareLogEntry{Time: time.Now(), Status: status, Subject: it.URL, Detail: detail, Error: errText,
				Sent: "POST " + urlhausSubmitURL + " (Auth-Key: •••)\n" + string(one)}
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
	// Die API-Seite verlangt den Schlüssel als Feld "Auth-Key" in der Anfrage, das Beispielskript
	// von abuse.ch schickt ihn als Kopf. Bis 0.9.4 ging er nur im Kopf, und URLhaus antwortete
	// "User unknown" trotz angemeldetem Konto. Jetzt an beiden Stellen (dasselbe Ziel).
	body, _ := json.Marshal(map[string]any{"Auth-Key": x.AbuseChKey, "anonymous": "0", "submission": batch})
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
	// URLhaus meldet Kontoprobleme mit Status 200 und Klartext. Bis 0.9.4 stand das als
	// "gesendet" im Protokoll, und die Adressen galten als gemeldet.
	if msg := urlhausRefusal(answer); msg != "" {
		if strings.Contains(strings.ToLower(answer), "user unknown") {
			msg += urlhausKeyCheck(ctx, x.AbuseChKey)
		}
		h.share.setErr("urlhaus", msg, time.Hour)
		logAll("error", "", msg)
		return
	}
	h.share.setErr("urlhaus", "", 0)
	logAll("ok", clip(answer, 200), "")
}

// urlhausRefusal: verständliche Meldung, wenn URLhaus die Einreichung trotz Status 200
// ablehnt; leer, wenn die Antwort nach Erfolg aussieht.
//
// "User unknown, please visit https://urlhaus.abuse.ch/ and try again": URLhaus ordnet die
// Einreichung keinem Konto zu. Bis 0.9.4 ging der Schlüssel nur im Kopf mit; die Doku
// verlangt ihn als Feld der Anfrage (jetzt beides). urlhausKeyCheck sagt dazu, ob der
// Schlüssel für Abfragen gilt.
func urlhausRefusal(answer string) string {
	a := strings.ToLower(answer)
	switch {
	case strings.Contains(a, "user unknown"):
		return "URLhaus ordnet die Meldung keinem Konto zu (Antwort: " + clip(answer, 120) + ")."
	case strings.Contains(a, "unknown_auth_key"), strings.Contains(a, "invalid_auth_key"), strings.Contains(a, "missing_auth_key"), strings.Contains(a, "no_api_key"):
		return "URLhaus lehnt den abuse.ch-Schlüssel ab. Schlüssel unter https://auth.abuse.ch/ prüfen und neu eintragen (Antwort: " + clip(answer, 120) + ")"
	case strings.Contains(a, "blacklist"), strings.Contains(a, "banned"), strings.Contains(a, "blocked"):
		return "URLhaus hat das Konto gesperrt (Antwort: " + clip(answer, 120) + ")"
	case strings.Contains(a, "error"), strings.Contains(a, "invalid"), strings.Contains(a, "expected"):
		return "URLhaus lehnt die Meldung ab: " + clip(answer, 150)
	}
	return ""
}

var urlhausQueryURL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1/"

// urlhausKeyCheck: Gilt der Schlüssel für Abfragen? Ergänzt die Meldung zu "User unknown".
func urlhausKeyCheck(ctx context.Context, key string) string {
	req, _ := http.NewRequestWithContext(ctx, "GET", urlhausQueryURL, nil)
	req.Header.Set("Auth-Key", key)
	resp, err := shareHTTP.Do(req)
	if err != nil {
		return " Ob der Schlüssel für Abfragen gilt, ließ sich nicht prüfen (urlhaus-api.abuse.ch nicht erreichbar)."
	}
	defer resp.Body.Close()
	var out struct {
		Status string `json:"query_status"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out)
	if resp.StatusCode == 200 && out.Status == "ok" {
		return " Der Schlüssel selbst ist gültig (Abfragen bei URLhaus gehen); abgelehnt wird nur das Einreichen. Prüfe unter https://urlhaus.abuse.ch/ (angemeldet, Profil), ob dasselbe Konto dort Meldungen abgeben darf, sonst bitte das Protokoll an abuse.ch melden."
	}
	return " Auch Abfragen mit diesem Schlüssel lehnt URLhaus ab (" + resp.Status + "): Schlüssel unter https://auth.abuse.ch/ neu erzeugen und eintragen."
}

// shareHTTP: Verbindungen zu den Diensten selbst (URLhaus, MalwareBazaar, DShield).
var shareHTTP = &http.Client{Timeout: 60 * time.Second, CheckRedirect: keyRedirect}

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
		if k == "sample" {
			sk := append([]sampleSkip{}, h.share.skips...)
			m["skipped"] = sk
		}
		var waiting []reportWait
		for _, w := range h.share.waits[k] {
			if time.Now().Before(w.Until) {
				waiting = append(waiting, w)
			}
		}
		if waiting == nil {
			waiting = []reportWait{}
		}
		m["waiting"] = waiting
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
	out["report_delay_min"] = x.ReportDelayMin
	writeJSON(w, out)
}
