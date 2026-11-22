package main

// Tab „Funde“: alles, was Angreifer nachladen wollten, was der Hive davon geholt hat und was
// an wen gemeldet wurde oder würde.
//
//   GET /api/funde?range=7d          Trichter, Stand je Anbieter, Fundbuch (Dateien,
//                                    Nachlade-Adressen, Angreifer, Infrastruktur, KI-Antworten,
//                                    nicht geholt)
//   GET /api/funde/file?sha=<sha256> Fallakte einer Datei: Inhalt, Nachlade-Stufen,
//                                    eingebettete Ziele, Verknüpfungen, Prüfprotokoll mit dem
//                                    gesendeten Wortlaut, externe Daten, KI-Antworten
//
// Nur Lesen. Dateien selbst gibt die Web-UI nie heraus; bei Skripten und Text erscheint der
// Inhalt als Text (höchstens 64 KB, Steuerzeichen ersetzt), wie Befehle in den Angriffen.
// Die Adressen folgen denselben Regeln wie die Weitergabe (scanURLs in share.go).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	fundeMaxRange   = 30 * 24 * time.Hour
	fundeMaxFiles   = 150
	fundeScriptMax  = 64 << 10
	fundeScriptRows = 400
)

type fundURL struct {
	URL        string   `json:"url"`
	Host       string   `json:"host,omitempty"`
	First      int64    `json:"first"`
	Last       int64    `json:"last"`
	Uses       int      `json:"uses"`
	IPs        []string `json:"ips"`
	NIPs       int      `json:"n_ips"`
	Services   []string `json:"services"`
	Why        string   `json:"why,omitempty"`   // nicht zulässig: Grund
	Fetch      string   `json:"fetch,omitempty"` // ok | error | "" (noch nicht versucht)
	FetchError string   `json:"fetch_error,omitempty"`
	SHA256     string   `json:"sha256,omitempty"`
	Malware    bool     `json:"malware,omitempty"`
	URLhaus    string   `json:"urlhaus,omitempty"` // ok | dry | error | wait
	Note       string   `json:"note,omitempty"`
	ipSet      map[string]bool
}

type fundFile struct {
	SHA256   string   `json:"sha256"`
	Name     string   `json:"name"`
	Type     string   `json:"type,omitempty"`
	Arch     string   `json:"arch,omitempty"`
	Bits     int      `json:"bits,omitempty"`
	Size     int64    `json:"size,omitempty"`
	Packed   string   `json:"packed,omitempty"`
	Static   bool     `json:"static,omitempty"`
	Patterns []string `json:"patterns"`
	IOCs     int      `json:"iocs"`
	Sources  []string `json:"sources"`
	IPs      []string `json:"ips"`
	Sessions int      `json:"sessions"`
	First    int64    `json:"first"`
	Last     int64    `json:"last"`
	Missing  string   `json:"missing,omitempty"` // Datei nicht (mehr) da: Grund
	Malware  bool     `json:"malware,omitempty"`
	URLhaus  string   `json:"urlhaus,omitempty"`
	Bazaar   string   `json:"bazaar,omitempty"` // ok | known | dry | skipped | error | wait
	sess     map[string]bool
	ipSet    map[string]bool
}

type fundAttacker struct {
	IP      string `json:"ip"`
	Country string `json:"country,omitempty"`
	ASOrg   string `json:"as_org,omitempty"`
	First   int64  `json:"first"`
	Last    int64  `json:"last"`
	URLs    int    `json:"urls"`
	Files   int    `json:"files"`
	Abuse   string `json:"abuse,omitempty"` // ok | dry | error | wait
	Note    string `json:"note,omitempty"`
	urlSet  map[string]bool
	fileSet map[string]bool
}

type fundInfra struct {
	Kind  string   `json:"kind"` // ip | url | wallet | pool
	Value string   `json:"value"`
	Files []string `json:"files"`
}

type fundAI struct {
	T       int64  `json:"t"`
	IP      string `json:"ip"`
	Session string `json:"session,omitempty"`
	Kind    string `json:"kind"`
	Input   string `json:"input"`
	Output  string `json:"output"`
	Cached  bool   `json:"cached,omitempty"`
}

// fundeData sammelt die Funde seit since (gemeinsam für Übersicht und Fallakte).
type fundeData struct {
	urls  map[string]*fundURL // Schlüssel: bereinigte Adresse bzw. "skip:"+roh
	files map[string]*fundFile
	atts  map[string]*fundAttacker
	order []string // Reihenfolge der Adressen (jüngste zuletzt)
	st    *fundeState
}

func (h *Hive) collectFunde(ctx context.Context, since time.Time) (*fundeData, error) {
	d := &fundeData{urls: map[string]*fundURL{}, files: map[string]*fundFile{}, atts: map[string]*fundAttacker{}, st: h.fundeState(ctx)}
	att := func(s *sighting) *fundAttacker {
		a := d.atts[s.ip]
		if a == nil {
			a = &fundAttacker{IP: s.ip, First: s.ts, urlSet: map[string]bool{}, fileSet: map[string]bool{}}
			d.atts[s.ip] = a
		}
		if s.ts >= a.Last {
			a.Last, a.Country, a.ASOrg = s.ts, s.country, s.asOrg
		}
		return a
	}
	file := func(sha string, t int64) *fundFile {
		f := d.files[sha]
		if f == nil {
			f = &fundFile{SHA256: sha, First: t, sess: map[string]bool{}, ipSet: map[string]bool{}, Patterns: []string{}, Sources: []string{}, IPs: []string{}}
			d.files[sha] = f
		}
		f.First, f.Last = min(f.First, t), max(f.Last, t)
		return f
	}
	list, err := h.fundeSightings(ctx)
	if err != nil {
		return nil, err
	}
	// Regeln je Absender und je Adresse nur einmal prüfen
	rules := h.urlRules()
	type checked struct{ u, shown, why string }
	srcWhy := map[[3]string]string{}
	urlWhy := map[string]checked{}
	from0 := since.UnixMilli()
	for i := range list {
		s := &list[i]
		if s.ts < from0 {
			continue
		}
		k := [3]string{s.ip, s.sensor, s.asOrg}
		from, ok := srcWhy[k]
		if !ok {
			from = rules.source(s.ip, s.sensor, s.asOrg)
			srcWhy[k] = from
		}
		c := checked{shown: s.raw, why: from}
		if from == "" {
			if c, ok = urlWhy[s.raw]; !ok {
				c.u, c.shown, c.why = rules.check(s.raw)
				urlWhy[s.raw] = c
			}
		}
		key := c.u
		if c.why != "" {
			key = "skip:" + clip(c.shown, 300)
		}
		u := d.urls[key]
		if u == nil {
			u = &fundURL{URL: c.u, Why: c.why, First: s.ts, ipSet: map[string]bool{}, IPs: []string{}, Services: []string{}}
			if c.why != "" {
				u.URL = clip(c.shown, 300)
			}
			if p, err := url.Parse(u.URL); err == nil {
				u.Host = p.Hostname()
			}
			d.urls[key] = u
			d.order = append(d.order, key)
		}
		u.Uses++
		u.Last = s.ts
		if !u.ipSet[s.ip] {
			u.ipSet[s.ip] = true
			if len(u.IPs) < 5 {
				u.IPs = append(u.IPs, s.ip)
			}
		}
		if !contains(u.Services, s.service) {
			u.Services = append(u.Services, s.service)
		}
		if c.why != "" {
			continue
		}
		a := att(s)
		a.urlSet[c.u] = true
		if sha256HexRe.MatchString(s.sha) { // von Cowrie geladen
			f := file(s.sha, s.ts)
			if !contains(f.Sources, c.u) && len(f.Sources) < 20 {
				f.Sources = append(f.Sources, c.u)
			}
			f.ipSet[s.ip], f.sess[s.session] = true, true
			a.fileSet[s.sha] = true
		}
	}
	// Ergebnis des eigenen Holens je Adresse (samplecollect.go); geholte Dateien kommen dazu
	for _, key := range d.order {
		u := d.urls[key]
		u.NIPs = len(u.ipSet)
		if u.Why != "" {
			continue
		}
		if v, ok := d.st.lk["sample_fetch"][urlSubject(u.URL)]; ok {
			var r sampleFetchResult
			json.Unmarshal([]byte(v), &r)
			u.Fetch, u.FetchError, u.SHA256, u.Malware = r.Status, r.Error, r.SHA256, r.Malware
			if r.Status == "ok" && sha256HexRe.MatchString(r.SHA256) {
				f := file(r.SHA256, u.Last)
				f.First = min(f.First, u.First)
				if !contains(f.Sources, u.URL) && len(f.Sources) < 20 {
					f.Sources = append(f.Sources, u.URL)
				}
				for ip := range u.ipSet {
					f.ipSet[ip] = true
					if a := d.atts[ip]; a != nil {
						a.fileSet[r.SHA256] = true
					}
				}
				f.Malware = f.Malware || r.Malware
			}
		}
		u.URLhaus, u.Note = d.st.urlhaus(u.URL)
	}
	return d, nil
}

// lastFor: jüngster Protokolleintrag eines Kanals, der match erfüllt.
func (s *shareState) lastFor(kind string, match func(shareLogEntry) bool) (shareLogEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.channel(kind).Log {
		if match(e) {
			return e, true
		}
	}
	return shareLogEntry{}, false
}

// fillFile ergänzt Merkmale aus der Untersuchung der Datei (sample.go, zwischengespeichert).
func (h *Hive) fillFile(st *fundeState, f *fundFile, analyze bool) *SampleInfo {
	f.IPs = f.IPs[:0]
	for ip := range f.ipSet {
		f.IPs = append(f.IPs, ip)
	}
	sort.Strings(f.IPs)
	f.Sessions = len(f.sess)
	if len(f.Sources) > 0 {
		f.Name = fileNameOf(f.Sources[0])
	}
	f.URLhaus = ""
	for _, u := range f.Sources {
		if s, _ := st.urlhaus(u); rankState(s) > rankState(f.URLhaus) {
			f.URLhaus = s
		}
	}
	f.Bazaar = st.bazaar(f.SHA256)
	var si SampleInfo
	v, cached := st.lk["sample"]["sample:"+f.SHA256]
	switch {
	case cached && json.Unmarshal([]byte(v), &si) == nil:
	case analyze:
		var err error
		if si, err = h.loadSample(f.SHA256); err != nil {
			f.Missing = err.Error()
			return nil
		}
	default:
		f.Missing = "noch nicht untersucht"
		return nil
	}
	f.Type, f.Arch, f.Bits, f.Size, f.Packed, f.Static = si.Type, si.Arch, si.Bits, si.Size, si.Packed, si.Static
	for _, p := range si.Patterns {
		f.Patterns = append(f.Patterns, nonEmptyFirst(p.Label, p.Key))
	}
	f.IOCs = len(si.URLs) + len(si.IPs) + len(si.Wallets) + len(si.Pools)
	f.Malware = f.Malware || bazaarEligible(si)
	return &si
}

// rankState: Fehler und Wartendes zuerst zeigen.
func rankState(s string) int {
	return map[string]int{"": 0, "dry": 1, "ok": 2, "known": 2, "wait": 3, "error": 4}[s]
}

func fileNameOf(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	name := p.Path[strings.LastIndex(p.Path, "/")+1:]
	if name == "" {
		name = p.Hostname()
	}
	return clip(name, 60)
}

// funde: GET /api/funde?range=7d
func (h *Hive) funde(w http.ResponseWriter, r *http.Request) {
	rng := min(rangeDur(r.URL.Query().Get("range"), 7*24*time.Hour), fundeMaxRange)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	since := time.Now().Add(-rng)
	d, err := h.collectFunde(ctx, since)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	// Adressen, jüngste zuerst
	urls := []*fundURL{}
	skipped := []*fundURL{}
	why := map[string]int{}
	funnel := map[string]int{}
	for i := len(d.order) - 1; i >= 0; i-- {
		u := d.urls[d.order[i]]
		funnel["seen"]++
		if u.Why != "" {
			skipped = append(skipped, u)
			why[u.Why]++
			continue
		}
		urls = append(urls, u)
		funnel["allowed"]++
		switch u.Fetch {
		case "ok":
			funnel["fetched"]++
		case "error":
			funnel["fetch_error"]++
		default:
			funnel["not_tried"]++
		}
		if u.Malware {
			funnel["malware"]++
		}
		funnel["urlhaus_"+nonEmptyFirst(u.URLhaus, "none")]++
	}
	// Dateien: zuletzt gesehene zuerst; nur die ersten fundeMaxFiles werden ggf. untersucht
	files := make([]*fundFile, 0, len(d.files))
	for _, f := range d.files {
		files = append(files, f)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Last > files[j].Last })
	if len(files) > fundeMaxFiles {
		files = files[:fundeMaxFiles]
	}
	infra := map[string]*fundInfra{}
	analyzed := 0
	for _, f := range files {
		si := h.fillFile(d.st, f, analyzed < 20) // höchstens 20 neue Untersuchungen je Aufruf
		if f.Missing == "" {
			analyzed++
		}
		if si == nil {
			continue
		}
		add := func(kind string, vals []string) {
			for _, v := range vals {
				k := kind + "|" + v
				x := infra[k]
				if x == nil {
					x = &fundInfra{Kind: kind, Value: clip(v, 300)}
					infra[k] = x
				}
				if !contains(x.Files, f.SHA256) {
					x.Files = append(x.Files, f.SHA256)
				}
			}
		}
		add("ip", si.IPs)
		add("url", si.URLs)
		add("wallet", si.Wallets)
		add("pool", si.Pools)
	}
	infraList := make([]*fundInfra, 0, len(infra))
	for _, x := range infra {
		infraList = append(infraList, x)
	}
	sort.Slice(infraList, func(i, j int) bool {
		if len(infraList[i].Files) != len(infraList[j].Files) {
			return len(infraList[i].Files) > len(infraList[j].Files)
		}
		return infraList[i].Kind+infraList[i].Value < infraList[j].Kind+infraList[j].Value
	})
	// Angreifer
	atts := make([]*fundAttacker, 0, len(d.atts))
	for _, a := range d.atts {
		a.URLs, a.Files = len(a.urlSet), len(a.fileSet)
		a.Abuse, a.Note = d.st.abuse(a.IP)
		atts = append(atts, a)
	}
	sort.Slice(atts, func(i, j int) bool { return atts[i].Last > atts[j].Last })
	if len(atts) > 300 {
		atts = atts[:300]
	}
	// KI-Antworten an Angreifer
	ai := []fundAI{}
	if evs, err := h.loadEvents(ctx, "type = 'ai_reply' AND ts >= ?", []any{since.UnixMilli()}, "DESC", 300); err == nil {
		for _, e := range evs {
			x := aiReplyFrom(e)
			ai = append(ai, fundAI{T: x.T, IP: e.SrcIP, Session: e.Session, Kind: x.Kind, Input: x.Input, Output: clip(x.Output, 800), Cached: x.Cached})
		}
	}
	// Abgelehnte Dateien der eigenen Runde (Limit, Quarantäne voll …) kennt nur der Speicher
	h.share.mu.Lock()
	fetchSkips := append([]sampleSkip{}, h.share.skips...)
	h.share.mu.Unlock()
	if len(urls) > 500 {
		urls = urls[:500]
	}
	if len(skipped) > 300 {
		skipped = skipped[:300]
	}
	writeJSON(w, map[string]any{
		"range_ms": rng.Milliseconds(), "funnel": funnel, "skip_reasons": why,
		"providers": h.fundeProviders(since), "urls": urls, "skipped": skipped, "fetch_skips": fetchSkips,
		"files": files, "attackers": atts, "infra": infraList, "ai": ai,
		"delay_min": h.Extras().ReportDelayMin,
	})
}

type fundProvider struct {
	Kind     string         `json:"kind"`
	Counts   map[string]int `json:"counts"`
	Waiting  int            `json:"waiting"`
	LastErr  string         `json:"last_error,omitempty"`
	Pause    *time.Time     `json:"pause_until,omitempty"`
	Days     []int          `json:"days"` // Erfolge je Tag, älteste zuerst (7 Tage)
	DryRun   bool           `json:"dry_run,omitempty"`
	Enabled  bool           `json:"enabled"`
	Quota    string         `json:"quota,omitempty"`
	LastRun  *time.Time     `json:"last_run,omitempty"`
	Disabled string         `json:"disabled,omitempty"` // warum aus
}

// fundeProviders: Stand je Anbieter aus den Protokollen (share.go, abusereport.go).
func (h *Hive) fundeProviders(since time.Time) []fundProvider {
	x := h.Extras()
	day0 := time.Now().Add(-7 * 24 * time.Hour)
	dayOf := func(t time.Time) int { return int(t.Sub(day0) / (24 * time.Hour)) }
	var out []fundProvider
	for _, k := range []string{"urlhaus", "bazaar", "dshield", "sample"} {
		p := fundProvider{Kind: k, Counts: map[string]int{}, Days: make([]int, 7)}
		h.share.mu.Lock()
		c := h.share.channel(k)
		for _, e := range c.Log {
			if e.Time.After(since) {
				p.Counts[e.Status]++
			}
			if i := dayOf(e.Time); i >= 0 && i < 7 && (e.Status == "ok" || e.Status == "known") {
				p.Days[i]++
			}
		}
		p.LastErr = c.LastErr
		if time.Now().Before(c.PauseUntil) {
			t := c.PauseUntil
			p.Pause = &t
		}
		if !c.LastRun.IsZero() {
			t := c.LastRun
			p.LastRun = &t
		}
		h.share.mu.Unlock()
		if k == "bazaar" {
			p.Waiting = h.countLookups("bazaar_wait")
		} else {
			p.Waiting = len(h.share.waitList(k))
		}
		switch k {
		case "urlhaus":
			p.Enabled, p.DryRun = x.URLhausReport.Enabled && x.AbuseChKey != "", x.URLhausReport.DryRun
			if x.AbuseChKey == "" {
				p.Disabled = "kein abuse.ch-Schlüssel"
			}
		case "bazaar":
			p.Enabled, p.DryRun = (x.Bazaar.Lookup || x.Bazaar.Upload) && x.AbuseChKey != "" && x.Samples.Enabled, x.Bazaar.DryRun
			if !x.Samples.Enabled {
				p.Disabled = "„Dateien sammeln“ ist aus"
			}
		case "dshield":
			p.Enabled, p.DryRun = x.DShield.Enabled, x.DShield.DryRun
		case "sample":
			p.Enabled = x.Samples.Enabled
		}
		out = append(out, p)
	}
	p := fundProvider{Kind: "abuseipdb", Counts: map[string]int{}, Days: make([]int, 7), Waiting: len(h.share.waitList("abuseipdb")),
		Enabled: x.AbuseReport.Enabled && x.AbuseIPDBKey != "", DryRun: x.AbuseReport.DryRun}
	if x.AbuseIPDBKey == "" {
		p.Disabled = "kein AbuseIPDB-Schlüssel"
	}
	h.abuse.mu.Lock()
	for _, e := range h.abuse.log {
		if e.Time.After(since) {
			p.Counts[e.Status]++
		}
		if i := dayOf(e.Time); i >= 0 && i < 7 && e.Status == "ok" {
			p.Days[i]++
		}
	}
	p.LastErr = h.abuse.lastErr
	if time.Now().Before(h.abuse.pauseUntil) {
		t := h.abuse.pauseUntil
		p.Pause = &t
	}
	if h.abuse.remaining >= 0 && h.abuse.limit > 0 {
		p.Quota = strconv.Itoa(h.abuse.remaining) + " von " + strconv.Itoa(h.abuse.limit)
	}
	if !h.abuse.lastRun.IsZero() {
		t := h.abuse.lastRun
		p.LastRun = &t
	}
	h.abuse.mu.Unlock()
	return append([]fundProvider{p}, out...)
}

func (h *Hive) countLookups(source string) int {
	var n int
	h.st.db.QueryRow(`SELECT COUNT(*) FROM lookups WHERE source = ?`, source).Scan(&n)
	return n
}

// ---- Fallakte ----

type auditEntry struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"` // urlhaus | bazaar | sample | abuseipdb | wait
	Status  string    `json:"status"`
	Subject string    `json:"subject"`
	Detail  string    `json:"detail,omitempty"`
	Error   string    `json:"error,omitempty"`
	Sent    string    `json:"sent,omitempty"`
}

type stageInfo struct {
	URL     string `json:"url"`
	Why     string `json:"why,omitempty"`   // nicht zulässig
	Seen    int    `json:"seen"`            // in Befehlen und Downloads benutzt
	Fetch   string `json:"fetch,omitempty"` // ok | error
	Error   string `json:"error,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Type    string `json:"type,omitempty"`
	Arch    string `json:"arch,omitempty"`
	URLhaus string `json:"urlhaus,omitempty"`
}

// fundeFile: GET /api/funde/file?sha=<sha256>
func (h *Hive) fundeFile(w http.ResponseWriter, r *http.Request) {
	sha := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sha")))
	if !sha256HexRe.MatchString(sha) {
		httpErr(w, 400, "SHA-256 erwartet")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	d, err := h.collectFunde(ctx, time.Now().Add(-fundeMaxRange))
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	f := d.files[sha]
	if f == nil {
		f = &fundFile{SHA256: sha, sess: map[string]bool{}, ipSet: map[string]bool{}, Patterns: []string{}, Sources: []string{}, IPs: []string{}}
		// ältere Datei aus der Quarantäne: Herkunft aus den Metadaten
		if v, _, ok := h.st.lookupGet("qsample:"+sha, "quarantine", 0); ok {
			var m quarantineMeta
			if json.Unmarshal([]byte(v), &m) == nil && m.URL != "" {
				f.Sources, f.First, f.Last = []string{m.URL}, m.Fetched, m.Fetched
			}
		}
	}
	si := h.fillFile(d.st, f, true)
	out := map[string]any{"file": f}
	if si != nil {
		out["info"] = si
		if (si.Type == "Skript" || si.Type == "Text") && si.Size <= fundeScriptMax {
			if b, _, err := h.readSample(sha, fundeScriptMax); err == nil {
				out["script"] = scriptLines(b)
			}
		}
	}
	if v, _, ok := h.st.lookupGet("qsample:"+sha, "quarantine", 0); ok {
		var m quarantineMeta
		if json.Unmarshal([]byte(v), &m) == nil {
			out["quarantine"] = m
		}
	}
	// Quellen mit Nutzung
	var sources []*fundURL
	hosts := map[string]bool{}
	for _, u := range f.Sources {
		if x := d.urls[u]; x != nil {
			x.NIPs = len(x.ipSet)
			sources = append(sources, x)
		} else {
			sources = append(sources, &fundURL{URL: u, IPs: []string{}, Services: []string{}})
		}
		if p, err := url.Parse(u); err == nil {
			hosts[p.Hostname()] = true
		}
	}
	out["sources"] = sources
	// Nachlade-Stufen: Adressen in der Datei
	stages := []stageInfo{}
	if si != nil {
		own := h.ownPublicIP()
		for _, raw := range si.URLs {
			st := stageInfo{URL: clip(raw, 300)}
			u, why := shareURLProblem(raw, own)
			if why != "" {
				st.Why = why
			} else {
				st.URL = u
				if x := d.urls[u]; x != nil {
					st.Seen = x.Uses
				}
				if v, ok := d.st.lk["sample_fetch"][urlSubject(u)]; ok {
					var fr sampleFetchResult
					json.Unmarshal([]byte(v), &fr)
					st.Fetch, st.Error, st.SHA256 = fr.Status, fr.Error, fr.SHA256
					if v, ok := d.st.lk["sample"]["sample:"+fr.SHA256]; ok {
						var s2 SampleInfo
						if json.Unmarshal([]byte(v), &s2) == nil {
							st.Type, st.Arch = s2.Type, s2.Arch
						}
					}
				}
				st.URLhaus, _ = d.st.urlhaus(u)
			}
			stages = append(stages, st)
		}
	}
	out["stages"] = stages
	// Angreifer
	atts := []*fundAttacker{}
	for _, ip := range f.IPs {
		a := d.atts[ip]
		if a == nil {
			a = &fundAttacker{IP: ip}
		}
		a.URLs, a.Files = len(a.urlSet), len(a.fileSet)
		a.Abuse, a.Note = d.st.abuse(ip)
		if a.Country == "" && a.ASOrg == "" {
			h.st.db.QueryRowContext(ctx, `SELECT COALESCE(country,''), COALESCE(as_org,'') FROM events WHERE src_ip = ? ORDER BY id DESC LIMIT 1`, ip).Scan(&a.Country, &a.ASOrg)
		}
		atts = append(atts, a)
	}
	out["attackers"] = atts
	// Andere Dateien vom selben Server
	same := []map[string]any{}
	for _, x := range d.urls {
		if x.Why != "" || !hosts[x.Host] || x.SHA256 == "" || x.SHA256 == sha || contains(f.Sources, x.URL) || len(same) >= 30 {
			continue
		}
		e := map[string]any{"url": x.URL, "sha256": x.SHA256}
		if v, ok := d.st.lk["sample"]["sample:"+x.SHA256]; ok {
			var s2 SampleInfo
			if json.Unmarshal([]byte(v), &s2) == nil {
				e["type"], e["arch"] = s2.Type, s2.Arch
			}
		}
		same = append(same, e)
	}
	sort.Slice(same, func(i, j int) bool { return same[i]["url"].(string) < same[j]["url"].(string) })
	out["same_host"] = same
	// Prüfprotokoll
	audit := []auditEntry{}
	addShare := func(kind string, match func(shareLogEntry) bool) {
		h.share.mu.Lock()
		for _, e := range h.share.channel(kind).Log {
			if match(e) && len(audit) < 200 {
				audit = append(audit, auditEntry{Time: e.Time, Kind: kind, Status: e.Status, Subject: e.Subject, Detail: e.Detail, Error: e.Error, Sent: e.Sent})
			}
		}
		h.share.mu.Unlock()
	}
	isSource := func(e shareLogEntry) bool { return contains(f.Sources, e.Subject) }
	addShare("urlhaus", isSource)
	addShare("sample", func(e shareLogEntry) bool { return e.SHA256 == sha || isSource(e) })
	addShare("bazaar", func(e shareLogEntry) bool { return e.SHA256 == sha })
	h.abuse.mu.Lock()
	for _, e := range h.abuse.log {
		if f.ipSet[e.IP] || contains(f.IPs, e.IP) {
			audit = append(audit, auditEntry{Time: e.Time, Kind: "abuseipdb", Status: e.Status, Subject: e.IP, Error: e.Error,
				Sent: "POST https://api.abuseipdb.com/api/v2/report\nip=" + e.IP + "\ncategories=" + joinInts(e.Categories) + "\ncomment=" + e.Comment})
		}
	}
	h.abuse.mu.Unlock()
	for _, k := range []string{"urlhaus", "abuseipdb"} {
		for _, wt := range h.share.waitList(k) {
			if contains(f.Sources, wt.Subject) || contains(f.IPs, wt.Subject) {
				audit = append(audit, auditEntry{Time: time.Now(), Kind: k, Status: "wait", Subject: wt.Subject, Detail: wt.Detail})
			}
		}
	}
	if v, t, ok := h.st.lookupGet("hash:"+sha, "bazaar_wait", 0); ok {
		var bw bazaarWait
		json.Unmarshal([]byte(v), &bw)
		until := time.UnixMilli(bw.Fetched).Add(h.Extras().reportDelay())
		audit = append(audit, auditEntry{Time: t, Kind: "bazaar", Status: "wait", Subject: sha, Detail: waitText(until)})
	}
	sort.Slice(audit, func(i, j int) bool { return audit[i].Time.After(audit[j].Time) })
	out["audit"] = audit
	// Externe Daten (nur gespeicherte Abfragen, keine neuen)
	ext := map[string]any{}
	if v, t, ok := h.st.lookupGet("hash:"+sha, "malwarebazaar", 0); ok {
		ext["malwarebazaar"] = map[string]any{"at": t, "data": json.RawMessage(v)}
	}
	uh := []map[string]any{}
	for _, u := range f.Sources {
		if v, t, ok := h.st.lookupGet(urlSubject(u), "urlhaus", 0); ok {
			uh = append(uh, map[string]any{"url": u, "at": t, "data": json.RawMessage(v)})
		}
	}
	ext["urlhaus"] = uh
	out["external"] = ext
	// KI-Antworten an diese Angreifer
	ai := []fundAI{}
	if len(f.IPs) > 0 {
		args := []any{time.Now().Add(-fundeMaxRange).UnixMilli()}
		ph := make([]string, 0, len(f.IPs))
		for _, ip := range f.IPs[:min(len(f.IPs), 50)] {
			ph = append(ph, "?")
			args = append(args, ip)
		}
		if evs, err := h.loadEvents(ctx, "type = 'ai_reply' AND ts >= ? AND src_ip IN ("+strings.Join(ph, ",")+")", args, "DESC", 100); err == nil {
			for _, e := range evs {
				x := aiReplyFrom(e)
				ai = append(ai, fundAI{T: x.T, IP: e.SrcIP, Session: e.Session, Kind: x.Kind, Input: x.Input, Output: clip(x.Output, 1200), Cached: x.Cached})
			}
		}
	}
	out["ai"] = ai
	writeJSON(w, out)
}

// scriptLines: Skripttext zum Anzeigen, Steuerzeichen ersetzt, Zeilen begrenzt.
func scriptLines(b []byte) []string {
	s := strings.ToValidUTF8(string(b), "?")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	if len(lines) > fundeScriptRows {
		lines = append(lines[:fundeScriptRows], "… (gekürzt)")
	}
	for i, l := range lines {
		lines[i] = clip(strings.Map(func(r rune) rune {
			if r == '\t' {
				return r
			}
			if r < 0x20 || r == 0x7f || r >= 0x80 && r < 0xa0 {
				return '?'
			}
			return r
		}, l), 400)
	}
	return lines
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ",")
}
