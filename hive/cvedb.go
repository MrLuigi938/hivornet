package main

// Lückendetails aus öffentlichen Quellen (abschaltbar unter Einstellungen → Auswertung und KI):
//
//   - CISA KEV (Known Exploited Vulnerabilities): der ganze Katalog als JSON, einmal am Tag,
//     lokal in der Tabelle kev. Ohne Schlüssel; mit ETag, damit unveränderte Kataloge nicht
//     erneut geladen werden.
//   - NVD (NIST): Beschreibung, CVSS, Schwäche (CWE), Veröffentlichung, Hersteller/Produkt und
//     Verweise, je CVE auf Abruf, 14 Tage in lookups (Quelle "nvd"). Ohne Schlüssel erlaubt die
//     NVD 5 Abfragen in 30 Sekunden; Hivornet fragt höchstens alle 7 Sekunden (mit Schlüssel
//     jede Sekunde) und pausiert nach einer Absage 10 Minuten.
//   - FIRST EPSS: Wahrscheinlichkeit einer Ausnutzung in den nächsten 30 Tagen, gebündelt bis
//     100 CVEs je Abfrage, einen Tag in lookups (Quelle "epss").
//
// Hinaus gehen nur CVE-Nummern, nie Adressen, Pfade oder andere Daten der Angreifer. Abfragen
// laufen im Hintergrund (runCVEDB); die Oberfläche bekommt sofort, was schon da ist, und
// fragt nach, solange etwas aussteht ("pending").

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CVEDBConfig: Teil der Einstellungen (extras.go).
type CVEDBConfig struct {
	Enabled bool   `json:"enabled"` // KEV laden, NVD und EPSS auf Abruf fragen
	NVDKey  string `json:"nvd_key"` // optional: höheres Kontingent bei der NVD
}

// Adressen der Quellen; in Tests überschrieben.
var (
	kevURL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	nvdBase  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	epssBase = "https://api.first.org/data/v1/epss"
	cveHTTP  = &http.Client{Timeout: 60 * time.Second, CheckRedirect: keyRedirect}
)

const (
	nvdMaxAge     = 14 * 24 * time.Hour
	nvdMissingAge = 2 * 24 * time.Hour // unbekannte CVE: bald erneut fragen (vielleicht reserviert)
	epssMaxAge    = 24 * time.Hour
	kevInterval   = 24 * time.Hour
	cveRetryPause = 10 * time.Minute
	kevMaxBytes   = 16 << 20
)

// Abstand zwischen zwei NVD-Abfragen (ohne bzw. mit Schlüssel); in Tests 0.
var nvdGap, nvdGapKey = 7 * time.Second, time.Second

var cveIDRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)

// CVEInfo: alles, was zu einer CVE bekannt ist.
type CVEInfo struct {
	CVE        string   `json:"cve"`
	KEV        bool     `json:"kev"`
	KEVAdded   string   `json:"kev_added,omitempty"`
	KEVName    string   `json:"kev_name,omitempty"`
	Ransomware bool     `json:"ransomware,omitempty"` // von Ransomware-Gruppen genutzt (laut KEV)
	Vendor     string   `json:"vendor,omitempty"`
	Product    string   `json:"product,omitempty"`
	Desc       string   `json:"desc,omitempty"`
	CVSS       float64  `json:"cvss,omitempty"`
	CVSSVer    string   `json:"cvss_version,omitempty"`
	Severity   string   `json:"severity,omitempty"` // CRITICAL, HIGH …
	Vector     string   `json:"vector,omitempty"`
	CWE        []string `json:"cwe,omitempty"`
	Published  string   `json:"published,omitempty"`
	Refs       []string `json:"refs,omitempty"` // höchstens 4, nur https
	EPSS       float64  `json:"epss,omitempty"`
	EPSSPct    float64  `json:"epss_pct,omitempty"`
	EPSSDate   string   `json:"epss_date,omitempty"`
	NVD        bool     `json:"nvd"`               // Details der NVD liegen vor
	Unknown    bool     `json:"unknown,omitempty"` // die NVD kennt die Nummer nicht
	Pending    bool     `json:"pending,omitempty"` // Abfrage steht aus
}

type nvdData struct {
	Missing   bool     `json:"missing,omitempty"`
	Desc      string   `json:"desc,omitempty"`
	CVSS      float64  `json:"cvss,omitempty"`
	Version   string   `json:"version,omitempty"`
	Severity  string   `json:"severity,omitempty"`
	Vector    string   `json:"vector,omitempty"`
	CWE       []string `json:"cwe,omitempty"`
	Published string   `json:"published,omitempty"`
	Vendor    string   `json:"vendor,omitempty"`
	Product   string   `json:"product,omitempty"`
	Refs      []string `json:"refs,omitempty"`
}

type epssData struct {
	Missing bool    `json:"missing,omitempty"`
	EPSS    float64 `json:"epss"`
	Pct     float64 `json:"pct"`
	Date    string  `json:"date,omitempty"`
}

// kevMeta: Stand des Katalogs (kv "kev_meta").
type kevMeta struct {
	Version string    `json:"version,omitempty"`
	Count   int       `json:"count"`
	Updated time.Time `json:"updated"` // zuletzt neu eingelesen
	Checked time.Time `json:"checked"` // zuletzt nachgesehen
	ETag    string    `json:"etag,omitempty"`
	Error   string    `json:"error,omitempty"`
}

// cveQueue: ausstehende NVD-/EPSS-Abfragen.
var cveQ = struct {
	mu      sync.Mutex
	pending []string
	set     map[string]bool
	wake    chan struct{}
	kevNow  chan struct{}
	pause   time.Time // nach einer Absage
	lastNVD time.Time
	lastErr string
	asked   int
}{set: map[string]bool{}, wake: make(chan struct{}, 1), kevNow: make(chan struct{}, 1)}

const cveQueueMax = 500

func cveEnqueue(ids ...string) {
	cveQ.mu.Lock()
	added := false
	for _, id := range ids {
		if !cveIDRe.MatchString(id) || cveQ.set[id] || len(cveQ.pending) >= cveQueueMax {
			continue
		}
		cveQ.set[id] = true
		cveQ.pending = append(cveQ.pending, id)
		added = true
	}
	cveQ.mu.Unlock()
	if added {
		select {
		case cveQ.wake <- struct{}{}:
		default:
		}
	}
}

// normCVEs: gültige, großgeschriebene Nummern ohne Doppelte (höchstens n).
func normCVEs(raw []string, n int) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range raw {
		s = strings.ToUpper(strings.TrimSpace(s))
		if cveIDRe.MatchString(s) && !seen[s] && len(out) < n {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// cveInfos liefert, was zu den Nummern bekannt ist, und stellt Fehlendes in die Warteschlange
// (nur wenn eingeschaltet).
func (h *Hive) cveInfos(ctx context.Context, ids []string) map[string]*CVEInfo {
	return h.cveInfosQ(ctx, ids, true)
}

// cveInfosQ wie cveInfos; enqueue=false fragt nichts nach (beliebige Nummern von Lesern).
func (h *Hive) cveInfosQ(ctx context.Context, ids []string, enqueue bool) map[string]*CVEInfo {
	out := map[string]*CVEInfo{}
	if len(ids) == 0 {
		return out
	}
	for _, id := range ids {
		out[id] = &CVEInfo{CVE: id}
	}
	q := `SELECT cve, vendor, product, name, added, ransomware FROM kev WHERE cve IN (` + strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + `)`
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	if rs, err := h.st.db.QueryContext(ctx, q, args...); err == nil {
		for rs.Next() {
			var id, vendor, product, name, added, ransom string
			if rs.Scan(&id, &vendor, &product, &name, &added, &ransom) == nil && out[id] != nil {
				x := out[id]
				x.KEV, x.Vendor, x.Product, x.KEVName, x.KEVAdded, x.Ransomware = true, vendor, product, name, added, ransom == "Known"
			}
		}
		rs.Close()
	}
	enabled := h.Extras().CVEDB.Enabled
	var missing []string
	for _, id := range ids {
		x := out[id]
		fresh := true
		if data, at, ok := h.st.lookupGet("cve:"+id, "nvd", 0); ok {
			var d nvdData
			if json.Unmarshal([]byte(data), &d) == nil {
				if d.Missing {
					x.Unknown = !x.KEV
					fresh = time.Since(at) < nvdMissingAge
				} else {
					x.NVD = true
					x.Desc, x.CVSS, x.CVSSVer, x.Severity, x.Vector, x.CWE, x.Published, x.Refs = d.Desc, d.CVSS, d.Version, d.Severity, d.Vector, d.CWE, d.Published, d.Refs
					if x.Vendor == "" {
						x.Vendor, x.Product = d.Vendor, d.Product
					}
					fresh = time.Since(at) < nvdMaxAge
				}
			}
		} else {
			fresh = false
		}
		if data, at, ok := h.st.lookupGet("cve:"+id, "epss", 0); ok {
			var d epssData
			if json.Unmarshal([]byte(data), &d) == nil && !d.Missing {
				x.EPSS, x.EPSSPct, x.EPSSDate = d.EPSS, d.Pct, d.Date
			}
			fresh = fresh && time.Since(at) < epssMaxAge
		} else {
			fresh = false
		}
		if !fresh && enabled && enqueue {
			missing = append(missing, id)
		}
	}
	cveEnqueue(missing...)
	for _, id := range missing {
		out[id].Pending = true
	}
	return out
}

// cveCheck: Ist die Nummer echt? "kev" (im Katalog), "nvd" (in der NVD), "unbekannt" (die NVD
// kennt sie nicht), "offen" (noch nicht geprüft) oder "ungültig".
func (h *Hive) cveCheck(ctx context.Context, id string) string {
	if !cveIDRe.MatchString(id) {
		return "ungültig"
	}
	x := h.cveInfos(ctx, []string{id})[id]
	switch {
	case x.KEV:
		return "kev"
	case x.NVD:
		return "nvd"
	case x.Unknown:
		return "unbekannt"
	}
	return "offen"
}

// ---- Hintergrund ----

// runCVEDB: KEV einmal am Tag, Warteschlange für NVD und EPSS.
func (h *Hive) runCVEDB(stop <-chan struct{}) {
	select {
	case <-stop:
		return
	case <-time.After(30 * time.Second):
	}
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		cfg := h.Extras().CVEDB
		if cfg.Enabled {
			m := h.kevMeta()
			if time.Since(m.Checked) > kevInterval-time.Hour {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				if err := h.updateKEV(ctx); err != nil {
					log.Printf("KEV-Katalog: %v", err)
				}
				cancel()
			}
			h.workCVEQueue(stop)
		}
		select {
		case <-stop:
			return
		case <-tick.C:
		case <-cveQ.wake:
		case <-cveQ.kevNow:
			m := h.kevMeta()
			m.Checked = time.Time{}
			h.saveKEVMeta(m)
		}
	}
}

func (h *Hive) kevMeta() kevMeta {
	var m kevMeta
	if v, ok := h.st.GetKV("kev_meta"); ok {
		json.Unmarshal([]byte(v), &m)
	}
	return m
}

func (h *Hive) saveKEVMeta(m kevMeta) {
	b, _ := json.Marshal(m)
	h.st.SetKV("kev_meta", string(b))
}

func cveGet(ctx context.Context, u string, hdr map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Hivornet/"+version)
	req.Header.Set("Accept", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return cveHTTP.Do(req)
}

// updateKEV lädt den Katalog, wenn er sich geändert hat, und ersetzt die Tabelle kev.
func (h *Hive) updateKEV(ctx context.Context) error {
	m := h.kevMeta()
	m.Checked = time.Now()
	hdr := map[string]string{}
	if m.ETag != "" && m.Count > 0 {
		hdr["If-None-Match"] = m.ETag
	}
	fail := func(err error) error {
		m.Error = clip(err.Error(), 200)
		h.saveKEVMeta(m)
		return err
	}
	resp, err := cveGet(ctx, kevURL, hdr)
	if err != nil {
		return fail(fmt.Errorf("nicht erreichbar"))
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		m.Error = ""
		h.saveKEVMeta(m)
		return nil
	}
	if resp.StatusCode != 200 {
		return fail(fmt.Errorf("Antwort %s", resp.Status))
	}
	var cat struct {
		Version string `json:"catalogVersion"`
		Vulns   []struct {
			CVE        string   `json:"cveID"`
			Vendor     string   `json:"vendorProject"`
			Product    string   `json:"product"`
			Name       string   `json:"vulnerabilityName"`
			Added      string   `json:"dateAdded"`
			Desc       string   `json:"shortDescription"`
			Action     string   `json:"requiredAction"`
			Due        string   `json:"dueDate"`
			Ransomware string   `json:"knownRansomwareCampaignUse"`
			CWEs       []string `json:"cwes"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, kevMaxBytes)).Decode(&cat); err != nil {
		return fail(fmt.Errorf("Katalog nicht lesbar"))
	}
	if len(cat.Vulns) < 10 { // offensichtlich unvollständig: alten Stand behalten
		return fail(fmt.Errorf("Katalog leer"))
	}
	tx, err := h.st.db.BeginTx(ctx, nil)
	if err != nil {
		return fail(err)
	}
	if _, err := tx.Exec(`DELETE FROM kev`); err != nil {
		tx.Rollback()
		return fail(err)
	}
	n := 0
	for _, v := range cat.Vulns {
		id := strings.ToUpper(strings.TrimSpace(v.CVE))
		if !cveIDRe.MatchString(id) {
			continue
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO kev(cve, vendor, product, name, added, descr, action, due, ransomware, cwes) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			id, clip(v.Vendor, 100), clip(v.Product, 100), clip(v.Name, 200), clip(v.Added, 20), clip(v.Desc, 1000), clip(v.Action, 500), clip(v.Due, 20), clip(v.Ransomware, 20), clip(strings.Join(v.CWEs, ","), 100)); err != nil {
			tx.Rollback()
			return fail(err)
		}
		n++
	}
	if err := tx.Commit(); err != nil {
		return fail(err)
	}
	m.Version, m.Count, m.Updated, m.Error = clip(cat.Version, 40), n, time.Now(), ""
	m.ETag = clip(resp.Header.Get("ETag"), 200)
	h.saveKEVMeta(m)
	log.Printf("KEV-Katalog eingelesen: %d Einträge (Stand %s)", n, m.Version)
	return nil
}

// workCVEQueue arbeitet die Warteschlange ab: erst EPSS gebündelt, dann NVD einzeln mit Abstand.
func (h *Hive) workCVEQueue(stop <-chan struct{}) {
	for {
		cveQ.mu.Lock()
		if len(cveQ.pending) == 0 || time.Now().Before(cveQ.pause) {
			cveQ.mu.Unlock()
			return
		}
		batch := append([]string(nil), cveQ.pending[:min(100, len(cveQ.pending))]...)
		cveQ.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		var needEPSS []string
		for _, id := range batch {
			if _, _, ok := h.st.lookupGet("cve:"+id, "epss", epssMaxAge); !ok {
				needEPSS = append(needEPSS, id)
			}
		}
		if len(needEPSS) > 0 {
			if err := h.fetchEPSS(ctx, needEPSS); err != nil {
				h.cveFailed("EPSS: " + err.Error())
				cancel()
				return
			}
		}
		for _, id := range batch {
			if d, at, ok := h.st.lookupGet("cve:"+id, "nvd", 0); ok {
				age := nvdMaxAge
				if strings.Contains(d, `"missing":true`) {
					age = nvdMissingAge
				}
				if time.Since(at) < age {
					cveDone(id)
					continue
				}
			}
			wait := nvdGap
			if h.Extras().CVEDB.NVDKey != "" {
				wait = nvdGapKey
			}
			cveQ.mu.Lock()
			next := cveQ.lastNVD.Add(wait)
			cveQ.mu.Unlock()
			if d := time.Until(next); d > 0 {
				select {
				case <-stop:
					cancel()
					return
				case <-time.After(d):
				}
			}
			cveQ.mu.Lock()
			cveQ.lastNVD = time.Now()
			cveQ.mu.Unlock()
			if err := h.fetchNVD(ctx, id); err != nil {
				h.cveFailed("NVD: " + err.Error())
				cancel()
				return
			}
			cveDone(id)
		}
		cancel()
		if !h.Extras().CVEDB.Enabled {
			return
		}
	}
}

func cveDone(id string) {
	cveQ.mu.Lock()
	defer cveQ.mu.Unlock()
	if !cveQ.set[id] {
		return
	}
	delete(cveQ.set, id)
	for i, x := range cveQ.pending {
		if x == id {
			cveQ.pending = append(cveQ.pending[:i], cveQ.pending[i+1:]...)
			break
		}
	}
	cveQ.asked++
}

func (h *Hive) cveFailed(msg string) {
	cveQ.mu.Lock()
	cveQ.lastErr = clip(msg, 200)
	cveQ.pause = time.Now().Add(cveRetryPause)
	cveQ.mu.Unlock()
	log.Printf("Lückendetails: %s (neuer Versuch in 10 Minuten)", msg)
}

// fetchEPSS fragt bis zu 100 CVEs auf einmal.
func (h *Hive) fetchEPSS(ctx context.Context, ids []string) error {
	resp, err := cveGet(ctx, epssBase+"?cve="+url.QueryEscape(strings.Join(ids, ",")), nil)
	if err != nil {
		return fmt.Errorf("nicht erreichbar")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Antwort %s", resp.Status)
	}
	var out struct {
		Data []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
			Date       string `json:"date"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return fmt.Errorf("Antwort nicht lesbar")
	}
	got := map[string]bool{}
	for _, d := range out.Data {
		id := strings.ToUpper(d.CVE)
		if !cveIDRe.MatchString(id) {
			continue
		}
		e, p := epssValue(d.EPSS), epssValue(d.Percentile)
		b, _ := json.Marshal(epssData{EPSS: e, Pct: p, Date: clip(d.Date, 20)})
		h.st.lookupPut("cve:"+id, "epss", string(b))
		got[id] = true
	}
	for _, id := range ids {
		if !got[id] {
			h.st.lookupPut("cve:"+id, "epss", `{"missing":true}`)
		}
	}
	return nil
}

// epssValue: Wahrscheinlichkeit bzw. Perzentil zwischen 0 und 1; alles andere (NaN, Inf,
// negativ, zu groß) gilt als 0. Die Antwort von FIRST ist nicht vertrauenswürdig.
func epssValue(s string) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || math.IsNaN(v) || v < 0 || v > 1 {
		return 0
	}
	return v
}

// fetchNVD fragt eine CVE bei der NVD.
func (h *Hive) fetchNVD(ctx context.Context, id string) error {
	hdr := map[string]string{}
	if k := h.Extras().CVEDB.NVDKey; k != "" {
		hdr["apiKey"] = k
	}
	resp, err := cveGet(ctx, nvdBase+"?cveId="+url.QueryEscape(id), hdr)
	if err != nil {
		return fmt.Errorf("nicht erreichbar")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Antwort %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("Antwort nicht lesbar")
	}
	d, err := parseNVD(raw)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(d)
	return h.st.lookupPut("cve:"+id, "nvd", string(b))
}

type nvdMetric struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	Severity string `json:"baseSeverity"` // v2
	Data     struct {
		Version  string  `json:"version"`
		Vector   string  `json:"vectorString"`
		Score    float64 `json:"baseScore"`
		Severity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

// parseNVD liest die Antwort der CVE-API 2.0 und behält nur, was die Oberfläche zeigt.
func parseNVD(raw []byte) (nvdData, error) {
	var resp struct {
		Total int `json:"totalResults"`
		Vulns []struct {
			CVE struct {
				Published string `json:"published"`
				Descs     []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics map[string][]nvdMetric `json:"metrics"`
				Weak    []struct {
					Desc []struct {
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
				Configs []struct {
					Nodes []struct {
						Match []struct {
							Criteria string `json:"criteria"`
						} `json:"cpeMatch"`
					} `json:"nodes"`
				} `json:"configurations"`
				Refs []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nvdData{}, fmt.Errorf("Antwort nicht lesbar")
	}
	if len(resp.Vulns) == 0 {
		return nvdData{Missing: true}, nil
	}
	c := resp.Vulns[0].CVE
	d := nvdData{Published: clip(c.Published, 10)}
	for _, x := range c.Descs {
		if x.Lang == "en" {
			d.Desc = clip(x.Value, 1500)
			break
		}
	}
	// CVSS: 3.1 bevorzugt (am weitesten verbreitet), dann 4.0, 3.0, 2; je die Bewertung der NVD zuerst
	for _, key := range []string{"cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"} {
		ms := c.Metrics[key]
		if len(ms) == 0 {
			continue
		}
		sort.SliceStable(ms, func(i, j int) bool { return ms[i].Type == "Primary" && ms[j].Type != "Primary" })
		m := ms[0]
		d.CVSS, d.Version, d.Vector = m.Data.Score, clip(m.Data.Version, 10), clip(m.Data.Vector, 200)
		if math.IsNaN(d.CVSS) || d.CVSS < 0 || d.CVSS > 10 {
			d.CVSS = 0
		}
		d.Severity = clip(strings.ToUpper(nonEmptyFirst(m.Data.Severity, m.Severity)), 20)
		break
	}
	for _, w := range c.Weak {
		for _, x := range w.Desc {
			if strings.HasPrefix(x.Value, "CWE-") && len(x.Value) <= 20 && !contains(d.CWE, x.Value) && len(d.CWE) < 4 {
				d.CWE = append(d.CWE, x.Value)
			}
		}
	}
	for _, cfg := range c.Configs {
		for _, n := range cfg.Nodes {
			for _, m := range n.Match {
				// cpe:2.3:a:<hersteller>:<produkt>:…
				if p := strings.Split(m.Criteria, ":"); len(p) > 4 && d.Vendor == "" {
					d.Vendor, d.Product = clip(strings.ReplaceAll(p[3], "_", " "), 80), clip(strings.ReplaceAll(p[4], "_", " "), 80)
				}
			}
		}
	}
	for _, r := range c.Refs {
		if u, err := url.Parse(r.URL); err == nil && u.Scheme == "https" && u.Host != "" && len(r.URL) <= 300 && len(d.Refs) < 4 {
			d.Refs = append(d.Refs, r.URL)
		}
	}
	return d, nil
}

// ---- API ----

type cveStatusResp struct {
	Enabled    bool      `json:"enabled"`
	KEVCount   int       `json:"kev_count"`
	KEVVersion string    `json:"kev_version,omitempty"`
	KEVUpdated time.Time `json:"kev_updated"`
	KEVChecked time.Time `json:"kev_checked"`
	KEVError   string    `json:"kev_error,omitempty"`
	Pending    int       `json:"pending"`
	Asked      int       `json:"asked"`
	LastError  string    `json:"last_error,omitempty"`
	PausedTill time.Time `json:"paused_till,omitzero"`
}

func (h *Hive) cveStatus() cveStatusResp {
	m := h.kevMeta()
	st := cveStatusResp{Enabled: h.Extras().CVEDB.Enabled, KEVCount: m.Count, KEVVersion: m.Version, KEVUpdated: m.Updated, KEVChecked: m.Checked, KEVError: m.Error}
	cveQ.mu.Lock()
	st.Pending, st.Asked, st.LastError = len(cveQ.pending), cveQ.asked, cveQ.lastErr
	if time.Now().Before(cveQ.pause) {
		st.PausedTill = cveQ.pause
	}
	cveQ.mu.Unlock()
	return st
}

// cveInfoAPI: GET /api/cve/info?ids=CVE-…,CVE-… (höchstens 100)
func (h *Hive) cveInfoAPI(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := qctx(r)
	defer cancel()
	ids := normCVEs(strings.Split(r.URL.Query().Get("ids"), ","), 100)
	// Nachfragen bei der NVD (mit dem Schlüssel des Admins) nur für Admins: Leser könnten sonst
	// mit beliebigen Nummern die Warteschlange füllen (wie /api/lookup/ für Leser gesperrt).
	admin := false
	if h.auth != nil {
		_, role := h.auth.Who(r)
		admin = role == "admin"
	}
	writeJSON(w, map[string]any{"info": h.cveInfosQ(ctx, ids, admin), "status": h.cveStatus()})
}

// cveStatusAPI: GET /api/cve/status
func (h *Hive) cveStatusAPI(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, h.cveStatus())
}

// cveRefreshAPI: POST /api/cve/refresh (nur Admin): KEV sofort neu laden.
func (h *Hive) cveRefreshAPI(w http.ResponseWriter, r *http.Request) {
	if !h.Extras().CVEDB.Enabled {
		httpErr(w, 400, "Lückendetails sind ausgeschaltet (Einstellungen → Auswertung und KI).")
		return
	}
	select {
	case cveQ.kevNow <- struct{}{}:
	default:
	}
	writeJSON(w, map[string]any{"ok": true, "status": h.cveStatus()})
}
