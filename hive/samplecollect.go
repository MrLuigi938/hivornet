package main

// Dateien sammeln: Der Hive holt die Datei einer Nachlade-Adresse selbst (safefetch.go),
// legt sie in die Quarantäne und wertet sie statisch aus (sample.go). Danach optional
// MalwareBazaar: Hash nachschlagen, unbekannte Schadprogramme hochladen.
//
// Grenzen: Downloads je Tag und je Server und Tag, Größe je Datei, Platz insgesamt,
// Aufbewahrung in Tagen. Jede Adresse wird höchstens einmal am Tag versucht, eine
// erfolgreich geholte nie wieder.
//
// Der Hive verrät dabei dem Server des Angreifers seine öffentliche IP-Adresse (die der
// Angreifer ohnehin kennt). Der User-Agent ist der eines gewöhnlichen Werkzeugs (wget).
//
// MalwareBazaar (Stand bazaar.abuse.ch/api, November 2026): POST https://mb-api.abuse.ch/api/v1/
// mit Kopf "Auth-Key"; Nachschlagen per Formular query=get_info&hash=…; Hochladen als
// multipart mit "file" und "json_data" ({"anonymous":0,"tags":[…],"delivery_method":…}).
// Regeln: nur bestätigte Schadsoftware, keine Adware, nur frische Dateien (höchstens 10 Tage).
// Hochgeladen werden deshalb nur Programme (ELF, PE) und Skripte mit eindeutig schädlichen
// Mustern, nur frisch geholte, nie Text, HTML oder Archive.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type sampleFetchResult struct {
	Status  string `json:"status"` // ok | error
	SHA256  string `json:"sha256,omitempty"`
	Error   string `json:"error,omitempty"`
	FileTag string `json:"file_tag,omitempty"` // elf, exe, sh (für URLhaus)
	// Malware: Die Datei erfüllt die Regeln für MalwareBazaar (bazaarEligible). Nur dann gilt
	// die Adresse für URLhaus als bestätigt (Audit 4).
	Malware bool `json:"malware,omitempty"`
}

type quarantineMeta struct {
	URL         string `json:"url"`
	Host        string `json:"host"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type,omitempty"`
	Fetched     int64  `json:"fetched"`
}

func (h *Hive) quarantineDir() string {
	h.share.mu.Lock()
	d := h.share.dir
	h.share.mu.Unlock()
	if d != "" {
		return d
	}
	if v := os.Getenv("HIVE_QUARANTINE_DIR"); v != "" {
		return v
	}
	if h.dbPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(h.dbPath), "quarantine")
}

func fileTag(si SampleInfo) string {
	switch {
	case strings.HasPrefix(si.Type, "ELF"):
		return "elf"
	case strings.HasPrefix(si.Type, "Windows"):
		return "exe"
	case si.Type == "Skript":
		return "sh"
	}
	return ""
}

// collectSample versucht eine Adresse; false = Tageslimit erreicht (Runde beenden).
func (h *Hive) collectSample(ctx context.Context, x Extras, f urlFinding) bool {
	cfg := x.Samples
	dir := h.quarantineDir()
	if dir == "" {
		h.share.skip(f.URL, "kein Ordner für die Quarantäne")
		return false
	}
	own := h.ownPublicIP()
	u, err := url.Parse(f.URL)
	if err != nil {
		h.share.skip(f.URL, "Adresse unlesbar")
		return true
	}
	if why := fetchURLProblem(u, own); why != "" {
		h.share.skip(f.URL, "wird nicht geholt: "+why) // ftp, tftp, Zugangsdaten
		return true
	}
	subj := urlSubject(f.URL)
	if v, _, ok := h.st.lookupGet(subj, "sample_fetch", 0); ok {
		var r sampleFetchResult
		json.Unmarshal([]byte(v), &r)
		if r.Status == "ok" {
			return true // schon geholt (steht im Protokoll)
		}
		if _, _, recent := h.st.lookupGet(subj, "sample_fetch", 24*time.Hour); recent {
			return true // in den letzten 24 Stunden vergeblich versucht (steht im Protokoll)
		}
	}
	day := time.Now().Add(-24 * time.Hour)
	if h.share.count("sample", day, func(shareLogEntry) bool { return true }) >= cfg.DailyLimit {
		h.share.skipLater(f.URL, "Tageslimit erreicht; wird später versucht")
		return false
	}
	host := strings.ToLower(u.Hostname())
	if h.share.count("sample", day, func(e shareLogEntry) bool { return e.Host == host }) >= cfg.PerHostDaily {
		h.share.skipLater(f.URL, "Limit je Server und Tag erreicht; wird später versucht")
		return true
	}
	// Platz insgesamt vor jedem Download prüfen, nicht nur bei der stündlichen Aufräumrunde:
	// sonst wüchse die Quarantäne um bis zu Tageslimit × Größe je Datei über die Grenze.
	maxBytes := int64(cfg.MaxMB) << 20
	if _, total := quarantineScan(dir); total+maxBytes > int64(cfg.MaxTotalMB)<<20 {
		h.cleanupQuarantineRes(cfg, true, maxBytes)
		if _, total = quarantineScan(dir); total+maxBytes > int64(cfg.MaxTotalMB)<<20 {
			h.share.setErr("sample", "Quarantäne voll", 0)
			h.share.skipLater(f.URL, "Quarantäne voll; wird später versucht")
			return false
		}
	}
	fetcher := newSafeFetcher(own, cfg.UserAgent, maxBytes)
	res, err := fetcher.fetchTo(ctx, f.URL, dir)
	e := shareLogEntry{Time: time.Now(), Subject: f.URL, Host: host}
	var r sampleFetchResult
	if err != nil {
		e.Status, e.Error = "error", err.Error()
		r = sampleFetchResult{Status: "error", Error: clip(err.Error(), 200)}
	} else {
		e.Status, e.SHA256 = "ok", res.SHA256
		r = sampleFetchResult{Status: "ok", SHA256: res.SHA256}
		if !res.New {
			e.Detail = "schon in der Quarantäne"
		}
		meta, _ := json.Marshal(quarantineMeta{URL: clip(f.URL, 500), Host: host, Size: res.Size, ContentType: res.ContentType, Fetched: time.Now().UnixMilli()})
		h.st.lookupPut("qsample:"+res.SHA256, "quarantine", string(meta))
		si, aerr := h.loadSample(res.SHA256)
		if aerr == nil {
			r.FileTag = fileTag(si)
			r.Malware = bazaarEligible(si)
			e.Detail = strings.TrimSpace(si.Type + " " + si.Arch + " " + e.Detail)
		}
		defer func() {
			if aerr == nil && res.New {
				h.bazaarHandle(ctx, x, res.SHA256, si, f.URL)
			}
		}()
	}
	h.share.add("sample", e)
	b, _ := json.Marshal(r)
	h.st.lookupPut(subj, "sample_fetch", string(b))
	return true
}

// ---- Quarantäne ----

type quarantineFile struct {
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Time    int64  `json:"time"`
	Host    string `json:"host,omitempty"`
	URL     string `json:"url,omitempty"`
	Type    string `json:"type,omitempty"`
	Arch    string `json:"arch,omitempty"`
	Bazaar  string `json:"bazaar,omitempty"`
	Pattern int    `json:"patterns,omitempty"`
}

// quarantineScan: reguläre Dateien mit SHA-256 als Namen, neueste zuerst.
func quarantineScan(dir string) ([]os.FileInfo, int64) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0
	}
	var out []os.FileInfo
	var total int64
	for _, de := range ents {
		fi, err := de.Info()
		if err != nil || !fi.Mode().IsRegular() || !sha256Re.MatchString(de.Name()) {
			continue
		}
		out = append(out, fi)
		total += fi.Size()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModTime().After(out[j].ModTime()) })
	return out, total
}

func (h *Hive) quarantineList() ([]quarantineFile, int64) {
	dir := h.quarantineDir()
	files := []quarantineFile{}
	if dir == "" {
		return files, 0
	}
	fis, total := quarantineScan(dir)
	for _, fi := range fis[:min(len(fis), 100)] {
		q := quarantineFile{SHA256: fi.Name(), Size: fi.Size(), Time: fi.ModTime().UnixMilli()}
		if v, _, ok := h.st.lookupGet("qsample:"+q.SHA256, "quarantine", 0); ok {
			var m quarantineMeta
			if json.Unmarshal([]byte(v), &m) == nil {
				q.Host, q.URL = m.Host, m.URL
			}
		}
		if v, _, ok := h.st.lookupGet("sample:"+q.SHA256, "sample", 0); ok {
			var si SampleInfo
			if json.Unmarshal([]byte(v), &si) == nil {
				q.Type, q.Arch, q.Pattern = si.Type, si.Arch, len(si.Patterns)
			}
		}
		if v, _, ok := h.st.lookupGet("hash:"+q.SHA256, "bazaar_upload", 0); ok {
			q.Bazaar = v
		}
		files = append(files, q)
	}
	return files, total
}

// cleanupQuarantine löscht alte Dateien und, wenn der Platz nicht reicht, die ältesten.
// Ohne force höchstens einmal je Stunde.
func (h *Hive) cleanupQuarantine(cfg SampleCollectConfig, force bool) {
	h.cleanupQuarantineRes(cfg, force, 0)
}

// cleanupQuarantineRes wie cleanupQuarantine; reserve: so viel Platz bleibt danach frei.
func (h *Hive) cleanupQuarantineRes(cfg SampleCollectConfig, force bool, reserve int64) {
	dir := h.quarantineDir()
	if dir == "" {
		return
	}
	h.share.mu.Lock()
	if !force && time.Since(h.share.cleaned) < time.Hour {
		h.share.mu.Unlock()
		return
	}
	h.share.cleaned = time.Now()
	h.share.mu.Unlock()
	// Reste abgebrochener Downloads
	if ents, err := os.ReadDir(dir); err == nil {
		for _, de := range ents {
			if fi, err := de.Info(); err == nil && strings.HasPrefix(de.Name(), ".part-") && time.Since(fi.ModTime()) > time.Hour {
				os.Remove(filepath.Join(dir, de.Name()))
			}
		}
	}
	fis, total := quarantineScan(dir)
	limit := int64(cfg.MaxTotalMB) << 20
	cut := time.Now().AddDate(0, 0, -cfg.KeepDays)
	for i := len(fis) - 1; i >= 0; i-- { // älteste zuerst
		fi := fis[i]
		if fi.ModTime().Before(cut) || total+reserve > limit {
			if os.Remove(filepath.Join(dir, fi.Name())) == nil {
				total -= fi.Size()
			}
		}
	}
}

// ---- MalwareBazaar ----

// severePatterns: Muster, die ein Skript eindeutig als Schadsoftware ausweisen.
var severePatterns = map[string]bool{"download_exec": true, "miner": true, "iot_botnet": true, "kill_rivals": true,
	"persist_cron": true, "persist_ssh": true}

// bazaarEligible: Darf die Datei hochgeladen werden (nur bestätigte Schadsoftware)?
func bazaarEligible(si SampleInfo) bool {
	if si.Mismatch || si.Truncated || si.Size == 0 {
		return false
	}
	switch fileTag(si) {
	case "elf", "exe":
		return true
	case "sh":
		for _, p := range si.Patterns {
			if severePatterns[p.Key] {
				return true
			}
		}
	}
	return false
}

func bazaarTags(si SampleInfo) []string {
	tags := []string{"honeypot"}
	if t := fileTag(si); t != "" {
		tags = append(tags, t)
	}
	if si.Arch != "" && !strings.HasPrefix(si.Arch, "unbekannt") {
		a, _, _ := strings.Cut(si.Arch, " ")
		if a = strings.ToLower(cleanTag(a)); a != "" {
			tags = append(tags, a)
		}
	}
	if si.Packed != "" {
		tags = append(tags, strings.ToLower(cleanTag(si.Packed)))
	}
	return tags
}

func (h *Hive) bazaarHandle(ctx context.Context, x Extras, sha string, si SampleInfo, srcURL string) {
	cfg := x.Bazaar
	if !cfg.Lookup && !cfg.Upload || x.AbuseChKey == "" || !h.share.begin("bazaar") {
		return
	}
	subj := "hash:" + sha
	if _, _, done := h.st.lookupGet(subj, "bazaar_upload", 0); done {
		return
	}
	e := shareLogEntry{Time: time.Now(), Subject: sha, SHA256: sha}
	if u, err := url.Parse(srcURL); err == nil {
		e.Host = u.Hostname()
	}
	finish := func(status, detail string) {
		e.Status, e.Detail = status, detail
		h.share.add("bazaar", e)
		if status != "error" {
			h.st.lookupPut(subj, "bazaar_upload", status)
		}
	}
	out, code, err := bazaarCall(ctx, x.AbuseChKey, "application/x-www-form-urlencoded",
		strings.NewReader(url.Values{"query": {"get_info"}, "hash": {sha}}.Encode()))
	if err != nil {
		h.share.setErr("bazaar", err.Error(), pauseFor(code))
		e.Error = err.Error()
		finish("error", "")
		return
	}
	switch qs, _ := out["query_status"].(string); qs {
	case "ok":
		sig := ""
		if d, ok := out["data"].([]any); ok && len(d) > 0 {
			if m, ok := d[0].(map[string]any); ok {
				sig, _ = m["signature"].(string)
			}
		}
		finish("known", strings.TrimSpace("bei MalwareBazaar bekannt "+clip(sig, 60)))
		return
	case "hash_not_found":
	default:
		e.Error = bazaarStatusText(qs)
		h.share.setErr("bazaar", e.Error, 0)
		finish("error", "")
		return
	}
	switch {
	case !cfg.Upload:
		finish("skipped", "unbekannt; Hochladen ist aus")
		return
	case !bazaarEligible(si):
		finish("skipped", "unbekannt; kein eindeutiges Schadprogramm, nicht hochgeladen")
		return
	case cfg.DryRun:
		finish("dry", "würde hochladen, Tags: "+strings.Join(bazaarTags(si), ", "))
		return
	}
	content, err := readQuarantine(h.quarantineDir(), sha)
	if err != nil {
		e.Error = err.Error()
		finish("error", "")
		return
	}
	// Skripte tragen manchmal die Adresse oder den Namen des Ziels: nie öffentlich hochladen.
	if containsMarker(string(content), h.ownMarkers()) {
		finish("skipped", "unbekannt; enthält die eigene Adresse oder den Namen des Honeypots, nicht hochgeladen")
		return
	}
	meta, _ := json.Marshal(map[string]any{"anonymous": 0, "tags": bazaarTags(si), "delivery_method": "web_download",
		"context": map[string]string{"comment": "Collected by a honeypot from a download URL used in an attack."}})
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	jh := textproto.MIMEHeader{}
	jh.Set("Content-Disposition", `form-data; name="json_data"`)
	jh.Set("Content-Type", "application/json")
	pw, _ := mw.CreatePart(jh)
	pw.Write(meta)
	fw, _ := mw.CreateFormFile("file", sha)
	fw.Write(content)
	mw.Close()
	out, code, err = bazaarCall(ctx, x.AbuseChKey, mw.FormDataContentType(), &body)
	if err != nil {
		h.share.setErr("bazaar", err.Error(), pauseFor(code))
		e.Error = err.Error()
		finish("error", "")
		return
	}
	switch qs, _ := out["query_status"].(string); qs {
	case "inserted":
		h.share.setErr("bazaar", "", 0)
		finish("ok", "hochgeladen")
	case "file_already_known":
		finish("known", "bei MalwareBazaar schon bekannt")
	default:
		e.Error = bazaarStatusText(qs)
		h.share.setErr("bazaar", e.Error, 0)
		finish("error", "")
	}
}

// bazaarStatusText: verständliche Meldung zu einem query_status von MalwareBazaar.
func bazaarStatusText(qs string) string {
	switch qs {
	case "no_api_key", "unknown_auth_key", "invalid_auth_key", "missing_auth_key":
		return "MalwareBazaar lehnt den abuse.ch-Schlüssel ab (" + qs + "). Schlüssel unter https://auth.abuse.ch/ prüfen"
	case "user_blacklisted":
		return "MalwareBazaar hat das Konto gesperrt (user_blacklisted)"
	}
	return "MalwareBazaar: " + clip(qs, 60)
}

func bazaarCall(ctx context.Context, key, ctype string, body io.Reader) (map[string]any, int, error) {
	req, _ := http.NewRequestWithContext(ctx, "POST", bazaarBase+"/api/v1/", body)
	req.Header.Set("Auth-Key", key)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("Accept", "application/json")
	resp, err := shareHTTP.Do(req)
	if err != nil {
		return nil, 0, errors.New("MalwareBazaar nicht erreichbar")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	var out map[string]any
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, resp.StatusCode, errors.New("MalwareBazaar lehnt den abuse.ch-Schlüssel ab (" + resp.Status + "). Schlüssel unter https://auth.abuse.ch/ prüfen")
	}
	if resp.StatusCode != 200 || json.Unmarshal(raw, &out) != nil {
		return nil, resp.StatusCode, errors.New("MalwareBazaar antwortet " + resp.Status)
	}
	return out, 200, nil
}

// readQuarantine liest eine Datei der Quarantäne (nur reguläre Dateien, Hash geprüft).
func readQuarantine(dir, sha string) ([]byte, error) {
	if dir == "" || !sha256Re.MatchString(sha) {
		return nil, errNoSample
	}
	p := filepath.Join(dir, sha)
	lst, err := os.Lstat(p)
	if err != nil || !lst.Mode().IsRegular() {
		return nil, errNoSample
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, errNoSample
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != sha {
		return nil, errors.New("Datei verändert (Hash passt nicht)")
	}
	return b, nil
}
