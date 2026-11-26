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
// MalwareBazaar (geprüft an bazaar.abuse.ch/api, 24.11.2026): POST https://mb-api.abuse.ch/api/v1/
// mit Kopf "Auth-Key"; Nachschlagen per Formular query=get_info&hash=…; Hochladen als
// multipart mit "file" (Datei-Part) und "json_data" (Feld ohne Dateinamen, application/json:
// {"anonymous":0,"tags":[…],"delivery_method":…,"context":{…}}). Dateiarten nennt die Doku
// nicht; maßgeblich ist die Einreichungsregel (nur bestätigte Schadsoftware).
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
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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
			switch {
			case aerr != nil || !res.New:
			case x.ReportDelayMin > 0 && x.AbuseChKey != "" && (x.Bazaar.Lookup || x.Bazaar.Upload):
				h.bazaarLater(res.SHA256, f.URL) // erst nach der Wartezeit (delay.go)
			default:
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

// bazaarMaxTries: Versuche je Datei, wenn MalwareBazaar nicht erreichbar ist, gestört ist
// oder unverständlich antwortet. Jeder Versuch schlägt zuerst den Hash nach; eine Datei,
// die ein früherer Versuch schon hochgeladen hat, gilt dann als bekannt und wird nicht noch
// einmal gesendet.
const bazaarMaxTries = 3

// bazaarRetryWait: Wartezeit vor dem nächsten Versuch (1 h, 4 h, 16 h …).
func bazaarRetryWait(tries int) time.Duration {
	d := time.Hour
	for i := 0; i < tries && d < 24*time.Hour; i++ {
		d *= 4
	}
	return d
}

func (h *Hive) bazaarHandle(ctx context.Context, x Extras, sha string, si SampleInfo, srcURL string) {
	h.bazaarRun(ctx, x, sha, si, srcURL, 0)
}

// bazaarRun: ein Versuch für eine Datei; tries zählt die bisherigen Fehlversuche.
func (h *Hive) bazaarRun(ctx context.Context, x Extras, sha string, si SampleInfo, srcURL string, tries int) {
	cfg := x.Bazaar
	if !cfg.Lookup && !cfg.Upload || x.AbuseChKey == "" {
		return
	}
	subj := "hash:" + sha
	if _, _, done := h.st.lookupGet(subj, "bazaar_upload", 0); done {
		return
	}
	if !h.share.begin("bazaar") {
		// Kanal pausiert (Schlüssel abgelehnt, Störung): vormerken statt verwerfen.
		h.bazaarRequeue(sha, srcURL, tries, h.share.pausedUntil("bazaar"))
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
	// fail: Fehler protokollieren (mit Auszug der Antwort) und, wenn sinnvoll, begrenzt
	// später erneut versuchen. Fehler werden nie als erledigt gespeichert.
	fail := func(msg, reply string, retry bool) {
		e.Error = msg
		var d []string
		if reply != "" {
			d = append(d, "Antwort: "+clip(reply, 200))
		}
		switch {
		case retry && tries+1 < bazaarMaxTries:
			next := time.Now().Add(bazaarRetryWait(tries))
			if pu := h.share.pausedUntil("bazaar"); pu.After(next) {
				next = pu
			}
			h.bazaarRequeue(sha, srcURL, tries+1, next)
			d = append(d, fmt.Sprintf("neuer Versuch ab %s (%d von %d)", next.In(hiveLoc()).Format("02.01. 15:04"), tries+2, bazaarMaxTries))
		case retry:
			d = append(d, fmt.Sprintf("kein weiterer Versuch (%d von %d)", tries+1, bazaarMaxTries))
		}
		finish("error", strings.Join(d, "; "))
	}
	e.Sent = "POST " + bazaarBase + "/api/v1/ (Auth-Key: •••)\nquery=get_info&hash=" + sha
	out, reply, code, err := bazaarCall(ctx, x.AbuseChKey, "application/x-www-form-urlencoded",
		strings.NewReader(url.Values{"query": {"get_info"}, "hash": {sha}}.Encode()))
	if err != nil {
		h.share.setErr("bazaar", err.Error(), pauseFor(code))
		fail(err.Error(), reply, true)
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
		msg, retry := bazaarStatusText(qs)
		h.share.setErr("bazaar", msg, 0)
		fail(msg, reply, retry)
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
		fail(err.Error(), "", false)
		return
	}
	// Skripte tragen manchmal die Adresse oder den Namen des Ziels: nie öffentlich hochladen.
	if containsMarker(string(content), h.ownMarkers()) {
		finish("skipped", "unbekannt; enthält die eigene Adresse oder den Namen des Honeypots, nicht hochgeladen")
		return
	}
	meta, _ := json.Marshal(map[string]any{"anonymous": 0, "tags": bazaarTags(si), "delivery_method": "web_download",
		"context": map[string]string{"comment": "Collected by a honeypot from a download URL used in an attack."}})
	name := bazaarFileName(sha, srcURL, si)
	e.Sent += "\n\nPOST " + bazaarBase + "/api/v1/ (Auth-Key: •••, multipart)\njson_data=" + string(meta) +
		fmt.Sprintf("\nfile=%s (%d Byte)", name, len(content))
	body, ctype := bazaarUploadBody(meta, name, content)
	out, reply, code, err = bazaarCall(ctx, x.AbuseChKey, ctype, body)
	if err != nil {
		h.share.setErr("bazaar", err.Error(), pauseFor(code))
		fail(err.Error(), reply, true)
		return
	}
	switch qs, _ := out["query_status"].(string); qs {
	case "inserted":
		h.share.setErr("bazaar", "", 0)
		finish("ok", "hochgeladen als "+name)
	case "file_already_known":
		finish("known", "bei MalwareBazaar schon bekannt")
	default:
		msg, retry := bazaarStatusText(qs)
		h.share.setErr("bazaar", msg, 0)
		fail(msg, reply, retry)
	}
}

// bazaarUploadBody baut das Formular wie im Beispiel der Doku (bazaar.abuse.ch/api):
// "json_data" als gewöhnliches Feld ohne Dateinamen mit Content-Type application/json,
// "file" als Datei-Part (application/octet-stream).
func bazaarUploadBody(meta []byte, name string, content []byte) (*bytes.Buffer, string) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	jh := textproto.MIMEHeader{}
	jh.Set("Content-Disposition", `form-data; name="json_data"`)
	jh.Set("Content-Type", "application/json")
	pw, _ := mw.CreatePart(jh)
	pw.Write(meta)
	fw, _ := mw.CreateFormFile("file", name)
	fw.Write(content)
	mw.Close()
	return &body, mw.FormDataContentType()
}

// bazaarFileName: Dateiname für den Upload. MalwareBazaar übernimmt ihn als file_name;
// ein bloßer Hash ohne Endung sagt dort nichts. Genommen wird der letzte Teil der
// Nachlade-Adresse (bereinigt), sonst der Hash; dazu eine Endung nach Dateiart, falls keine da ist.
func bazaarFileName(sha, srcURL string, si SampleInfo) string {
	name := ""
	if u, err := url.Parse(srcURL); err == nil {
		p := u.Path
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			p = p[i+1:]
		}
		var b strings.Builder
		for _, r := range p {
			if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
				b.WriteRune(r)
			}
		}
		name = strings.Trim(b.String(), ".")
		if len(name) > 64 {
			name = name[:64]
		}
	}
	if name == "" {
		name = sha
	}
	ext := map[string]string{"elf": ".elf", "exe": ".exe", "sh": ".sh"}[fileTag(si)]
	if ext != "" && !strings.Contains(name, ".") {
		name += ext
	}
	return name
}

// bazaarStatusText: verständliche Meldung zu einem query_status von MalwareBazaar und ob
// ein späterer Versuch etwas ändern kann. Dokumentiert (bazaar.abuse.ch/api, November
// 2026) sind fürs Hochladen http_post_expected, no_api_key, user_blacklisted,
// file_already_known, inserted, file_expected; fürs Nachschlagen hash_not_found,
// illegal_hash, no_hash_provided. Die übrigen kommen bei abuse.ch-Diensten vor.
func bazaarStatusText(qs string) (string, bool) {
	switch qs {
	case "no_api_key", "unknown_auth_key", "invalid_auth_key", "missing_auth_key", "wrong_auth_key":
		return "MalwareBazaar lehnt den abuse.ch-Schlüssel ab (" + qs + "). Schlüssel unter https://auth.abuse.ch/ prüfen", true
	case "user_blacklisted":
		return "MalwareBazaar hat das Konto gesperrt (user_blacklisted). Entsperren nur über abuse.ch/Spamhaus", false
	case "inserted":
		return "MalwareBazaar hat die Datei aufgenommen (inserted)", false
	case "file_already_known":
		return "MalwareBazaar kennt die Datei schon (file_already_known)", false
	case "file_expected", "no_file":
		return "MalwareBazaar hat keine Datei erhalten (" + qs + ")", true
	case "http_post_expected":
		return "MalwareBazaar erwartet eine POST-Anfrage (http_post_expected)", false
	case "illegal_hash", "illegal_sha256_hash":
		return "MalwareBazaar hält den Hash für ungültig (" + qs + ")", false
	case "no_hash_provided", "no_sha256_hash":
		return "MalwareBazaar hat keinen Hash erhalten (" + qs + ")", false
	case "hash_not_found", "file_not_found":
		return "MalwareBazaar kennt die Datei nicht (" + qs + ")", false
	case "illegal_file", "unknown_file_type", "file_type_not_allowed":
		return "MalwareBazaar nimmt diese Dateiart nicht an (" + qs + ")", false
	case "file_too_large", "file_too_small", "empty_file":
		return "MalwareBazaar lehnt die Dateigröße ab (" + qs + ")", false
	case "illegal_tag", "unknown_tag", "illegal_tags":
		return "MalwareBazaar lehnt ein Schlagwort (Tag) ab (" + qs + ")", false
	case "illegal_delivery_method", "unknown_delivery_method":
		return "MalwareBazaar lehnt den Lieferweg ab (" + qs + ")", false
	case "rate_limited", "too_many_requests":
		return "MalwareBazaar bremst: zu viele Anfragen (" + qs + ")", true
	case "":
		return "MalwareBazaar antwortet ohne query_status", true
	}
	return "MalwareBazaar meldet einen unbekannten Status: " + clip(qs, 60), true
}

// bazaarStatusWordRe: eine Antwort, die nur aus einem Statuswort besteht (statt JSON).
var bazaarStatusWordRe = regexp.MustCompile(`^[a-z][a-z0-9_]{2,40}$`)

// bazaarReplyText: Auszug einer Antwort fürs Prüfprotokoll (gültiges UTF-8, ohne
// Steuerzeichen, Leerraum zusammengefasst, Schlüssel geschwärzt, höchstens 300 Zeichen).
func bazaarReplyText(raw []byte, key string) string {
	s := strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || r >= 0x80 && r < 0xa0 {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(string(raw), "?"))
	s = strings.Join(strings.Fields(s), " ")
	if key != "" {
		s = strings.ReplaceAll(s, key, "•••")
	}
	return clip(s, 300)
}

// bazaarCall sendet eine Anfrage und liest die Antwort als JSON-Objekt. reply ist immer
// ein bereinigter Auszug der Antwort (auch bei Fehlern), damit das Prüfprotokoll zeigt,
// was wirklich zurückkam. Bis 0.9.6 meldete eine unlesbare Antwort nur "antwortet 200 OK".
func bazaarCall(ctx context.Context, key, ctype string, body io.Reader) (out map[string]any, reply string, code int, err error) {
	req, _ := http.NewRequestWithContext(ctx, "POST", bazaarBase+"/api/v1/", body)
	req.Header.Set("Auth-Key", key)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("Accept", "application/json")
	resp, err := shareHTTP.Do(req)
	if err != nil {
		return nil, "", 0, errors.New("MalwareBazaar nicht erreichbar")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	reply = bazaarReplyText(raw, key)
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, reply, resp.StatusCode, errors.New("MalwareBazaar lehnt den abuse.ch-Schlüssel ab (" + resp.Status + "). Schlüssel unter https://auth.abuse.ch/ prüfen")
	}
	if resp.StatusCode != 200 {
		return nil, reply, resp.StatusCode, errors.New("MalwareBazaar antwortet " + resp.Status)
	}
	if out, ok := bazaarParse(raw); ok {
		return out, reply, 200, nil
	}
	t := bytes.TrimSpace(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")))
	switch {
	case len(t) == 0:
		err = errors.New("MalwareBazaar antwortet 200 OK, aber ohne Inhalt")
	case t[0] == '<':
		err = errors.New("MalwareBazaar antwortet 200 OK mit einer Webseite statt JSON (Störung oder Schutzseite vor der API)")
	default:
		err = errors.New("MalwareBazaar antwortet 200 OK, aber nicht im erwarteten Format (kein JSON-Objekt)")
	}
	return nil, reply, 200, err
}

// bazaarParse liest eine Antwort tolerant: JSON-Objekt (auch mit BOM), ein Array, dessen
// erstes Element ein Objekt mit query_status ist, oder ein bloßes Statuswort (als JSON-
// Zeichenkette oder Klartext).
func bazaarParse(raw []byte) (map[string]any, bool) {
	t := bytes.TrimSpace(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")))
	var v any
	if json.Unmarshal(t, &v) == nil {
		switch x := v.(type) {
		case map[string]any:
			return x, true
		case []any:
			if len(x) > 0 {
				if m, ok := x[0].(map[string]any); ok {
					if _, has := m["query_status"]; has {
						return m, true
					}
				}
			}
		case string:
			if bazaarStatusWordRe.MatchString(x) {
				return map[string]any{"query_status": x}, true
			}
		}
		return nil, false
	}
	if s := string(t); bazaarStatusWordRe.MatchString(s) {
		return map[string]any{"query_status": s}, true
	}
	return nil, false
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
