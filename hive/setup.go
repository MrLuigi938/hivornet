package main

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Ersteinrichtung, Update-Prüfung und Update-Auslösung.
//
// Ersteinrichtung: Gibt es noch kein Admin-Konto (und wurde keines per
// HIVE_ADMIN_PASSWORD vorgegeben), zeigt die UI statt der Anmeldung einen
// Assistenten. Wer ihn zuerst ausfüllt, legt das Passwort fest; das ist bei
// Geräten im Heimnetz üblich und der Grund, warum die UI nie ins Internet gehört.
// Sobald ein Konto existiert, ist der Weg dauerhaft geschlossen.

var setupMu sync.Mutex

func (a *Auth) NeedsSetup() bool {
	var n int
	if err := a.st.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return false // im Zweifel keinen Assistenten anbieten
	}
	return n == 0
}

func (h *Hive) setupStatus(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"needed": h.auth.NeedsSetup()}
	if out["needed"] == true { // nach der Einrichtung verrät der Endpunkt nichts mehr
		out["home"] = h.Extras().Home
	}
	writeJSON(w, out)
}

func (h *Hive) setupRun(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Requested-With") != "hivornet" { // wie bei allen schreibenden Aufrufen
		httpErr(w, 403, "fehlender Header")
		return
	}
	var req struct {
		Password string `json:"password"`
		Home     *struct {
			Lat   float64 `json:"lat"`
			Lon   float64 `json:"lon"`
			Label string  `json:"label"`
		} `json:"home"`
	}
	if readJSON(w, r, &req) != nil {
		httpErr(w, 400, "ungültige Anfrage")
		return
	}
	if !h.auth.attempt(clientIP(r)) {
		httpErr(w, 429, "zu viele Versuche, bitte später erneut")
		return
	}
	setupMu.Lock()
	defer setupMu.Unlock()
	if !h.auth.NeedsSetup() {
		httpErr(w, 409, "Hivornet ist bereits eingerichtet. Bitte anmelden.")
		return
	}
	x := h.Extras()
	if req.Home != nil {
		x.Home.Lat, x.Home.Lon, x.Home.Label = req.Home.Lat, req.Home.Lon, req.Home.Label
		if err := x.Validate(); err != nil {
			httpErr(w, 400, err.Error())
			return
		}
	}
	user := env("HIVE_ADMIN_USER", "admin")
	if err := h.auth.SetPassword(user, req.Password); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	if req.Home != nil {
		b, _ := json.Marshal(x)
		h.st.SetKV("extras", string(b))
		h.extras.mu.Lock()
		h.extras.x = x
		h.extras.mu.Unlock()
	}
	log.Printf("Ersteinrichtung abgeschlossen, Admin-Konto %q angelegt", user)
	h.auth.success(clientIP(r))
	if err := h.auth.startSession(w, r, user); err != nil {
		httpErr(w, 500, "Konto angelegt, aber die Anmeldung schlug fehl. Bitte anmelden.")
		return
	}
	writeJSON(w, map[string]string{"username": user})
}

// ---- Gespeicherte Port-Konfigurationen an neue Dienste anpassen ----

// configUpgrades: je Stufe die Dienste, die hinzukommen, sofern ihr Port frei ist.
// Stufe 1 (0.3.0): 5900 wird von "raw" zu "vnc", dazu SMTP, Telnet, RDP.
// Stufe 2 (0.3.0): UDP-Dienste SIP und SNMP, DNS zunächst aus.
// Neue Stufen nur anhängen.
var configUpgrades = [][]ListenerConfig{
	{{"smtp", 25, "emulate", true}, {"telnet", 2323, "emulate", true}, {"rdp", 3389, "emulate", true}},
	{{"sip", 5060, "emulate", true}, {"snmp", 161, "emulate", true}, {"dns", 53, "emulate", false}},
}

// upgradeSensorConfigs bringt gespeicherte Port-Konfigurationen einmal je Stufe auf
// den neuen Stand (Merker "config_level" in kv). Was der Nutzer selbst eingestellt
// hat, bleibt; ein entfernter Dienst kommt nicht wieder, weil jede Stufe nur einmal läuft.
func upgradeSensorConfigs(st *Store) {
	const key = "config_level"
	done := 0
	if v, ok := st.GetKV(key); ok {
		done, _ = strconv.Atoi(v)
	}
	if done >= len(configUpgrades) {
		return
	}
	rows, err := st.db.Query(`SELECT k, v FROM kv WHERE k = 'sensor_config' OR k LIKE 'sensor_config:%'`)
	if err != nil {
		return
	}
	cfgs := map[string]string{}
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil {
			cfgs[k] = v
		}
	}
	rows.Close()
	for k, v := range cfgs {
		var c SensorConfig
		if json.Unmarshal([]byte(v), &c) != nil {
			continue
		}
		used := map[int]bool{}
		for i, l := range c.Listeners {
			used[l.Port] = true
			if done < 1 && l.Port == 5900 && l.Service == "raw" {
				c.Listeners[i].Service = "vnc"
			}
		}
		for _, stage := range configUpgrades[done:] {
			for _, add := range stage {
				if !used[add.Port] {
					c.Listeners = append(c.Listeners, add)
					used[add.Port] = true
				}
			}
		}
		if c.Validate() != nil {
			continue
		}
		b, _ := json.Marshal(c)
		st.SetKV(k, string(b))
		log.Printf("Port-Konfiguration %q um neue Dienste ergänzt (Stufe %d bis %d)", k, done+1, len(configUpgrades))
	}
	st.SetKV(key, strconv.Itoa(len(configUpgrades)))
}

// ---- Update-Prüfung ----
//
// Zweimal am Tag fragt der Hive GitHub nach der neuesten Version, damit die
// Fußzeile darauf hinweisen kann. Es wird nichts übertragen außer der Anfrage
// selbst. Abschalten: HIVE_UPDATE_CHECK=off. Entwicklungs-Builds ("dev") prüfen nie.
// Solange das Repository privat ist, antwortet GitHub mit 404 und es erscheint kein Hinweis.

// releasesURL ist die Liste der Veröffentlichungen; in Tests überschrieben.
var releasesURL = "https://api.github.com/repos/MrLuigi938/hivornet/releases?per_page=20"

type releaseInfo struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}

type semver struct {
	n   [3]int
	pre string
	ok  bool
}

func parseSemver(s string) semver {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	core, pre, _ := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semver{}
	}
	v := semver{pre: pre, ok: true}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}
		}
		v.n[i] = n
	}
	return v
}

// newer: a ist neuer als b. Eine Vorabversion ist älter als die fertige gleicher Nummer;
// Vorabversionen untereinander vergleicht comparePre (beta.2 ist neuer als beta.1).
func (a semver) newer(b semver) bool {
	for i := range a.n {
		if a.n[i] != b.n[i] {
			return a.n[i] > b.n[i]
		}
	}
	switch {
	case a.pre == "" || b.pre == "":
		return a.pre == "" && b.pre != ""
	default:
		return comparePre(a.pre, b.pre) > 0
	}
}

// comparePre vergleicht Vorabkennungen nach Semantic Versioning (Abschnitt 11):
// Teile zwischen Punkten einzeln, Zahlen numerisch und vor Text, bei gleichem
// Anfang ist die kürzere Kennung älter (beta < beta.1 < beta.2 < beta.10 < rc.1).
func comparePre(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aerr := strconv.Atoi(as[i])
		bn, berr := strconv.Atoi(bs[i])
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				return cmp.Compare(an, bn)
			}
		case aerr == nil:
			return -1
		case berr == nil:
			return 1
		default:
			if c := strings.Compare(as[i], bs[i]); c != 0 {
				return c
			}
		}
	}
	return cmp.Compare(len(as), len(bs))
}

// Update-Kanal: "stable" sieht nur fertige Veröffentlichungen, "pre" zusätzlich
// Vorabversionen (auf GitHub als "Pre-release" markiert, Tag z. B. v0.4.0-beta.1).
const (
	channelStable = "stable"
	channelPre    = "pre"
)

// updateChannel liefert den eingestellten Kanal. Ohne Einstellung: Wer selbst eine
// Vorabversion installiert hat, bleibt auf Vorabversionen, sonst "stable".
func (h *Hive) updateChannel() string {
	if v, ok := h.st.GetKV("update_channel"); ok && (v == channelStable || v == channelPre) {
		return v
	}
	if parseSemver(version).pre != "" {
		return channelPre
	}
	return channelStable
}

// newestRelease liefert die neueste Veröffentlichung, die neuer als current ist, sonst nil.
// allowPre: auch Vorabversionen berücksichtigen (Kanal "pre").
func newestRelease(ctx context.Context, current string, allowPre bool) (*releaseInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", releasesURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := intelHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub antwortet %s", resp.Status)
	}
	var list []struct {
		Tag        string `json:"tag_name"`
		URL        string `json:"html_url"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&list); err != nil {
		return nil, err
	}
	cur := parseSemver(current)
	var best *releaseInfo
	var bestV semver
	for _, r := range list {
		v := parseSemver(r.Tag)
		if r.Draft || !v.ok || ((r.Prerelease || v.pre != "") && !allowPre) || !v.newer(cur) {
			continue
		}
		// Nur Adressen des eigenen Repositorys verlinken.
		if !strings.HasPrefix(r.URL, "https://github.com/MrLuigi938/hivornet/") {
			continue
		}
		if best == nil || v.newer(bestV) {
			best, bestV = &releaseInfo{Version: strings.TrimPrefix(r.Tag, "v"), URL: r.URL}, v
		}
	}
	return best, nil
}

type updater struct {
	mu      sync.Mutex
	newest  *releaseInfo
	checked time.Time
	lastErr string
	checkMu sync.Mutex // nur eine Prüfung gleichzeitig (Zeitplan und Knopf)
}

func (h *Hive) newerRelease() *releaseInfo {
	h.upd.mu.Lock()
	defer h.upd.mu.Unlock()
	return h.upd.newest
}

func updateCheckEnabled() bool {
	return parseSemver(version).ok && os.Getenv("HIVE_UPDATE_CHECK") != "off"
}

// runUpdateCheck fragt GitHub einmal ab und merkt sich das Ergebnis.
func (h *Hive) runUpdateCheck(ctx context.Context) {
	h.upd.checkMu.Lock()
	defer h.upd.checkMu.Unlock()
	r, err := newestRelease(ctx, version, h.updateChannel() == channelPre)
	h.upd.mu.Lock()
	defer h.upd.mu.Unlock()
	h.upd.checked = time.Now()
	if err != nil {
		h.upd.lastErr = err.Error()
		return
	}
	h.upd.newest, h.upd.lastErr = r, ""
}

func (h *Hive) checkUpdates(stop <-chan struct{}) {
	if !updateCheckEnabled() {
		return
	}
	for {
		h.runUpdateCheck(context.Background())
		select {
		case <-stop:
			return
		case <-time.After(12 * time.Hour):
		}
	}
}

// updateCheckNow: Knopf "Jetzt prüfen". Höchstens alle 10 Sekunden eine echte Anfrage,
// damit GitHub (60 Anfragen pro Stunde ohne Anmeldung) nicht sperrt.
func (h *Hive) updateCheckNow(w http.ResponseWriter, r *http.Request) {
	if !updateCheckEnabled() {
		httpErr(w, 400, updateCheckOffReason())
		return
	}
	h.upd.mu.Lock()
	recent := time.Since(h.upd.checked) < 10*time.Second
	h.upd.mu.Unlock()
	if !recent {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		h.runUpdateCheck(ctx)
		cancel()
	}
	writeJSON(w, h.updateStatus())
}

// updateSetChannel stellt den Update-Kanal um und prüft gleich neu.
func (h *Hive) updateSetChannel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Channel string `json:"channel"`
	}
	if readJSON(w, r, &req) != nil || (req.Channel != channelStable && req.Channel != channelPre) {
		httpErr(w, 400, `Kanal muss "stable" oder "pre" sein`)
		return
	}
	if err := h.st.SetKV("update_channel", req.Channel); err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	if updateCheckEnabled() {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		h.runUpdateCheck(ctx)
		cancel()
	}
	writeJSON(w, h.updateStatus())
}

func updateCheckOffReason() string {
	if !parseSemver(version).ok {
		return "Dies ist eine Entwicklungsversion; sie sucht nicht nach Updates."
	}
	return "Die Update-Prüfung ist abgeschaltet (HIVE_UPDATE_CHECK=off)."
}

// ---- Update auslösen (nur wo ein Updater eingerichtet ist, z. B. Raspberry-Pi-Image) ----
//
// Der Hive hat keine Rechte, sich selbst zu ersetzen. Er legt nur eine Datei mit
// der gewünschten Version ab (HIVE_UPDATE_REQUEST). Ein eigener Dienst mit
// Root-Rechten (tools/pi/hivornet-update) bemerkt sie, lädt die Version von der
// festen GitHub-Adresse, prüft die Prüfsumme und startet die Dienste neu.
// Ohne die Variable (Docker-Betrieb) gibt es keinen Knopf; dort: sh update.sh.

func (h *Hive) updateStatus() map[string]any {
	h.upd.mu.Lock()
	defer h.upd.mu.Unlock()
	out := map[string]any{"available": h.upd.newest, "checked": h.upd.checked, "error": h.upd.lastErr,
		"can_install": os.Getenv("HIVE_UPDATE_REQUEST") != "", "current": version,
		"channel": h.updateChannel(), "check_enabled": updateCheckEnabled()}
	if !updateCheckEnabled() {
		out["disabled_reason"] = updateCheckOffReason()
	}
	// Ergebnis des letzten Laufs, vom Updater geschrieben (liegt außerhalb des Datenordners des Hive).
	if p := os.Getenv("HIVE_UPDATE_STATUS"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			out["last_run"] = clip(strings.TrimSpace(string(b)), 300)
		}
	}
	return out
}

func (h *Hive) updateRun(w http.ResponseWriter, r *http.Request) {
	p := os.Getenv("HIVE_UPDATE_REQUEST")
	rel := h.newerRelease()
	switch {
	case p == "":
		httpErr(w, 400, "Auf diesem System wird über die Kommandozeile aktualisiert: sh update.sh")
		return
	case rel == nil || !parseSemver(rel.Version).ok:
		httpErr(w, 400, "Es ist keine neuere Version bekannt.")
		return
	}
	// Inhalt ist nur die geprüfte Versionsnummer, nie eine Adresse.
	if err := os.WriteFile(p, []byte("v"+rel.Version+"\n"), 0o644); err != nil {
		httpErr(w, 500, "Update konnte nicht angestoßen werden: "+err.Error())
		return
	}
	log.Printf("Update auf %s angefordert", rel.Version)
	writeJSON(w, map[string]any{"ok": true, "version": rel.Version})
}

// ---- Muster für alte Ereignisse nachzählen ----

// backfillPatterns trägt Muster, Werkzeuge und Nachlade-Adressen für Ereignisse nach,
// die vor Version 0.3.0 gespeichert wurden (bis einschließlich maxID). Läuft einmal
// im Hintergrund, in kleinen Transaktionen, damit der Schreiber nicht wartet.
// maxID muss vor dem Start des Schreibers ermittelt sein, sonst würde doppelt gezählt.
func backfillPatterns(st *Store, maxID int64) {
	const key = "patterns_backfilled"
	if _, done := st.GetKV(key); done {
		return
	}
	var last, total int64
	for last < maxID {
		rows, err := st.db.Query(`SELECT id, ts, service, type, data FROM events
			WHERE id > ? AND id <= ? AND type IN ('command','request','payload','client_version','download') ORDER BY id LIMIT 500`, last, maxID)
		if err != nil {
			log.Printf("Muster nachzählen: %v", err)
			return
		}
		var evs []*Event
		for rows.Next() {
			e := &Event{}
			var ms int64
			var data *string
			if rows.Scan(&e.ID, &ms, &e.Service, &e.Type, &data) != nil {
				continue
			}
			e.TS = time.UnixMilli(ms)
			if data != nil {
				e.Data = json.RawMessage(*data)
			}
			evs = append(evs, e)
		}
		rows.Close()
		if len(evs) == 0 {
			break
		}
		tx, err := st.db.Begin()
		if err != nil {
			return
		}
		for _, e := range evs {
			last = e.ID
			for _, k := range topKeys(e) {
				if k[0] == "tag" || k[0] == "tool" || k[0] == "url" {
					if _, err := tx.Exec(topUpsert, e.TS.UnixMilli()/3600000, k[0], k[1], k[2]); err != nil {
						tx.Rollback()
						log.Printf("Muster nachzählen: %v", err)
						return
					}
				}
			}
		}
		if tx.Commit() != nil {
			return
		}
		total += int64(len(evs))
		time.Sleep(50 * time.Millisecond)
	}
	st.SetKV(key, "1")
	if total > 0 {
		log.Printf("Muster für %d ältere Ereignisse nachgezählt", total)
	}
}

// ---- Top-Listen nach neuen Regeln neu zählen (Version 0.5.3) ----

// recountFields: Felder der Zähltabelle, die aus Logins, Befehlen und Anfragen entstehen.
// Seit 0.5.3 gelten neue Regeln (einstufung.go: SNMP, SIP und DNS in eigenen Feldern,
// TLS-Handshakes keine Befehle, Eingaben an der Login-Abfrage keine Zugangsdaten, eigene
// Tests nicht gezählt). Die Felder aus Verbindungen (Land, Port, IP …) bleiben.
var recountFields = []string{"username", "password", "cred", "command", "path", "useragent", "client", "tag", "tool", "url", "snmp", "sip", "dns", "ja3", "ja4", "hassh", "httpfp", "cve"}

const recountKey = "top_recounted_053"

// prepareRecount löscht die alten Zähler dieser Felder, einmalig und VOR dem Start des
// Schreibers; danach zählt recountTop alle Ereignisse bis maxID im Hintergrund neu.
// Liefert false, wenn nichts zu tun ist. Ersetzt auch backfillPatterns.
func prepareRecount(st *Store) bool {
	if _, done := st.GetKV(recountKey); done {
		return false
	}
	q := `DELETE FROM top_hourly WHERE field IN (` + strings.TrimSuffix(strings.Repeat("?,", len(recountFields)), ",") + `)`
	args := make([]any, len(recountFields))
	for i, f := range recountFields {
		args[i] = f
	}
	if _, err := st.db.Exec(q, args...); err != nil {
		log.Printf("Top-Listen neu zählen: %v", err)
		return false
	}
	st.SetKV("patterns_backfilled", "1")
	return true
}

func recountTop(st *Store, maxID int64) {
	want := map[string]bool{}
	for _, f := range recountFields {
		want[f] = true
	}
	var last, total int64
	for last < maxID {
		rows, err := st.db.Query(`SELECT id, ts, service, type, src_ip, username, password, data FROM events
			WHERE id > ? AND id <= ? AND type NOT IN ('connect','disconnect') ORDER BY id LIMIT 500`, last, maxID)
		if err != nil {
			log.Printf("Top-Listen neu zählen: %v", err)
			return
		}
		var evs []*Event
		for rows.Next() {
			e := &Event{}
			var ms int64
			var data *string
			if rows.Scan(&e.ID, &ms, &e.Service, &e.Type, &e.SrcIP, &e.Username, &e.Password, &data) != nil {
				continue
			}
			e.TS = time.UnixMilli(ms)
			if data != nil {
				e.Data = json.RawMessage(*data)
			}
			evs = append(evs, e)
		}
		rows.Close()
		if len(evs) == 0 {
			break
		}
		tx, err := st.db.Begin()
		if err != nil {
			return
		}
		for _, e := range evs {
			last = e.ID
			if ownHidden(e.SrcIP) {
				continue
			}
			for _, k := range topKeys(e) {
				if want[k[0]] {
					if _, err := tx.Exec(topUpsert, e.TS.UnixMilli()/3600000, k[0], k[1], k[2]); err != nil {
						tx.Rollback()
						log.Printf("Top-Listen neu zählen: %v", err)
						return
					}
				}
			}
		}
		if tx.Commit() != nil {
			return
		}
		total += int64(len(evs))
		time.Sleep(50 * time.Millisecond)
	}
	st.SetKV(recountKey, "1")
	log.Printf("Top-Listen für %d Ereignisse nach neuen Regeln gezählt", total)
}
