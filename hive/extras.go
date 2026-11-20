package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Extras sind die Einstellungen der Zusatzfunktionen: Standort für die Karte,
// Benachrichtigungen, KI-Auswertung und AbuseIPDB. Sie liegen als ein JSON-Objekt
// unter dem Schlüssel "extras" in der Tabelle kv.
//
// Geheimnisse (Token, Schlüssel) verlassen den Hive nie wieder: Die API liefert
// sie leer zurück und meldet nur, ob einer gesetzt ist (Feld "secrets"). Beim
// Speichern bedeutet ein leerer Wert "behalten" und "-" "löschen".
type Extras struct {
	Home struct {
		Lat   float64 `json:"lat"`
		Lon   float64 `json:"lon"`
		Label string  `json:"label"`
	} `json:"home"`
	Notify       NotifyConfig      `json:"notify"`
	AI           AIConfig          `json:"ai"`
	AbuseIPDBKey string            `json:"abuseipdb_key"`
	GreyNoiseKey string            `json:"greynoise_key"` // optional; ohne Schlüssel geht die Community-API mit kleinem Kontingent
	AbuseChKey   string            `json:"abusech_key"`   // URLhaus und MalwareBazaar (abusech.go)
	Own          OwnNets           `json:"own"`           // eigene Netze (ownnet.go)
	AbuseReport  AbuseReportConfig `json:"abuse_report"`  // automatische Meldung (abusereport.go)
	Mimic        MimicConfig       `json:"mimic"`         // Antworten vom Sprachmodell für Unbekanntes (mimic.go)
	CVEDB        CVEDBConfig       `json:"cvedb"`         // Lückendetails aus KEV, NVD und EPSS (cvedb.go)
	// Weitergabe an die Community (share.go, samplecollect.go, dshield.go)
	URLhausReport URLhausReportConfig `json:"urlhaus_report"`
	Samples       SampleCollectConfig `json:"samples"`
	Bazaar        BazaarConfig        `json:"bazaar"`
	DShield       DShieldConfig       `json:"dshield"`
}

type NotifyConfig struct {
	Enabled       bool   `json:"enabled"`
	NtfyURL       string `json:"ntfy_url"` // vollständige Themen-Adresse, z. B. https://ntfy.sh/mein-thema
	NtfyToken     string `json:"ntfy_token"`
	TelegramToken string `json:"telegram_token"`
	TelegramChat  string `json:"telegram_chat"`
	WebhookURL    string `json:"webhook_url"` // bekommt JSON {title, text, kind, ip, time}
	OnLogin       bool   `json:"on_login"`    // erfolgreicher Login (Cowrie)
	OnDownload    bool   `json:"on_download"`
	OnCommand     bool   `json:"on_command"`    // erster Befehl einer Sitzung
	OnSevere      bool   `json:"on_severe"`     // Muster mit Schweregrad 3 (Nachladen, Miner, ...)
	OnWarning     bool   `json:"on_warning"`    // kritische Systemwarnung
	WeeklyReport  bool   `json:"weekly_report"` // Wochenbericht montags (weekly.go)
	OnSpike       bool   `json:"on_spike"`      // ungewöhnlich viele Verbindungen je Dienst (insights.go)
	MaxPerHour    int    `json:"max_per_hour"`
}

type AIConfig struct {
	Enabled bool   `json:"enabled"`
	BaseURL string `json:"base_url"` // OpenAI-kompatibel, z. B. http://192.168.1.5:11434/v1 oder https://openrouter.ai/api/v1
	Model   string `json:"model"`
	APIKey  string `json:"api_key"`
}

func defaultExtras() Extras {
	var x Extras
	// Ohne Angabe liegt das Ziel der Angriffslinien in der Mitte Deutschlands.
	x.Home.Lat, x.Home.Lon, x.Home.Label = 51.1, 10.4, "Honeypot"
	x.Notify.OnLogin, x.Notify.OnDownload, x.Notify.OnSevere, x.Notify.OnWarning = true, true, true, true
	x.Notify.MaxPerHour = 20
	x.Own.Private = true
	x.AbuseReport = defaultAbuseReport()
	x.Mimic = defaultMimic()
	x.CVEDB.Enabled = true // es gehen nur CVE-Nummern hinaus
	defaultShare(&x)
	return x
}

// secretFields: Name in der API -> Zeiger auf das Feld.
func (x *Extras) secretFields() map[string]*string {
	return map[string]*string{
		"ntfy_token": &x.Notify.NtfyToken, "telegram_token": &x.Notify.TelegramToken,
		"ai_api_key": &x.AI.APIKey, "mimic_api_key": &x.Mimic.APIKey, "abuseipdb_key": &x.AbuseIPDBKey, "greynoise_key": &x.GreyNoiseKey, "abusech_key": &x.AbuseChKey,
		"nvd_key":     &x.CVEDB.NVDKey,
		"dshield_key": &x.DShield.APIKey,
	}
}

func checkURL(name, v string) error {
	if v == "" {
		return nil
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || len(v) > 500 {
		return fmt.Errorf("%s: bitte eine vollständige Adresse mit http:// oder https:// angeben", name)
	}
	return nil
}

func (x *Extras) Validate() error {
	if x.Home.Lat < -90 || x.Home.Lat > 90 || x.Home.Lon < -180 || x.Home.Lon > 180 {
		return fmt.Errorf("Standort: Breite -90 bis 90, Länge -180 bis 180")
	}
	x.Home.Label = clip(strings.TrimSpace(x.Home.Label), 40)
	for name, v := range map[string]string{"ntfy-Adresse": x.Notify.NtfyURL, "Webhook-Adresse": x.Notify.WebhookURL, "KI-Adresse": x.AI.BaseURL, "Adresse für Sprachmodell-Antworten": x.Mimic.BaseURL} {
		if err := checkURL(name, v); err != nil {
			return err
		}
	}
	if x.Notify.MaxPerHour < 1 || x.Notify.MaxPerHour > 500 {
		return fmt.Errorf("Benachrichtigungen pro Stunde: 1 bis 500")
	}
	if len(x.Notify.TelegramChat) > 64 || len(x.AI.Model) > 200 {
		return fmt.Errorf("Eingabe zu lang")
	}
	for name, p := range x.secretFields() {
		if len(*p) > 500 || strings.ContainsAny(*p, "\r\n") {
			return fmt.Errorf("%s ist ungültig", name)
		}
	}
	if err := x.Own.validate(); err != nil {
		return err
	}
	if err := x.AbuseReport.validate(); err != nil {
		return err
	}
	if x.AI.Enabled && (x.AI.BaseURL == "" || x.AI.Model == "") {
		return fmt.Errorf("KI-Auswertung braucht Adresse und Modell")
	}
	if err := x.Mimic.validate(x.AI); err != nil {
		return err
	}
	if err := x.validateShare(); err != nil {
		return err
	}
	return nil
}

// extrasCache hält die Einstellungen im Speicher (sie werden bei jedem Ereignis gebraucht).
type extrasCache struct {
	mu sync.RWMutex
	x  Extras
}

func (h *Hive) loadExtras() {
	x := defaultExtras()
	if v, ok := h.st.GetKV("extras"); ok {
		json.Unmarshal([]byte(v), &x)
	}
	h.extras.mu.Lock()
	h.extras.x = x
	h.extras.mu.Unlock()
	setOwnNets(x.Own)
}

func (h *Hive) Extras() Extras {
	h.extras.mu.RLock()
	defer h.extras.mu.RUnlock()
	return h.extras.x
}

func (h *Hive) getExtras(w http.ResponseWriter, r *http.Request) {
	x := h.Extras()
	set := map[string]bool{}
	for name, p := range x.secretFields() {
		set[name] = *p != ""
		*p = ""
	}
	writeJSON(w, map[string]any{"extras": x, "secrets": set, "notify_status": h.notifier.Status()})
}

func (h *Hive) putExtras(w http.ResponseWriter, r *http.Request) {
	x := h.Extras()
	old := x
	if err := readJSON(w, r, &x); err != nil {
		httpErr(w, 400, "ungültige Anfrage")
		return
	}
	oldSecrets := old.secretFields()
	for name, p := range x.secretFields() {
		switch strings.TrimSpace(*p) {
		case "":
			*p = *oldSecrets[name]
		case "-":
			*p = ""
		}
	}
	if err := x.Validate(); err != nil {
		httpErr(w, 400, err.Error())
		return
	}
	b, _ := json.Marshal(x)
	if err := h.st.SetKV("extras", string(b)); err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	h.extras.mu.Lock()
	h.extras.x = x
	h.extras.mu.Unlock()
	setOwnNets(x.Own)
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- Zwischenspeicher für Abfragen bei Dritten (AbuseIPDB, KI-Auswertung) ----

// lookupGet liefert einen gespeicherten Eintrag, wenn er jünger als maxAge ist.
func (s *Store) lookupGet(subject, source string, maxAge time.Duration) (string, time.Time, bool) {
	var data string
	var ms int64
	if s.db.QueryRow(`SELECT data, fetched FROM lookups WHERE subject=? AND source=?`, subject, source).Scan(&data, &ms) != nil {
		return "", time.Time{}, false
	}
	t := time.UnixMilli(ms)
	if maxAge > 0 && time.Since(t) > maxAge {
		return "", t, false
	}
	return data, t, true
}

func (s *Store) lookupPut(subject, source, data string) error {
	_, err := s.db.Exec(`INSERT INTO lookups(subject, source, fetched, data) VALUES(?,?,?,?)
		ON CONFLICT(subject, source) DO UPDATE SET fetched=excluded.fetched, data=excluded.data`,
		subject, source, time.Now().UnixMilli(), data)
	return err
}
