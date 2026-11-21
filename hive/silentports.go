package main

// Stille Ports: Kommt auf einem Port, den der Honeypot seit Tagen anbietet, keine einzige
// Verbindung an, obwohl gerade dieser Port im Internet ständig abgetastet wird, erreicht ihn
// vermutlich niemand. Häufigste Gründe: Der Internetanbieter sperrt ihn (Vodafone und viele
// andere bei 25 und 445), oder er ist im Router nicht weitergeleitet bzw. im Docker-Betrieb in
// der .env nicht freigegeben. Der Hive merkt sich je Sensor und Port, seit wann der Honeypot
// dort lauscht (Lebenszeichen, listeners.running), und zählt die Verbindungen aus der
// Zähltabelle (top_hourly, Feld "port"). Diese zählt über alle Sensoren zusammen; bei mehreren
// Sensoren heißt "still" also: an keinem Sensor kam etwas an.
//
// Aktiv wird nichts geprüft und nichts nach außen geschickt. Ob ein Port von außen offen ist,
// kann man auf Knopfdruck bei Shodan nachsehen (exposure.go) oder selbst mit einem
// Portprüfer im Browser testen; die UI weist nur darauf hin.
//
//   GET /api/ports/activity?sensor=…  Verbindungen je aktivem Port (7 Tage, 48 Stunden),
//                                     seit wann aktiv, Hinweis bei stillen Ports

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	kvPortSince   = "port_active_since"
	silentAfter   = 48 * time.Hour     // so lange still, dann Hinweis (häufig abgetastete Ports)
	silentRareAft = 7 * 24 * time.Hour // seltene Ports erst nach einer Woche
	fewWindow     = 7 * 24 * time.Hour
	fewMax        = 3 // häufig abgetasteter Port mit höchstens so vielen Verbindungen in 7 Tagen: "kaum"
)

// commonPorts: Ports, die im Internet laufend abgetastet werden. Auf ihnen kommen an einem
// erreichbaren Anschluss täglich Dutzende bis Tausende Verbindungen an.
var commonPorts = map[int]bool{21: true, 22: true, 23: true, 25: true, 80: true, 443: true, 445: true, 1433: true,
	1883: true, 2222: true, 2323: true, 2375: true, 3306: true, 3389: true, 5432: true, 5900: true, 6379: true,
	8080: true, 9200: true}

// ispBlocked: Ports, die Internetanbieter häufig für Privatanschlüsse sperren.
var ispBlocked = map[int]bool{25: true, 135: true, 137: true, 138: true, 139: true, 445: true}

// portActivity: seit wann ein Port aktiv ist ("sensor|port" -> ms), in der kv-Tabelle gesichert.
type portActivity struct {
	mu     sync.Mutex
	loaded bool
	since  map[string]int64
}

func (h *Hive) portSinceLocked() map[string]int64 {
	p := &h.ports
	if !p.loaded {
		p.since = map[string]int64{}
		if v, ok := h.st.GetKV(kvPortSince); ok {
			json.Unmarshal([]byte(v), &p.since)
		}
		p.loaded = true
	}
	return p.since
}

const maxTrackedPorts = 256

// trackListeners merkt sich aus dem Lebenszeichen, welche Ports laufen und seit wann.
func (h *Hive) trackListeners(hb Heartbeat, now time.Time) {
	var ls []struct {
		Port    int  `json:"port"`
		Running bool `json:"running"`
	}
	if len(hb.Listeners) == 0 || json.Unmarshal(hb.Listeners, &ls) != nil {
		return
	}
	h.ports.mu.Lock()
	defer h.ports.mu.Unlock()
	since := h.portSinceLocked()
	prefix := hb.Sensor + "|"
	running := map[string]bool{}
	changed := false
	// Audit 4: nur echte Ports und höchstens maxTrackedPorts je Sensor. Ein Sensor mit
	// gültigem Token schrieb sonst mit jedem Lebenszeichen Zehntausende Einträge in die DB.
	n := 0
	for _, l := range ls {
		if !l.Running || l.Port < 1 || l.Port > 65535 || n >= maxTrackedPorts {
			continue
		}
		n++
		k := prefix + strconv.Itoa(l.Port)
		running[k] = true
		if _, ok := since[k]; !ok {
			since[k] = now.UnixMilli()
			changed = true
		}
	}
	for k := range since {
		if strings.HasPrefix(k, prefix) && !running[k] {
			delete(since, k)
			changed = true
		}
	}
	if changed {
		b, _ := json.Marshal(since)
		h.st.SetKV(kvPortSince, string(b))
	}
}

// activeSince: seit wann der Port läuft; sensor "" = am längsten laufender Sensor. 0 = läuft nicht.
func (h *Hive) activeSince(sensor string, port int) int64 {
	h.ports.mu.Lock()
	defer h.ports.mu.Unlock()
	var best int64
	for k, v := range h.portSinceLocked() {
		s, p, _ := strings.Cut(k, "|")
		if p != strconv.Itoa(port) || sensor != "" && s != sensor {
			continue
		}
		if best == 0 || v < best {
			best = v
		}
	}
	return best
}

// PortStat: Verbindungen eines aktiven Ports.
type PortStat struct {
	Port        int    `json:"port"`
	Service     string `json:"service"`
	ActiveSince int64  `json:"active_since"` // ms; 0 = läuft gerade nicht
	Conns7d     int64  `json:"conns_7d"`
	Conns48h    int64  `json:"conns_48h"`
	LastConn    int64  `json:"last_conn"` // Beginn der letzten Stunde mit Verbindung (ms); 0 = keine in 8 Tagen
	Silent      bool   `json:"silent"`
	Text        string `json:"text,omitempty"`
}

// portCounts: Verbindungen je Port aus der Zähltabelle (7 Tage, 48 Stunden, letzte Stunde).
func (h *Hive) portCounts(now time.Time) (map[int]*PortStat, error) {
	hourNow := now.UnixMilli() / 3600000
	rows, err := h.st.db.Query(`SELECT key, hour, n FROM top_hourly WHERE field = 'port' AND hour >= ?`, hourNow-8*24)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]*PortStat{}
	for rows.Next() {
		var key string
		var hour, n int64
		if rows.Scan(&key, &hour, &n) != nil {
			continue
		}
		p, err := strconv.Atoi(key)
		if err != nil {
			continue
		}
		s := out[p]
		if s == nil {
			s = &PortStat{Port: p}
			out[p] = s
		}
		if hour > hourNow-7*24 {
			s.Conns7d += n
		}
		if hour > hourNow-48 {
			s.Conns48h += n
		}
		if ms := hour * 3600000; ms > s.LastConn {
			s.LastConn = ms
		}
	}
	return out, rows.Err()
}

// portStats: Verbindungen aller eingeschalteten Ports der Konfiguration des Sensors.
func (h *Hive) portStats(sensor string, now time.Time) ([]PortStat, error) {
	raw, _ := h.SensorConfigFor(sensor)
	var c SensorConfig
	if raw != nil {
		json.Unmarshal(raw, &c)
	}
	counts, err := h.portCounts(now)
	if err != nil {
		return nil, err
	}
	var total48h int64
	for _, s := range counts {
		total48h += s.Conns48h
	}
	direct := os.Getenv("HIVE_DIRECT_PORTS") == "1"
	out := []PortStat{}
	for _, l := range c.Listeners {
		if !l.Enabled {
			continue
		}
		s := PortStat{Port: l.Port}
		if cs := counts[l.Port]; cs != nil {
			s = *cs
		}
		s.Service = l.Service
		s.ActiveSince = h.activeSince(sensor, l.Port)
		judgePort(&s, now, total48h, direct, os.Getenv(publishedPorts[l.Port]))
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out, nil
}

// judgePort entscheidet, ob ein Port still ist, und schreibt den Hinweis. total48h: alle
// Verbindungen der letzten 48 Stunden; ist sie 0, kommt gar nichts an, dann liegt es nicht
// am einzelnen Port (siehe silentWarnings). pubHost: Port auf der NAS laut .env (Docker).
func judgePort(s *PortStat, now time.Time, total48h int64, direct bool, pubHost string) {
	if s.ActiveSince == 0 || total48h == 0 {
		return
	}
	nowMs := now.UnixMilli()
	quietFrom := s.ActiveSince
	if end := s.LastConn + 3600000; s.LastConn > 0 && end > quietFrom {
		quietFrom = min(end, nowMs)
	}
	quiet := time.Duration(nowMs-quietFrom) * time.Millisecond
	observed := time.Duration(nowMs-s.ActiveSince) * time.Millisecond
	common := commonPorts[s.Port]
	label := fmt.Sprintf("Port %d (%s)", s.Port, svcTitle(s.Service))
	var what string
	switch {
	case quiet >= silentAfter && (common || quiet >= silentRareAft):
		if s.LastConn == 0 || s.LastConn+3600000 <= s.ActiveSince {
			what = fmt.Sprintf("%s: seit %s keine einzige Verbindung", label, sinceDays(quiet))
		} else {
			what = fmt.Sprintf("%s: seit %s keine Verbindung mehr", label, sinceDays(quiet))
		}
	case common && observed >= fewWindow && s.Conns7d <= fewMax:
		what = fmt.Sprintf("%s: in 7 Tagen nur %d Verbindung%s, obwohl dieser Port sonst laufend abgetastet wird", label, s.Conns7d, map[bool]string{true: "", false: "en"}[s.Conns7d == 1])
	default:
		return
	}
	var why string
	switch {
	case direct:
		why = "im Router nicht auf dieses Gerät weitergeleitet"
	case pubHost == "":
		why = "in der .env nicht freigegeben oder im Router nicht weitergeleitet"
	default:
		why = "im Router nicht auf NAS-Port " + pubHost + " weitergeleitet"
	}
	if ispBlocked[s.Port] {
		why = "vermutlich vom Internetanbieter gesperrt (häufig bei 25 und 445) oder " + why
	} else {
		why = "vermutlich " + why
	}
	s.Silent = true
	s.Text = what + ", " + why + "."
}

// sinceDays: "3 Tagen" (Dativ, für "seit …"); unter zwei Tagen in Stunden.
func sinceDays(d time.Duration) string {
	if d < 48*time.Hour {
		return fmt.Sprintf("%d Stunden", int(d.Hours()))
	}
	return fmt.Sprintf("%d Tagen", int(d.Hours()/24))
}

// svcTitle: Dienstname wie in der Web-UI (charts.js: svcName), für Hinweise.
func svcTitle(s string) string {
	if t, ok := map[string]string{"http": "HTTP", "https": "HTTPS", "dockerapi": "Docker-API", "ftp": "FTP", "redis": "Redis",
		"mysql": "MySQL", "ssh-tarpit": "SSH-Tarpit", "raw": "Rohdaten", "telnet": "Telnet", "smtp": "SMTP", "vnc": "VNC",
		"rdp": "RDP", "sip": "SIP", "snmp": "SNMP", "dns": "DNS", "adb": "ADB", "mqtt": "MQTT", "postgres": "PostgreSQL",
		"elasticsearch": "Elasticsearch", "ollama": "Ollama", "kubernetes": "Kubernetes"}[s]; ok {
		return t
	}
	return s
}

// silentWarnings: Hinweise für die Seite System (alle Sensoren mit eigener Konfiguration und
// der Standard; gleiche Ports nur einmal).
func (h *Hive) silentWarnings(now time.Time) []warning {
	sensors := []string{""}
	for _, s := range h.sensors.All() {
		if _, own := h.SensorConfigFor(s.Sensor); own {
			sensors = append(sensors, s.Sensor)
		}
	}
	seen := map[int]bool{}
	var out []warning
	var anyLong bool
	for _, sensor := range sensors {
		stats, err := h.portStats(sensor, now)
		if err != nil {
			return nil
		}
		for _, s := range stats {
			if s.ActiveSince > 0 && now.UnixMilli()-s.ActiveSince >= silentAfter.Milliseconds() {
				anyLong = true
			}
			if s.Silent && !seen[s.Port] {
				seen[s.Port] = true
				out = append(out, warning{"warn", s.Text + " Prüfen oder abschalten unter Einstellungen → Honeypot → Ports und Modi."})
			}
		}
	}
	if anyLong && len(out) == 0 {
		if counts, err := h.portCounts(now); err == nil {
			var total int64
			for _, s := range counts {
				total += s.Conns48h
			}
			if total == 0 {
				out = append(out, warning{"warn", "Seit 48 Stunden kam auf keinem Port des Honeypots eine Verbindung an. Ist der Anschluss online und sind die Ports im Router weitergeleitet?"})
			}
		}
	}
	if w := h.cowrieSilentWarning(now); w != nil {
		out = append(out, *w)
	}
	return out
}

// cowrieSilentAfter: so lange darf der SSH-Port von Cowrie (22) still sein, während andere Ports
// Verbindungen bekommen. Port 22 wird sonst laufend abgetastet (Dutzende Verbindungen je Tag).
const cowrieSilentAfter = 6 * time.Hour

// cowrieSilentWarning: Cowrie lauscht (die Hinweise zu den Sensorports erfassen nur den Honeypot),
// aber auf Port 22 kommt seit Stunden nichts mehr an, obwohl andere Ports noch Verbindungen sehen.
// Dann liegt es am Port selbst: Weiterleitung im Router, Sperre des Anbieters oder die Drossel
// der Firewall. Nur wenn Port 22 vorher lebhaft war (neue Installation: kein Hinweis).
func (h *Hive) cowrieSilentWarning(now time.Time) *warning {
	if h.cowrie == nil {
		return nil
	}
	counts, err := h.portCounts(now)
	if err != nil {
		return nil
	}
	s := counts[22]
	if s == nil || s.Conns7d < 50 {
		return nil
	}
	nowMs := now.UnixMilli()
	quiet := time.Duration(nowMs-(s.LastConn+3600000)) * time.Millisecond
	if quiet < cowrieSilentAfter {
		return nil
	}
	others := false
	for port, o := range counts {
		if port != 22 && port != 23 && nowMs-(o.LastConn+3600000) < cowrieSilentAfter.Milliseconds() {
			others = true
		}
	}
	if !others {
		return nil // es kommt überall nichts an: kein Fehler von Port 22
	}
	return &warning{"warn", fmt.Sprintf("SSH (Cowrie, Port 22): seit %s keine Verbindung mehr, obwohl auf anderen Ports "+
		"Verbindungen ankommen. Mögliche Ursachen: Port 22 im Router nicht (mehr) weitergeleitet, vom Internetanbieter "+
		"gesperrt oder die Drossel gegen Dauer-Brute-Force. Zum Prüfen die Drossel kurz ausschalten (Einstellungen → "+
		"Dauer-Brute-Force) und Port 22 von außen (Mobilfunk) testen.", sinceDays(quiet))}
}

func (h *Hive) portActivityAPI(w http.ResponseWriter, r *http.Request) {
	stats, err := h.portStats(clip(r.URL.Query().Get("sensor"), 64), time.Now())
	if err != nil {
		httpErr(w, 500, "Verbindungszahlen nicht lesbar")
		return
	}
	writeJSON(w, map[string]any{"ports": stats, "silent_after_h": int(silentAfter.Hours()), "direct_ports": os.Getenv("HIVE_DIRECT_PORTS") == "1"})
}

// cowrieLast: Zeitpunkt des letzten Cowrie-Ereignisses. Der Zähler im Speicher ist nach jedem
// Neustart des Hive leer (Null); dann gilt die letzte SSH-Verbindung der letzten 30 Tage aus der
// Datenbank. Ohne das fehlten die Hinweise "kein Cowrie-Ereignis" und die Anzeige nach einem
// Neustart.
func (h *Hive) cowrieLast() (bool, time.Time) {
	found, last := h.cowrie.Status()
	if last.IsZero() {
		var ms sql.NullInt64
		h.st.db.QueryRow(`SELECT ts FROM events WHERE service = 'ssh' AND ts >= ? ORDER BY ts DESC LIMIT 1`,
			time.Now().Add(-30*24*time.Hour).UnixMilli()).Scan(&ms)
		if ms.Valid {
			last = time.UnixMilli(ms.Int64)
		}
	}
	return found, last
}
