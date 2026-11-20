package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Sensor-Konfiguration: gleiche Struktur wie im Honeypot (config.go).
type ListenerConfig struct {
	Service string `json:"service"`
	Port    int    `json:"port"`
	Mode    string `json:"mode"`
	Enabled bool   `json:"enabled"`
}

type TarpitConfig struct {
	IntervalMs     int `json:"interval_ms"`
	MaxConns       int `json:"max_conns"`
	MaxPerIP       int `json:"max_per_ip"`
	MaxDurationMin int `json:"max_duration_min"`
}

type SensorConfig struct {
	Hostname  string           `json:"hostname"`
	Profile   string           `json:"profile,omitempty"` // Geräteprofil (honeypot/profile.go); leer = bisher
	Lures     string           `json:"lures,omitempty"`   // Köder des Web-Honeypots (honeypot/lures.go): leer = passend zum Profil, "all", "off" oder Liste
	Listeners []ListenerConfig `json:"listeners"`
	Tarpit    TarpitConfig     `json:"tarpit"`
}

// Geräteprofile, die der Honeypot kennt (honeypot/profile.go).
var knownProfiles = []string{"", "linux-server", "nas", "router", "ip-camera", "smart-home", "dev-server"}

// Köder des Web-Honeypots für häufig angegriffene Produkte (honeypot/lures.go, TestLureNamesInSync).
var knownLures = []string{"fortinet", "ivanti", "cisco-asa", "hikvision", "onvif", "tomcat", "java-app"}

// validLures: leer (passend zum Profil), "all", "off" oder eine Liste bekannter Köder.
func validLures(v string) bool {
	switch v {
	case "", "all", "off":
		return true
	}
	if len(v) > 200 {
		return false
	}
	for _, n := range strings.Split(v, ",") {
		if !contains(knownLures, strings.TrimSpace(n)) {
			return false
		}
	}
	return true
}

// Muss zur Tabelle "handlers" im Honeypot passen (dort prüft das TestServiceListsInSync).
var knownServices = []string{"http", "https", "dockerapi", "ftp", "redis", "mysql", "ssh-tarpit", "raw", "telnet", "smtp", "vnc", "rdp", "sip", "snmp", "dns",
	"adb", "mqtt", "postgres", "elasticsearch", "ollama", "kubernetes"}
var knownModes = []string{"emulate", "tarpit", "hybrid"}

// defaultPorts: üblicher Port je Dienst. Die Web-UI setzt ihn beim Hinzufügen eines Ports,
// sobald der Dienst gewählt wird (eine Quelle für UI und Tests). SSH (22) und Telnet (23)
// gehören Cowrie, auf dem Raspberry Pi wie im Docker-Betrieb; der Go-Honeypot nimmt dafür
// 2222 (SSH-Tarpit) und 2323 (Telnet) wie in den mitgelieferten Konfigurationen.
// "raw" hat keinen festen Port.
var defaultPorts = map[string]int{
	"http": 80, "https": 443, "dockerapi": 2375, "ftp": 21, "redis": 6379, "mysql": 3306,
	"ssh-tarpit": 2222, "telnet": 2323, "smtp": 25, "vnc": 5900, "rdp": 3389,
	"sip": 5060, "snmp": 161, "dns": 53,
	"adb": 5555, "mqtt": 1883, "postgres": 5432, "elasticsearch": 9200, "ollama": 11434, "kubernetes": 6443,
}

// reservedPorts: alle Ports, die reservedPort ablehnt, für Hinweise in der UI.
func reservedPorts() map[string]string {
	out := map[string]string{}
	for _, p := range []int{22, 23, 8088, 8089} {
		if why := reservedPort(p); why != "" {
			out[strconv.Itoa(p)] = why
		}
	}
	return out
}

const maxTarpitConns = 8000 // wie im Honeypot

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// reservedPort: Ports, die ein Honeypot-Dienst nie belegen darf:
// Web-UI und Sensor-API des Hive, auf dem Raspberry Pi zusätzlich Cowrie (SSH 22, Telnet 23).
func reservedPort(p int) string {
	switch {
	case p == 8088:
		return "Web-UI des Hive"
	case p == 8089:
		return "Sensor-API des Hive"
	case os.Getenv("HIVE_DIRECT_PORTS") == "1" && (p == 22 || p == 23):
		return "Cowrie"
	}
	return ""
}

func (c *SensorConfig) Validate() error {
	if len(c.Hostname) > 64 {
		return fmt.Errorf("Hostname zu lang")
	}
	if !contains(knownProfiles, c.Profile) {
		return fmt.Errorf("unbekanntes Geräteprofil %q", c.Profile)
	}
	if !validLures(c.Lures) {
		return fmt.Errorf("unbekannte Köder %q", c.Lures)
	}
	if len(c.Listeners) > 64 {
		return fmt.Errorf("höchstens 64 Ports")
	}
	seen := map[int]bool{}
	for _, l := range c.Listeners {
		if !contains(knownServices, l.Service) {
			return fmt.Errorf("unbekannter Dienst %q", l.Service)
		}
		if !contains(knownModes, l.Mode) {
			return fmt.Errorf("unbekannter Modus %q", l.Mode)
		}
		if l.Port < 1 || l.Port > 65535 {
			return fmt.Errorf("ungültiger Port %d", l.Port)
		}
		if seen[l.Port] {
			return fmt.Errorf("Port %d ist doppelt", l.Port)
		}
		if why := reservedPort(l.Port); why != "" {
			return fmt.Errorf("Port %d ist reserviert (%s)", l.Port, why)
		}
		seen[l.Port] = true
	}
	t := c.Tarpit
	if t.IntervalMs < 200 || t.IntervalMs > 600000 {
		return fmt.Errorf("Tarpit-Intervall muss zwischen 0,2 s und 10 min liegen")
	}
	if t.MaxConns < 1 || t.MaxConns > maxTarpitConns {
		return fmt.Errorf("max. Verbindungen gesamt: 1 bis %d", maxTarpitConns)
	}
	if t.MaxPerIP < 1 || t.MaxPerIP > t.MaxConns {
		return fmt.Errorf("max. Verbindungen pro IP: 1 bis %d", t.MaxConns)
	}
	if t.MaxDurationMin < 0 || t.MaxDurationMin > 525600 {
		return fmt.Errorf("maximale Dauer ungültig")
	}
	sort.Slice(c.Listeners, func(i, j int) bool { return c.Listeners[i].Port < c.Listeners[j].Port })
	return nil
}

// Konfiguration: "sensor_config" gilt für alle Sensoren, "sensor_config:<name>" überschreibt sie für einen.
func configKey(sensor string) string {
	if sensor == "" {
		return "sensor_config"
	}
	return "sensor_config:" + sensor
}

// SensorConfigFor liefert die wirksame Konfiguration eines Sensors und ob sie eigen ist.
func (h *Hive) SensorConfigFor(sensor string) (json.RawMessage, bool) {
	if sensor != "" {
		if v, ok := h.st.GetKV(configKey(sensor)); ok {
			return json.RawMessage(v), true
		}
	}
	if v, ok := h.st.GetKV(configKey("")); ok {
		return json.RawMessage(v), false
	}
	return nil, false
}

type Heartbeat struct {
	Sensor          string          `json:"sensor"`
	Version         string          `json:"version"`
	UptimeS         int64           `json:"uptime_s"`
	Config          *SensorConfig   `json:"config,omitempty"`
	Listeners       json.RawMessage `json:"listeners"`
	Connections     int             `json:"connections"`
	Tarpits         int             `json:"tarpits"`
	HeldTarpits     []HeldTarpit    `json:"held_tarpits"` // gerade festgehaltene Verbindungen (ab Honeypot 0.5.2)
	EventsSent      int64           `json:"events_sent"`
	EventsDropped   int64           `json:"events_dropped"`
	EventsThrottled int64           `json:"events_throttled"`
	ConnsRejected   int64           `json:"conns_rejected"`
	ProxiedConns    int64           `json:"proxied_conns"`
	Egress          string          `json:"egress"`
	LastError       string          `json:"last_error"`
	MemBytes        uint64          `json:"mem_bytes"`
	Goroutines      int             `json:"goroutines"`
	Seen            time.Time       `json:"seen"`
}

// HeldTarpit ist eine Verbindung, die ein Sensor gerade im Tarpit festhält.
type HeldTarpit struct {
	IP      string    `json:"ip"`
	SrcPort int       `json:"src_port"`
	Port    int       `json:"port"`
	Service string    `json:"service"`
	Mode    string    `json:"mode"`
	Since   time.Time `json:"since"`
}

type Sensors struct {
	mu   sync.Mutex
	last map[string]Heartbeat
}

func (s *Sensors) Put(hb Heartbeat) {
	s.mu.Lock()
	hb.Seen = time.Now()
	hb.Config = nil // nicht im Speicher halten, steht in der Datenbank
	if len(s.last) < 100 || s.last[hb.Sensor].Sensor != "" {
		s.last[hb.Sensor] = hb
	}
	s.mu.Unlock()
}

func (s *Sensors) All() []Heartbeat {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Heartbeat, 0, len(s.last))
	for _, hb := range s.last {
		out = append(out, hb)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sensor < out[j].Sensor })
	return out
}

// Held liefert die festgehaltenen Verbindungen aller Sensoren mit frischem Lebenszeichen und
// ob jeder dieser Sensoren die Liste überhaupt meldet (ältere Honeypot-Versionen nicht).
func (s *Sensors) Held() (out []map[string]any, complete bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	complete = true
	for _, hb := range s.last {
		if time.Since(hb.Seen) >= time.Minute {
			continue
		}
		if hb.HeldTarpits == nil && hb.Tarpits > 0 {
			complete = false
		}
		for _, t := range hb.HeldTarpits {
			if len(out) >= 500 {
				break
			}
			out = append(out, map[string]any{"sensor": hb.Sensor, "ip": clip(t.IP, 64), "src_port": t.SrcPort, "port": t.Port,
				"service": clip(t.Service, 32), "mode": clip(t.Mode, 16), "since": t.Since.UnixMilli()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["since"].(int64) < out[j]["since"].(int64) })
	return out, complete
}

// ActiveTarpits zählt festgehaltene Verbindungen aller Sensoren mit frischem Lebenszeichen.
func (s *Sensors) ActiveTarpits() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, hb := range s.last {
		if time.Since(hb.Seen) < time.Minute {
			n += hb.Tarpits
		}
	}
	return n
}
