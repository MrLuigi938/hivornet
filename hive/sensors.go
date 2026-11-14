package main

import (
	"encoding/json"
	"fmt"
	"sort"
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
	Listeners []ListenerConfig `json:"listeners"`
	Tarpit    TarpitConfig     `json:"tarpit"`
}

// Muss zur Tabelle "handlers" im Honeypot passen (dort prüft das TestServiceListsInSync).
var knownServices = []string{"http", "https", "dockerapi", "ftp", "redis", "mysql", "ssh-tarpit", "raw", "telnet", "smtp", "vnc", "rdp"}
var knownModes = []string{"emulate", "tarpit", "hybrid"}

const maxTarpitConns = 8000 // wie im Honeypot

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (c *SensorConfig) Validate() error {
	if len(c.Hostname) > 64 {
		return fmt.Errorf("Hostname zu lang")
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
