package main

import (
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// Welche Dienste es gibt, steht nur an einer Stelle: in der Tabelle "handlers"
// (manager.go). TestServiceListsInSync prüft, dass Hive und UI dieselben kennen.

var knownModes = map[string]bool{"emulate": true, "tarpit": true, "hybrid": true}

// Obergrenze für gleichzeitig festgehaltene Verbindungen. Jede kostet grob
// 10–20 KB (Goroutine, Puffer, Dateideskriptor); 8000 passen ins Speicherlimit.
const maxTarpitConns = 8000

type ListenerConfig struct {
	Service string `json:"service" yaml:"service"`
	Port    int    `json:"port" yaml:"port"`
	Mode    string `json:"mode" yaml:"mode"`
	Enabled bool   `json:"enabled" yaml:"enabled"`
}

type TarpitConfig struct {
	IntervalMs     int `json:"interval_ms" yaml:"interval_ms"`
	MaxConns       int `json:"max_conns" yaml:"max_conns"`
	MaxPerIP       int `json:"max_per_ip" yaml:"max_per_ip"`
	MaxDurationMin int `json:"max_duration_min" yaml:"max_duration_min"` // 0 = unbegrenzt
}

type Config struct {
	Hostname  string           `json:"hostname" yaml:"hostname"`
	Profile   string           `json:"profile,omitempty" yaml:"profile"` // Geräteprofil (profile.go); leer = bisher
	Listeners []ListenerConfig `json:"listeners" yaml:"listeners"`
	Tarpit    TarpitConfig     `json:"tarpit" yaml:"tarpit"`
}

func DefaultConfig() Config {
	return Config{
		Hostname: "nas-backup01",
		Listeners: []ListenerConfig{
			{"ftp", 21, "emulate", true},
			{"http", 80, "emulate", true},
			{"https", 443, "emulate", true},
			{"dockerapi", 2375, "emulate", true},
			{"ssh-tarpit", 2222, "tarpit", true},
			{"mysql", 3306, "emulate", true},
			{"redis", 6379, "emulate", true},
			{"vnc", 5900, "hybrid", true},
			{"http", 8080, "hybrid", true},
			{"smtp", 25, "emulate", true},
			{"telnet", 2323, "emulate", true},
			{"rdp", 3389, "emulate", true},
			{"sip", 5060, "emulate", true}, // UDP, nur aufzeichnen
			{"snmp", 161, "emulate", true}, // UDP, nur aufzeichnen
			{"dns", 53, "emulate", false},  // UDP, nur aufzeichnen; aus, weil viele Router 53 selbst brauchen
			// seit 0.7: zunächst aus, unter Einstellungen einschaltbar
			{"adb", 5555, "emulate", false},
			{"mqtt", 1883, "emulate", false},
			{"postgres", 5432, "emulate", false},
			{"elasticsearch", 9200, "emulate", false},
			{"ollama", 11434, "emulate", false},
			{"kubernetes", 6443, "emulate", false},
			{"kubernetes", 10250, "emulate", false},
		},
		Tarpit: TarpitConfig{IntervalMs: 10000, MaxConns: 4096, MaxPerIP: 32, MaxDurationMin: 1440},
	}
}

// fileConfig erlaubt in der YAML-Datei fehlende Felder (enabled default = true).
type fileListener struct {
	Service string `yaml:"service"`
	Port    int    `yaml:"port"`
	Mode    string `yaml:"mode"`
	Enabled *bool  `yaml:"enabled"`
}

type fileConfig struct {
	Hostname  string         `yaml:"hostname"`
	Profile   string         `yaml:"profile"`
	Listeners []fileListener `yaml:"listeners"`
	Tarpit    TarpitConfig   `yaml:"tarpit"`
}

func LoadConfigFile(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var fc fileConfig
	if err := yaml.Unmarshal(b, &fc); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	c := Config{Hostname: fc.Hostname, Profile: fc.Profile, Tarpit: fc.Tarpit}
	for _, l := range fc.Listeners {
		en := true
		if l.Enabled != nil {
			en = *l.Enabled
		}
		c.Listeners = append(c.Listeners, ListenerConfig{l.Service, l.Port, l.Mode, en})
	}
	return c, nil
}

// BindPort: Ports unter 1024 lauschen im Container auf Port+Offset (Standard im
// Image: 10000), damit der Honeypot ohne Root und ohne Sonderrechte läuft.
// Gemeldet wird weiter der echte Port (z. B. 80).
func BindPort(port, lowOffset int) int {
	if port < 1024 && lowOffset > 0 {
		return port + lowOffset
	}
	return port
}

// Normalize setzt Standardwerte und verwirft ungültige Listener. lowOffset ist der
// Port-Versatz für Ports unter 1024; Kollisionen werden auf den echten Bind-Ports geprüft.
func (c *Config) Normalize(lowOffset int) []string {
	var warn []string
	d := DefaultConfig()
	if c.Hostname == "" {
		c.Hostname = d.Hostname
	}
	if _, ok := profiles[c.Profile]; !ok {
		warn = append(warn, "unbekanntes Geräteprofil "+c.Profile+", nutze das bisherige")
		c.Profile = ""
	}
	if c.Tarpit.IntervalMs < 200 {
		c.Tarpit.IntervalMs = d.Tarpit.IntervalMs
	}
	if c.Tarpit.MaxConns <= 0 {
		c.Tarpit.MaxConns = d.Tarpit.MaxConns
	}
	if c.Tarpit.MaxConns > maxTarpitConns {
		warn = append(warn, fmt.Sprintf("max_conns auf %d begrenzt", maxTarpitConns))
		c.Tarpit.MaxConns = maxTarpitConns
	}
	if c.Tarpit.MaxPerIP <= 0 {
		c.Tarpit.MaxPerIP = d.Tarpit.MaxPerIP
	}
	if c.Tarpit.MaxPerIP > c.Tarpit.MaxConns {
		c.Tarpit.MaxPerIP = c.Tarpit.MaxConns
	}
	if c.Tarpit.MaxDurationMin < 0 {
		c.Tarpit.MaxDurationMin = 0
	}
	seen := map[int]int{} // Bind-Port -> konfigurierter Port
	var out []ListenerConfig
	for _, l := range c.Listeners {
		if l.Mode == "" {
			l.Mode = "emulate"
		}
		bp := BindPort(l.Port, lowOffset)
		switch {
		case handlers[l.Service] == nil && !isUDP(l.Service):
			warn = append(warn, fmt.Sprintf("unbekannter Dienst %q ignoriert", l.Service))
			continue
		case !knownModes[l.Mode]:
			warn = append(warn, fmt.Sprintf("unbekannter Modus %q bei Port %d ignoriert", l.Mode, l.Port))
			continue
		case l.Port < 1 || l.Port > 65535 || bp > 65535:
			warn = append(warn, fmt.Sprintf("ungültiger Port %d ignoriert", l.Port))
			continue
		}
		if other, dup := seen[bp]; dup {
			warn = append(warn, fmt.Sprintf("Port %d kollidiert mit Port %d (beide lauschen im Container auf %d), ignoriert", l.Port, other, bp))
			continue
		}
		seen[bp] = l.Port
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	c.Listeners = out
	return warn
}
