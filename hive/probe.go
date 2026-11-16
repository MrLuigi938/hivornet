package main

// Dienst-Prüfung: Lauschen die Dienste, die laufen sollen, wirklich?
//
// Cowrie meldet einen Startfehler nur in seinem eigenen Protokoll. Bricht etwa der
// SSH-Teil beim Lesen eines leeren Host-Schlüssels ab, läuft Telnet weiter, das Log
// wächst, und ohne diese Prüfung sähe alles gesund aus. Darum verbindet sich der Hive
// regelmäßig mit den Cowrie-Ports und warnt, wenn einer zweimal nacheinander nicht
// antwortet. Auf dem Raspberry Pi (HIVE_DIRECT_PORTS=1 mit Cowrie) sind das
// 127.0.0.1:22 und :23; mit HIVE_COWRIE_PROBE lässt sich die Liste setzen
// ("ssh=host:port,telnet=host:port") oder abschalten ("off"). Im Docker-Betrieb
// erreicht der Hive das Cowrie-Netz nicht; dort ist die Prüfung standardmäßig aus.
//
// Die eigenen Prüfverbindungen kommen von 127.0.0.1; CowrieTail verwirft Ereignisse
// von Loopback-Adressen, damit sie nicht als Angriffe zählen.
//
// Ports des Honeypots meldet der Sensor selbst (Lebenszeichen, Feld listeners.error);
// warnings() macht daraus ebenfalls eine Warnung.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	probeInterval = time.Minute
	probeFailWarn = 2 // so viele Fehlschläge nacheinander, bevor gewarnt wird
)

type probeTarget struct {
	Name string // ssh | telnet
	Addr string
}

type probeResult struct {
	Name    string    `json:"name"`
	Addr    string    `json:"addr"`
	OK      bool      `json:"ok"`
	Error   string    `json:"error,omitempty"`
	Fails   int       `json:"fails"`
	Since   time.Time `json:"since"` // seit wann im jetzigen Zustand
	Checked time.Time `json:"checked"`
	Hint    string    `json:"hint,omitempty"` // erkannte Ursache aus dem Cowrie-Protokoll
}

type portProbe struct {
	mu      sync.Mutex
	targets []probeTarget
	res     map[string]*probeResult
	dial    func(ctx context.Context, t probeTarget) error // in Tests ersetzbar
	hint    func(ctx context.Context) string
}

// cowrieProbeTargets liest HIVE_COWRIE_PROBE bzw. den Standard des Pi.
func cowrieProbeTargets() []probeTarget {
	v := strings.TrimSpace(os.Getenv("HIVE_COWRIE_PROBE"))
	if v == "off" {
		return nil
	}
	if v == "" {
		if os.Getenv("HIVE_DIRECT_PORTS") != "1" || os.Getenv("HIVE_COWRIE_LOG") == "" {
			return nil
		}
		v = "ssh=127.0.0.1:22,telnet=127.0.0.1:23"
	}
	var out []probeTarget
	for _, part := range strings.Split(v, ",") {
		name, addr, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || (name != "ssh" && name != "telnet") {
			continue
		}
		if _, _, err := net.SplitHostPort(addr); err == nil && len(out) < 4 {
			out = append(out, probeTarget{name, addr})
		}
	}
	return out
}

// dialProbe: Verbindung aufbauen; bei SSH zusätzlich auf die Kennung "SSH-" warten.
func dialProbe(ctx context.Context, t probeTarget) error {
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "tcp", t.Addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if t.Name != "ssh" {
		return nil
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReaderSize(c, 512).ReadString('\n')
	if !strings.HasPrefix(line, "SSH-") {
		if err == nil {
			err = fmt.Errorf("keine SSH-Kennung")
		}
		return err
	}
	return nil
}

// cowrieHint sucht im Cowrie-Protokoll (nur Pi) nach bekannten Startfehlern.
func cowrieHint(ctx context.Context) string {
	if !logsEnabled() {
		return ""
	}
	text, err := journal(ctx, "hivornet-cowrie.service", 400)
	if err != nil {
		return ""
	}
	switch {
	case strings.Contains(text, "BadKeyError") || strings.Contains(text, "cannot guess the type of"):
		return "Ein SSH-Host-Schlüssel von Cowrie ist leer oder beschädigt (meist ein Stromausfall beim ersten Start)."
	case strings.Contains(text, "Address already in use") || strings.Contains(text, "CannotListenError"):
		return "Ein anderes Programm belegt den Port."
	}
	return ""
}

func newPortProbe(targets []probeTarget) *portProbe {
	return &portProbe{targets: targets, res: map[string]*probeResult{}, dial: dialProbe, hint: cowrieHint}
}

// once prüft alle Ziele einmal.
func (p *portProbe) once(ctx context.Context) {
	for _, t := range p.targets {
		err := p.dial(ctx, t)
		hint := ""
		if err != nil && t.Name == "ssh" {
			hint = p.hint(ctx)
		}
		p.mu.Lock()
		r := p.res[t.Name]
		if r == nil {
			r = &probeResult{Name: t.Name, Addr: t.Addr, OK: err == nil, Since: time.Now()}
			p.res[t.Name] = r
		}
		if r.OK != (err == nil) {
			r.Since = time.Now()
		}
		r.OK, r.Checked, r.Error, r.Hint = err == nil, time.Now(), "", hint
		if err != nil {
			r.Fails++
			r.Error = clip(err.Error(), 200)
		} else {
			r.Fails = 0
		}
		p.mu.Unlock()
	}
}

func (p *portProbe) run(stop <-chan struct{}, ready func() bool) {
	if p == nil || len(p.targets) == 0 {
		return
	}
	t := time.NewTicker(probeInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		if !ready() {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		p.once(ctx)
		cancel()
	}
}

// Results liefert den letzten Stand, nach Name sortiert.
func (p *portProbe) Results() []probeResult {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]probeResult, 0, len(p.res))
	for _, r := range p.res {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

var probeLabel = map[string]string{"ssh": "SSH", "telnet": "Telnet"}

// probeWarnings: Warnungen für Ports, die mehrmals nacheinander nicht antworteten.
func (p *portProbe) warnings() []warning {
	var out []warning
	for _, r := range p.Results() {
		if r.OK || r.Fails < probeFailWarn {
			continue
		}
		_, port, _ := net.SplitHostPort(r.Addr)
		t := fmt.Sprintf("Cowrie-%s (Port %s) lauscht nicht; Angriffe auf diesen Port werden nicht aufgezeichnet.", probeLabel[r.Name], port)
		if r.Hint != "" {
			t += " Ursache laut Cowrie-Protokoll: " + r.Hint
			if strings.Contains(r.Hint, "Host-Schlüssel") {
				t += " Ein Update über die Web-UI behebt das nicht; nötig ist ein neues Image (Sicherung exportieren, Image aufspielen, Sicherung einspielen; siehe README)."
			}
		} else {
			t += " Einzelheiten zeigt die Seite Protokolle (Quelle Cowrie)."
		}
		out = append(out, warning{"critical", t})
	}
	return out
}

// listenerWarnings: Ports, die der Honeypot nicht öffnen konnte (aus dem Lebenszeichen).
func listenerWarnings(hb Heartbeat) []warning {
	var ls []struct {
		Port    int    `json:"port"`
		Service string `json:"service"`
		Running bool   `json:"running"`
		Error   string `json:"error"`
	}
	if len(hb.Listeners) == 0 || json.Unmarshal(hb.Listeners, &ls) != nil {
		return nil
	}
	var out []warning
	for _, l := range ls {
		if l.Running || l.Error == "" {
			continue
		}
		out = append(out, warning{"warn", fmt.Sprintf("Sensor %s: Port %d (%s) lauscht nicht: %s", hb.Sensor, l.Port, l.Service, clip(l.Error, 200))})
	}
	return out
}
