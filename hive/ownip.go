package main

// Eigene öffentliche Adresse automatisch ermitteln. Viele Schutzregeln brauchen sie: Sie geht
// nie an Sprachmodelle, URLhaus, MalwareBazaar oder DShield, und Nachlade-Adressen, die auf
// den eigenen Anschluss zeigen, werden nicht geholt. Bisher kannte der Hive sie nur, wenn sie
// unter System → "Wie Shodan dich sieht" abgefragt wurde, und sie veraltete beim nächsten
// Wechsel der Adresse durch den Provider.
//
// runOwnIP fragt stündlich bei api.ipify.org (IPv4) und api6.ipify.org (IPv6) nach. ipify
// erfährt dabei nur die eigene Adresse, die es durch die Verbindung ohnehin sieht. Frühere
// Adressen bleiben 30 Tage bekannt, denn ältere Angriffsdaten können sie noch enthalten.
// Zusätzlich lassen sich eigene Namen (Domain, DynDNS) eintragen; auch sie gehen nie hinaus.
//
//   GET  /api/ownip          Stand und Einstellung (nur Admin)
//   POST /api/ownip/refresh  sofort neu ermitteln (nur Admin)

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ownIPv4URL   = "https://api.ipify.org?format=json"
	ownIPv6URL   = "https://api6.ipify.org?format=json"
	ownIPEvery   = time.Hour
	ownIPKeep    = 30 * 24 * time.Hour
	ownIPMaxSeen = 32
)

// OwnIPConfig: Einstellungen (Zugang und Sicherheit → Eigene öffentliche Adresse).
type OwnIPConfig struct {
	Auto  bool     `json:"auto"`  // regelmäßig ermitteln (Standard an)
	Names []string `json:"names"` // eigene Domains und DynDNS-Namen, gehen nie nach außen
}

func (c *OwnIPConfig) validate() error {
	if len(c.Names) > 20 {
		return fmt.Errorf("Eigene Namen: höchstens 20 Einträge")
	}
	var clean []string
	for _, s := range c.Names {
		s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
		s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
		if s == "" {
			continue
		}
		if len(s) < 4 || len(s) > 253 || !strings.Contains(s, ".") {
			return fmt.Errorf("Eigene Namen: %q ist kein vollständiger Name (z. B. hivornet.example.de)", clip(s, 60))
		}
		for _, r := range s {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
				return fmt.Errorf("Eigene Namen: %q enthält unzulässige Zeichen", clip(s, 60))
			}
		}
		if !contains(clean, s) {
			clean = append(clean, s)
		}
	}
	c.Names = clean
	return nil
}

// ownIPState: gespeichert unter lookups("self", "ownip").
type ownIPState struct {
	Current []string         `json:"current"`         // zuletzt ermittelte Adressen (IPv4, ggf. IPv6)
	Seen    map[string]int64 `json:"seen"`            // Adresse -> zuletzt gesehen (ms)
	Checked int64            `json:"checked"`         // letzter Versuch (ms)
	Changed int64            `json:"changed"`         // letzter Wechsel der IPv4-Adresse (ms)
	Error   string           `json:"error,omitempty"` // letzter Fehler
}

var ownIPMu sync.Mutex

func (h *Hive) ownIPState() ownIPState {
	var s ownIPState
	if data, _, ok := h.st.lookupGet("self", "ownip", 0); ok {
		json.Unmarshal([]byte(data), &s)
	}
	if s.Seen == nil {
		s.Seen = map[string]int64{}
	}
	return s
}

// usablePublic: nur öffentliche Unicast-Adressen (kein Heimnetz, kein CGNAT, kein Loopback).
func usablePublic(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range []string{"100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15"} {
		if netip.MustParsePrefix(p).Contains(a) {
			return false
		}
	}
	return true
}

// askOwnIP: eine Adresse bei einem ipify-Endpunkt erfragen.
func askOwnIP(ctx context.Context, url string, v6 bool) (netip.Addr, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := intelHTTP.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return netip.Addr{}, fmt.Errorf("Antwort %s", resp.Status)
	}
	var v struct{ IP string }
	if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&v) != nil {
		return netip.Addr{}, fmt.Errorf("Antwort unlesbar")
	}
	a, err := netip.ParseAddr(strings.TrimSpace(v.IP))
	if err != nil || a.Unmap().Is4() == v6 || !usablePublic(a) {
		return netip.Addr{}, fmt.Errorf("keine öffentliche Adresse")
	}
	return a.Unmap(), nil
}

// refreshOwnIP ermittelt die Adressen neu und speichert sie. IPv6 ist freiwillig: Viele
// Anschlüsse haben keine, dann zählt nur IPv4.
func (h *Hive) refreshOwnIP(ctx context.Context) (ownIPState, error) {
	v4, err4 := askOwnIP(ctx, ownIPv4URL, false)
	v6, err6 := askOwnIP(ctx, ownIPv6URL, true)
	ownIPMu.Lock()
	defer ownIPMu.Unlock()
	s := h.ownIPState()
	now := time.Now()
	s.Checked = now.UnixMilli()
	var cur []string
	if err4 == nil {
		cur = append(cur, v4.String())
	}
	if err6 == nil {
		cur = append(cur, v6.String())
	}
	if len(cur) == 0 {
		s.Error = "öffentliche Adresse nicht ermittelbar: " + err4.Error()
		h.saveOwnIP(s)
		return s, fmt.Errorf("%s", s.Error)
	}
	s.Error = ""
	if err4 == nil && (len(s.Current) == 0 || s.Current[0] != v4.String()) {
		if len(s.Current) > 0 {
			log.Printf("Eigene öffentliche Adresse hat sich geändert")
		}
		s.Changed = s.Checked
	}
	if err4 != nil && len(s.Current) > 0 {
		// IPv4 gerade nicht erreichbar: die bekannte IPv4-Adresse vorne behalten
		if a, e := netip.ParseAddr(s.Current[0]); e == nil && a.Is4() {
			cur = append([]string{s.Current[0]}, cur...)
		}
	}
	s.Current = cur
	for _, ip := range cur {
		s.Seen[ip] = s.Checked
	}
	s.prune(now)
	h.saveOwnIP(s)
	return s, nil
}

// prune: alte und überzählige frühere Adressen vergessen.
func (s *ownIPState) prune(now time.Time) {
	limit := now.Add(-ownIPKeep).UnixMilli()
	for ip, t := range s.Seen {
		if t < limit && !contains(s.Current, ip) {
			delete(s.Seen, ip)
		}
	}
	if len(s.Seen) > ownIPMaxSeen {
		type e struct {
			ip string
			t  int64
		}
		var l []e
		for ip, t := range s.Seen {
			l = append(l, e{ip, t})
		}
		sort.Slice(l, func(i, j int) bool { return l[i].t > l[j].t })
		for _, x := range l[ownIPMaxSeen:] {
			if !contains(s.Current, x.ip) {
				delete(s.Seen, x.ip)
			}
		}
	}
}

func (h *Hive) saveOwnIP(s ownIPState) {
	b, _ := json.Marshal(s)
	h.st.lookupPut("self", "ownip", string(b))
}

// runOwnIP: kurz nach dem Start und danach stündlich, solange eingeschaltet.
func (h *Hive) runOwnIP(stop <-chan struct{}) {
	select {
	case <-stop:
		return
	case <-time.After(20 * time.Second):
	}
	tick := time.NewTicker(ownIPEvery)
	defer tick.Stop()
	for {
		if h.Extras().OwnIP.Auto {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if _, err := h.refreshOwnIP(ctx); err != nil {
				log.Printf("Eigene Adresse: %v", err)
			}
			cancel()
		}
		select {
		case <-stop:
			return
		case <-tick.C:
		}
	}
}

// knownOwnIPs: alle bekannten eigenen Adressen, die aktuelle IPv4-Adresse zuerst: automatisch
// ermittelte (aktuelle und der letzten 30 Tage) sowie die zuletzt bei Shodan abgefragte.
func (h *Hive) knownOwnIPs() []string {
	s := h.ownIPState()
	out := append([]string{}, s.Current...)
	type e struct {
		ip string
		t  int64
	}
	var older []e
	for ip, t := range s.Seen {
		if !contains(out, ip) {
			older = append(older, e{ip, t})
		}
	}
	sort.Slice(older, func(i, j int) bool { return older[i].t > older[j].t })
	for _, x := range older {
		out = append(out, x.ip)
	}
	if data, _, ok := h.st.lookupGet("self", "internetdb", 0); ok {
		var x struct{ IP string }
		if json.Unmarshal([]byte(data), &x) == nil {
			if a, err := netip.ParseAddr(x.IP); err == nil && !contains(out, a.String()) {
				out = append(out, a.String())
			}
		}
	}
	return out
}

// ownIPAPI: GET /api/ownip
func (h *Hive) ownIPAPI(w http.ResponseWriter, r *http.Request) {
	s := h.ownIPState()
	var prev []string
	for _, ip := range h.knownOwnIPs() {
		if !contains(s.Current, ip) {
			prev = append(prev, ip)
		}
	}
	writeJSON(w, map[string]any{
		"auto": h.Extras().OwnIP.Auto, "current": s.Current, "previous": prev,
		"checked": s.Checked, "changed": s.Changed, "error": s.Error,
	})
}

// ownIPRefreshAPI: POST /api/ownip/refresh
func (h *Hive) ownIPRefreshAPI(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if _, err := h.refreshOwnIP(ctx); err != nil {
		httpErr(w, 502, err.Error())
		return
	}
	h.ownIPAPI(w, r)
}
