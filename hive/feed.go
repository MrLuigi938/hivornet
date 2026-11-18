package main

// Blockliste zum Abonnieren: eine Adresse mit Token, die eine Firewall im Heimnetz
// regelmäßig abruft (OPNsense/pfSense "URL Table", MikroTik-Skript, nftables-Cronjob …).
// So schützt der Honeypot direkt das echte Netz.
//
//   GET /feed/blocklist.txt?token=…   eine IP je Zeile, Kommentarzeilen mit "#"
//   GET/PUT /api/feed                 Einstellungen (nur Admin); PUT {"rotate":true} erzeugt ein neues Token
//
// In die Liste kommen nur öffentliche IPs mit mindestens der eingestellten Stufe im
// Zeitraum. Nie enthalten: eigene Netze, Angreifer, die nur über UDP kamen (Absender
// fälschbar), und auf Wunsch Forschungsscanner und geprüfte Suchmaschinen-Bots.
// Das Ergebnis wird 10 Minuten zwischengespeichert; der Abruf kostet dann nichts.

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type FeedConfig struct {
	Enabled      bool   `json:"enabled"`
	Token        string `json:"token"`
	Range        string `json:"range"`         // 24h, 7d, 30d
	MinStufe     int    `json:"min_stufe"`     // 0 Abtasten … 4 Datei nachgeladen
	SkipScanners bool   `json:"skip_scanners"` // Forschungsscanner und echte Suchmaschinen-Bots auslassen
	// Schutz gegen gefälschte Ereignisse (protect.go)
	NeverBlock    []string `json:"never_block"`      // Adressen/Netze, die nie in die Liste kommen
	MaxNewPerHour int      `json:"max_new_per_hour"` // höchstens so viele neue Adressen je Stunde
}

const feedKV = "feed_config"
const feedCacheTTL = 10 * time.Minute

type feedCache struct {
	mu        sync.Mutex
	key       string
	at        time.Time
	ips       []string
	err       error
	busy      chan struct{}
	published map[string]int64 // Adresse -> seit wann in der Liste (für die Obergrenze je Stunde)
	held      int              // zuletzt zurückgehaltene neue Adressen
}

func (h *Hive) feedConfig() FeedConfig {
	c := FeedConfig{Range: "7d", MinStufe: 1, SkipScanners: true, MaxNewPerHour: 300}
	if v, ok := h.st.GetKV(feedKV); ok {
		json.Unmarshal([]byte(v), &c)
	}
	if c.Range != "24h" && c.Range != "7d" && c.Range != "30d" {
		c.Range = "7d"
	}
	c.MinStufe = min(max(c.MinStufe, 0), 4)
	if c.MaxNewPerHour < 1 {
		c.MaxNewPerHour = 300
	}
	return c
}

// capNew lässt je Stunde höchstens max neue Adressen in die Liste; bekannte bleiben.
// Liefert die Liste und die Zahl der zurückgehaltenen Adressen. pub wird fortgeschrieben.
func capNew(ips []string, pub map[string]int64, max int, now time.Time) ([]string, int) {
	hourAgo := now.Add(-time.Hour).UnixMilli()
	added := 0
	for _, t := range pub {
		if t >= hourAgo {
			added++
		}
	}
	out := make([]string, 0, len(ips))
	keep := make(map[string]bool, len(ips))
	held := 0
	for _, ip := range ips { // nach Wichtigkeit sortiert: die wichtigsten zuerst
		if _, ok := pub[ip]; ok {
			out = append(out, ip)
			keep[ip] = true
			continue
		}
		if added >= max {
			held++
			continue
		}
		pub[ip] = now.UnixMilli()
		added++
		out = append(out, ip)
		keep[ip] = true
	}
	for ip := range pub { // was nicht mehr in der Liste steht, vergessen
		if !keep[ip] {
			delete(pub, ip)
		}
	}
	return out, held
}

func udpOnly(services []string) bool {
	if len(services) == 0 {
		return false
	}
	for _, s := range services {
		if s != "sip" && s != "snmp" && s != "dns" {
			return false
		}
	}
	return true
}

// feedIPs wählt die IPs für die Blockliste aus (ohne Datenbank, für Tests). skip schließt
// zusätzlich Angriffe aus (nicht vertrauenswürdige Sensoren, geschützte Adressen; protect.go).
func feedIPs(list []*Attack, c FeedConfig, skip func(*Attack) bool) []string {
	type best struct {
		stufe  int
		events int
	}
	byIP := map[string]*best{}
	for _, a := range list {
		if a.Own || udpOnly(a.Services) || (c.SkipScanners && a.Scanner != "" && a.scannerExempt()) || skip != nil && skip(a) {
			continue
		}
		if p := net.ParseIP(a.IP); p == nil || p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast() || p.IsUnspecified() || ownHidden(a.IP) {
			continue
		}
		b := byIP[a.IP]
		if b == nil {
			b = &best{}
			byIP[a.IP] = b
		}
		b.stufe = max(b.stufe, a.Stufe)
		b.events += a.Events
	}
	var out []string
	for ip, b := range byIP {
		if b.stufe >= c.MinStufe {
			out = append(out, ip)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		bi, bj := byIP[out[i]], byIP[out[j]]
		return bi.stufe > bj.stufe || bi.stufe == bj.stufe && (bi.events > bj.events || bi.events == bj.events && out[i] < out[j])
	})
	if len(out) > 100000 {
		out = out[:100000]
	}
	return out
}

// feedList liefert die (zwischengespeicherte) Liste; gleichzeitige Abrufe rechnen nur einmal.
func (h *Hive) feedList(ctx context.Context, c FeedConfig) ([]string, error) {
	fc := &h.feed
	key := fmt.Sprintf("%s|%d|%v", c.Range, c.MinStufe, c.SkipScanners)
	for {
		fc.mu.Lock()
		if fc.key == key && time.Since(fc.at) < feedCacheTTL {
			ips, err := fc.ips, fc.err
			fc.mu.Unlock()
			return ips, err
		}
		if fc.busy == nil {
			fc.busy = make(chan struct{})
			busy := fc.busy
			fc.mu.Unlock()
			list, _, err := h.loadAttacks(ctx, time.Now().Add(-rangeDur(c.Range, 7*24*time.Hour)), nil)
			var ips []string
			if err == nil {
				untrusted := h.untrustedSensors()
				ips = feedIPs(list, c, func(a *Attack) bool { return !trustedAttack(a, untrusted) || h.neverBlock(a.IP) })
			}
			fc.mu.Lock()
			held := 0
			if err == nil {
				if fc.published == nil {
					fc.published = map[string]int64{}
				}
				ips, held = capNew(ips, fc.published, c.MaxNewPerHour, time.Now())
			}
			fc.key, fc.at, fc.ips, fc.err, fc.busy, fc.held = key, time.Now(), ips, err, nil, held
			fc.mu.Unlock()
			if held > 0 && h.notifier != nil {
				h.notifier.Warn(fmt.Sprintf("Blockliste: %d neue Adressen zurückgehalten (mehr als %d je Stunde). Gefälschte Ereignisse eines Sensors?", held, c.MaxNewPerHour))
			}
			close(busy)
			return ips, err
		}
		busy := fc.busy
		fc.mu.Unlock()
		select {
		case <-busy:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// feedBlocklist: GET /feed/blocklist.txt?token=… (ohne Anmeldung, nur mit Token)
func (h *Hive) feedBlocklist(w http.ResponseWriter, r *http.Request) {
	c := h.feedConfig()
	tok := r.URL.Query().Get("token")
	if !c.Enabled || c.Token == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(c.Token)) != 1 {
		httpErr(w, 404, "nicht gefunden")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	ips, err := h.feedList(ctx, c)
	if err != nil {
		httpErr(w, 503, "Liste gerade nicht verfügbar")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, "# Hivornet Blockliste, %s, Zeitraum %s, ab Stufe %d, %d Adressen\n", time.Now().Format(time.RFC3339), c.Range, c.MinStufe, len(ips))
	io.WriteString(w, strings.Join(ips, "\n"))
	if len(ips) > 0 {
		io.WriteString(w, "\n")
	}
}

// feedSettings: GET/PUT /api/feed (nur Admin; Leserolle siehe viewerAllowed)
func (h *Hive) feedSettings(w http.ResponseWriter, r *http.Request) {
	c := h.feedConfig()
	if r.Method == "PUT" {
		var in struct {
			FeedConfig
			Rotate bool `json:"rotate"`
		}
		in.FeedConfig = c
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in); err != nil {
			httpErr(w, 400, "ungültige Eingabe")
			return
		}
		if len(in.NeverBlock) > 500 {
			httpErr(w, 400, "höchstens 500 Einträge bei „Nie sperren“")
			return
		}
		if _, bad := parseNets(in.NeverBlock); len(bad) > 0 {
			httpErr(w, 400, "„Nie sperren“: ungültig: "+strings.Join(bad[:min(len(bad), 3)], ", "))
			return
		}
		if in.MaxNewPerHour < 1 || in.MaxNewPerHour > 100000 {
			httpErr(w, 400, "neue Adressen je Stunde: 1 bis 100.000")
			return
		}
		tok := c.Token // das Token setzt nur der Hive
		if tok == "" || in.Rotate {
			tok = randToken(24)
		}
		c = in.FeedConfig
		c.Token = tok
		b, _ := json.Marshal(c)
		if err := h.st.SetKV(feedKV, string(b)); err != nil {
			httpErr(w, 500, err.Error())
			return
		}
		h.feed.mu.Lock()
		h.feed.key = "" // neu berechnen
		h.feed.mu.Unlock()
		c = h.feedConfig()
	}
	out := map[string]any{"config": c, "path": "/feed/blocklist.txt?token=" + c.Token, "untrusted": len(h.untrustedSensors())}
	if c.Enabled {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		if ips, err := h.feedList(ctx, c); err == nil {
			out["count"] = len(ips)
			h.feed.mu.Lock()
			out["held"] = h.feed.held
			h.feed.mu.Unlock()
			out["sample"] = ips[:min(len(ips), 5)]
		}
	}
	writeJSON(w, out)
}
