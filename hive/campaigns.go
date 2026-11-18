package main

// Kampagnen: Angreifer, die offensichtlich zusammengehören. Zusammengefasst werden IPs,
//   - die dieselbe Liste von Zugangsdaten durchprobieren (mindestens 3 verschiedene, die
//     Menge ist gleich; typisch für ein Botnetz mit gemeinsamer Wortliste), oder
//   - die von derselben Adresse nachladen (gleicher Host in den Nachlade-Adressen).
// Beides wird verkettet: Teilen zwei Gruppen eine IP, sind sie eine Kampagne.
// Gleiche Fingerabdrücke (JA4, HASSH, HTTP-Kopfzeilen) zeigen dagegen nur dasselbe
// Werkzeug; sie werden getrennt aufgeführt und nicht zu Kampagnen verkettet, weil
// verbreitete Werkzeuge (curl, Go, python-requests) sonst alles zusammenwerfen würden.
//
// Berechnet auf Abruf aus den Angriffen des Zeitraums (GET /api/campaigns?range=7d).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type Campaign struct {
	ID        string   `json:"id"`
	Reasons   []string `json:"reasons"` // z. B. "gleiche Zugangsdatenliste (12 Einträge)"
	IPs       []string `json:"ips"`     // höchstens 50
	NIPs      int      `json:"n_ips"`
	Countries []Count  `json:"countries"`
	NASNs     int      `json:"n_asns"`
	Attacks   int      `json:"attacks"`
	First     int64    `json:"first"`
	Last      int64    `json:"last"`
	Stufe     int      `json:"stufe"` // höchste
	Profile   string   `json:"profile"`
	Creds     []string `json:"creds,omitempty"` // Beispiele
	URLs      []string `json:"urls,omitempty"`
	Wallets   []string `json:"wallets,omitempty"`
}

type FingerprintGroup struct {
	Fingerprint string  `json:"fingerprint"`
	NIPs        int     `json:"n_ips"`
	Countries   []Count `json:"countries"`
	Attacks     int     `json:"attacks"`
	Last        int64   `json:"last"`
}

type unionFind map[string]string

func (u unionFind) find(x string) string {
	for u[x] != "" && u[x] != x {
		u[x] = u[u[x]]
		x = u[x]
	}
	return x
}

func (u unionFind) union(a, b string) {
	if _, ok := u[a]; !ok {
		u[a] = a
	}
	if _, ok := u[b]; !ok {
		u[b] = b
	}
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		u[ra] = rb
	}
}

// credListKey: Schlüssel für die Menge der Zugangsdaten eines Angriffs ("" = zu wenige).
func credListKey(a *Attack) string {
	if len(a.creds) < 3 {
		return ""
	}
	keys := make([]string, 0, len(a.creds))
	for k := range a.creds {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return "creds:" + hex.EncodeToString(sum[:8])
}

// buildCampaigns fasst Angriffe zu Kampagnen zusammen (nur Gruppen mit mindestens 2 IPs).
func buildCampaigns(list []*Attack) ([]Campaign, []FingerprintGroup) {
	uf := unionFind{}
	reasons := map[string]string{} // Schlüssel -> Begründung
	for _, a := range list {
		if a.Own {
			continue
		}
		node := "ip:" + a.IP
		uf.union(node, node)
		if k := credListKey(a); k != "" {
			uf.union(node, k)
			reasons[k] = "gleiche Zugangsdatenliste"
		}
		for _, raw := range a.URLs {
			if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
				k := "url:" + strings.ToLower(u.Hostname())
				uf.union(node, k)
				reasons[k] = "gleiche Nachlade-Adresse " + u.Hostname()
			}
		}
		for _, w := range a.Wallets { // gleiche Wallet: dasselbe Konto kassiert (indicators.go)
			k := "wallet:" + w
			uf.union(node, k)
			reasons[k] = "gleiche Wallet " + shortWallet(w)
		}
	}
	type group struct {
		ips     map[string]bool
		attacks []*Attack
		keys    map[string]bool
	}
	groups := map[string]*group{}
	get := func(root string) *group {
		g := groups[root]
		if g == nil {
			g = &group{ips: map[string]bool{}, keys: map[string]bool{}}
			groups[root] = g
		}
		return g
	}
	for k := range reasons {
		get(uf.find(k)).keys[k] = true
	}
	for _, a := range list {
		if a.Own {
			continue
		}
		g := get(uf.find("ip:" + a.IP))
		g.ips[a.IP] = true
		g.attacks = append(g.attacks, a)
	}
	var out []Campaign
	for root, g := range groups {
		if len(g.ips) < 2 {
			continue
		}
		c := Campaign{ID: strings.TrimPrefix(strings.TrimPrefix(root, "ip:"), "creds:"), NIPs: len(g.ips), Attacks: len(g.attacks)}
		ctry, asns, profiles := map[string]int{}, map[int]bool{}, map[string]int{}
		credSeen := map[string]bool{}
		for _, a := range g.attacks {
			if c.First == 0 || a.First < c.First {
				c.First = a.First
			}
			c.Last = max(c.Last, a.Last)
			c.Stufe = max(c.Stufe, a.Stufe)
			if a.Country != "" {
				ctry[a.Country]++
			}
			if a.ASN != 0 {
				asns[a.ASN] = true
			}
			profiles[a.Profile]++
			for _, cr := range a.Creds {
				if !credSeen[cr.Key] && len(c.Creds) < 8 {
					credSeen[cr.Key] = true
					c.Creds = append(c.Creds, clip(cr.Key, 80))
				}
			}
			for _, u := range a.URLs {
				if len(c.URLs) < 6 && !contains(c.URLs, u) {
					c.URLs = append(c.URLs, u)
				}
			}
			for _, wl := range a.Wallets {
				if len(c.Wallets) < 4 && !contains(c.Wallets, wl) {
					c.Wallets = append(c.Wallets, wl)
				}
			}
		}
		for ip := range g.ips {
			c.IPs = append(c.IPs, ip)
		}
		sort.Strings(c.IPs)
		if len(c.IPs) > 50 {
			c.IPs = c.IPs[:50]
		}
		c.Countries, c.NASNs = topCounts(ctry, 8), len(asns)
		best := 0
		for p, n := range profiles {
			if n > best || n == best && p < c.Profile {
				c.Profile, best = p, n
			}
		}
		for k := range g.keys {
			r := reasons[k]
			if strings.HasPrefix(k, "creds:") {
				r = "gleiche Zugangsdatenliste"
			}
			if !contains(c.Reasons, r) {
				c.Reasons = append(c.Reasons, r)
			}
		}
		sort.Strings(c.Reasons)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].NIPs > out[j].NIPs || out[i].NIPs == out[j].NIPs && out[i].Last > out[j].Last
	})
	if len(out) > 100 {
		out = out[:100]
	}

	// Werkzeuge: gleicher Fingerabdruck bei mindestens 3 IPs
	type fpAgg struct {
		ips  map[string]bool
		ctry map[string]int
		n    int
		last int64
	}
	fps := map[string]*fpAgg{}
	for _, a := range list {
		if a.Own {
			continue
		}
		for _, f := range a.Fingerprints {
			if strings.HasPrefix(f, "JA3 ") { // JA4 genügt; JA3 doppelt sonst jede Zeile
				continue
			}
			g := fps[f]
			if g == nil {
				g = &fpAgg{ips: map[string]bool{}, ctry: map[string]int{}}
				fps[f] = g
			}
			g.ips[a.IP] = true
			g.n++
			g.last = max(g.last, a.Last)
			if a.Country != "" {
				g.ctry[a.Country]++
			}
		}
	}
	var tools []FingerprintGroup
	for f, g := range fps {
		if len(g.ips) >= 3 {
			tools = append(tools, FingerprintGroup{Fingerprint: f, NIPs: len(g.ips), Countries: topCounts(g.ctry, 5), Attacks: g.n, Last: g.last})
		}
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].NIPs > tools[j].NIPs })
	if len(tools) > 30 {
		tools = tools[:30]
	}
	return out, tools
}

// campaigns: GET /api/campaigns?range=7d
func (h *Hive) campaigns(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	since := time.Now().Add(-7 * 24 * time.Hour)
	if _, ok := parseRange(r.URL.Query().Get("range")); ok {
		since, _ = rangeSince(r)
	}
	list, truncated, err := h.loadAttacks(ctx, since, nil)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	camps, tools := buildCampaigns(list)
	if camps == nil {
		camps = []Campaign{}
	}
	if tools == nil {
		tools = []FingerprintGroup{}
	}
	writeJSON(w, map[string]any{"campaigns": camps, "tools": tools, "hp_check": hpCheckStats(list), "no_cve": noCVEStats(list), "truncated": truncated})
}
