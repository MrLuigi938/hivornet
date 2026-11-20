package main

// Zusammengehörige IPs: Angreifer, die vermutlich derselbe Betreiber sind (z. B. ein Bot, der
// nach einer Sperre mit der Nachbaradresse weitermacht). Angezeigt auf der Angreiferseite
// ("Gehört vermutlich zu …" mit Begründung) und als dezentes Merkmal in den Angriffslisten.
//
// Bewusst vorsichtig: Verbreitete Werkzeuge (Go, curl, Mirai-Standardlisten) teilen viele
// Fremde. Zwei IPs gehören nur zusammen, wenn eines dieser Kriterien zutrifft:
//   1. dieselbe Zugangsdatenliste mit mindestens 10 verschiedenen Kombinationen (gleiche Menge),
//   2. dieselbe Nachlade-Adresse (Host) oder dieselbe Krypto-Wallet,
//   3. derselbe seltene Fingerabdruck (HASSH, JA4, HTTP; bei höchstens 10 IPs im Zeitraum)
//      UND dasselbe Netz (/24 bzw. /48),
//   4. derselbe sehr seltene Fingerabdruck (höchstens 5 IPs) UND dasselbe autonome System,
//   5. dieselbe Befehlsfolge (normalisiert, mindestens 2 Befehle) UND dasselbe Netz,
//   6. dieselben ersten 20 Zugangsdaten in derselben Reihenfolge UND dasselbe Netz oder AS
//      (ein Bot, der nach einer Sperre mit der Nachbaradresse von vorn beginnt).
// Gleiches Netz, gleiches AS oder zeitliche Nähe allein genügen nie. Forschungsscanner und
// eigene Tests bleiben außen vor. Gruppen werden verkettet (teilen zwei Paare eine IP, ist es
// eine Gruppe). Grundlage sind die Angriffe der letzten sieben Tage (attacksnap.go).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type IPGroup struct {
	ID      string   `json:"id"`
	IPs     []string `json:"ips"` // höchstens 50
	NIPs    int      `json:"n_ips"`
	Reasons []string `json:"reasons"`
}

// relKey: ein Merkmal, das IPs verbindet, mit lesbarer Begründung.
type relKey struct{ key, reason string }

func netOf(ip string) string {
	a := net.ParseIP(ip)
	if a == nil {
		return ""
	}
	if v4 := a.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	return (&net.IPNet{IP: a.Mask(net.CIDRMask(48, 128)), Mask: net.CIDRMask(48, 128)}).String()
}

func credSetKey(a *Attack) (string, int) {
	if len(a.creds) < 10 {
		return "", 0
	}
	keys := make([]string, 0, len(a.creds))
	for k := range a.creds {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return hex.EncodeToString(sum[:8]), len(keys)
}

// credOrderMax: so viele erste Kombinationen merkt sich ein Angriff in Reihenfolge.
const credOrderMax = 20

// credSeqKey: die ersten 20 Kombinationen in derselben Reihenfolge (dieselbe Wortliste im
// selben Werkzeug). Nur zusammen mit demselben Netz oder Netzbetreiber ein Kriterium.
func credSeqKey(a *Attack) string {
	if len(a.credOrder) < credOrderMax {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.Join(a.credOrder, "\n")))
	return hex.EncodeToString(sum[:8])
}

func cmdSetKey(a *Attack) string {
	if len(a.Commands) < 2 {
		return ""
	}
	var parts []string
	for _, c := range a.Commands {
		parts = append(parts, normCommand(c))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:8])
}

func shortFP(f string) string {
	kind, v, _ := strings.Cut(f, " ")
	if len(v) > 16 {
		v = v[:16] + "…"
	}
	return kind + " " + v
}

// relatedKeys: verbindende Merkmale eines Angriffs. fpIPs: Zahl der IPs je Fingerabdruck.
func relatedKeys(a *Attack, fpIPs map[string]int) []relKey {
	var out []relKey
	if k, n := credSetKey(a); k != "" {
		out = append(out, relKey{"creds:" + k, fmt.Sprintf("dieselbe Zugangsdatenliste (%d Kombinationen)", n)})
	}
	for _, raw := range a.URLs {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			host := strings.ToLower(u.Hostname())
			out = append(out, relKey{"url:" + host, "dieselbe Nachlade-Adresse " + host})
		}
	}
	for _, w := range a.Wallets {
		out = append(out, relKey{"wallet:" + w, "dieselbe Wallet " + shortWallet(w)})
	}
	if a.Scanner != "" {
		return out // Forschungsscanner teilen Netz und Werkzeug, sind aber kein Betreiber
	}
	nw := netOf(a.IP)
	for _, f := range a.Fingerprints {
		if strings.HasPrefix(f, "JA3 ") {
			continue
		}
		n := fpIPs[f]
		if n >= 2 && n <= 10 && nw != "" {
			out = append(out, relKey{"fpnet:" + f + "|" + nw, "derselbe seltene Fingerabdruck " + shortFP(f) + " aus demselben Netz " + nw})
		}
		if n >= 2 && n <= 5 && a.ASN != 0 {
			out = append(out, relKey{"fpas:" + f + "|" + strconv.Itoa(a.ASN), fmt.Sprintf("derselbe sehr seltene Fingerabdruck %s aus demselben Netzbetreiber AS%d", shortFP(f), a.ASN)})
		}
	}
	if k := credSeqKey(a); k != "" {
		if nw != "" {
			out = append(out, relKey{"credseqnet:" + k + "|" + nw, "dieselben ersten 20 Zugangsdaten in derselben Reihenfolge aus demselben Netz " + nw})
		}
		if a.ASN != 0 {
			out = append(out, relKey{"credseqas:" + k + "|" + strconv.Itoa(a.ASN), fmt.Sprintf("dieselben ersten 20 Zugangsdaten in derselben Reihenfolge aus demselben Netzbetreiber AS%d", a.ASN)})
		}
	}
	if k := cmdSetKey(a); k != "" && nw != "" {
		out = append(out, relKey{"cmdnet:" + k + "|" + nw, "dieselbe Befehlsfolge aus demselben Netz " + nw})
	}
	return out
}

// relatedGroups: Gruppen zusammengehöriger IPs (nur Gruppen mit mindestens 2 IPs) und je IP
// die Gruppe sowie die Merkmale, die sie mit anderen verbinden.
type relatedResult struct {
	groups map[string]*IPGroup          // IP -> Gruppe
	edges  map[string]map[string]string // IP -> Merkmal -> Begründung
	byKey  map[string][]string          // Merkmal -> IPs
}

func buildRelated(list []*Attack) *relatedResult {
	fpIPs := map[string]int{}
	{
		seen := map[string]bool{}
		for _, a := range list {
			if a.Own {
				continue
			}
			for _, f := range a.Fingerprints {
				if k := f + "\x00" + a.IP; !seen[k] {
					seen[k] = true
					fpIPs[f]++
				}
			}
		}
	}
	uf := unionFind{}
	res := &relatedResult{groups: map[string]*IPGroup{}, edges: map[string]map[string]string{}, byKey: map[string][]string{}}
	for _, a := range list {
		if a.Own {
			continue
		}
		for _, k := range relatedKeys(a, fpIPs) {
			e := res.edges[a.IP]
			if e == nil {
				e = map[string]string{}
				res.edges[a.IP] = e
			}
			if _, ok := e[k.key]; !ok {
				e[k.key] = k.reason
				res.byKey[k.key] = append(res.byKey[k.key], a.IP)
			}
		}
	}
	// nur Merkmale, die wirklich mehrere IPs verbinden
	for k, ips := range res.byKey {
		if len(ips) < 2 {
			delete(res.byKey, k)
			continue
		}
		for _, ip := range ips {
			uf.union("ip:"+ip, "k:"+k)
		}
	}
	members := map[string][]string{}
	for ip := range res.edges {
		if _, ok := uf["ip:"+ip]; !ok {
			continue
		}
		root := uf.find("ip:" + ip)
		members[root] = append(members[root], ip)
	}
	for _, ips := range members {
		if len(ips) < 2 {
			continue
		}
		sort.Strings(ips)
		sum := sha256.Sum256([]byte(strings.Join(ips, ",")))
		g := &IPGroup{ID: hex.EncodeToString(sum[:5]), NIPs: len(ips)}
		g.IPs = ips[:min(len(ips), 50)]
		for _, ip := range ips {
			for k, r := range res.edges[ip] {
				if len(res.byKey[k]) >= 2 && !contains(g.Reasons, r) && len(g.Reasons) < 8 {
					g.Reasons = append(g.Reasons, r)
				}
			}
			res.groups[ip] = g
		}
		sort.Strings(g.Reasons)
	}
	return res
}

// Related: andere IPs der Gruppe mit den Merkmalen, die sie direkt mit ip teilen.
type RelatedIP struct {
	IP      string   `json:"ip"`
	Reasons []string `json:"reasons"` // leer: nur über weitere IPs der Gruppe verbunden
}

func (r *relatedResult) related(ip string) (*IPGroup, []RelatedIP) {
	g := r.groups[ip]
	if g == nil {
		return nil, nil
	}
	direct := map[string][]string{}
	for k, reason := range r.edges[ip] {
		for _, other := range r.byKey[k] {
			if other != ip && !contains(direct[other], reason) {
				direct[other] = append(direct[other], reason)
			}
		}
	}
	var out []RelatedIP
	for _, other := range g.IPs {
		if other != ip {
			sort.Strings(direct[other])
			// nie nil: die UI liest reasons.length (Gruppe nur über weitere IPs verbunden)
			out = append(out, RelatedIP{IP: other, Reasons: append([]string{}, direct[other]...)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i].Reasons) > len(out[j].Reasons) })
	return g, out
}

// Zwischenspeicher: einmal je Fassung des Schnappschusses berechnen (hält nur IPs und
// Texte, keine Angriffe, damit ein freigegebener Schnappschuss wirklich frei wird).
var relatedCache struct {
	mu  sync.Mutex
	ver int64
	res *relatedResult
}

// relatedNow: Gruppen aus dem aktuellen Schnappschuss (nil, wenn er nicht aufgebaut werden kann).
func (h *Hive) relatedNow(ctx context.Context) *relatedResult {
	if h.refreshSnap(ctx) != nil {
		return nil
	}
	s := &h.snap
	s.mu.Lock()
	list, ver := s.list, s.ver
	s.mu.Unlock()
	if list == nil {
		return nil
	}
	c := &relatedCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.res == nil || c.ver != ver {
		c.ver, c.res = ver, buildRelated(list)
	}
	return c.res
}
