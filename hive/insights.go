package main

// Erkenntnisse (Ansicht "Erkenntnisse"):
//   C2 Angriffsfamilien: Angriffe mit Befehlen werden nach ihrer Befehlsfolge gruppiert
//      (normalisierte Wörter und Wortpaare, Jaccard-Ähnlichkeit). Familien, die erst in den
//      letzten 24 Stunden auftauchten, sind "neu"; Einzelgänger daraus sind "Ausreißer".
//   C3 Erstmals gesehen: Passwörter, Befehle, Pfade, Fingerabdrücke … deren erster Eintrag
//      in der Zähltabelle im Zeitraum liegt.
//   C4 Zusammenhänge: Wiederkehrer (IPs mit mehreren Angriffen), Erkunden → Angreifen (gleicher
//      seltener Fingerabdruck erst beim Abtasten, dann bei einem Angriff einer anderen IP) und
//      Spitzen-Warnung (Verbindungen je Dienst weit über dem Mittel; Benachrichtigung).
//
//   GET /api/insights?range=7d    Familien, Wiederkehrer, Erkunden → Angreifen (5 Min. zwischengespeichert)
//   GET /api/firstseen?range=24h  Erstmals gesehen

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------- C2: Familien ----------

var (
	normURL  = regexp.MustCompile(`(?i)\b(?:https?|ftp|tftp)://\S+`)
	normIP   = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b`)
	normHex  = regexp.MustCompile(`(?i)\b[0-9a-f]{8,}\b`)
	normNum  = regexp.MustCompile(`\b\d+\b`)
	normSplt = regexp.MustCompile(`[\s;|&]+`)
)

// commandTokens: normalisierte Wörter und Wortpaare einer Befehlsfolge. Zufällige Teile
// (Adressen, Hashes, Zahlen) werden durch Platzhalter ersetzt, damit Varianten derselben
// Kampagne zusammenfallen.
func commandTokens(cmds []string) map[string]bool {
	set := map[string]bool{}
	var prev string
	for _, c := range cmds {
		c = strings.ToLower(c)
		c = normURL.ReplaceAllString(c, "URL")
		c = normIP.ReplaceAllString(c, "IP")
		c = normHex.ReplaceAllString(c, "HEX")
		c = normNum.ReplaceAllString(c, "N")
		for _, w := range normSplt.Split(c, -1) {
			if w == "" || len(set) > 400 {
				continue
			}
			w = clip(w, 40)
			set[w] = true
			if prev != "" {
				set[prev+" "+w] = true
			}
			prev = w
		}
	}
	return set
}

func jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	in := 0
	for k := range a {
		if b[k] {
			in++
		}
	}
	return float64(in) / float64(len(a)+len(b)-in)
}

const familyThreshold = 0.5

type Family struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Attacks   int      `json:"attacks"`
	IPs       int      `json:"ips"`
	SampleIPs []string `json:"sample_ips"`
	Countries []Count  `json:"countries"`
	First     int64    `json:"first"`
	Last      int64    `json:"last"`
	Stufe     int      `json:"stufe"`
	Tags      []Count  `json:"tags,omitempty"`
	Example   []string `json:"example"` // Befehle des ersten Angriffs
	New       bool     `json:"new"`     // erst in den letzten 24 Stunden aufgetaucht
}

// maxFamilies begrenzt den Aufwand (Vergleich je Angriff gegen alle Familien):
// Ist die Grenze erreicht, kommt ein Angriff zur ähnlichsten vorhandenen Familie.
const maxFamilies = 400

func buildFamilies(ctx context.Context, list []*Attack, now time.Time) []Family {
	type fam struct {
		rep     map[string]bool
		members []*Attack
	}
	var fams []*fam
	sorted := make([]*Attack, 0, len(list))
	for _, a := range list {
		if !a.Own && len(a.Commands) > 0 {
			sorted = append(sorted, a)
		}
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].First < sorted[j].First })
	for i, a := range sorted {
		if i%200 == 0 && ctx.Err() != nil {
			break
		}
		toks := commandTokens(a.Commands)
		var best, closest *fam
		bestSim, closestSim := familyThreshold, -1.0
		for _, f := range fams {
			s := jaccard(toks, f.rep)
			if s >= bestSim {
				best, bestSim = f, s
			}
			if s > closestSim {
				closest, closestSim = f, s
			}
		}
		if best == nil && len(fams) >= maxFamilies {
			best = closest
		}
		if best == nil {
			best = &fam{rep: toks}
			fams = append(fams, best)
		}
		best.members = append(best.members, a)
	}
	dayAgo := now.Add(-24 * time.Hour).UnixMilli()
	out := make([]Family, 0, len(fams))
	for _, f := range fams {
		rep := f.members[0]
		sum := sha256.Sum256([]byte(strings.Join(rep.Commands, "\n")))
		fm := Family{ID: hex.EncodeToString(sum[:6]), Attacks: len(f.members), First: rep.First, Example: rep.Commands[:min(len(rep.Commands), 8)]}
		ips, ctry, tags := map[string]bool{}, map[string]int{}, map[string]int{}
		for _, a := range f.members {
			if !ips[a.IP] {
				ips[a.IP] = true
				if len(fm.SampleIPs) < 6 {
					fm.SampleIPs = append(fm.SampleIPs, a.IP)
				}
				if a.Country != "" {
					ctry[a.Country]++
				}
			}
			fm.Last = max(fm.Last, a.Last)
			fm.Stufe = max(fm.Stufe, a.Stufe)
			for _, t := range a.Tags {
				if t.Key != "recon" && t.Key != "obfuscation" {
					tags[t.Key]++
				}
			}
		}
		fm.IPs, fm.Countries = len(ips), topCounts(ctry, 5)
		fm.Tags = topCounts(tags, 4)
		for i := range fm.Tags {
			if p := patternByID[fm.Tags[i].Key]; p != nil {
				fm.Tags[i].Label = p.Name
			}
		}
		fm.New = fm.First >= dayAgo
		fm.Name = familyName(fm, rep)
		out = append(out, fm)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].New != out[j].New {
			return out[i].New
		}
		return out[i].Attacks > out[j].Attacks || out[i].Attacks == out[j].Attacks && out[i].Last > out[j].Last
	})
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

// familyName: stärkstes Muster plus Dienst, sonst das erste Befehlswort.
func familyName(f Family, rep *Attack) string {
	svc := strings.Join(rep.Services, "/")
	if len(f.Tags) > 0 {
		return f.Tags[0].Label + " über " + svcLabel(svc)
	}
	first := strings.Fields(rep.Commands[0])
	w := "Befehle"
	if len(first) > 0 {
		w = clip(first[0], 30)
	}
	return "„" + w + " …“ über " + svcLabel(svc)
}

func svcLabel(s string) string {
	switch s {
	case "ssh":
		return "SSH"
	case "telnet":
		return "Telnet"
	case "dockerapi":
		return "Docker-API"
	}
	return s
}

// ---------- C4: Wiederkehrer und Erkunden → Angreifen ----------

type Recurring struct {
	IP       string  `json:"ip"`
	Country  string  `json:"country,omitempty"`
	ASOrg    string  `json:"as_org,omitempty"`
	Attacks  int     `json:"attacks"`
	Days     int     `json:"days"`      // an wie vielen Tagen
	GapHours float64 `json:"gap_hours"` // mittlerer Abstand zwischen Angriffen
	Stufe    int     `json:"stufe"`
	Last     int64   `json:"last"`
	PerSlot  []int   `json:"per_slot"` // Angriffe je Fach (Kalenderstreifen in der UI)
}

func buildRecurring(list []*Attack, from time.Time, buckets int, step time.Duration) []Recurring {
	by := map[string][]*Attack{}
	for _, a := range list {
		if !a.Own {
			by[a.IP] = append(by[a.IP], a)
		}
	}
	var out []Recurring
	for ip, as := range by {
		if len(as) < 3 {
			continue
		}
		sort.Slice(as, func(i, j int) bool { return as[i].First < as[j].First })
		r := Recurring{IP: ip, Country: as[0].Country, ASOrg: as[0].ASOrg, Attacks: len(as), PerSlot: make([]int, max(buckets, 1))}
		days := map[int64]bool{}
		for _, a := range as {
			days[a.First/86400000] = true
			if step > 0 {
				i := int((a.First - from.UnixMilli()) / step.Milliseconds())
				r.PerSlot[min(max(i, 0), len(r.PerSlot)-1)]++
			}
			r.Stufe = max(r.Stufe, a.Stufe)
			r.Last = max(r.Last, a.Last)
		}
		r.Days = len(days)
		r.GapHours = float64(as[len(as)-1].First-as[0].First) / float64(len(as)-1) / 3600000
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Days > out[j].Days || out[i].Days == out[j].Days && out[i].Attacks > out[j].Attacks
	})
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

type Handoff struct {
	Fingerprint string `json:"fingerprint"`
	ScanIP      string `json:"scan_ip"`
	ScanAt      int64  `json:"scan_at"`
	AttackIP    string `json:"attack_ip"`
	AttackAt    int64  `json:"attack_at"`
	Stufe       int    `json:"stufe"`
	Profile     string `json:"profile"`
}

// buildHandoffs: gleicher seltener Fingerabdruck (bei 2 bis 10 IPs), erst beim Abtasten
// (Stufe 0) einer IP, binnen 48 Stunden danach bei einem Angriff (Stufe ≥ 1) einer anderen.
// Verbreitete Werkzeuge (Go, curl …) tauchen bei vielen IPs auf und sagen nichts; sie fallen weg.
func buildHandoffs(list []*Attack) []Handoff {
	by := map[string][]*Attack{}
	for _, a := range list {
		if a.Own {
			continue
		}
		for _, f := range a.Fingerprints {
			if !strings.HasPrefix(f, "JA3 ") {
				by[f] = append(by[f], a)
			}
		}
	}
	var out []Handoff
	for f, as := range by {
		ips := map[string]bool{}
		for _, a := range as {
			ips[a.IP] = true
		}
		if len(ips) < 2 || len(ips) > 10 {
			continue
		}
		sort.Slice(as, func(i, j int) bool { return as[i].First < as[j].First })
		for i, s := range as {
			if s.Stufe != 0 {
				continue
			}
			for _, a := range as[i+1:] {
				if a.IP != s.IP && a.Stufe >= 1 && a.First-s.Last <= 48*3600000 && a.First >= s.First {
					out = append(out, Handoff{Fingerprint: f, ScanIP: s.IP, ScanAt: s.First, AttackIP: a.IP, AttackAt: a.First, Stufe: a.Stufe, Profile: a.Profile})
					break
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AttackAt > out[j].AttackAt })
	if len(out) > 30 {
		out = out[:30]
	}
	return out
}

// ---------- Endpunkte ----------

type insightsCache struct {
	mu      sync.Mutex
	compute sync.Mutex // immer nur eine Berechnung gleichzeitig
	key     string
	at      time.Time
	val     map[string]any
	fsKey   string
	fsAt    time.Time
	fsVal   map[string][]map[string]any
}

func (c *insightsCache) get(rng string) (map[string]any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.key == rng && time.Since(c.at) < 5*time.Minute {
		return c.val, true
	}
	return nil, false
}

// insightBuckets: Fächer für den Kalenderstreifen der Wiederkehrer: Stunden bis zwei Tage,
// Tage bis 60 Tage, darüber Wochen.
func insightBuckets(rng string) (int, time.Duration) {
	d := rangeDur(rng, 7*24*time.Hour)
	step := 24 * time.Hour
	switch {
	case d <= 48*time.Hour:
		step = time.Hour
	case d > 60*24*time.Hour:
		step = 7 * 24 * time.Hour
	}
	return int((d + step - 1) / step), step
}

func (h *Hive) insights(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	if d, ok := parseRange(rng); !ok || d < 24*time.Hour {
		rng = "7d"
	}
	c := &h.insightsC
	if v, ok := c.get(rng); ok {
		writeJSON(w, v)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	c.compute.Lock()
	defer c.compute.Unlock()
	if v, ok := c.get(rng); ok { // inzwischen von einer anderen Anfrage berechnet
		writeJSON(w, v)
		return
	}
	// Für "neu" braucht es Vorgeschichte: mindestens 7 Tage laden.
	d := max(rangeDur(rng, 7*24*time.Hour), 7*24*time.Hour)
	list, truncated, err := h.loadAttacks(ctx, time.Now().Add(-d), nil)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	now := time.Now()
	sinceT := now.Add(-rangeDur(rng, 7*24*time.Hour))
	since := sinceT.UnixMilli()
	inRange := make([]*Attack, 0, len(list))
	for _, a := range list {
		if a.Last >= since {
			inRange = append(inRange, a)
		}
	}
	fams := buildFamilies(ctx, list, now)
	if ctx.Err() != nil {
		httpErr(w, 503, "Berechnung dauerte zu lange")
		return
	}
	shown := []Family{}
	for _, f := range fams {
		if f.Last >= since {
			shown = append(shown, f)
		}
	}
	nb, step := insightBuckets(rng)
	rec, ho := buildRecurring(inRange, sinceT, nb, step), buildHandoffs(inRange)
	if rec == nil {
		rec = []Recurring{}
	}
	if ho == nil {
		ho = []Handoff{}
	}
	v := map[string]any{"families": shown, "recurring": rec, "handoffs": ho, "spikes": h.pastSpikes(ctx, sinceT),
		"buckets": nb, "bucket_ms": step.Milliseconds(), "from": since, "truncated": truncated}
	c.mu.Lock()
	c.key, c.at, c.val = rng, time.Now(), v
	c.mu.Unlock()
	writeJSON(w, v)
}

// Spike: eine Stunde mit ungewöhnlich vielen Verbindungen auf einen Dienst.
type Spike struct {
	Service string  `json:"service"`
	Hour    int64   `json:"hour"` // Beginn der Stunde (ms)
	Count   int64   `json:"count"`
	Mean    float64 `json:"mean"`
}

// pastSpikes findet Spitzen im Zeitraum (Mittel aus den 7 Tagen vor dem Zeitraum und dem Zeitraum selbst).
func (h *Hive) pastSpikes(ctx context.Context, since time.Time) []Spike {
	out := []Spike{}
	from := since.UnixMilli() / 3600000
	rows, err := h.rows(ctx, `SELECT service, hour, SUM(cnt) AS n FROM hourly WHERE type = 'connect' AND hour >= ? AND country != 'LAN'
		GROUP BY service, hour`, from-7*24)
	if err != nil {
		return out
	}
	type agg struct {
		sum   int64
		hours map[int64]int64
	}
	by := map[string]*agg{}
	nowH := time.Now().UnixMilli() / 3600000
	for _, row := range rows {
		svc, _ := row["service"].(string)
		a := by[svc]
		if a == nil {
			a = &agg{hours: map[int64]int64{}}
			by[svc] = a
		}
		n := toInt64(row["n"])
		a.sum += n
		a.hours[toInt64(row["hour"])] = n
	}
	span := float64(nowH - (from - 7*24) + 1)
	for svc, a := range by {
		for hr, n := range a.hours {
			if hr < from {
				continue
			}
			mean := float64(a.sum-n) / (span - 1)
			if spikeCheck(float64(n), mean) {
				out = append(out, Spike{Service: svc, Hour: hr * 3600000, Count: n, Mean: mean})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hour > out[j].Hour })
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

// firstSeenFields: Felder der Zähltabelle, für die "erstmals gesehen" etwas aussagt.
var firstSeenFields = []string{"password", "cred", "command", "path", "hassh", "ja4", "url", "wallet", "port", "tag", "cve", "useragent"}

// firstSeen: GET /api/firstseen – teuer auf großen Datenbanken (je Feld über die ganze
// Zähltabelle), deshalb 10 Minuten zwischengespeichert und nie parallel berechnet.
func (h *Hive) firstSeen(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	c := &h.insightsC
	cached := func() (map[string][]map[string]any, bool) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.fsKey == rng && time.Since(c.fsAt) < 10*time.Minute {
			return c.fsVal, true
		}
		return nil, false
	}
	if v, ok := cached(); ok {
		writeJSON(w, v)
		return
	}
	c.compute.Lock()
	defer c.compute.Unlock()
	if v, ok := cached(); ok {
		writeJSON(w, v)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	since, _ := rangeSince(r)
	from := since.UnixMilli() / 3600000
	out := map[string][]map[string]any{}
	for _, f := range firstSeenFields {
		rows, err := h.rows(ctx, `SELECT key, MAX(label) AS label, MIN(hour) AS first, SUM(n) AS n FROM top_hourly WHERE field = ?
			GROUP BY key HAVING MIN(hour) >= ? ORDER BY n DESC LIMIT 15`, f, from)
		if err != nil {
			httpErr(w, 500, err.Error())
			return
		}
		for _, row := range rows {
			row["first"] = toInt64(row["first"]) * 3600000
		}
		if rows == nil {
			rows = []map[string]any{}
		}
		out[f] = rows
	}
	c.mu.Lock()
	c.fsKey, c.fsAt, c.fsVal = rng, time.Now(), out
	c.mu.Unlock()
	writeJSON(w, out)
}

// ---------- Spitzen-Warnung ----------

// spikeCheck vergleicht die letzte Stunde je Dienst mit dem Stundenmittel der 7 Tage davor.
// Ausgelöst wird bei mindestens 100 Verbindungen und dem Dreifachen des Mittels (mindestens +50).
func spikeCheck(cur, mean float64) bool {
	return cur >= 100 && cur >= 3*mean && cur >= mean+50
}

func (h *Hive) runSpikes(stop <-chan struct{}) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	lastSent := map[string]time.Time{}
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		c := h.Extras().Notify
		if !c.Enabled || !c.OnSpike {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		nowH := time.Now().UnixMilli() / 3600000
		rows, err := h.rows(ctx, `SELECT service, SUM(CASE WHEN hour >= ? THEN cnt ELSE 0 END) AS cur,
			SUM(CASE WHEN hour < ? THEN cnt ELSE 0 END) AS hist FROM hourly WHERE type = 'connect' AND hour >= ? AND country != 'LAN' GROUP BY service`,
			nowH-1, nowH-1, nowH-1-7*24)
		cancel()
		if err != nil {
			continue
		}
		for _, row := range rows {
			svc, _ := row["service"].(string)
			cur, mean := float64(toInt64(row["cur"]))/2, float64(toInt64(row["hist"]))/(7*24) // cur: letzte 2 Stundenfächer -> je Stunde
			if !spikeCheck(cur, mean) || time.Since(lastSent[svc]) < 6*time.Hour {
				continue
			}
			lastSent[svc] = time.Now()
			h.notifier.push(notice{Kind: "spike", Title: "Hivornet: ungewöhnlich viele Angriffe",
				Text: fmt.Sprintf("%s: etwa %.0f Verbindungen je Stunde, sonst %.0f.", svcLabel(svc), cur, mean), Time: time.Now()}, svc, c.MaxPerHour)
		}
	}
}
