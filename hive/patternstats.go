package main

// Daten für die Ansicht "Analyse" (Konzept A, konzepte/d-auswertung.html):
//   - GET /api/analysis/patterns: alle erkannten Muster mit Phase, Schwere, MITRE und
//     einem Verlauf in 14 Abschnitten, aus der Zähltabelle (ein Abfragelauf);
//   - noCVEStats: Exploit-Versuche, für die es keine CVE-Regel gibt (cve.go), damit neue
//     Regeln schnell geschrieben sind (Teil der Antwort von /api/campaigns).

import (
	"net/http"
	"sort"
)

type PatternStat struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Desc   string   `json:"desc"`
	Sev    int      `json:"sev"`
	Phase  int      `json:"phase"`
	Mitre  []string `json:"mitre,omitempty"`
	N      int64    `json:"n"`
	Series []int64  `json:"series"`
}

const seriesBuckets = 14

func (h *Hive) patternStats(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := qctx(r)
	defer cancel()
	since, d := rangeSince(r)
	from := since.UnixMilli() / 3600000
	hours := max(int64(d.Hours()), 1)
	rows, err := h.rows(ctx, `SELECT key, hour, SUM(n) AS n FROM top_hourly WHERE field = 'tag' AND hour >= ? GROUP BY key, hour`, from)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	stats := map[string]*PatternStat{}
	for _, row := range rows {
		id, _ := row["key"].(string)
		p := patternByID[id]
		if p == nil {
			continue
		}
		s := stats[id]
		if s == nil {
			s = &PatternStat{ID: id, Name: p.Name, Desc: p.Desc, Sev: p.Sev, Phase: patternPhase[id], Mitre: patternMitre[id], Series: make([]int64, seriesBuckets)}
			stats[id] = s
		}
		n, hr := toInt64(row["n"]), toInt64(row["hour"])
		s.N += n
		b := min(max((hr-from)*seriesBuckets/hours, 0), seriesBuckets-1)
		s.Series[b] += n
	}
	out := make([]*PatternStat, 0, len(stats))
	for _, s := range stats {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].N > out[j].N || out[i].N == out[j].N && out[i].ID < out[j].ID })
	writeJSON(w, map[string]any{"phases": chainPhases, "patterns": out})
}

func toInt64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	}
	return 0
}

// ---- Exploits ohne CVE ----

var exploitTags = []string{"iot_exploit", "web_rce", "log4shell"}

type NoCVEItem struct {
	IP      string `json:"ip"`
	Country string `json:"country,omitempty"`
	Pattern string `json:"pattern"`
	Path    string `json:"path"`
	Last    int64  `json:"last"`
}

type NoCVEStats struct {
	Attacks int         `json:"attacks"`
	Paths   []Count     `json:"paths"`  // häufigste Pfade der Versuche ohne CVE
	Recent  []NoCVEItem `json:"recent"` // neueste Beispiele
}

func noCVEStats(list []*Attack) NoCVEStats {
	st := NoCVEStats{Paths: []Count{}, Recent: []NoCVEItem{}}
	paths := map[string]int{}
	for _, a := range list {
		if a.Own || len(a.CVEs) > 0 {
			continue
		}
		tag := ""
		for _, t := range a.Tags {
			if contains(exploitTags, t.Key) {
				tag = t.Label
				break
			}
		}
		if tag == "" {
			continue
		}
		st.Attacks++
		path := ""
		for _, p := range a.Paths {
			if p.Key != "" && p.Key != "/" && p.Key != "/favicon.ico" {
				path = p.Key
				paths[p.Key] += p.N
				if len(paths) > 2000 {
					break
				}
			}
		}
		if path == "" && len(a.Paths) > 0 {
			path = a.Paths[0].Key
		}
		st.Recent = append(st.Recent, NoCVEItem{IP: a.IP, Country: a.Country, Pattern: tag, Path: path, Last: a.Last})
	}
	st.Paths = topCounts(paths, 15)
	sort.Slice(st.Recent, func(i, j int) bool { return st.Recent[i].Last > st.Recent[j].Last })
	if len(st.Recent) > 15 {
		st.Recent = st.Recent[:15]
	}
	return st
}
