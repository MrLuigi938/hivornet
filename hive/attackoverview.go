package main

// Übersicht für die Seite "Angriffe" in der Ansicht "Lagebild" (/api/attacks?overview=1):
//   - Verlauf: Angriffe je Abschnitt des Zeitraums (96 Säulen), nach Stufe; alle Filter außer
//     Stufe und Zeitfenster, damit man im Verlauf einen Ausschnitt wählen kann;
//   - Stufen: Anzahl je Stufe mit allen Filtern außer der Stufe (Trichter);
//   - Felder: häufigste Werte (Art, Muster, Dienst, Land, Netz, Zugangsdaten, Befehl,
//     Nachlade-Host) über alle passenden Angriffe, je Wert mit dem Suchbegriff der Suchsprache
//     (query.go), der genau diesen Wert filtert. Ein Klick in der Oberfläche hängt ihn an die Suche.

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const (
	overviewBuckets = 96
	overviewTop     = 8
)

type overviewValue struct {
	Value string `json:"v"`
	Label string `json:"l,omitempty"`
	N     int    `json:"n"`
	Query string `json:"q"`
}

type overviewField struct {
	Key      string          `json:"key"`
	Title    string          `json:"title"`
	Distinct int             `json:"distinct"`
	Top      []overviewValue `json:"top"`
}

type attackOverview struct {
	From   int64           `json:"from"`
	Step   int64           `json:"step"`
	Hist   [][5]int        `json:"hist"`
	Stufen [5]int          `json:"stufen"`
	Fields []overviewField `json:"fields"`

	counts map[string]map[string]int
	labels map[string]map[string]string
}

// Reihenfolge und Titel der Felder; der Suchbegriff je Feld steht in overviewQuery.
var overviewFields = []struct{ key, title string }{
	{"art", "Vermutete Art"}, {"tag", "Erkannte Muster"}, {"service", "Dienste"}, {"country", "Länder"},
	{"asn", "Netzbetreiber"}, {"cred", "Zugangsdaten"}, {"cmd", "Befehle"}, {"host", "Nachlade-Hosts"},
}

func newOverview(from, to int64) *attackOverview {
	step := max((to-from)/overviewBuckets, 1)
	return &attackOverview{From: from, Step: step, Hist: make([][5]int, overviewBuckets),
		counts: map[string]map[string]int{}, labels: map[string]map[string]string{}}
}

func (o *attackOverview) addHist(a *Attack) {
	i := int((a.First - o.From) / o.Step)
	o.Hist[min(max(i, 0), overviewBuckets-1)][a.Stufe]++
}

func (o *attackOverview) add(field, v, label string) {
	if v == "" {
		return
	}
	m := o.counts[field]
	if m == nil {
		m = map[string]int{}
		o.counts[field], o.labels[field] = m, map[string]string{}
	}
	m[v]++
	if label != "" {
		o.labels[field][v] = label
	}
}

// addFields zählt jeden Wert einmal je Angriff.
func (o *attackOverview) addFields(a *Attack) {
	o.add("art", a.Profile, "")
	for k := range a.tags {
		name := k
		if p := patternByID[k]; p != nil {
			name = p.Name
		}
		o.add("tag", k, name)
	}
	for _, s := range a.Services {
		o.add("service", s, "")
	}
	o.add("country", a.Country, a.CountryName)
	if a.ASN > 0 {
		o.add("asn", strconv.Itoa(a.ASN), "AS"+strconv.Itoa(a.ASN)+" "+a.ASOrg)
	}
	for k := range a.creds {
		o.add("cred", k, "")
	}
	seen := map[string]bool{}
	for _, c := range a.Commands {
		if !seen[c] {
			seen[c] = true
			o.add("cmd", c, "")
		}
	}
	seen = map[string]bool{}
	for _, u := range a.URLs {
		if p, err := url.Parse(u); err == nil && p.Hostname() != "" && !seen[p.Hostname()] {
			seen[p.Hostname()] = true
			o.add("host", p.Hostname(), "")
		}
	}
}

// overviewQuery: Suchbegriff, der genau diesen Wert trifft. Anführungszeichen im Wert kann die
// Suchsprache nicht ausdrücken; sie werden zum Platzhalter * (Vergleich über den ganzen Wert).
func overviewQuery(field, v string) string {
	switch field {
	case "country":
		return "country:" + v
	case "asn":
		return "asn=" + v
	case "host":
		return `url:"` + strings.ReplaceAll(v, `"`, "") + `"`
	}
	if strings.Contains(v, `"`) {
		return field + `:"` + strings.ReplaceAll(v, `"`, "*") + `"`
	}
	return field + `="` + v + `"`
}

func (o *attackOverview) finish() *attackOverview {
	for _, f := range overviewFields {
		m := o.counts[f.key]
		if len(m) == 0 {
			continue
		}
		vals := make([]overviewValue, 0, len(m))
		for v, n := range m {
			vals = append(vals, overviewValue{Value: v, Label: o.labels[f.key][v], N: n, Query: overviewQuery(f.key, v)})
		}
		sort.Slice(vals, func(i, j int) bool {
			return vals[i].N > vals[j].N || vals[i].N == vals[j].N && vals[i].Value < vals[j].Value
		})
		o.Fields = append(o.Fields, overviewField{Key: f.key, Title: f.title, Distinct: len(vals), Top: vals[:min(len(vals), overviewTop)]})
	}
	return o
}
