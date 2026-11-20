package main

// Verlauf eines Angreifers über alle seine Angriffe (Angreiferseite, ab dem 4. Angriff):
// Kennzahlen, ein Punkt je Angriff für den Zeitstreifen, Stufen, häufigste Zugangsdaten,
// alle Befehle in Reihenfolge und einige Sätze, was er gemacht hat. Berechnet auf dem Hive
// über alles, was die Aufbewahrung hält (nicht nur die in der UI geladenen Karten), aus den
// Ereignissen dieser einen IP (Index ev_ip, also schnell).
//
// Sätze ohne Uhrzeiten (nur Dauern): Uhrzeiten zeigt die UI in der Zeitzone des Browsers.
// "Rund um die Uhr" wird in der eingestellten Zeitzone des Hives bestimmt (timezone.go).

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

type historyPoint struct {
	T        int64  `json:"t"`
	Last     int64  `json:"last"`
	Stufe    int    `json:"stufe"`
	Kind     string `json:"kind"`
	Logins   int    `json:"logins"`
	Commands int    `json:"commands"`
	Success  bool   `json:"success,omitempty"`
}

type AttackerHistory struct {
	Attacks       int            `json:"attacks"`
	Days          int            `json:"days"` // Kalendertage mit Angriffen (Zeitzone des Hives)
	First         int64          `json:"first"`
	Last          int64          `json:"last"`
	MedianGapMs   int64          `json:"median_gap_ms"`
	Logins        int            `json:"logins"`
	LoginsOK      int            `json:"logins_ok"` // Angriffe mit angenommenem Login
	ByStufe       [5]int         `json:"by_stufe"`
	Points        []historyPoint `json:"points"` // aufsteigend, höchstens historyMaxPoints (die neuesten)
	Creds         []Count        `json:"creds"`
	CredsDistinct int            `json:"creds_distinct"`
	OKCreds       []Count        `json:"ok_creds"`
	Commands      []string       `json:"commands"` // alle Befehle in zeitlicher Reihenfolge (gekürzt)
	CommandsMore  int            `json:"commands_more,omitempty"`
	Story         []string       `json:"story"`
	Truncated     bool           `json:"truncated,omitempty"`
}

const (
	historyMaxPoints   = 1000
	historyMaxCommands = 200
)

func fmtSpan(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d Min", max(1, int(d.Minutes()+0.5)))
	case d < 48*time.Hour:
		h := int(d.Hours())
		if m := int(d.Minutes()) % 60; m >= 5 && h < 10 {
			return fmt.Sprintf("%d Std %d Min", h, m)
		}
		return fmt.Sprintf("%d Std", int(d.Hours()+0.5))
	}
	return fmt.Sprintf("%d Tagen", int(d.Hours()/24+0.5))
}

// buildHistory: list ist beliebig sortiert; eigene Liste wird erzeugt.
func buildHistory(list []*Attack, truncated bool) *AttackerHistory {
	as := append([]*Attack(nil), list...)
	sort.Slice(as, func(i, j int) bool { return as[i].First < as[j].First })
	hs := &AttackerHistory{Attacks: len(as), Truncated: truncated, Points: []historyPoint{}, Creds: []Count{}, OKCreds: []Count{}, Commands: []string{}, Story: []string{}}
	if len(as) == 0 {
		return hs
	}
	loc := hiveLoc()
	hs.First, hs.Last = as[0].First, as[0].Last
	days, quarters := map[string]bool{}, map[int]bool{}
	creds, ok := map[string]int{}, map[string]int{}
	var tagOrder, hosts []string
	clients, hassh := map[string]bool{}, map[string]bool{}
	withClient, brute, cmdAttacks := 0, 0, 0
	var gaps []int64
	for i, a := range as {
		hs.Last = max(hs.Last, a.Last)
		t := time.UnixMilli(a.First).In(loc)
		days[t.Format("2006-01-02")] = true
		quarters[t.Hour()/6] = true
		if i > 0 {
			gaps = append(gaps, a.First-as[i-1].First)
		}
		logins := a.Counts["login"]
		hs.Logins += logins
		hs.ByStufe[min(max(a.Stufe, 0), 4)]++
		hs.Points = append(hs.Points, historyPoint{T: a.First, Last: a.Last, Stufe: a.Stufe, Kind: a.Profile, Logins: logins, Commands: len(a.Commands), Success: a.Success})
		for k, n := range a.creds {
			if len(creds) < 20000 || creds[k] > 0 {
				creds[k] += n
			}
		}
		if a.Success {
			hs.LoginsOK++
			if a.SuccessCred != "" {
				ok[a.SuccessCred]++
			}
		}
		if len(a.Commands) > 0 {
			cmdAttacks++
		}
		for _, c := range a.Commands {
			if len(hs.Commands) < historyMaxCommands {
				hs.Commands = append(hs.Commands, c)
			} else {
				hs.CommandsMore++
			}
		}
		for _, tg := range a.Tags {
			if l := nonEmptyFirst(tg.Label, tg.Key); !contains(tagOrder, l) && len(tagOrder) < 8 {
				tagOrder = append(tagOrder, l)
			}
		}
		for _, raw := range a.URLs {
			if u, err := url.Parse(raw); err == nil && u.Hostname() != "" && !contains(hosts, u.Hostname()) && len(hosts) < 3 {
				hosts = append(hosts, u.Hostname())
			}
		}
		if len(a.Clients) > 0 {
			withClient++
			for _, c := range a.Clients {
				clients[c] = true
			}
		}
		for _, f := range a.Fingerprints {
			if strings.HasPrefix(f, "HASSH ") {
				hassh[f] = true
			}
		}
		if a.Brute {
			brute++
		}
	}
	if len(hs.Points) > historyMaxPoints {
		hs.Points = hs.Points[len(hs.Points)-historyMaxPoints:]
	}
	hs.Days = len(days)
	if len(gaps) > 0 {
		sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
		hs.MedianGapMs = gaps[len(gaps)/2]
	}
	hs.CredsDistinct = len(creds)
	hs.Creds, hs.OKCreds = topCounts(creds, 8), topCounts(ok, 5)
	if hs.Creds == nil {
		hs.Creds = []Count{}
	}
	if hs.OKCreds == nil {
		hs.OKCreds = []Count{}
	}

	// ---- in Sätzen ----
	n := len(as)
	s := fmt.Sprintf("%d Angriffe in %s", n, fmtSpan(time.Duration(hs.Last-hs.First)*time.Millisecond))
	if n >= 2 {
		s += ", etwa alle " + fmtSpan(time.Duration(hs.MedianGapMs)*time.Millisecond)
	}
	if len(quarters) >= 3 && n >= 6 {
		s += ", rund um die Uhr"
	}
	if n >= 6 && hs.MedianGapMs > 0 && hs.MedianGapMs < int64(6*time.Hour/time.Millisecond) {
		s += ": wirkt wie ein automatischer Bot"
	}
	hs.Story = append(hs.Story, s+".")
	if hs.Logins > 0 {
		s = fmt.Sprintf("%d Login-Versuche mit %d verschiedenen Kombinationen", hs.Logins, hs.CredsDistinct)
		if len(hs.OKCreds) > 0 {
			var k []string
			for _, c := range hs.OKCreds {
				k = append(k, c.Key)
			}
			s += "; angenommen wurden " + strings.Join(k, ", ")
		} else {
			s += "; keiner angenommen"
		}
		hs.Story = append(hs.Story, s+".")
	}
	if cmdAttacks > 0 {
		s = fmt.Sprintf("%d-mal Befehle ausgeführt (%d insgesamt)", cmdAttacks, len(hs.Commands)+hs.CommandsMore)
		if len(tagOrder) > 0 {
			s += ", in dieser Abfolge: " + strings.Join(tagOrder, " → ")
		}
		hs.Story = append(hs.Story, s+".")
	} else if len(tagOrder) > 0 {
		hs.Story = append(hs.Story, "Erkannte Muster: "+strings.Join(tagOrder, ", ")+".")
	}
	if len(hosts) > 0 {
		hs.Story = append(hs.Story, "Nachladeversuch von "+strings.Join(hosts, ", ")+".")
	}
	if withClient >= 2 && len(clients) == 1 {
		var c string
		for k := range clients {
			c = k
		}
		s = "Gleicher Client " + clip(c, 60)
		if len(hassh) == 1 {
			s += " und gleicher HASSH"
		}
		if withClient == n {
			s += " bei allen Angriffen."
		} else {
			s += fmt.Sprintf(" bei %d von %d Angriffen.", withClient, n)
		}
		hs.Story = append(hs.Story, s)
	}
	if brute > 0 {
		hs.Story = append(hs.Story, fmt.Sprintf("%d davon als Dauer-Brute-Force erkannt.", brute))
	}
	return hs
}
