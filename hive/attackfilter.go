package main

// Gemeinsame Filter der drei Ansichten der Seite "Angriffe" (gebündelt, Sitzungen, einzelne
// Ereignisse): Zeitraum (range), Suchsprache (aq bzw. bei /api/attacks q, query.go), Stufe,
// Dienst und Zeitabschnitt (from/to). Sitzungen und Ereignisse werden über die passenden
// Angriffe gefiltert: eine Sitzung gehört dazu, wenn ihr Angriff passt; ein Ereignis, wenn es
// von einer IP eines passenden Angriffs innerhalb dessen Zeitspanne stammt.

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// attackFilter: Bedingungen aus der Anfrage. active=false: keine Angriffsfilter gesetzt.
type attackFilter struct {
	terms    []qTerm
	stufe    map[int]bool
	service  string
	from, to int64
	active   bool
}

func parseAttackFilter(r *http.Request, queryParam string) attackFilter {
	q := r.URL.Query()
	f := attackFilter{terms: parseQuery(q.Get(queryParam)), service: q.Get("service")}
	if v := q.Get("stufe"); v != "" {
		f.stufe = map[int]bool{}
		for _, s := range strings.Split(v, ",") {
			if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 4 {
				f.stufe[n] = true
			}
		}
	}
	f.from, _ = strconv.ParseInt(q.Get("from"), 10, 64)
	f.to, _ = strconv.ParseInt(q.Get("to"), 10, 64)
	f.active = len(f.terms) > 0 || len(f.stufe) > 0 || f.service != "" || f.from > 0 || f.to > 0
	return f
}

func (f attackFilter) match(a *Attack) bool {
	return (len(f.stufe) == 0 || f.stufe[a.Stufe]) && (f.service == "" || a.svc[f.service]) && a.matchQuery(f.terms) &&
		(f.from <= 0 || a.Last >= f.from) && (f.to <= 0 || a.First <= f.to)
}

// matchingAttacks: Angriffe des Zeitraums, die passen (eigene Tests ausgenommen).
func (h *Hive) matchingAttacks(ctx context.Context, r *http.Request, f attackFilter) ([]*Attack, error) {
	since := time.Now().Add(-24 * time.Hour)
	if rng := r.URL.Query().Get("range"); rng == "all" {
		since = time.Now().AddDate(0, 0, -max(h.retentionDays(), 1))
	} else if _, ok := parseRange(rng); ok {
		since, _ = rangeSince(r)
	}
	list, _, err := h.attacksSince(ctx, since)
	if err != nil {
		return nil, err
	}
	out := list[:0:0]
	for _, a := range list {
		if !a.Own && f.match(a) {
			out = append(out, a)
		}
	}
	return out, nil
}

// sessAttackIndex ordnet Sitzungen ihrem Angriff zu (Stufe, Art und Befehle für die Sitzungsliste).
// Ein Angriff merkt sich höchstens 50 Sitzungs-IDs (attacks.go); weitere Sitzungen findet die
// Zuordnung über IP und Zeitspanne des Angriffs, ohne alle IDs im Speicher zu halten.
type sessAttackIndex struct {
	bySess map[string]*Attack
	byIP   map[string][]*Attack
}

func sessionAttacks(list []*Attack) sessAttackIndex {
	x := sessAttackIndex{bySess: map[string]*Attack{}, byIP: map[string][]*Attack{}}
	for _, a := range list {
		for _, s := range a.Sessions {
			x.bySess[s] = a
		}
		x.byIP[a.IP] = append(x.byIP[a.IP], a)
	}
	return x
}

// find: Angriff der Sitzung; sonst der Angriff derselben IP, in dessen Zeitspanne die Sitzung
// beginnt (bei Überlappung der mit dem spätesten Beginn).
func (x sessAttackIndex) find(sess, ip string, start int64) *Attack {
	if a := x.bySess[sess]; a != nil {
		return a
	}
	var best *Attack
	for _, a := range x.byIP[ip] {
		if start >= a.First && start <= a.Last && (best == nil || a.First > best.First) {
			best = a
		}
	}
	return best
}

// ipWindows: je IP die Zeitspannen ihrer passenden Angriffe (Ereignisfilter).
type ipWindows map[string][][2]int64

func attackWindows(list []*Attack) ipWindows {
	w := ipWindows{}
	for _, a := range list {
		w[a.IP] = append(w[a.IP], [2]int64{a.First, a.Last})
	}
	return w
}

func (w ipWindows) has(ip string, ts int64) bool {
	for _, x := range w[ip] {
		if ts >= x[0] && ts <= x[1] {
			return true
		}
	}
	return false
}
