package main

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Verweildauer nach dem Login (Konzept KI-Honeypot, Vorschlag 2): Kennzahlen je Dienst, damit sich
// jede Änderung an Shell, Prüfreihe oder Persona messen lässt. Gemessen wird nur an Sitzungen mit
// angenommenem Login. Alles wird auf Abruf aus der Ereignistabelle gerechnet und fünf Minuten
// zwischengespeichert; es kommt nichts Neues in die Datenbank.

const (
	dwellMaxRows   = 2_000_000          // Obergrenze gelesener Ereignisse (Speicher auf dem Pi)
	dwellOpenGrace = 10 * time.Minute   // Sitzung ohne Ende, jünger als das: noch offen, nicht werten
	dwellReturnWin = 7 * 24 * time.Hour // Wiederkehr: neue Verbindung binnen 7 Tagen
	dwellCohort    = 30 * 24 * time.Hour
)

// DwellStat: Kennzahlen eines Dienstes.
type DwellStat struct {
	Service       string  `json:"service"`
	Logins        int     `json:"logins"`          // Sitzungen mit angenommenem Login
	NoCmd         int     `json:"no_cmd"`          // davon ohne einen Befehl
	MedianDwellMs int64   `json:"median_dwell_ms"` // Median Dauer vom Login bis zum Ende
	MedianCmds    float64 `json:"median_cmds"`
	AvgCmds       float64 `json:"avg_cmds"`
	CheckSessions int     `json:"check_sessions"` // Sitzungen mit Honeypot-Prüfreihe
	CheckFollow   int     `json:"check_follow"`   // davon mit weiterer Aktion (Befehl, Download) nach der Reihe
	ReturnIPs     int     `json:"return_ips"`     // IPs mit erstem Login vor 7 bis 37 Tagen
	ReturnBack    int     `json:"return_back"`    // davon binnen 7 Tagen nach dem Login erneut verbunden
}

type dwellSess struct {
	svc, ip   string
	login     int64 // ms, 0 = kein Login gesehen
	last, end int64
	cmds      int
	checked   bool // Prüfreihe gesehen
	follow    bool // nach dem letzten Prüfbefehl noch Befehl oder Download
}

type dwellAcc struct {
	dwell []int64
	cmds  []int
	st    DwellStat
}

func (a *dwellAcc) add(s *dwellSess) {
	a.st.Logins++
	if s.cmds == 0 {
		a.st.NoCmd++
	}
	end := s.end
	if end == 0 {
		end = s.last
	}
	a.dwell = append(a.dwell, max(0, end-s.login))
	a.cmds = append(a.cmds, s.cmds)
	if s.checked {
		a.st.CheckSessions++
		if s.follow {
			a.st.CheckFollow++
		}
	}
}

func (a *dwellAcc) finish() DwellStat {
	st := a.st
	n := len(a.dwell)
	if n == 0 {
		return st
	}
	sort.Slice(a.dwell, func(i, j int) bool { return a.dwell[i] < a.dwell[j] })
	sort.Ints(a.cmds)
	if n%2 == 1 {
		st.MedianDwellMs = a.dwell[n/2]
		st.MedianCmds = float64(a.cmds[n/2])
	} else {
		st.MedianDwellMs = (a.dwell[n/2-1] + a.dwell[n/2]) / 2
		st.MedianCmds = float64(a.cmds[n/2-1]+a.cmds[n/2]) / 2
	}
	sum := 0
	for _, c := range a.cmds {
		sum += c
	}
	st.AvgCmds = float64(sum) / float64(n)
	return st
}

// dwellRow: ein gelesenes Ereignis.
type dwellRow struct {
	svc, ip, sess, typ string
	ts                 int64
	ok                 bool
	input              string
}

// dwellCompute rechnet die Kennzahlen aus Ereignissen in Zeitfolge; die letzte Zeile der
// Antwort ist die Summe über alle Dienste. now dient nur dazu, noch offene Sitzungen auszulassen.
func dwellCompute(rows []dwellRow, now time.Time) []DwellStat {
	sess := map[string]*dwellSess{}
	checkRe := patternByID["honeypot_check"].re
	for _, r := range rows {
		if r.sess == "" {
			continue
		}
		s := sess[r.sess]
		if s == nil {
			s = &dwellSess{svc: r.svc, ip: r.ip}
			sess[r.sess] = s
		}
		if r.ts > s.last {
			s.last = r.ts
		}
		switch r.typ {
		case "login":
			if r.ok && s.login == 0 {
				s.login = r.ts
			}
		case "command":
			if s.login == 0 {
				continue
			}
			s.cmds++
			if checkRe.MatchString(r.input) {
				s.checked, s.follow = true, false
			} else if s.checked {
				s.follow = true
			}
		case "download":
			if s.checked && s.login != 0 {
				s.follow = true
			}
		case "disconnect":
			s.end = r.ts
		}
	}
	by := map[string]*dwellAcc{}
	all := &dwellAcc{}
	grace := now.Add(-dwellOpenGrace).UnixMilli()
	for _, s := range sess {
		if s.login == 0 || (s.end == 0 && s.last > grace) {
			continue
		}
		a := by[s.svc]
		if a == nil {
			a = &dwellAcc{st: DwellStat{Service: s.svc}}
			by[s.svc] = a
		}
		a.add(s)
		all.add(s)
	}
	out := make([]DwellStat, 0, len(by)+1)
	for _, a := range by {
		out = append(out, a.finish())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Logins != out[j].Logins {
			return out[i].Logins > out[j].Logins
		}
		return out[i].Service < out[j].Service
	})
	return append(out, all.finish())
}

func (h *Hive) dwellRows(ctx context.Context, since time.Time) ([]dwellRow, bool, error) {
	rs, err := h.st.db.QueryContext(ctx, `SELECT service, src_ip, session, type, ts,
		COALESCE(json_extract(data,'$.success'),0), COALESCE(json_extract(data,'$.input'),'')
		FROM events WHERE ts >= ? AND session != '' AND country != 'LAN'
		AND type IN ('login','command','disconnect','download')
		AND (type != 'login' OR json_extract(data,'$.success') = 1) ORDER BY ts LIMIT ?`, since.UnixMilli(), dwellMaxRows+1)
	if err != nil {
		return nil, false, err
	}
	defer rs.Close()
	var out []dwellRow
	for rs.Next() {
		var r dwellRow
		var ok int
		if err := rs.Scan(&r.svc, &r.ip, &r.sess, &r.typ, &r.ts, &ok, &r.input); err != nil {
			return nil, false, err
		}
		if ownHidden(r.ip) {
			continue
		}
		r.ok = ok == 1
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		return nil, false, err
	}
	trunc := len(out) > dwellMaxRows
	if trunc {
		out = out[:dwellMaxRows]
	}
	return out, trunc, nil
}

// dwellReturns: je Dienst die IPs, die vor 7 bis 37 Tagen zum ersten Mal einen Login hatten, und
// wie viele davon binnen 7 Tagen danach erneut verbunden haben (Wert: {IPs, davon zurück}).
func (h *Hive) dwellReturns(ctx context.Context, now time.Time) (map[string][2]int, error) {
	to := now.Add(-dwellReturnWin).UnixMilli()
	from := now.Add(-dwellReturnWin - dwellCohort).UnixMilli()
	rs, err := h.st.db.QueryContext(ctx, `SELECT f.service, f.ip,
		EXISTS(SELECT 1 FROM events c WHERE c.src_ip = f.ip AND c.service = f.service AND c.type = 'connect' AND c.ts > f.t AND c.ts <= f.t + ?)
		FROM (SELECT service, src_ip AS ip, MIN(ts) AS t FROM events WHERE type = 'login' AND ts >= ? AND ts < ? AND country != 'LAN'
		AND json_extract(data,'$.success') = 1 GROUP BY service, src_ip) f`, dwellReturnWin.Milliseconds(), from, to)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := map[string][2]int{}
	for rs.Next() {
		var svc, ip string
		var back int
		if err := rs.Scan(&svc, &ip, &back); err != nil {
			return nil, err
		}
		if ownHidden(ip) {
			continue
		}
		v := out[svc]
		v[0]++
		v[1] += back
		out[svc] = v
	}
	return out, rs.Err()
}

// dwellMerge setzt die Wiederkehr-Werte in die Dienstzeilen (Dienste ohne Login im Zeitraum, aber
// mit Wiederkehr-Gruppe, bekommen eine eigene Zeile) und liefert Zeilen und Summe getrennt.
func dwellMerge(stats []DwellStat, ret map[string][2]int) ([]DwellStat, DwellStat) {
	total := stats[len(stats)-1]
	rows := stats[:len(stats)-1]
	have := map[string]bool{}
	for i := range rows {
		have[rows[i].Service] = true
		v := ret[rows[i].Service]
		rows[i].ReturnIPs, rows[i].ReturnBack = v[0], v[1]
	}
	var extra []string
	for svc, v := range ret {
		total.ReturnIPs += v[0]
		total.ReturnBack += v[1]
		if !have[svc] {
			extra = append(extra, svc)
		}
	}
	sort.Strings(extra)
	for _, svc := range extra {
		rows = append(rows, DwellStat{Service: svc, ReturnIPs: ret[svc][0], ReturnBack: ret[svc][1]})
	}
	return rows, total
}

var dwellCache struct {
	mu   sync.Mutex
	h    *Hive
	rng  string
	at   time.Time
	val  map[string]any
	busy sync.Mutex // immer nur eine Berechnung gleichzeitig
}

func (h *Hive) dwell(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	if d, ok := parseRange(rng); !ok || d < 24*time.Hour {
		rng = "7d"
	}
	c := &dwellCache
	get := func() (map[string]any, bool) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.h == h && c.rng == rng && time.Since(c.at) < 5*time.Minute {
			return c.val, true
		}
		return nil, false
	}
	if v, ok := get(); ok {
		writeJSON(w, v)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	c.busy.Lock()
	defer c.busy.Unlock()
	if v, ok := get(); ok {
		writeJSON(w, v)
		return
	}
	now := time.Now()
	since := now.Add(-rangeDur(rng, 7*24*time.Hour))
	rows, trunc, err := h.dwellRows(ctx, since)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	ret, err := h.dwellReturns(ctx, now)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	svcs, total := dwellMerge(dwellCompute(rows, now), ret)
	v := map[string]any{"services": svcs, "total": total, "from": since.UnixMilli(), "truncated": trunc,
		"return_cohort_days": int(dwellCohort / (24 * time.Hour))}
	c.mu.Lock()
	c.h, c.rng, c.at, c.val = h, rng, time.Now(), v
	c.mu.Unlock()
	writeJSON(w, v)
}
