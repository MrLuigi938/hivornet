package main

// Gemeinsamer Schnappschuss der Angriffe der letzten sieben Tage.
//
// Erkenntnisse, Kampagnen, Exploits und die Seite "Angriffe" bauten jeder für sich alle
// Angriffe der Woche aus den Rohdaten auf (loadAttacks). Auf einem Raspberry Pi mit einigen
// hunderttausend Ereignissen dauerte das je Aufruf rund 7 Sekunden (Live-Check 0.8.0), fast
// nur für das Lesen der Zeilen aus SQLite.
//
// Jetzt gibt es einen Schnappschuss:
//   - Voller Aufbau beim ersten Bedarf, danach alle 30 Minuten (und nach geänderten
//     Einstellungen, die die Einstufung betreffen).
//   - Dazwischen inkrementell: Nur IPs mit neuen Ereignissen (id > zuletzt gesehene) werden
//     neu aufgebaut und ersetzen ihre Angriffe; alle anderen bleiben, wie sie sind.
//   - Höchstens alle 20 Sekunden wird nach Neuem geschaut.
//   - Speicher: etwa 4 KB je Angriff (Zugangsdaten, Pfade und Befehle bleiben vollständig für
//     die Suche). Wird der Schnappschuss 20 Minuten nicht gebraucht, gibt der Hive ihn frei;
//     vor einem vollen Neuaufbau ebenso, damit nie zwei Fassungen gleichzeitig im Speicher liegen.
//
// Die Angriffe im Schnappschuss sind nach dem Aufbau unveränderlich. Verbraucher bekommen
// eine eigene Liste (attacksSince), dürfen die Angriffe selbst aber nicht verändern.
// Zeiträume über sieben Tage lesen wie bisher direkt.

import (
	"context"
	"sort"
	"sync"
	"time"
)

const (
	snapWindow     = 7 * 24 * time.Hour
	snapFullEvery  = 30 * time.Minute
	snapCheckEvery = 20 * time.Second
	snapMaxIPs     = 3000 // mehr IPs mit Neuem: lieber voll neu aufbauen
	snapIdle       = 20 * time.Minute
)

type attackSnap struct {
	build sync.Mutex // immer nur ein Aufbau

	mu        sync.Mutex
	list      []*Attack // nach Last absteigend
	since     time.Time // Beginn beim vollen Aufbau
	maxID     int64     // höchste berücksichtigte Ereignis-ID
	truncated bool
	fullAt    time.Time
	checkAt   time.Time
	usedAt    time.Time // letzter Zugriff (attacksSince)
	ver       int64     // zählt jede neue Fassung der Liste (related.go)
	dirty     bool      // Einstellungen geändert: beim nächsten Mal voll neu aufbauen
	gen       int64     // analysisGen beim vollen Aufbau (geänderte Regeln: neu aufbauen)
	run       *snapRun  // Aufbau für Anfragen im Hintergrund (snapWait)

	// Zustand für die Systemseite (snapStatus)
	fullStart time.Time     // voller Aufbau läuft seit (null: keiner)
	fullDur   time.Duration // Dauer des letzten fertigen vollen Aufbaus
	fullErr   string        // Fehler des letzten vollen Aufbaus
	fullFails int           // abgebrochene volle Aufbauten seit dem Start
}

// snapStatus: Zustand des Schnappschusses für /api/system.
func (s *attackSnap) status() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[string]any{"ready": s.list != nil, "attacks": len(s.list), "full_ms": s.fullDur.Milliseconds(), "fails": s.fullFails}
	if !s.fullAt.IsZero() {
		m["full_at"] = s.fullAt
	}
	if !s.fullStart.IsZero() {
		m["building_since"] = s.fullStart
	}
	if s.fullErr != "" {
		m["error"] = s.fullErr
	}
	return m
}

// snapRun: ein Aufbau im Hintergrund; done wird geschlossen, wenn err feststeht.
type snapRun struct {
	done chan struct{}
	err  error
}

// snapBuild: Frist eines Aufbaus im Hintergrund. Live-Check 0.9.7-beta.1: Auf einem Pi 3 mit
// rund 40.000 Ereignissen am Tag brauchte der volle Aufbau über sieben Tage länger als die
// früheren 5 Minuten (jedes Ereignis wird gegen alle Regeln geprüft, analysiscache.go). Er wurde
// abgebrochen, verworfen und neu begonnen, belegte dabei dauerhaft einen Platz in heavySem und
// einen CPU-Kern, und die Seite Angriffe bekam nie eine Antwort. Ist er einmal fertig, geht es
// inkrementell weiter (Millisekunden).
var snapBuild = 30 * time.Minute

// invalidate: beim nächsten Zugriff voll neu aufbauen (geänderte eigene Netze, Brute-Force …).
func (s *attackSnap) invalidate() {
	s.mu.Lock()
	s.dirty = true
	s.mu.Unlock()
}

func (s *attackSnap) get() ([]*Attack, time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.list, s.since, s.truncated
}

// attacksSince liefert alle Angriffe mit Aktivität ab since (Liste gehört dem Aufrufer, die
// Angriffe nicht). Angriffe, die vor since begannen, sind vollständig enthalten.
func (h *Hive) attacksSince(ctx context.Context, since time.Time) ([]*Attack, bool, error) {
	if time.Since(since) > snapWindow+time.Minute {
		return h.loadAttacks(ctx, since, nil)
	}
	h.snap.mu.Lock()
	h.snap.usedAt = time.Now()
	h.snap.mu.Unlock()
	var list []*Attack
	var from time.Time
	var truncated bool
	// Zweiter Versuch, falls zwischen Prüfung und Lesen ein voller Neuaufbau begann (die alte
	// Fassung ist dann schon freigegeben); refreshSnap wartet auf dessen Ende.
	for try := 0; try < 2 && list == nil; try++ {
		if err := h.snapWait(ctx); err != nil {
			return nil, false, err
		}
		list, from, truncated = h.snap.get()
	}
	cut := since.UnixMilli()
	out := make([]*Attack, 0, len(list))
	for _, a := range list {
		if a.Last >= cut {
			out = append(out, a)
		}
	}
	// War der volle Aufbau gekürzt (sehr viele Ereignisse), fehlen die ältesten Angriffe.
	return out, truncated && from.After(since), nil
}

// snapWait bringt den Schnappschuss für eine Anfrage auf Stand, wartet aber höchstens bis ctx
// abläuft (dann errBusy). Live-Check 0.9.7: Vorher baute die Anfrage selbst auf, mit ihrer
// 20-Sekunden-Frist; dauerte der volle Aufbau auf dem Pi länger, war die alte Fassung schon
// freigegeben, die neue wurde verworfen und die nächste Anfrage begann von vorn. Weitere Anfragen
// warteten ohne Frist an der Sperre und hingen minutenlang. Jetzt läuft der Aufbau im
// Hintergrund zu Ende, auch wenn die Anfrage aufgibt.
func (h *Hive) snapWait(ctx context.Context) error {
	s := &h.snap
	s.mu.Lock()
	if s.list != nil && !s.dirty && time.Since(s.checkAt) < snapCheckEvery {
		s.mu.Unlock()
		return nil
	}
	run := s.run
	if run == nil {
		run = &snapRun{done: make(chan struct{})}
		s.run = run
		go func() {
			bctx, cancel := context.WithTimeout(context.Background(), snapBuild)
			err := h.refreshSnap(bctx)
			cancel()
			s.mu.Lock()
			run.err = err
			if s.run == run {
				s.run = nil
			}
			s.mu.Unlock()
			close(run.done)
		}()
	}
	s.mu.Unlock()
	select {
	case <-run.done:
		return run.err
	case <-ctx.Done():
		return errBusy
	}
}

// snapReady: Der Schnappschuss ist aufgebaut (vielleicht nicht ganz aktuell).
func (h *Hive) snapReady() bool {
	h.snap.mu.Lock()
	defer h.snap.mu.Unlock()
	return h.snap.list != nil && !h.snap.dirty
}

func (h *Hive) refreshSnap(ctx context.Context) error {
	s := &h.snap
	s.mu.Lock()
	fresh := s.list != nil && !s.dirty && time.Since(s.checkAt) < snapCheckEvery
	s.mu.Unlock()
	if fresh {
		return nil
	}
	s.build.Lock()
	defer s.build.Unlock()
	s.mu.Lock()
	fresh = s.list != nil && !s.dirty && time.Since(s.checkAt) < snapCheckEvery // inzwischen erledigt?
	full := s.list == nil || s.dirty || time.Since(s.fullAt) > snapFullEvery || s.gen != analysisGen.Load()
	lastID, since := s.maxID, s.since
	s.mu.Unlock()
	if fresh {
		return nil
	}
	var maxID int64
	if err := h.st.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM events`).Scan(&maxID); err != nil {
		return err
	}
	if !full && maxID == lastID {
		s.mu.Lock()
		s.checkAt = time.Now()
		s.mu.Unlock()
		return nil
	}
	var ips []string
	if !full {
		rs, err := h.st.db.QueryContext(ctx, `SELECT DISTINCT src_ip FROM events WHERE id > ? AND id <= ? LIMIT ?`, lastID, maxID, snapMaxIPs+1)
		if err != nil {
			return err
		}
		for rs.Next() {
			var ip string
			if rs.Scan(&ip) == nil {
				ips = append(ips, ip)
			}
		}
		rs.Close()
		full = len(ips) > snapMaxIPs
	}
	if full {
		now, gen := time.Now(), analysisGen.Load()
		s.mu.Lock()
		s.list = nil // alte Fassung freigeben, bevor die neue entsteht
		s.fullStart = now
		s.mu.Unlock()
		list, truncated, err := h.loadAttacks(ctx, now.Add(-snapWindow), nil)
		s.mu.Lock()
		s.fullStart = time.Time{}
		if err != nil {
			s.fullErr = err.Error()
			s.fullFails++
		} else {
			s.fullErr, s.fullDur = "", time.Since(now)
		}
		s.mu.Unlock()
		if err != nil {
			return err
		}
		if list == nil {
			list = []*Attack{} // nil hieße "noch nicht aufgebaut"
		}
		s.mu.Lock()
		s.list, s.since, s.maxID, s.truncated, s.fullAt, s.checkAt, s.dirty, s.gen = list, now.Add(-snapWindow), maxID, truncated, now, now, false, gen
		s.ver++
		s.mu.Unlock()
		return nil
	}
	// Inkrementell: die Angriffe dieser IPs neu aufbauen (ab demselben Beginn wie der Rest)
	fresh2 := make([]*Attack, 0, len(ips)*2)
	for i := 0; i < len(ips); i += activeIPChunk {
		part, _, err := h.loadAttacks(ctx, since, ips[i:min(i+activeIPChunk, len(ips))])
		if err != nil {
			return err
		}
		fresh2 = append(fresh2, part...)
	}
	changed := make(map[string]bool, len(ips))
	for _, ip := range ips {
		changed[ip] = true
	}
	s.mu.Lock()
	old := s.list
	s.mu.Unlock()
	list := make([]*Attack, 0, len(old)+len(fresh2))
	for _, a := range old {
		if !changed[a.IP] {
			list = append(list, a)
		}
	}
	list = append(list, fresh2...)
	sort.SliceStable(list, func(i, j int) bool { return list[i].Last > list[j].Last })
	s.mu.Lock()
	s.list, s.maxID, s.checkAt = list, maxID, time.Now()
	s.ver++
	s.mu.Unlock()
	return nil
}

// warmSnap baut den Schnappschuss kurz nach dem Start im Hintergrund auf, damit schon der
// erste Aufruf von Erkenntnissen und Kampagnen schnell ist, und hält ihn aktuell, solange
// die Oberfläche ihn braucht. Ungenutzt wird er freigegeben.
func (h *Hive) warmSnap(stop <-chan struct{}) {
	select {
	case <-stop:
		return
	case <-time.After(45 * time.Second):
	}
	if !waitStartupQuiet(stop, 2*time.Hour) { // erst nach der Neuzählung (setup.go)
		return
	}
	h.snap.mu.Lock()
	h.snap.usedAt = time.Now()
	h.snap.mu.Unlock()
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		s := &h.snap
		s.mu.Lock()
		idle := time.Since(s.usedAt) > snapIdle
		if idle {
			s.list = nil
		}
		s.mu.Unlock()
		if !idle { // gemeinsamer Aufbau mit den Anfragen (snapWait), ohne eigene kürzere Frist
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				select {
				case <-stop:
					cancel()
				case <-ctx.Done():
				}
			}()
			h.snapWait(ctx)
			cancel()
		}
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}
