package main

// Zwischenspeicher für die Musterprüfung. Die Seite "Angriffe", das Dashboard ("Gerade aktiv"),
// Angriffskette und Bericht prüfen jedes Ereignis gegen alle Regeln (analyze.go, cve.go) und
// entschlüsseln verschleierte Inhalte (deobf.go). Das kostet je Ereignis etwa 0,1 ms auf einem
// Desktop-Rechner und ein Vielfaches auf einem Raspberry Pi; bei jedem Seitenaufruf neu
// gerechnet, dauerte die Seite "Angriffe" auf einem Pi mit 35.000 Ereignissen über 15 Sekunden.
//
// Das Ergebnis hängt nur vom Text und der Regelgruppe ab, also wird es je (Gruppe, Text) gemerkt.
// Beim Einliefern (store.go) wird jedes Ereignis ohnehin geprüft; neue Ereignisse liegen damit
// schon im Speicher, wenn die Seite sie braucht. Köder (bait.go) prüft eventPatterns weiterhin
// jedes Mal, weil sich die Köder-Zugangsdaten ändern können.
//
// Zwei Generationen: Ist die aktuelle voll, wird sie zur alten, die alte fällt weg. Treffer in
// der alten wandern in die aktuelle. So bleibt der Speicher begrenzt und Häufiges erhalten.

import (
	"context"
	"hash/maphash"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// analysisGen zählt Regeländerungen (resetAnalysisCache).
var analysisGen atomic.Int64

type textAnalysis struct {
	revealed       []string
	ids            []string  // Muster ohne Köder
	rules          []cveRule // alle Regeltreffer (cve.go)
	cves           []cveRule // davon Ausnutzungen mit CVE
	urls           []string  // Nachlade-Adressen; bei "web" nur aus Entschlüsseltem (Pfade sind oft nur Proben)
	wallets, pools []string  // nur "cmd" und "raw" (indicators.go)
}

// analysisGenMax: Einträge je Generation. Die meisten Einträge sind klein (keine Funde);
// große Texte werden nicht gespeichert, nur ihr Ergebnis.
const analysisGenMax = 40000

var analysisCache = struct {
	mu        sync.Mutex
	seed      maphash.Seed
	cur, prev map[uint64]*textAnalysis
}{seed: maphash.MakeSeed(), cur: map[uint64]*textAnalysis{}}

// analyzeText liefert Entschlüsseltes, Muster und Lücken für einen Text. Die Listen sind
// geteilt und dürfen nicht verändert werden (Kapazität = Länge, append kopiert).
func analyzeText(text, on string) *textAnalysis {
	if text == "" {
		return &textAnalysis{}
	}
	c := &analysisCache
	k := maphash.String(c.seed, on+"\x00"+text)
	c.mu.Lock()
	if a := c.cur[k]; a != nil {
		c.mu.Unlock()
		return a
	}
	if a := c.prev[k]; a != nil {
		c.cur[k] = a
		c.mu.Unlock()
		return a
	}
	c.mu.Unlock()
	a := &textAnalysis{}
	if !isTLSText(text) { // Handshake-Bytes sind keine Verschleierung
		a.revealed = slices.Clip(revealHidden(text))
	}
	a.rules = slices.Clip(matchRules(text, on))
	a.cves = slices.Clip(exploitsOnly(a.rules))
	a.ids = slices.Clip(append(matchAll(text, on, a.revealed), ruleTags(a.rules)...))
	src := text
	if on == "web" {
		src = ""
	}
	a.urls = slices.Clip(allURLs(src, a.revealed, 6))
	if on == "cmd" || on == "raw" {
		for _, t := range append([]string{text}, a.revealed...) {
			ws, ps := cryptoIndicators(t)
			for _, w := range ws {
				if len(a.wallets) < 6 && !slices.Contains(a.wallets, w) {
					a.wallets = append(a.wallets, w)
				}
			}
			for _, p := range ps {
				if len(a.pools) < 6 && !slices.Contains(a.pools, p) {
					a.pools = append(a.pools, p)
				}
			}
		}
		a.wallets, a.pools = slices.Clip(a.wallets), slices.Clip(a.pools)
	}
	c.mu.Lock()
	if len(c.cur) >= analysisGenMax {
		c.prev, c.cur = c.cur, make(map[uint64]*textAnalysis, analysisGenMax/4)
	}
	c.cur[k] = a
	c.mu.Unlock()
	return a
}

// warmAnalysis füllt den Zwischenspeicher nach dem Start mit den Ereignissen der letzten
// 24 Stunden, damit schon der erste Aufruf von Dashboard und "Angriffe" schnell ist. Läuft
// einmal im Hintergrund, kurz verzögert und in kleinen Schritten, damit Einliefern und
// Oberfläche nicht warten.
func (h *Hive) warmAnalysis(stop <-chan struct{}) {
	select {
	case <-stop:
		return
	case <-time.After(20 * time.Second):
	}
	since := time.Now().Add(-24 * time.Hour).UnixMilli()
	var lastID int64
	for n := 0; n < analysisGenMax; {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		rs, err := h.st.db.QueryContext(ctx, `SELECT id, type, service, data FROM events WHERE ts >= ? AND id > ? AND type NOT IN ('connect', 'disconnect') ORDER BY id LIMIT 500`, since, lastID)
		if err != nil {
			cancel()
			return
		}
		var batch []*Event
		for rs.Next() {
			e := &Event{}
			var data []byte
			if rs.Scan(&e.ID, &e.Type, &e.Service, &data) == nil {
				e.Data = data
				batch = append(batch, e)
			}
		}
		rs.Close()
		cancel()
		if len(batch) == 0 {
			return
		}
		for _, e := range batch {
			analysisText(e)
			lastID = e.ID
		}
		n += len(batch)
		select {
		case <-stop:
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// resetAnalysisCache: nach Änderungen an Regeln (eigene Regeln, cvesuggest.go; Tests).
func resetAnalysisCache() {
	analysisGen.Add(1) // Angriffs-Schnappschuss (attacksnap.go) voll neu aufbauen
	c := &analysisCache
	c.mu.Lock()
	c.cur, c.prev = map[uint64]*textAnalysis{}, nil
	c.mu.Unlock()
}
