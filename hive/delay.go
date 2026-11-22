package main

// Verzögerung für Meldungen an AbuseIPDB, URLhaus, MalwareBazaar und DShield.
//
// Gemeldet wird erst, wenn ein Angriff seit der eingestellten Zeit ruhig ist (Standard
// 15 Minuten, Einstellungen → Weitergabe und Meldungen). So erfährt ein Angreifer nicht
// mitten im Angriff, dass der Honeypot ihn meldet (Blocklisten, Benachrichtigungen der
// Dienste), und eine Meldung fasst den ganzen Angriff zusammen statt seines Anfangs.
//
//   - AbuseIPDB: die IP war so lange still (letztes Ereignis des Angriffs).
//   - URLhaus: die Nachlade-Adresse wurde so lange nicht mehr benutzt.
//   - MalwareBazaar: die Datei wurde sofort geholt (Adressen gehen schnell offline), aber erst
//     nach der Wartezeit nachgeschlagen und hochgeladen.
//   - DShield: nur Ereignisse, die mindestens so alt sind.
//
// Was wartet, steht mit "wartet bis …" im Protokoll der Einstellungen (nur im Speicher;
// nach einem Neustart findet die nächste Runde es wieder).

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	reportDelayDefault = 15
	reportDelayMax     = 24 * 60
)

func (x Extras) reportDelay() time.Duration {
	return time.Duration(x.ReportDelayMin) * time.Minute
}

// reportWait: ein Eintrag, der auf die Verzögerung wartet.
type reportWait struct {
	Subject string    `json:"subject"`
	Until   time.Time `json:"until"`
	Detail  string    `json:"detail,omitempty"`
}

const reportWaitMax = 50

// setWaits ersetzt die Warteliste eines Kanals (urlhaus, bazaar, dshield, abuseipdb).
func (s *shareState) setWaits(kind string, list []reportWait) {
	sort.Slice(list, func(i, j int) bool { return list[i].Until.Before(list[j].Until) })
	if len(list) > reportWaitMax {
		list = list[:reportWaitMax]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.waits == nil {
		s.waits = map[string][]reportWait{}
	}
	s.waits[kind] = list
}

// waitList: Kopie der Warteliste, ohne abgelaufene Einträge.
func (s *shareState) waitList(kind string) []reportWait {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []reportWait{}
	for _, w := range s.waits[kind] {
		if time.Now().Before(w.Until) {
			out = append(out, w)
		}
	}
	return out
}

func waitText(until time.Time) string {
	return "wartet bis " + until.In(hiveLoc()).Format("15:04")
}

// ---- MalwareBazaar: geholte Dateien erst nach der Wartezeit melden ----

type bazaarWait struct {
	URL     string `json:"url"`
	Fetched int64  `json:"fetched"` // Unix-Millisekunden
}

// bazaarLater merkt eine frisch geholte Datei für MalwareBazaar vor.
func (h *Hive) bazaarLater(sha, srcURL string) {
	b, _ := json.Marshal(bazaarWait{URL: clip(srcURL, 500), Fetched: time.Now().UnixMilli()})
	h.st.lookupPut("hash:"+sha, "bazaar_wait", string(b))
}

// bazaarDue meldet vorgemerkte Dateien, deren Wartezeit um ist.
func (h *Hive) bazaarDue(ctx context.Context, x Extras) {
	rs, err := h.st.db.QueryContext(ctx, `SELECT subject, data FROM lookups WHERE source = 'bazaar_wait' ORDER BY fetched LIMIT 200`)
	if err != nil {
		return
	}
	type item struct {
		sha string
		w   bazaarWait
	}
	var items []item
	for rs.Next() {
		var subj, data string
		if rs.Scan(&subj, &data) != nil {
			continue
		}
		var w bazaarWait
		json.Unmarshal([]byte(data), &w)
		items = append(items, item{strings.TrimPrefix(subj, "hash:"), w})
	}
	rs.Close()
	var waits []reportWait
	delay := x.reportDelay()
	for _, it := range items {
		until := time.UnixMilli(it.w.Fetched).Add(delay)
		if time.Now().Before(until) {
			waits = append(waits, reportWait{Subject: it.sha, Until: until, Detail: waitText(until)})
			continue
		}
		if ctx.Err() != nil {
			break
		}
		h.st.db.Exec(`DELETE FROM lookups WHERE subject = ? AND source = 'bazaar_wait'`, "hash:"+it.sha)
		if si, err := h.loadSample(it.sha); err == nil {
			h.bazaarHandle(ctx, x, it.sha, si, it.w.URL)
		}
	}
	h.share.setWaits("bazaar", waits)
}

func validateReportDelay(min int) error {
	if min < 0 || min > reportDelayMax {
		return fmt.Errorf("Verzögerung der Meldungen: 0 bis %d Minuten", reportDelayMax)
	}
	return nil
}
