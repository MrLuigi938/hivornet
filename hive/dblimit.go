package main

// Größengrenze der Datenbank: einstellbar in der Web-UI (Einstellungen → Daten),
// mit Obergrenze aus dem Datenträger und optionaler automatischer Erweiterung.
//
// Vorrang:
//  1. HIVE_MAX_DB_CAP_MB (falls gesetzt): harte Obergrenze, die weder die Einstellung
//     noch die automatische Erweiterung überschreiten (für Docker-Hosts).
//  2. Die Einstellung aus der Web-UI (kv "db_limit_mb"), höchstens bis zur Obergrenze
//     aus dem Datenträger (dbDiskCap).
//  3. Ohne Einstellung gilt HIVE_MAX_DB_MB als Vorgabe (Pi: 1024, Docker: 2048).
//
// Die Vorgabe aus HIVE_MAX_DB_MB bleibt immer erlaubt, auch wenn der Datenträger knapp
// ist: Dann greift wie bisher HIVE_MIN_FREE_MB. Nur Erhöhungen darüber hinaus müssen in
// den sicheren Rahmen passen.

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

const (
	kvDBLimit   = "db_limit_mb"  // Grenze aus der Web-UI in MB
	kvDBGrow    = "db_autogrow"  // "1" = automatisch erweitern
	kvDBGrowLog = "db_grow_log"  // letzte automatische Erweiterungen (JSON)
	mib         = int64(1) << 20 // 1 MB im Sinne der Anzeige (MiB)
	gib         = int64(1) << 30 // 1 GB im Sinne der Anzeige (GiB)
	dbLimitMin  = 256 * mib      // kleinste einstellbare Grenze
	dbGrowAt    = 90             // ab diesem Anteil (Prozent) der Grenze wird erweitert
	dbGrowMin   = 512 * mib      // kleinster Schritt der Erweiterung
	dbNoDiskCap = 16 * gib       // Obergrenze, wenn der Datenträger unbekannt ist (nicht Linux)
	dbGrowLogN  = 10             // so viele Erweiterungen bleiben im Protokoll
)

// dbDiskStat ist für Tests austauschbar.
var dbDiskStat = diskTotalFree

// dbReserve: So viel soll auf dem Datenträger immer frei bleiben (Cowrie-Logs und
// Downloads, Updates, System, Swap, Sicherungen): das Größte aus HIVE_MIN_FREE_MB,
// 2 GB und 15 % der Größe; der Prozentanteil zählt höchstens mit 20 GB.
func dbReserve(total, minFree int64) int64 {
	return max(minFree, 2*gib, min(total*15/100, 20*gib))
}

// dbDiskCap: höchste Grenze, die der Datenträger hergibt. Höchstens die Hälfte des
// Datenträgers und nur so viel, dass die Reserve frei bleibt, wenn die Datenbank bis
// zur Grenze wächst. dbFile ist die heutige Dateigröße (schon im Belegten enthalten).
// Ohne Angaben zum Datenträger (total <= 0) gilt dbNoDiskCap.
func dbDiskCap(total, free, dbFile, minFree int64) (limit, reserve int64) {
	if total <= 0 {
		return dbNoDiskCap, 0
	}
	reserve = dbReserve(total, minFree)
	limit = min(total/2, dbFile+free-reserve)
	limit = limit / (256 * mib) * (256 * mib)
	return max(limit, dbLimitMin), reserve
}

// dbSuggest: Vorschlag für die Grenze, ein Viertel des Datenträgers in ganzen GB,
// mindestens 1 GB, höchstens 10 GB (mehr braucht ein Honeypot selten) und nie über
// der Obergrenze.
func dbSuggest(total, ceiling int64) int64 {
	s := 1 * gib
	if total > 0 {
		s = max(s, min(total/4/gib*gib, 10*gib))
	}
	return min(s, ceiling)
}

// dbNextLimit: neue Grenze bei automatischer Erweiterung. Ab 90 % Belegung wächst die
// Grenze um ein Viertel, mindestens 512 MB, gerundet auf 512 MB, höchstens bis ceiling.
// ok ist false, wenn nichts zu tun ist oder die Obergrenze erreicht ist.
func dbNextLimit(limit, used, ceiling int64) (int64, bool) {
	if limit <= 0 || used*100 < limit*dbGrowAt || limit >= ceiling {
		return limit, false
	}
	next := limit + max(dbGrowMin, limit/4)
	next = (next + dbGrowMin - 1) / dbGrowMin * dbGrowMin
	next = min(next, ceiling)
	return next, next > limit
}

type dbGrowEntry struct {
	At   time.Time `json:"at"`
	From int64     `json:"from"`
	To   int64     `json:"to"`
}

// dbLimitInfo: alles zur Grenze für Einstellungen, System-Seite und Hardware-Monitor.
type dbLimitInfo struct {
	Limit      int64         `json:"limit"`          // gilt jetzt (Einstellung bzw. Vorgabe, auf die Obergrenze begrenzt)
	Configured int64         `json:"configured"`     // eingestellter Wert (0 = Vorgabe)
	Default    int64         `json:"default"`        // HIVE_MAX_DB_MB
	Ceiling    int64         `json:"ceiling"`        // höchste erlaubte Grenze
	EnvCap     int64         `json:"env_cap"`        // HIVE_MAX_DB_CAP_MB (0 = nicht gesetzt)
	Suggest    int64         `json:"suggest"`        // Vorschlag
	Reserve    int64         `json:"reserve"`        // bleibt auf dem Datenträger mindestens frei
	MinFree    int64         `json:"min_free"`       // HIVE_MIN_FREE_MB
	Used       int64         `json:"used"`           // belegter Platz in der Datenbank
	File       int64         `json:"file"`           // Dateigröße mit WAL
	DiskTotal  int64         `json:"disk_total"`     // 0 = unbekannt
	DiskFree   int64         `json:"disk_free"`      // -1 = unbekannt
	AutoGrow   bool          `json:"auto_grow"`      // automatisch erweitern
	AtCeiling  bool          `json:"at_ceiling"`     // Grenze kann nicht weiter wachsen
	Reason     string        `json:"ceiling_reason"` // woher die Obergrenze kommt
	GrowLog    []dbGrowEntry `json:"grow_log"`       // neueste zuerst
	Source     string        `json:"source"`         // "setting" | "env"
}

// dbCeiling: höchste erlaubte Grenze aus Datenträger, HIVE_MAX_DB_CAP_MB und Vorgabe.
func (h *Hive) dbCeiling(total, free, file int64) (ceiling, reserve int64) {
	ceiling, reserve = dbDiskCap(total, free, file, h.minFreeBytes)
	ceiling = max(ceiling, h.maxDBBytes) // die Vorgabe bleibt immer erlaubt (siehe oben)
	if h.maxDBCapBytes > 0 {
		ceiling = min(ceiling, h.maxDBCapBytes)
	}
	return ceiling, reserve
}

func (h *Hive) dbLimitInfo() dbLimitInfo {
	total, free := dbDiskStat(h.dbPath)
	if total <= 0 {
		free = -1
	}
	file, used := h.st.Size()
	in := dbLimitInfo{Default: h.maxDBBytes, EnvCap: h.maxDBCapBytes, MinFree: h.minFreeBytes,
		Used: used, File: file, DiskTotal: total, DiskFree: free, Source: "env", GrowLog: h.dbGrowLog()}
	in.Ceiling, in.Reserve = h.dbCeiling(total, max(free, 0), file)
	in.Limit = h.maxDBBytes
	if v, ok := h.st.GetKV(kvDBLimit); ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			in.Configured, in.Limit, in.Source = n*mib, n*mib, "setting"
		}
	}
	if h.maxDBCapBytes > 0 { // auch die Vorgabe nie über HIVE_MAX_DB_CAP_MB
		in.Limit = min(in.Limit, h.maxDBCapBytes)
	}
	in.Limit = min(in.Limit, in.Ceiling)
	in.Suggest = max(dbSuggest(total, in.Ceiling), min(h.maxDBBytes, in.Ceiling))
	v, _ := h.st.GetKV(kvDBGrow)
	in.AutoGrow = v == "1"
	in.AtCeiling = in.Limit >= in.Ceiling
	in.Reason = h.ceilingReason(in)
	return in
}

// dbLimit: Grenze, die das Aufräumen gerade anwendet.
func (h *Hive) dbLimit() int64 {
	return h.dbLimitInfo().Limit
}

func (h *Hive) dbGrowLog() []dbGrowEntry {
	out := []dbGrowEntry{}
	if v, ok := h.st.GetKV(kvDBGrowLog); ok {
		json.Unmarshal([]byte(v), &out)
	}
	if out == nil {
		out = []dbGrowEntry{}
	}
	return out
}

// autoGrowDB erhöht die Grenze, wenn die Datenbank fast voll ist und die automatische
// Erweiterung an ist. Läuft vor jedem Aufräumen (main.go).
func (h *Hive) autoGrowDB(now time.Time) (dbGrowEntry, bool) {
	h.dbLimMu.Lock()
	defer h.dbLimMu.Unlock()
	in := h.dbLimitInfo()
	if !in.AutoGrow {
		return dbGrowEntry{}, false
	}
	next, ok := dbNextLimit(in.Limit, in.Used, in.Ceiling)
	if !ok {
		return dbGrowEntry{}, false
	}
	e := dbGrowEntry{At: now, From: in.Limit, To: next}
	if err := h.st.SetKV(kvDBLimit, strconv.FormatInt(next/mib, 10)); err != nil {
		log.Printf("Datenbankgrenze: %v", err)
		return dbGrowEntry{}, false
	}
	lg := append([]dbGrowEntry{e}, in.GrowLog...)
	if len(lg) > dbGrowLogN {
		lg = lg[:dbGrowLogN]
	}
	b, _ := json.Marshal(lg)
	h.st.SetKV(kvDBGrowLog, string(b))
	log.Printf("Datenbankgrenze automatisch von %d MB auf %d MB erhöht (Obergrenze %d MB)", e.From/mib, e.To/mib, in.Ceiling/mib)
	return e, true
}

// setDBLimit prüft und speichert die Einstellung. mb = 0 heißt: zurück zur Vorgabe,
// nil lässt die Grenze unverändert.
func (h *Hive) setDBLimit(mbp *int64, autoGrow *bool) (dbLimitInfo, error) {
	h.dbLimMu.Lock()
	defer h.dbLimMu.Unlock()
	in := h.dbLimitInfo()
	mb := int64(0)
	if mbp != nil {
		mb = *mbp
	}
	switch {
	case mbp == nil:
	case mb < 0 || mb > 1<<30:
		return in, fmt.Errorf("ungültige Grenze")
	case mb == 0:
		h.st.DelKV(kvDBLimit)
	case mb*mib < dbLimitMin:
		return in, fmt.Errorf("die Grenze muss mindestens %d MB betragen", dbLimitMin/mib)
	case mb*mib > in.Ceiling:
		return in, fmt.Errorf("höchstens %s möglich (%s)", fmtGB(in.Ceiling), in.Reason)
	default:
		h.st.SetKV(kvDBLimit, strconv.FormatInt(mb, 10))
	}
	if autoGrow != nil {
		h.st.SetKV(kvDBGrow, map[bool]string{true: "1", false: "0"}[*autoGrow])
	}
	return h.dbLimitInfo(), nil
}

// ceilingReason erklärt, woher die Obergrenze kommt.
func (h *Hive) ceilingReason(in dbLimitInfo) string {
	if in.EnvCap > 0 && in.Ceiling == in.EnvCap {
		return "festgelegt mit HIVE_MAX_DB_CAP_MB"
	}
	if in.DiskTotal <= 0 {
		return "Datenträger unbekannt"
	}
	disk, _ := dbDiskCap(in.DiskTotal, max(in.DiskFree, 0), in.File, in.MinFree)
	switch {
	case disk < in.Ceiling:
		return "Vorgabe HIVE_MAX_DB_MB; mehr gibt der Datenträger gerade nicht her"
	case in.File+max(in.DiskFree, 0)-in.Reserve > in.DiskTotal/2:
		return "höchstens die Hälfte des Datenträgers"
	default:
		return fmt.Sprintf("auf dem Datenträger bleiben mindestens %s frei", fmtGB(in.Reserve))
	}
}

func fmtGB(b int64) string {
	if b < gib {
		return fmt.Sprintf("%d MB", b/mib)
	}
	s := strconv.FormatFloat(float64(b)/float64(gib), 'f', 1, 64)
	s = strings.TrimSuffix(s, ".0")
	return strings.Replace(s, ".", ",", 1) + " GB"
}

// dbWarnings: Hinweise zur Grenze für die Warnliste (api.go).
func (h *Hive) dbWarnings() []warning {
	in := h.dbLimitInfo()
	if in.Limit <= 0 || in.Used*100 < in.Limit*dbGrowAt {
		return nil
	}
	pct := in.Used * 100 / in.Limit
	switch {
	case in.AutoGrow && in.AtCeiling:
		return []warning{{"warn", fmt.Sprintf("Datenbank zu %d %% voll und die Obergrenze von %s ist erreicht (%s). Ab jetzt löscht der Hive die ältesten Ereignisse.", pct, fmtGB(in.Ceiling), in.Reason)}}
	case !in.AutoGrow && !in.AtCeiling:
		return []warning{{"warn", fmt.Sprintf("Datenbank zu %d %% voll (Grenze %s). Danach löscht der Hive die ältesten Ereignisse. Grenze erhöhen oder automatisch erweitern lassen unter Einstellungen → Daten (bis %s möglich).", pct, fmtGB(in.Limit), fmtGB(in.Ceiling))}}
	}
	return nil
}
