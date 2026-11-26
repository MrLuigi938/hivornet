package main

import (
	"database/sql"
	"fmt"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

// insertBruteEvents legt Login-Versuche einer IP direkt in der Datenbank ab (schneller als der
// Schreiber); mit mark zusätzlich eine Sammelzeile, die die IP als Dauer-Brute-Force markiert.
func insertBruteEvents(tb testing.TB, db *sql.DB, ip string, from time.Time, n int, mark bool) {
	tb.Helper()
	tx, err := db.Begin()
	if err != nil {
		tb.Fatal(err)
	}
	st, _ := tx.Prepare(`INSERT INTO events(ts, service, type, src_ip, dst_port, username, password, asn, as_org) VALUES(?,?,?,?,?,?,?,?,?)`)
	for i := range n {
		st.Exec(from.Add(time.Duration(i)*time.Second).UnixMilli(), "ssh", "login", ip, 22, "root", fmt.Sprintf("pw%d", i%50), 64496, "Beispiel")
	}
	st.Close()
	if mark {
		tx.Exec(`INSERT INTO events(ts, service, type, src_ip, dst_port) VALUES(?,?,?,?,?)`, from.UnixMilli(), "ssh", "condensed", ip, 22)
	}
	if err := tx.Commit(); err != nil {
		tb.Fatal(err)
	}
}

// Die Erneuerung zählt nur Neues dazu und kommt aufs selbe Ergebnis wie ein voller Neuaufbau.
func TestBruteTopIncremental(t *testing.T) {
	h := testHive(t)
	from := time.Now().Add(-3 * time.Hour)
	hour := from.UnixMilli() / 3600000
	insertBruteEvents(t, h.st.db, "198.51.100.1", from, 120, true)
	sub, err := h.bruteTopSub(t.Context(), hour)
	total := func(m map[string]map[string]int64) (n int64) {
		for _, v := range m["cred"] {
			n += v
		}
		return
	}
	if err != nil || sub["cred"]["root / pw1"] != 3 || total(sub) != 120 {
		t.Fatalf("erster Aufbau: %v %v", err, sub["cred"])
	}
	// Neues von der bekannten IP und eine neu markierte IP
	insertBruteEvents(t, h.st.db, "198.51.100.1", from.Add(time.Hour), 30, false)
	insertBruteEvents(t, h.st.db, "198.51.100.2", from.Add(time.Hour), 10, true)
	insertBruteEvents(t, h.st.db, "203.0.113.9", from.Add(time.Hour), 5, false) // nicht markiert
	h.bruteTop.mu.Lock()
	h.bruteTop.m[hour].at = time.Now().Add(-time.Hour)
	h.bruteTop.mu.Unlock()
	inc, err := h.bruteTopRefresh(t.Context(), hour)
	if err != nil {
		t.Fatal(err)
	}
	if total(sub) != 120 {
		t.Error("altes Ergebnis verändert (Leser ohne Sperre)")
	}
	h.bruteTop.mu.Lock()
	h.bruteTop.m = map[int64]*bruteTopEntry{}
	h.bruteTop.mu.Unlock()
	full, err := h.bruteTopRefresh(t.Context(), hour)
	if err != nil {
		t.Fatal(err)
	}
	if total(inc) != 160 || !reflect.DeepEqual(inc, full) {
		t.Fatalf("schrittweise %d, voll %d", total(inc), total(full))
	}
}

// Fertige Top-Listen: die zweite Anfrage kommt aus dem Speicher, auch nachdem sich die Daten
// geändert haben (bis zur Erneuerung im Hintergrund).
func TestTopResultCache(t *testing.T) {
	h := testHive(t)
	hr := time.Now().Add(-48*time.Hour).UnixMilli() / 3600000
	h.st.db.Exec(`INSERT INTO top_hourly(hour, field, key, label, n) VALUES(?,?,?,?,?)`, hr, "command", "uname -a", "", 5)
	get := func() string {
		rec := httptest.NewRecorder()
		h.top(rec, httptest.NewRequest("GET", "/api/stats/top?range=7d&field=command&nobrute=1", nil))
		return rec.Body.String()
	}
	first := get()
	h.st.db.Exec(`UPDATE top_hourly SET n = 9 WHERE field = 'command'`)
	if second := get(); second != first {
		t.Fatalf("nicht aus dem Speicher: %s / %s", first, second)
	}
	h.topRes.mu.Lock()
	for _, e := range h.topRes.m {
		e.at = time.Now().Add(-time.Hour) // zu alt zum Ausliefern
	}
	h.topRes.mu.Unlock()
	if third := get(); third == first {
		t.Fatalf("veraltete Liste ausgeliefert: %s", third)
	}
}

// Dashboard über 30 Tage mit viel Brute-Force: nach dem Aufwärmen kommen die Listen aus dem
// Speicher (Ziel auf dem Pi: unter einer Sekunde; hier Mikrosekunden). "kalt" misst den Aufbau.
func BenchmarkTopNoBrute30d(b *testing.B) {
	h := testHive(b)
	start := time.Now().Add(-29 * 24 * time.Hour)
	for i := range 10 {
		insertBruteEvents(b, h.st.db, fmt.Sprintf("198.51.100.%d", i+1), start.Add(time.Duration(i)*time.Hour), 5000, true)
	}
	tx, _ := h.st.db.Begin()
	st, _ := tx.Prepare(`INSERT INTO top_hourly(hour, field, key, label, n) VALUES(?,?,?,?,?)`)
	for hr := start.UnixMilli() / 3600000; hr <= time.Now().UnixMilli()/3600000; hr++ {
		for k := range 60 {
			for _, f := range []string{"cred", "command", "asn"} {
				st.Exec(hr, f, fmt.Sprintf("%s-%d", f, k), "", k+1)
			}
		}
	}
	st.Close()
	tx.Commit()
	get := func(field string) {
		rec := httptest.NewRecorder()
		h.top(rec, httptest.NewRequest("GET", "/api/stats/top?range=30d&limit=10&nobrute=1&field="+field, nil))
		if rec.Code != 200 {
			b.Fatal(rec.Code, rec.Body.String())
		}
	}
	b.Run("kalt", func(b *testing.B) {
		for b.Loop() {
			h.topRes.mu.Lock()
			h.topRes.m = nil
			h.topRes.mu.Unlock()
			h.bruteTop.mu.Lock()
			h.bruteTop.m = nil
			h.bruteTop.mu.Unlock()
			for _, f := range []string{"asn", "cred", "command"} {
				get(f)
			}
		}
	})
	b.Run("warm", func(b *testing.B) {
		for _, f := range []string{"asn", "cred", "command"} {
			get(f)
		}
		for b.Loop() {
			for _, f := range []string{"asn", "cred", "command"} {
				get(f)
			}
		}
	})
}
