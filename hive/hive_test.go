package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testStore(t testing.TB) *Store {
	t.Helper()
	st, err := OpenStore(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.db.Close() })
	return st
}

func testWriter(t *testing.T, st *Store) (*Writer, func() []*Event) {
	t.Helper()
	var mu sync.Mutex
	var got []*Event
	w, err := NewWriter(st, func(e *Event) { mu.Lock(); got = append(got, e); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	go w.Run()
	return w, func() []*Event {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) && w.QueueLen() > 0 {
			time.Sleep(20 * time.Millisecond)
		}
		time.Sleep(500 * time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		return append([]*Event(nil), got...)
	}
}

func ev(typ, ip string) *Event {
	return &Event{TS: time.Now(), Type: typ, Service: "http", SrcIP: ip, DstPort: 80}
}

// ---------- Befund 5: zu große Daten werden gekürzt, nicht verworfen ----------

func TestSanitizeTruncatesData(t *testing.T) {
	big := map[string]any{"path": "/x", "method": "GET", "body": strings.Repeat("A", 40000)}
	b, _ := json.Marshal(big)
	e := &Event{Type: "request", SrcIP: "203.0.113.9", Data: b}
	if err := e.Sanitize(); err != nil {
		t.Fatal(err)
	}
	if len(e.Data) > maxDataBytes {
		t.Fatalf("data %d > %d", len(e.Data), maxDataBytes)
	}
	var m map[string]any
	json.Unmarshal(e.Data, &m)
	if m["path"] != "/x" || m["truncated"] != true {
		t.Fatalf("Felder verloren: %v", m)
	}
}

func TestClipUTF8(t *testing.T) {
	if got := clip("ab\xffcdefgh", 5); len([]rune(got)) != 5 {
		t.Errorf("clip: %q", got)
	}
	if got := clip("äää", 3); got != "ä" {
		t.Errorf("clip: %q", got)
	}
}

// ---------- Befund 6: Duplikate ----------

func TestWriterDedupe(t *testing.T) {
	st := testStore(t)
	w, wait := testWriter(t, st)
	e1 := ev("connect", "203.0.113.1")
	e1.EID = "abc"
	e2 := *e1
	w.Submit(e1)
	w.Submit(&e2)
	wait()
	var n int
	st.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n)
	if n != 1 || w.dupes.Load() != 1 {
		t.Fatalf("events=%d dupes=%d", n, w.dupes.Load())
	}
}

// ---------- Befund 7: Fehler im Schreiber führen nicht zum Absturz ----------

func TestWriterSurvivesDBError(t *testing.T) {
	st := testStore(t)
	w, err := NewWriter(st, func(*Event) {})
	if err != nil {
		t.Fatal(err)
	}
	st.db.Exec(`DROP TABLE attackers`)
	go w.Run()
	w.Submit(ev("connect", "203.0.113.2"))
	time.Sleep(7 * time.Second) // 3 Versuche mit Pausen
	if w.dropped.Load() != 1 {
		t.Fatalf("dropped=%d, erwartet 1", w.dropped.Load())
	}
	var n int
	st.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n)
	if n != 0 {
		t.Fatalf("Teilweise geschrieben: %d", n)
	}
}

// ---------- Befund 21: Suche mit Backslash ----------

func TestSearchBackslash(t *testing.T) {
	st := testStore(t)
	w, wait := testWriter(t, st)
	e := ev("login", "203.0.113.3")
	e.Username = `dom\user`
	w.Submit(e)
	wait()
	r := httptest.NewRequest("GET", `/api/events?q=dom\user`, nil)
	where, args := eventFilter(r)
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM events WHERE `+where, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("Treffer %d, erwartet 1", n)
	}
}

// ---------- Befund 33: Top-Listen aus der Zähltabelle ----------

func TestTopCounters(t *testing.T) {
	st := testStore(t)
	w, wait := testWriter(t, st)
	for i := 0; i < 3; i++ {
		e := ev("login", "203.0.113.4")
		e.Username, e.Password = "root", "123456"
		w.Submit(e)
	}
	wait()
	var n int
	st.db.QueryRow(`SELECT SUM(n) FROM top_hourly WHERE field='cred' AND key='root / 123456'`).Scan(&n)
	if n != 3 {
		t.Fatalf("Zähler %d, erwartet 3", n)
	}
}

// ---------- Migration einer Datenbank aus Version 0.1.0 ----------

func TestMigrationFromV01(t *testing.T) {
	p := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(migrations[0])
	db.Exec(`INSERT INTO events(ts,type,src_ip,service,dst_port,country) VALUES(?,?,?,?,?,?)`, time.Now().UnixMilli(), "connect", "203.0.113.5", "ftp", 21, "DE")
	db.Close()
	st, err := OpenStore(p)
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	var v, n int
	st.db.QueryRow(`PRAGMA user_version`).Scan(&v)
	st.db.QueryRow(`SELECT COUNT(*) FROM top_hourly WHERE field='port' AND key='21'`).Scan(&n)
	if v != len(migrations) || n != 1 {
		t.Fatalf("version=%d top=%d", v, n)
	}
}

// ---------- Befund 3/17: Aufbewahrung nach Alter und Größe ----------

func TestRetention(t *testing.T) {
	st := testStore(t)
	old := time.Now().Add(-40 * 24 * time.Hour).UnixMilli()
	st.db.Exec(`INSERT INTO events(ts,type,src_ip) VALUES(?, 'connect', '203.0.113.6')`, old)
	st.db.Exec(`INSERT INTO attackers(ip,first_seen,last_seen) VALUES('203.0.113.6', ?, ?)`, old, old)
	st.db.Exec(`INSERT INTO events(ts,type,src_ip) VALUES(?, 'connect', '203.0.113.7')`, time.Now().UnixMilli())
	st.Retention(RetentionPolicy{Days: 30})
	var ev, at int
	st.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&ev)
	st.db.QueryRow(`SELECT COUNT(*) FROM attackers`).Scan(&at)
	if ev != 1 || at != 0 {
		t.Fatalf("events=%d attackers=%d", ev, at)
	}
	// nach Größe: Grenze 1 Byte -> alles weg, Grund gesetzt
	s := st.Retention(RetentionPolicy{Days: 30, MaxDBBytes: 1})
	st.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&ev)
	if ev != 0 || s.Pressure == "" {
		t.Fatalf("Größen-Aufbewahrung greift nicht: events=%d pressure=%q", ev, s.Pressure)
	}
}

func TestBackup(t *testing.T) {
	st := testStore(t)
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		if _, err := st.Backup(dir, 2); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1100 * time.Millisecond)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "hive-*.db"))
	if len(files) != 2 {
		t.Fatalf("%d Sicherungen, erwartet 2", len(files))
	}
}

// ---------- Befund 13: Cowrie-Rotation während der Hive aus ist ----------

func cowrieLine(i int) string {
	return fmt.Sprintf(`{"eventid":"cowrie.command.input","input":"cmd%d","session":"s1","src_ip":"203.0.113.8","timestamp":"2026-11-13T10:00:%02d.000000Z"}`+"\n", i, i%60)
}

func TestCowrieCatchUpAfterRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cowrie.json")
	os.WriteFile(path, []byte(cowrieLine(1)+cowrieLine(2)), 0o644)
	st := testStore(t)
	var mu sync.Mutex
	var got []string
	submit := func(e *Event) {
		mu.Lock()
		got = append(got, dataString(e.Data, "input"))
		mu.Unlock()
	}
	// Stand: erste Zeile gelesen
	c := NewCowrieTail(path, "s", st, submit)
	c.saveState(tailState{Head: fileHead(path), Off: int64(len(cowrieLine(1)))})
	// "Hive aus": Cowrie schreibt weiter und rotiert, neue Datei ist größer als der alte Offset
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(cowrieLine(3))
	f.Close()
	os.Rename(path, path+".2026-11-13")
	os.WriteFile(path, []byte(cowrieLine(4)+cowrieLine(5)+cowrieLine(6)+cowrieLine(7)), 0o644)

	done := make(chan struct{})
	go func() { c.Run(); close(done) }()
	t.Cleanup(func() { c.Stop(); <-done })
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 6 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	want := "cmd2,cmd3,cmd4,cmd5,cmd6,cmd7"
	if strings.Join(got, ",") != want {
		t.Fatalf("gelesen %v, erwartet %s", got, want)
	}
}

// ---------- Befund 41: DNS-Rebinding ----------

func TestHostAllowed(t *testing.T) {
	for _, h := range []string{"192.168.1.20:8088", "[::1]:8088", "localhost", "nas.local", "nas", "hivornet.fritz.box"} {
		if !hostAllowed(h, nil) {
			t.Errorf("%s sollte erlaubt sein", h)
		}
	}
	for _, h := range []string{"evil.example.com", "rebind.attacker.net:8088"} {
		if hostAllowed(h, nil) {
			t.Errorf("%s sollte abgelehnt werden", h)
		}
	}
	if !hostAllowed("hivornet.example.com", []string{"hivornet.example.com"}) {
		t.Error("Eintrag aus HIVE_ALLOWED_HOSTS wird nicht beachtet")
	}
}

// ---------- Befund 11: Login-Bremse ----------

func TestLoginThrottle(t *testing.T) {
	st := testStore(t)
	a := NewAuth(st, "", false)
	ok := 0
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if a.attempt("198.51.100.1") {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != failsPerIP {
		t.Fatalf("%d Versuche durchgelassen, erwartet %d", ok, failsPerIP)
	}
	if !a.attempt("198.51.100.2") {
		t.Fatal("andere IP darf nicht gesperrt sein")
	}
}

func TestPasswordLimits(t *testing.T) {
	if validPassword(strings.Repeat("x", 80)) == nil || validPassword("kurz") == nil || validPassword("langgenug123") != nil {
		t.Fatal("Passwortregeln falsch")
	}
}

// ---------- Angriffe je Land für die Karte ----------

func TestCountryStats(t *testing.T) {
	st := testStore(t)
	now := time.Now().UnixMilli() / 3600000
	st.db.Exec(`INSERT INTO hourly(hour,service,type,country,cnt) VALUES(?, 'ssh', 'connect', 'DE', 5)`, now)
	st.db.Exec(`INSERT INTO hourly(hour,service,type,country,cnt) VALUES(?, 'ssh', 'connect', 'DE', 7)`, now-48)
	st.db.Exec(`INSERT INTO hourly(hour,service,type,country,cnt) VALUES(?, 'ssh', 'login', 'DE', 99)`, now)
	st.db.Exec(`INSERT INTO hourly(hour,service,type,country,cnt) VALUES(?, 'ssh', 'connect', 'LAN', 3)`, now)
	h := &Hive{st: st}
	rec := httptest.NewRecorder()
	h.countryStats(rec, httptest.NewRequest("GET", fmt.Sprintf("/api/stats/countries?today_from=%d", (now-1)*3600000), nil))
	var got map[string]map[string]int64
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err, rec.Body.String())
	}
	if got["DE"]["today"] != 5 || got["DE"]["total"] != 12 {
		t.Fatalf("DE: %v (erwartet heute 5, insgesamt 12)", got["DE"])
	}
	if _, ok := got["LAN"]; ok {
		t.Fatal("LAN darf nicht als Land erscheinen")
	}
}
