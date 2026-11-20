package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Nachgestellt nach dem Anlass: Eine IP meldet sich 2,5 Stunden lang alle 7 Sekunden an Cowrie
// (Port 22) an, jede Kombination in einer eigenen Verbindung, Client SSH-2.0-Go mit zwei HASSH.
// Zum Schluss nimmt der Honeypot root / 12345 an, und es folgt ein einziger Befehl.
const (
	botIP    = "198.51.100.23"
	botTries = 1286
	botEvery = 7 * time.Second
)

func botEvents(ip string, start time.Time) []*Event {
	var out []*Event
	mk := func(ts time.Time, sess, typ string, data map[string]any) *Event {
		e := &Event{TS: ts, Sensor: "s", Service: "ssh", Type: typ, SrcIP: ip, SrcPort: 40000, DstPort: 22, Session: sess, Country: "ZZ"}
		if data != nil {
			e.Data, _ = json.Marshal(data)
		}
		return e
	}
	for i := 0; i < botTries; i++ {
		ts := start.Add(time.Duration(i) * botEvery)
		sess := fmt.Sprintf("bot%05d", i)
		out = append(out,
			mk(ts, sess, "connect", nil),
			mk(ts.Add(10*time.Millisecond), sess, "client_version", map[string]any{"version": "SSH-2.0-Go"}),
			mk(ts.Add(20*time.Millisecond), sess, "fingerprint", map[string]any{"hassh": fmt.Sprintf("hassh%d", i%2)}))
		l := mk(ts.Add(30*time.Millisecond), sess, "login", map[string]any{"success": false})
		l.Username, l.Password = fmt.Sprintf("user%d", i%97), fmt.Sprintf("pass%d", i)
		out = append(out, l, mk(ts.Add(40*time.Millisecond), sess, "disconnect", nil))
	}
	ts := start.Add(botTries * botEvery)
	ok := mk(ts.Add(30*time.Millisecond), "botok", "login", map[string]any{"success": true})
	ok.Username, ok.Password = "root", "12345"
	out = append(out, mk(ts, "botok", "connect", nil),
		mk(ts.Add(10*time.Millisecond), "botok", "client_version", map[string]any{"version": "SSH-2.0-Go"}), ok,
		mk(ts.Add(time.Second), "botok", "command", map[string]any{"input": "uname -s -v -n -r -m"}),
		mk(ts.Add(2*time.Second), "botok", "disconnect", nil))
	return out
}

// feedWriter schreibt die Ereignisse wie der Writer in Blöcken zu 500 und danach alle Sammelzeilen.
func feedWriter(t *testing.T, w *Writer, evs []*Event) {
	t.Helper()
	for i := 0; i < len(evs); i += 500 {
		w.flush(evs[i:min(i+500, len(evs))])
	}
	w.flush(w.brute.due(time.Now(), true))
}

func bruteWriter(t *testing.T, st *Store) *Writer {
	t.Helper()
	w, err := NewWriter(st, func(*Event) {})
	if err != nil {
		t.Fatal(err)
	}
	w.brute = newBruteTracker()
	w.brute.seed = st.bruteSeed
	return w
}

func count(t *testing.T, st *Store, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := st.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func TestBruteCondenseKeepsCountersAndValuables(t *testing.T) {
	setBrute(defaultBrute())
	st := testStore(t)
	w := bruteWriter(t, st)
	start := time.Now().Add(-3 * time.Hour).Truncate(time.Hour)
	evs := botEvents(botIP, start)
	feedWriter(t, w, evs)

	rows := count(t, st, `SELECT COUNT(*) FROM events WHERE src_ip = ?`, botIP)
	if rows > int64(len(evs))/4 { // bis zur Erkennung (200 Logins, 30 Minuten) einzeln
		t.Fatalf("%d von %d Ereignissen einzeln gespeichert, erwartet viel weniger", rows, len(evs))
	}
	// Zähler vollständig: Angreiferliste, Stundenwerte, jede Kombination
	if n := count(t, st, `SELECT events FROM attackers WHERE ip = ?`, botIP); n != int64(len(evs)) {
		t.Errorf("attackers.events = %d, erwartet %d", n, len(evs))
	}
	if n := count(t, st, `SELECT logins FROM attackers WHERE ip = ?`, botIP); n != botTries+1 {
		t.Errorf("attackers.logins = %d, erwartet %d", n, botTries+1)
	}
	if n := count(t, st, `SELECT SUM(cnt) FROM hourly WHERE type = 'connect'`); n != botTries+1 {
		t.Errorf("hourly connect = %d, erwartet %d", n, botTries+1)
	}
	if n := count(t, st, `SELECT COUNT(DISTINCT key) FROM top_hourly WHERE field = 'cred'`); n != botTries+1 {
		t.Errorf("verschiedene Kombinationen in den Top-Listen = %d, erwartet %d", n, botTries+1)
	}
	if n := count(t, st, `SELECT SUM(n) FROM top_hourly WHERE field = 'client'`); n != botTries+1 {
		t.Errorf("Client-Zähler = %d, erwartet %d", n, botTries+1)
	}
	// Wertvolles einzeln: angenommener Login, Befehl, Ende der Sitzung
	for _, q := range []string{
		`SELECT COUNT(*) FROM events WHERE type = 'login' AND username = 'root' AND password = '12345'`,
		`SELECT COUNT(*) FROM events WHERE type = 'command' AND session = 'botok'`,
		`SELECT COUNT(*) FROM events WHERE type = 'disconnect' AND session = 'botok'`,
	} {
		if count(t, st, q) != 1 {
			t.Errorf("fehlt: %s", q)
		}
	}
	// Die ersten Versuche (vor der Erkennung) sind einzeln da
	if n := count(t, st, `SELECT COUNT(*) FROM events WHERE type = 'login' AND src_ip = ?`, botIP); n < 200 || n > 400 {
		t.Errorf("einzeln gespeicherte Logins = %d, erwartet etwa die Schwelle (200 Logins, 30 Minuten)", n)
	}
	// Sammelzeilen tragen zusammen alle verdichteten Ereignisse
	var sum, credSum int
	rs, _ := st.db.Query(`SELECT data FROM events WHERE type = 'condensed'`)
	for rs.Next() {
		var data []byte
		rs.Scan(&data)
		d, ok := readCondensed(&Event{Type: "condensed", Data: data})
		if !ok {
			t.Fatal("Sammelzeile nicht lesbar")
		}
		if len(data) > maxDataBytes || d.From > d.To {
			t.Errorf("Sammelzeile ungültig: %d Bytes, %d > %d", len(data), d.From, d.To)
		}
		if d.To-d.From > bruteSumAge.Milliseconds() {
			t.Errorf("Sammelzeile über %v", time.Duration(d.To-d.From)*time.Millisecond)
		}
		sum += d.N
		for _, n := range d.Creds {
			credSum += n
		}
	}
	rs.Close()
	if int64(sum)+rows-count(t, st, `SELECT COUNT(*) FROM events WHERE type = 'condensed'`) != int64(len(evs)) {
		t.Errorf("einzeln %d + verdichtet %d ergibt nicht %d", rows, sum, len(evs))
	}
	if int64(credSum) != botTries-count(t, st, `SELECT COUNT(*) FROM events WHERE type = 'login' AND src_ip = ? AND username != 'root'`, botIP) {
		t.Errorf("Kombinationen in Sammelzeilen: %d", credSum)
	}
	if w.condensedN.Load() != int64(sum) || w.summaries.Load() == 0 {
		t.Errorf("Zähler des Writers: %d verdichtet, %d Sammelzeilen", w.condensedN.Load(), w.summaries.Load())
	}

	// Angriff: einer, erkannt, mit allen Zahlen
	h := &Hive{st: st}
	list, _, err := h.loadAttacks(context.Background(), start.Add(-time.Minute), []string{botIP})
	if err != nil || len(list) != 1 {
		t.Fatalf("Angriffe: %v, %d (erwartet 1)", err, len(list))
	}
	a := list[0]
	if !a.Brute || a.Condensed != sum || a.Events != len(evs) || a.Counts["login"] != botTries+1 || !a.Success || a.Stufe != stufeBefehle {
		t.Errorf("Angriff: brute=%v verdichtet=%d ereignisse=%d logins=%d ok=%v stufe=%d", a.Brute, a.Condensed, a.Events, a.Counts["login"], a.Success, a.Stufe)
	}
	if a.First != start.UnixMilli() || a.CredsDistinct != botTries+1 || len(a.Commands) != 1 || a.Profile != "SSH-Einbruch" {
		t.Errorf("Angriff: first=%d (%d) creds=%d cmds=%v art=%q", a.First, start.UnixMilli(), a.CredsDistinct, a.Commands, a.Profile)
	}
	if !a.matchQuery(parseQuery("dauer:ja")) || a.matchQuery(parseQuery("-brute:ja")) || !a.matchQuery(parseQuery("user:user5")) {
		t.Error("Suche dauer:ja / brute / user in Sammelzeilen")
	}

	// Kette und Bericht: wenige Zeilen, alle Zahlen
	evRows, err := h.loadEvents(context.Background(), "src_ip = ?", []any{botIP}, "ASC", 5000)
	if err != nil {
		t.Fatal(err)
	}
	c := BuildChain(evRows, false)
	var login *ChainNode
	for _, n := range c.Nodes {
		if n.ID == "login:ssh" {
			login = n
		}
	}
	if c.Condensed != sum || c.Events != len(evs) || c.Sessions-botTries-1 > 1 || login == nil || login.N != botTries {
		t.Errorf("Kette: verdichtet %d, %d Ereignisse, %d Sitzungen, Login-Knoten %+v", c.Condensed, c.Events, c.Sessions, login)
	}
	r := BuildReport("IP "+botIP, evRows, false)
	// ±1: Der Verbindungsaufbau der Sitzung mit angenommenem Login war vor dem Login schon verdichtet
	if r.Sessions-botTries-1 > 1 || r.Sessions < botTries+1 {
		t.Errorf("Bericht: %d Verbindungen, erwartet %d", r.Sessions, botTries+1)
	}
	if r.Events != len(evs) || r.Logins != botTries+1 || r.LoginsOK != 1 || r.Condensed != sum {
		t.Errorf("Bericht: %d Ereignisse, %d Logins, %d ok, %d verdichtet, %d Zeilen", r.Events, r.Logins, r.LoginsOK, r.Condensed, len(r.Timeline))
	}
	if !strings.Contains(strings.Join(r.Summary, " "), "Dauer-Brute-Force") {
		t.Errorf("Kurzfassung nennt die Verdichtung nicht: %v", r.Summary)
	}
	if len(r.Commands) != 1 || r.Commands[0] != "uname -s -v -n -r -m" {
		t.Errorf("Bericht: Befehle %v", r.Commands)
	}

	// Angreiferseite: Zugangsdaten und Ports mit verdichteten Zählern
	ports, _ := h.rows(context.Background(), `SELECT dst_port, service, COUNT(*) AS n FROM events WHERE src_ip = ? AND type='connect' GROUP BY dst_port, service`, botIP)
	creds, _ := h.rows(context.Background(), `SELECT username, password, COUNT(*) AS n FROM events WHERE src_ip = ? AND type='login' GROUP BY username, password ORDER BY n DESC LIMIT 50`, botIP)
	ports, creds, n := h.mergeCondensed(context.Background(), botIP, ports, creds)
	if n != sum || len(ports) != 1 || ports[0]["n"] != int64(botTries+1) || len(creds) != 50 {
		t.Errorf("Angreiferseite: %d verdichtet, Ports %v, %d Zugangsdaten", n, ports, len(creds))
	}

	// Neu zählen der Top-Listen (setup.go): Die verdichteten Kombinationen gehen nicht verloren
	before := count(t, st, `SELECT SUM(n) FROM top_hourly WHERE field = 'cred'`)
	st.DelKV(recountKey)
	if !prepareRecount(st) {
		t.Fatal("prepareRecount")
	}
	recountTop(st, count(t, st, `SELECT MAX(id) FROM events`))
	if after := count(t, st, `SELECT SUM(n) FROM top_hourly WHERE field = 'cred'`); after != before || after != botTries+1 {
		t.Errorf("Kombinationen nach dem Neuzählen: %d, vorher %d", after, before)
	}
	if n := count(t, st, `SELECT COUNT(DISTINCT key) FROM top_hourly WHERE field = 'cred'`); n != botTries+1 {
		t.Errorf("verschiedene Kombinationen nach dem Neuzählen: %d", n)
	}
}

// Eigene Netze, "Nie sperren" und ausgeschaltete Verdichtung: alles einzeln.
func TestBruteCondenseExemptAndOff(t *testing.T) {
	setOwnNets(OwnNets{Private: true, Nets: []string{"203.0.113.0/24"}})
	defer setOwnNets(OwnNets{Private: true})
	for _, c := range []struct {
		name, ip string
		on       bool
	}{{"privat", "192.168.1.50", true}, {"eigenes Netz", "203.0.113.9", true}, {"aus", botIP, false}} {
		t.Run(c.name, func(t *testing.T) {
			b := defaultBrute()
			b.Condense = c.on
			setBrute(b)
			defer setBrute(defaultBrute())
			st := testStore(t)
			w := bruteWriter(t, st)
			evs := botEvents(c.ip, time.Now().Add(-3*time.Hour))
			feedWriter(t, w, evs)
			if n := count(t, st, `SELECT COUNT(*) FROM events`); n != int64(len(evs)) {
				t.Errorf("%d von %d Ereignissen gespeichert", n, len(evs))
			}
		})
	}
	// "Nie sperren" über die Ausnahme des Hive
	setBrute(defaultBrute())
	st := testStore(t)
	w := bruteWriter(t, st)
	w.brute.exempt = func(ip string) bool { return ip == botIP }
	evs := botEvents(botIP, time.Now().Add(-3*time.Hour))
	feedWriter(t, w, evs)
	if n := count(t, st, `SELECT COUNT(*) FROM events`); n != int64(len(evs)) {
		t.Errorf("Nie sperren: %d von %d Ereignissen gespeichert", n, len(evs))
	}
}

// Kurze Angriffe, langsame Versuche und viele verschiedene Clients sind kein Dauer-Brute-Force.
func TestBruteDetection(t *testing.T) {
	setBrute(defaultBrute())
	mk := func(logins int, span time.Duration, clients int) *Attack {
		a := newAttack(&Event{SrcIP: botIP, TS: time.UnixMilli(0)})
		a.Counts["login"] = logins
		a.Last = span.Milliseconds()
		for i := 0; i < clients; i++ {
			a.Clients = append(a.Clients, fmt.Sprintf("SSH-2.0-Client%d", i))
		}
		return a
	}
	for _, c := range []struct {
		a    *Attack
		want bool
	}{
		{mk(1286, 150*time.Minute, 1), true},
		{mk(199, 150*time.Minute, 1), false}, // zu wenige Logins
		{mk(5000, 10*time.Minute, 1), false}, // kurzer, heftiger Angriff: bleibt einzeln sichtbar
		{mk(1286, 150*time.Minute, 4), false},
	} {
		if got := bruteAttack(c.a); got != c.want {
			t.Errorf("Logins %d über %d min, %d Clients: %v, erwartet %v", c.a.Counts["login"], c.a.Last/60000, len(c.a.Clients), got, c.want)
		}
	}
	a := mk(10, time.Minute, 9)
	a.Condensed = 5
	if !bruteAttack(a) {
		t.Error("Angriff mit Sammelzeile nicht erkannt")
	}
}

// Nach einem Neustart setzt die Verdichtung mit dem Stand aus der Datenbank fort.
func TestBruteSeedAfterRestart(t *testing.T) {
	setBrute(defaultBrute())
	st := testStore(t)
	evs := botEvents(botIP, time.Now().Add(-(botTries*botEvery)-time.Minute))
	half := len(evs) * 2 / 3
	w := bruteWriter(t, st)
	feedWriter(t, w, evs[:half])
	w2 := bruteWriter(t, st) // "Neustart": leerer Speicher
	feedWriter(t, w2, evs[half:])
	if w2.condensedN.Load() < int64(len(evs)-half)*9/10 {
		t.Errorf("nach dem Neustart nur %d von %d verdichtet", w2.condensedN.Load(), len(evs)-half)
	}
	if n := count(t, st, `SELECT logins FROM attackers WHERE ip = ?`, botIP); n != botTries+1 {
		t.Errorf("logins = %d", n)
	}
}

// Sammelzeilen kommen nie von Sensoren.
func TestCondensedNotFromSensors(t *testing.T) {
	e := &Event{Type: "condensed", SrcIP: botIP, TS: time.Now(), Data: json.RawMessage(`{"n":1000000,"types":{"login":1000000}}`)}
	if e.Sanitize() == nil {
		t.Fatal("Typ condensed von einem Sensor angenommen")
	}
}

func TestBruteConfigValidate(t *testing.T) {
	b := defaultBrute()
	if err := b.validate(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []func(*BruteConfig){
		func(b *BruteConfig) { b.MinLogins = 5 }, func(b *BruteConfig) { b.MinMinutes = 1 },
		func(b *BruteConfig) { b.Rate = 1 }, func(b *BruteConfig) { b.Burst = 2 }, func(b *BruteConfig) { b.BanMinutes = -1 },
		func(b *BruteConfig) { b.MaxClients = 0 },
	} {
		c := defaultBrute()
		f(&c)
		if c.validate() == nil {
			t.Errorf("ungültige Werte angenommen: %+v", c)
		}
	}
	// Extras ohne Feld "brute" (vor dem Update gespeichert): Standardwerte
	h := testHive(t)
	h.st.SetKV("extras", `{"own":{"private":true}}`)
	h.loadExtras()
	if got := h.Extras().Brute; got != defaultBrute() || bruteCfg() != defaultBrute() {
		t.Errorf("Standard nach dem Laden alter Einstellungen: %+v", got)
	}
}

// Anforderung an die Firewall des Raspberry Pi: streng aufgebaut, nur gültige Netze, ohne Wiederholung.
func TestBruteRequest(t *testing.T) {
	b := defaultBrute()
	if got := bruteRequest(b, []string{"203.0.113.0/24"}); got != "brute off\nallow 203.0.113.0/24\n" {
		t.Errorf("aus: %q", got)
	}
	b.Limit = true
	got := bruteRequest(b, []string{"203.0.113.7", "kein netz", "203.0.113.7/32", "2001:db8::/32", "# Kommentar"})
	want := "brute 6 20 15\nallow 203.0.113.7/32\nallow 2001:db8::/32\n"
	if got != want {
		t.Errorf("an: %q, erwartet %q", got, want)
	}
	cmd := dockerBruteCommand(b, []string{"203.0.113.7"})
	if cmd != `BRUTE_LIMIT=1 BRUTE_RATE=6 BRUTE_BURST=20 BRUTE_BAN=15 BRUTE_ALLOW="203.0.113.7/32" sudo -E sh tools/firewall.sh` {
		t.Errorf("Docker-Aufruf: %s", cmd)
	}
}

func TestBruteSyncAndStatus(t *testing.T) {
	dir := t.TempDir()
	req := filepath.Join(dir, "brute-request")
	t.Setenv("HIVE_BRUTE_REQUEST", req)
	t.Setenv("HIVE_BRUTE_STATUS", filepath.Join(dir, "status"))
	h := testHive(t)
	w, err := NewWriter(h.st, func(*Event) {})
	if err != nil {
		t.Fatal(err)
	}
	h.writer = w
	// nie eingeschaltet: Firewall bleibt unberührt
	if err := h.syncBruteLimit(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(req); err == nil {
		t.Fatal("Anforderung ohne eingeschaltete Drossel")
	}
	x := h.Extras()
	x.Brute.Limit = true
	x.Own.Nets = []string{"203.0.113.0/24"}
	h.extras.x = x
	if err := h.syncBruteLimit(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(req)
	if string(b) != "brute 6 20 15\nallow 203.0.113.0/24\n" {
		t.Errorf("Anforderung: %q", b)
	}
	os.Remove(req)
	h.syncBruteLimit() // unverändert: nicht noch einmal
	if _, err := os.Stat(req); err == nil {
		t.Error("unveränderte Anforderung erneut abgelegt")
	}
	os.WriteFile(filepath.Join(dir, "status"), []byte("ok\n1700000000\nDrossel aktiv\n"), 0o644)
	rec := httptest.NewRecorder()
	h.bruteStatus(rec, httptest.NewRequest("GET", "/api/brute", nil))
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out["platform"] != "pi" || out["status"] == nil {
		t.Errorf("Status: %s", rec.Body.String())
	}
	if viewerAllowed(httptest.NewRequest("GET", "/api/brute", nil)) {
		t.Error("Leserolle sieht die Drossel (eigene Netze)")
	}
	_ = http.StatusOK
}
