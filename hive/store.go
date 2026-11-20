package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

// Muss zum Honeypot passen (Vertragstest dort: hiveDataLimit).
const maxDataBytes = 16 << 10

// Event ist ein Ereignis nach der Anreicherung durch den Hive.
type Event struct {
	ID          int64           `json:"id"`
	EID         string          `json:"eid,omitempty"`
	TS          time.Time       `json:"ts"`
	Sensor      string          `json:"sensor"`
	Service     string          `json:"service"`
	Type        string          `json:"type"`
	SrcIP       string          `json:"src_ip"`
	SrcPort     int             `json:"src_port"`
	DstPort     int             `json:"dst_port"`
	Session     string          `json:"session,omitempty"`
	Username    string          `json:"username,omitempty"`
	Password    string          `json:"password,omitempty"`
	Data        json.RawMessage `json:"data,omitempty"`
	DurationMs  int64           `json:"duration_ms,omitempty"`
	Tarpit      bool            `json:"tarpit,omitempty"`
	TarpitMs    int64           `json:"tarpit_ms,omitempty"`
	Country     string          `json:"country,omitempty"`
	CountryName string          `json:"country_name,omitempty"`
	City        string          `json:"city,omitempty"`
	Lat         float64         `json:"lat,omitempty"`
	Lon         float64         `json:"lon,omitempty"`
	ASN         int             `json:"asn,omitempty"`
	ASOrg       string          `json:"as_org,omitempty"`
}

var validTypes = map[string]bool{
	"connect": true, "disconnect": true, "login": true, "request": true, "command": true,
	"download": true, "client_version": true, "payload": true, "tls": true, "fingerprint": true,
	"tty":      true, // Cowrie-Mitschnitt vorhanden (nur vom Cowrie-Leser erzeugt)
	"ai_reply": true, // das Sprachmodell hat dem Angreifer geantwortet (mimic.go)
}

// Sanitize prüft und kürzt Felder von Sensoren, bevor sie gespeichert werden.
func (e *Event) Sanitize() error {
	ip := net.ParseIP(strings.TrimSpace(e.SrcIP))
	if ip == nil {
		return fmt.Errorf("ungültige src_ip %q", e.SrcIP)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	e.SrcIP = ip.String()
	if !validTypes[e.Type] {
		return fmt.Errorf("unbekannter Typ %q", e.Type)
	}
	if e.TS.IsZero() || e.TS.After(time.Now().Add(time.Hour)) {
		e.TS = time.Now()
	}
	e.EID = clip(e.EID, 64)
	e.Sensor = clip(e.Sensor, 64)
	e.Service = clip(e.Service, 32)
	e.Session = clip(e.Session, 64)
	e.Username = clip(e.Username, 256)
	e.Password = clip(e.Password, 256)
	if len(e.Data) > 0 {
		if !json.Valid(e.Data) {
			e.Data = nil
		} else if len(e.Data) > maxDataBytes {
			e.Data = truncateData(e.Data)
		}
	}
	if e.SrcPort < 0 || e.SrcPort > 65535 {
		e.SrcPort = 0
	}
	if e.DstPort < 0 || e.DstPort > 65535 {
		e.DstPort = 0
	}
	if e.TarpitMs < 0 {
		e.TarpitMs = 0
	}
	if e.DurationMs < 0 {
		e.DurationMs = 0
	}
	return nil
}

// truncateData kürzt zu große Inhalte feldweise statt sie ganz zu verwerfen.
func truncateData(d json.RawMessage) json.RawMessage {
	var m map[string]any
	if json.Unmarshal(d, &m) == nil {
		for k, v := range m {
			if s, ok := v.(string); ok {
				m[k] = clip(s, 1024)
			}
		}
		m["truncated"] = true
		if b, err := json.Marshal(m); err == nil && len(b) <= maxDataBytes {
			return b
		}
	}
	return json.RawMessage(`{"truncated":true}`)
}

// clip kürzt auf höchstens n Bytes, ohne ein UTF-8-Zeichen zu zerschneiden;
// ungültige Bytes werden ersetzt statt den Rest abzuschneiden.
func clip(s string, n int) string {
	if len(s) > n {
		s = s[:n]
		for k := 0; k < 3 && len(s) > 0; k++ {
			r, size := utf8.DecodeLastRuneInString(s)
			if r != utf8.RuneError || size != 1 {
				break
			}
			s = s[:len(s)-1]
		}
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return s
}

type Store struct {
	db   *sql.DB
	path string
}

// Migrationen: Index = Zielversion - 1. Nie ändern, nur anhängen.
var migrations = []string{
	// 1: Grundschema (Version 0.1.0)
	`CREATE TABLE IF NOT EXISTS events (
	  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, sensor TEXT NOT NULL DEFAULT '', service TEXT NOT NULL DEFAULT '',
	  type TEXT NOT NULL, src_ip TEXT NOT NULL, src_port INTEGER NOT NULL DEFAULT 0, dst_port INTEGER NOT NULL DEFAULT 0,
	  session TEXT NOT NULL DEFAULT '', username TEXT NOT NULL DEFAULT '', password TEXT NOT NULL DEFAULT '', data TEXT,
	  duration_ms INTEGER NOT NULL DEFAULT 0, tarpit INTEGER NOT NULL DEFAULT 0, tarpit_ms INTEGER NOT NULL DEFAULT 0,
	  country TEXT NOT NULL DEFAULT '', country_name TEXT NOT NULL DEFAULT '', city TEXT NOT NULL DEFAULT '',
	  lat REAL NOT NULL DEFAULT 0, lon REAL NOT NULL DEFAULT 0, asn INTEGER NOT NULL DEFAULT 0, as_org TEXT NOT NULL DEFAULT '');
	CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
	CREATE INDEX IF NOT EXISTS ev_ip ON events(src_ip, ts);
	CREATE INDEX IF NOT EXISTS ev_type ON events(type, ts);
	CREATE INDEX IF NOT EXISTS ev_session ON events(session) WHERE session != '';
	CREATE TABLE IF NOT EXISTS hourly (hour INTEGER NOT NULL, service TEXT NOT NULL, type TEXT NOT NULL, country TEXT NOT NULL,
	  cnt INTEGER NOT NULL DEFAULT 0, tarpit_ms INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (hour, service, type, country)) WITHOUT ROWID;
	CREATE TABLE IF NOT EXISTS attackers (ip TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
	  events INTEGER NOT NULL DEFAULT 0, logins INTEGER NOT NULL DEFAULT 0, commands INTEGER NOT NULL DEFAULT 0,
	  tarpit_ms INTEGER NOT NULL DEFAULT 0, country TEXT NOT NULL DEFAULT '', country_name TEXT NOT NULL DEFAULT '',
	  city TEXT NOT NULL DEFAULT '', asn INTEGER NOT NULL DEFAULT 0, as_org TEXT NOT NULL DEFAULT '') WITHOUT ROWID;
	CREATE INDEX IF NOT EXISTS att_last ON attackers(last_seen);
	CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
	CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, hash TEXT NOT NULL);
	CREATE TABLE IF NOT EXISTS auth_sessions (token TEXT PRIMARY KEY, username TEXT NOT NULL, expires INTEGER NOT NULL);`,
	// 2: Zähltabelle für Top-Listen; Sitzungs-Token nur noch als Hash (alte Sitzungen ungültig)
	`CREATE TABLE IF NOT EXISTS top_hourly (hour INTEGER NOT NULL, field TEXT NOT NULL, key TEXT NOT NULL,
	  label TEXT NOT NULL DEFAULT '', n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (hour, field, key)) WITHOUT ROWID;
	CREATE INDEX IF NOT EXISTS top_field ON top_hourly(field, hour);
	DELETE FROM auth_sessions;`,
	// 3: Zwischenspeicher für Abfragen bei Dritten (AbuseIPDB, KI-Auswertung); subject = "ip:<IP>" oder "session:<ID>"
	`CREATE TABLE IF NOT EXISTS lookups (subject TEXT NOT NULL, source TEXT NOT NULL, fetched INTEGER NOT NULL,
	  data TEXT NOT NULL, PRIMARY KEY (subject, source)) WITHOUT ROWID;`,
	// 4: Rollen für weitere Benutzer ("admin" darf alles, "viewer" nur ansehen; siehe users.go)
	`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';`,
	// 5: Zwischenspeicher der Sprachmodell-Antworten für den Honeypot (mimic.go)
	`CREATE TABLE IF NOT EXISTS mimic_cache (k TEXT PRIMARY KEY, kind TEXT NOT NULL, input TEXT NOT NULL, out TEXT NOT NULL,
	  created INTEGER NOT NULL, hits INTEGER NOT NULL DEFAULT 0, last_hit INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;`,
	// 6: CISA-Katalog der ausgenutzten Lücken (cvedb.go), Regelvorschläge der KI und eigene Regeln (cvesuggest.go)
	`CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY, vendor TEXT NOT NULL DEFAULT '', product TEXT NOT NULL DEFAULT '',
	  name TEXT NOT NULL DEFAULT '', added TEXT NOT NULL DEFAULT '', descr TEXT NOT NULL DEFAULT '', action TEXT NOT NULL DEFAULT '',
	  due TEXT NOT NULL DEFAULT '', ransomware TEXT NOT NULL DEFAULT '', cwes TEXT NOT NULL DEFAULT '') WITHOUT ROWID;
	CREATE TABLE IF NOT EXISTS rule_suggestions (id INTEGER PRIMARY KEY, created INTEGER NOT NULL, path TEXT NOT NULL,
	  sample TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'neu', product TEXT NOT NULL DEFAULT '', cve TEXT NOT NULL DEFAULT '',
	  kind TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', explanation TEXT NOT NULL DEFAULT '', expr TEXT NOT NULL DEFAULT '', problem TEXT NOT NULL DEFAULT '',
	  model TEXT NOT NULL DEFAULT '', decided INTEGER NOT NULL DEFAULT 0);
	CREATE INDEX IF NOT EXISTS sugg_path ON rule_suggestions(path);
	CREATE TABLE IF NOT EXISTS custom_rules (id INTEGER PRIMARY KEY, created INTEGER NOT NULL, kind TEXT NOT NULL,
	  product TEXT NOT NULL, cve TEXT NOT NULL DEFAULT '', name TEXT NOT NULL, expr TEXT NOT NULL, note TEXT NOT NULL DEFAULT '',
	  suggestion INTEGER NOT NULL DEFAULT 0);`,
}

func OpenStore(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=auto_vacuum(INCREMENTAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	st := &Store{db: db, path: path}
	if err := st.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return st, nil
}

func (s *Store) migrate() error {
	var v int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	for v < len(migrations) {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			tx.Rollback()
			return fmt.Errorf("Migration %d: %w", v+1, err)
		}
		if v+1 == 2 { // vorhandene Ereignisse in die Zähltabelle übernehmen
			if err := backfillTop(tx); err != nil {
				tx.Rollback()
				return fmt.Errorf("Migration 2 (Zähltabelle): %w", err)
			}
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		v++
		log.Printf("Datenbank auf Schema-Version %d gebracht", v)
	}
	return nil
}

func backfillTop(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT ts, service, type, src_ip, dst_port, username, password, data, country, country_name, city, lat, lon, asn, as_org FROM events`)
	if err != nil {
		return err
	}
	var evs []*Event
	for rows.Next() {
		e := &Event{}
		var ms int64
		var data sql.NullString
		if err := rows.Scan(&ms, &e.Service, &e.Type, &e.SrcIP, &e.DstPort, &e.Username, &e.Password, &data, &e.Country, &e.CountryName, &e.City, &e.Lat, &e.Lon, &e.ASN, &e.ASOrg); err != nil {
			rows.Close()
			return err
		}
		e.TS = time.UnixMilli(ms)
		if data.Valid {
			e.Data = json.RawMessage(data.String)
		}
		evs = append(evs, e)
	}
	rows.Close()
	st, err := tx.Prepare(topUpsert)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, e := range evs {
		for _, t := range topKeys(e) {
			if _, err := st.Exec(e.TS.UnixMilli()/3600000, t[0], t[1], t[2]); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) GetKV(k string) (string, bool) {
	var v string
	if err := s.db.QueryRow(`SELECT v FROM kv WHERE k=?`, k).Scan(&v); err != nil {
		return "", false
	}
	return v, true
}

func (s *Store) SetKV(k, v string) error {
	_, err := s.db.Exec(`INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

func (s *Store) DelKV(k string) error {
	_, err := s.db.Exec(`DELETE FROM kv WHERE k=?`, k)
	return err
}

// Size liefert die Dateigröße (inkl. WAL) und den tatsächlich belegten Teil.
func (s *Store) Size() (file, used int64) {
	for _, suf := range []string{"", "-wal", "-shm"} {
		if fi, err := os.Stat(s.path + suf); err == nil {
			file += fi.Size()
		}
	}
	var pages, free, psize int64
	s.db.QueryRow(`PRAGMA page_count`).Scan(&pages)
	s.db.QueryRow(`PRAGMA freelist_count`).Scan(&free)
	s.db.QueryRow(`PRAGMA page_size`).Scan(&psize)
	return file, (pages - free) * psize
}

// ---- Zähltabelle für Top-Listen ----

const topUpsert = `INSERT INTO top_hourly(hour, field, key, label, n) VALUES(?, ?, ?, ?, 1)
	ON CONFLICT(hour, field, key) DO UPDATE SET n = n + 1,
	label = CASE WHEN excluded.label != '' THEN excluded.label ELSE label END`

func dataString(d json.RawMessage, key string) string {
	s, _ := dataMap(d)[key].(string)
	return s
}

// dataMemo: zuletzt gelesene Ereignisdaten. Die Auswertung fragt dieselben Daten oft mehrmals
// hintereinander ab (Pfad, Methode, Body, Kopfzeilen …); jedes Mal das ganze JSON zu lesen
// kostete beim Aufbau der Angriffe rund ein Drittel der Zeit. Verglichen wird der Inhalt,
// nicht die Adresse; das Ergebnis darf nur gelesen werden.
var dataMemo struct {
	mu  sync.Mutex
	raw []byte
	m   map[string]any
}

// dataMap: Ereignisdaten als Map (nil bei leeren oder ungültigen Daten). Nur lesen.
func dataMap(d json.RawMessage) map[string]any {
	if len(d) == 0 {
		return nil
	}
	dataMemo.mu.Lock()
	if dataMemo.raw != nil && bytes.Equal(dataMemo.raw, d) {
		m := dataMemo.m
		dataMemo.mu.Unlock()
		return m
	}
	dataMemo.mu.Unlock()
	var m map[string]any
	if json.Unmarshal(d, &m) != nil {
		m = nil
	}
	dataMemo.mu.Lock()
	dataMemo.raw, dataMemo.m = append([]byte(nil), d...), m
	dataMemo.mu.Unlock()
	return m
}

// topKeys liefert (Feld, Schlüssel, Beschriftung) für die Zähltabelle.
func topKeys(e *Event) [][3]string {
	var out [][3]string
	add := func(f, k, l string) {
		if k != "" {
			out = append(out, [3]string{f, clip(k, 512), clip(l, 256)})
		}
	}
	switch e.Type {
	case "connect":
		add("country", e.Country, e.CountryName)
		add("port", strconv.Itoa(e.DstPort), e.Service)
		add("ip", e.SrcIP, e.Country)
		if e.ASN != 0 {
			add("asn", strconv.Itoa(e.ASN), e.ASOrg)
		}
		add("service", e.Service, "")
		if e.Lat != 0 || e.Lon != 0 {
			add("geo", fmt.Sprintf("%.1f,%.1f", e.Lat, e.Lon), e.Country+"|"+e.City)
		}
	case "login":
		if e.Service == "snmp" { // Community-String: eigene Liste, keine Zugangsdaten
			add("snmp", e.Password, dataString(e.Data, "pdu"))
			break
		}
		if foreignEvent(e) { // HTTP-Zeilen an der Telnet-Anmeldung (einstufung.go, Regel 1b)
			break
		}
		if lines, ok := promptLines(e); ok { // Befehle an der Login-Abfrage sind keine Zugangsdaten
			for _, l := range lines {
				add("command", l, e.Service)
			}
			break
		}
		add("username", e.Username, "")
		add("password", e.Password, "")
		if e.Password != "" {
			add("cred", e.Username+" / "+e.Password, "")
		}
	case "command":
		if in := dataString(e.Data, "input"); !isTLSText(in) && !foreignEvent(e) {
			add("command", in, e.Service)
		}
	case "request":
		switch e.Service {
		case "sip": // SIP-Adressen und DNS-Namen sind keine Web-Pfade
			add("sip", requestKey(e), "")
			add("client", dataString(e.Data, "user_agent"), e.Service)
		case "dns":
			add("dns", requestKey(e), "")
		default:
			add("path", dataString(e.Data, "path"), e.Service)
			add("useragent", dataString(e.Data, "user_agent"), "")
		}
	case "client_version":
		add("client", dataString(e.Data, "version"), e.Service)
	case "tls":
		if j3s, j3, j4, ok := tlsFingerprints(e); ok { // Fingerabdrücke (tlsfp.go)
			add("ja4", j4, e.Service)
			add("ja3", j3, j3s)
		}
	case "fingerprint":
		add("hassh", dataString(e.Data, "hassh"), e.Service)
	}
	if h, order := headerFingerprint(e); h != "" {
		add("httpfp", h, order)
	}
	// Muster, Werkzeuge und Nachlade-Adressen (analyze.go) für die Ansicht "Analyse"
	text, on, revealed := analysisText(e)
	for _, id := range eventPatterns(e, text, on, revealed) {
		add("tag", id, patternByID[id].Name)
	}
	for _, r := range eventCVEs(text, on) {
		add("cve", r.CVE, r.Label())
	}
	for _, t := range eventTools(e) {
		add("tool", t, "")
	}
	if e.Type == "command" || e.Type == "download" || len(revealed) > 0 {
		src := text
		if e.Type == "request" {
			src = ""
		}
		for _, u := range allURLs(src, revealed, 4) {
			add("url", clip(u, 300), e.Service)
		}
	}
	if e.Type == "command" || e.Type == "payload" { // Wallets und Pools (indicators.go)
		for _, t := range append([]string{text}, revealed...) {
			ws, ps := cryptoIndicators(t)
			for _, w := range ws {
				add("wallet", w, walletKind(w))
			}
			for _, p := range ps {
				add("pool", p, e.Service)
			}
		}
	}
	return out
}

// ---- Duplikaterkennung über Ereignis-IDs ----

type dedupe struct {
	mu   sync.Mutex
	set  map[string]struct{}
	ring []string
	pos  int
}

func newDedupe(n int) *dedupe {
	return &dedupe{set: make(map[string]struct{}, n), ring: make([]string, n)}
}

func (d *dedupe) Has(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.set[id]
	return ok
}

func (d *dedupe) Add(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.set[id]; ok {
		return
	}
	if old := d.ring[d.pos]; old != "" {
		delete(d.set, old)
	}
	d.ring[d.pos] = id
	d.set[id] = struct{}{}
	d.pos = (d.pos + 1) % len(d.ring)
}

// ---- Schreiben: ein Writer, gebündelt in Transaktionen ----

const (
	writerQueueLen   = 5000
	writerQueueBytes = 32 << 20
)

type Writer struct {
	st      *Store
	ch      chan *Event
	pub     func(*Event)
	queued  atomic.Int64
	seen    *dedupe
	dropped atomic.Int64 // nach Fehlschlägen verworfen
	dupes   atomic.Int64
	written atomic.Int64
	lastErr atomic.Value // string
	ins     [4]*sql.Stmt
	// Interval: so oft wird geschrieben (HIVE_FLUSH_MS). Länger schont SD-Karten,
	// verzögert aber den Live-Feed und verliert bei Stromausfall mehr.
	Interval time.Duration
	stop     chan struct{}
	done     chan struct{}
}

func approxSize(e *Event) int64 {
	return int64(512 + len(e.Data) + len(e.Username) + len(e.Password) + len(e.City) + len(e.ASOrg))
}

func NewWriter(st *Store, pub func(*Event)) (*Writer, error) {
	w := &Writer{st: st, ch: make(chan *Event, writerQueueLen), pub: pub, seen: newDedupe(200000),
		Interval: 300 * time.Millisecond, stop: make(chan struct{}), done: make(chan struct{})}
	w.lastErr.Store("")
	qs := []string{
		`INSERT INTO events(ts,sensor,service,type,src_ip,src_port,dst_port,session,username,password,data,duration_ms,tarpit,tarpit_ms,country,country_name,city,lat,lon,asn,as_org)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		`INSERT INTO hourly(hour,service,type,country,cnt,tarpit_ms) VALUES(?,?,?,?,1,?)
		ON CONFLICT(hour,service,type,country) DO UPDATE SET cnt=cnt+1, tarpit_ms=tarpit_ms+excluded.tarpit_ms`,
		`INSERT INTO attackers(ip,first_seen,last_seen,events,logins,commands,tarpit_ms,country,country_name,city,asn,as_org)
		VALUES(?,?,?,1,?,?,?,?,?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET last_seen=max(last_seen,excluded.last_seen), first_seen=min(first_seen,excluded.first_seen),
		events=events+1, logins=logins+excluded.logins, commands=commands+excluded.commands, tarpit_ms=tarpit_ms+excluded.tarpit_ms,
		country=CASE WHEN excluded.country!='' THEN excluded.country ELSE country END,
		country_name=CASE WHEN excluded.country_name!='' THEN excluded.country_name ELSE country_name END,
		city=CASE WHEN excluded.city!='' THEN excluded.city ELSE city END,
		asn=CASE WHEN excluded.asn!=0 THEN excluded.asn ELSE asn END,
		as_org=CASE WHEN excluded.as_org!='' THEN excluded.as_org ELSE as_org END`,
		topUpsert,
	}
	for i, q := range qs {
		st, err := st.db.Prepare(q)
		if err != nil {
			return nil, fmt.Errorf("Statement %d vorbereiten: %w", i, err)
		}
		w.ins[i] = st
	}
	return w, nil
}

// Submit liefert false, wenn die Warteschlange voll ist. Doppelte Ereignis-IDs
// (Wiederholung durch den Sensor) werden still als angenommen behandelt.
func (w *Writer) Submit(e *Event) bool {
	if e.EID != "" && w.seen.Has(e.EID) {
		w.dupes.Add(1)
		return true
	}
	size := approxSize(e)
	if w.queued.Load()+size > writerQueueBytes {
		return false
	}
	select {
	case w.ch <- e:
		w.queued.Add(size)
		if e.EID != "" {
			w.seen.Add(e.EID)
		}
		return true
	default:
		return false
	}
}

func (w *Writer) QueueLen() int { return len(w.ch) }

func (w *Writer) Run() {
	defer close(w.done)
	batch := make([]*Event, 0, 500)
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	take := func(e *Event) {
		w.queued.Add(-approxSize(e))
		batch = append(batch, e)
	}
	for {
		select {
		case e := <-w.ch:
			take(e)
			if len(batch) >= 500 {
				w.flush(batch)
				batch = batch[:0]
			}
		case <-t.C:
			if len(batch) > 0 {
				w.flush(batch)
				batch = batch[:0]
			}
		case <-w.stop:
			for {
				select {
				case e := <-w.ch:
					take(e)
					continue
				default:
				}
				break
			}
			if len(batch) > 0 {
				w.flush(batch)
			}
			return
		}
	}
}

// Stop schreibt alles Wartende und beendet den Writer.
func (w *Writer) Stop(timeout time.Duration) {
	close(w.stop)
	select {
	case <-w.done:
	case <-time.After(timeout):
		log.Printf("Writer: Zeitüberschreitung beim Beenden, %d Ereignisse nicht geschrieben", len(w.ch))
	}
}

func (w *Writer) flush(batch []*Event) {
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		if err = w.writeBatch(batch); err == nil {
			w.written.Add(int64(len(batch)))
			for _, e := range batch {
				w.pub(e)
			}
			return
		}
		log.Printf("DB: Schreiben fehlgeschlagen (Versuch %d/3): %v", attempt, err)
		time.Sleep(time.Duration(attempt) * time.Second)
	}
	w.dropped.Add(int64(len(batch)))
	w.lastErr.Store(err.Error())
	log.Printf("DB: %d Ereignisse verworfen: %v", len(batch), err)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (w *Writer) writeBatch(batch []*Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tx, err := w.st.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ev, hr, at, top := tx.Stmt(w.ins[0]), tx.Stmt(w.ins[1]), tx.Stmt(w.ins[2]), tx.Stmt(w.ins[3])
	for _, e := range batch {
		ms := e.TS.UnixMilli()
		var data any
		if len(e.Data) > 0 {
			data = string(e.Data)
		}
		res, err := ev.Exec(ms, e.Sensor, e.Service, e.Type, e.SrcIP, e.SrcPort, e.DstPort, e.Session, e.Username, e.Password,
			data, e.DurationMs, b2i(e.Tarpit), e.TarpitMs, e.Country, e.CountryName, e.City, e.Lat, e.Lon, e.ASN, e.ASOrg)
		if err != nil {
			return fmt.Errorf("events: %w", err)
		}
		e.ID, _ = res.LastInsertId()
		if ownHidden(e.SrcIP) { // eigener Test (ownnet.go): nur das Ereignis selbst
			continue
		}
		if _, err := hr.Exec(ms/3600000, e.Service, e.Type, e.Country, e.TarpitMs); err != nil {
			return fmt.Errorf("hourly: %w", err)
		}
		if _, err := at.Exec(e.SrcIP, ms, ms, b2i(e.Type == "login"), b2i(e.Type == "command"), e.TarpitMs,
			e.Country, e.CountryName, e.City, e.ASN, e.ASOrg); err != nil {
			return fmt.Errorf("attackers: %w", err)
		}
		for _, k := range topKeys(e) {
			if _, err := top.Exec(ms/3600000, k[0], k[1], k[2]); err != nil {
				return fmt.Errorf("top: %w", err)
			}
		}
	}
	return tx.Commit()
}

// ---- Aufbewahrung ----

type RetentionPolicy struct {
	Days         int   // Rohdaten, Angreiferliste und Top-Zähler
	MaxDBBytes   int64 // belegter Platz in der Datenbank
	MinFreeBytes int64 // freier Speicher, der mindestens bleiben soll
}

type RetentionStatus struct {
	LastRun  time.Time `json:"last_run"`
	Pressure string    `json:"pressure,omitempty"` // Grund, falls nach Größe gelöscht wurde
	Deleted  int64     `json:"deleted"`
}

func (s *Store) deleteChunks(q string, args ...any) int64 {
	var total int64
	for {
		res, err := s.db.Exec(q, args...)
		if err != nil {
			log.Printf("Aufräumen: %v", err)
			return total
		}
		n, _ := res.RowsAffected()
		total += n
		if n < 5000 {
			return total
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (s *Store) Retention(p RetentionPolicy) RetentionStatus {
	st := RetentionStatus{LastRun: time.Now()}
	if p.Days > 0 {
		cut := time.Now().Add(-time.Duration(p.Days) * 24 * time.Hour).UnixMilli()
		st.Deleted += s.deleteChunks(`DELETE FROM events WHERE id IN (SELECT id FROM events WHERE ts < ? LIMIT 5000)`, cut)
		s.deleteChunks(`DELETE FROM attackers WHERE ip IN (SELECT ip FROM attackers WHERE last_seen < ? LIMIT 5000)`, cut)
		s.db.Exec(`DELETE FROM top_hourly WHERE hour < ?`, cut/3600000)
		s.db.Exec(`DELETE FROM lookups WHERE fetched < ?`, cut)
	}
	s.db.Exec(`DELETE FROM hourly WHERE hour < ?`, time.Now().Add(-400*24*time.Hour).UnixMilli()/3600000)
	s.db.Exec(`DELETE FROM auth_sessions WHERE expires < ?`, time.Now().Unix())

	// Nach Größe: älteste Ereignisse löschen, bis wieder Luft ist.
	for i := 0; i < 200; i++ {
		_, used := s.Size()
		free := diskFree(s.path)
		reason := ""
		switch {
		case p.MaxDBBytes > 0 && used > p.MaxDBBytes:
			reason = fmt.Sprintf("Datenbank über %d MB", p.MaxDBBytes>>20)
		case p.MinFreeBytes > 0 && free >= 0 && free < p.MinFreeBytes:
			reason = fmt.Sprintf("weniger als %d MB frei", p.MinFreeBytes>>20)
		}
		if reason == "" {
			break
		}
		st.Pressure = reason
		res, err := s.db.Exec(`DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id LIMIT 20000)`)
		if err != nil {
			break
		}
		n, _ := res.RowsAffected()
		st.Deleted += n
		if n == 0 {
			break
		}
		s.db.Exec(`PRAGMA incremental_vacuum`)
	}
	if st.Pressure != "" {
		log.Printf("Speicher knapp (%s): älteste Ereignisse gelöscht", st.Pressure)
	}
	s.db.Exec(`PRAGMA incremental_vacuum`) // alle freien Seiten zurückgeben
	s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return st
}

// Backup schreibt eine konsistente Kopie (auch bei laufendem Hive im WAL-Modus)
// und behält die neuesten keep Sicherungen im Ordner.
func (s *Store) Backup(dir string, keep int) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := filepath.Join(dir, "hive-"+time.Now().Format("20060102-150405")+".db")
	if _, err := s.db.Exec(`VACUUM INTO ?`, name); err != nil {
		return "", err
	}
	files, _ := filepath.Glob(filepath.Join(dir, "hive-*.db"))
	sort.Strings(files)
	for len(files) > keep {
		os.Remove(files[0])
		files = files[1:]
	}
	return name, nil
}
