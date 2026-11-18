package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// hiveDataLimit muss zu hive/store.go (maxDataBytes) passen.
const hiveDataLimit = 16 << 10

// ---------- Hilfen ----------

func testManager() *Manager {
	em := NewEmitter(&HiveClient{URL: "http://127.0.0.1:1", HTTP: http.DefaultClient}, "test")
	m := NewManager(em, "127.0.0.1", 0)
	tc := DefaultConfig().Tarpit
	tc.IntervalMs = 200
	m.tarpit.Store(&tc)
	return m
}

// run startet einen Handler an einer Pipe und liefert das Client-Ende.
func run(t *testing.T, m *Manager, service, mode string) (net.Conn, chan struct{}) {
	t.Helper()
	c1, c2 := net.Pipe()
	rl := &runListener{}
	lc := ListenerConfig{Service: service, Port: 80, Mode: mode, Enabled: true}
	rl.cfg.Store(&lc)
	done := make(chan struct{})
	go func() { m.handle(rl, c2); close(done) }()
	t.Cleanup(func() { c1.Close() })
	return c1, done
}

func events(m *Manager) []Event {
	var out []Event
	for {
		select {
		case b := <-m.em.ch:
			m.em.queued.Add(-int64(len(b)))
			var e Event
			json.Unmarshal(b, &e)
			out = append(out, e)
		default:
			return out
		}
	}
}

func rawEvents(m *Manager) [][]byte {
	var out [][]byte
	for {
		select {
		case b := <-m.em.ch:
			out = append(out, b)
		default:
			return out
		}
	}
}

func waitDone(t *testing.T, done chan struct{}, d time.Duration) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatal("Handler hat sich nicht beendet")
	}
}

// ---------- Befund 1: HTTP-Kopf begrenzt ----------

func TestHTTPHeaderLimit(t *testing.T) {
	m := testManager()
	c, done := run(t, m, "http", "emulate")
	go func() {
		c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nX-Big: "))
		big := bytes.Repeat([]byte("a"), 32<<10)
		for i := 0; i < 64; i++ { // 2 MB, deutlich über dem Limit
			if _, err := c.Write(big); err != nil {
				return
			}
		}
	}()
	go io.Copy(io.Discard, c)
	waitDone(t, done, 5*time.Second)
}

func TestHTTPBodyNotDrained(t *testing.T) {
	m := testManager()
	c, done := run(t, m, "http", "emulate")
	go func() {
		c.Write([]byte("POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 10000000000\r\n\r\nusername=a&password=b"))
		big := bytes.Repeat([]byte("x"), 32<<10)
		for i := 0; i < 8; i++ {
			if _, err := c.Write(big); err != nil {
				return
			}
		}
	}()
	go io.Copy(io.Discard, c)
	waitDone(t, done, 5*time.Second)
	for _, e := range events(m) {
		if e.Type == "request" && e.Data["body_truncated"] != true {
			t.Errorf("body_truncated fehlt: %v", e.Data)
		}
	}
}

// ---------- Befund 27: Tarpit ohne Anfrage ----------

func TestHTTPTarpitImmediate(t *testing.T) {
	m := testManager()
	c, _ := run(t, m, "http", "tarpit")
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "HTTP/1.1 200 OK\r\n" {
		t.Fatalf("erwartet sofortige Tarpit-Antwort, bekam %q, %v", line, err)
	}
}

// Festgehaltene Verbindungen stehen in HeldTarpits (für die UI), nach dem Auflegen nicht mehr.
func TestHeldTarpitsListed(t *testing.T) {
	m := testManager()
	c, _ := run(t, m, "http", "tarpit")
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	bufio.NewReader(c).ReadString('\n')
	held := m.HeldTarpits(10)
	if len(held) != 1 || held[0].Service != "http" || held[0].Mode != "tarpit" || held[0].Since.IsZero() {
		t.Fatalf("festgehaltene Verbindung fehlt: %+v", held)
	}
	c.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(m.HeldTarpits(10)) > 0 {
		time.Sleep(50 * time.Millisecond)
	}
	if n := len(m.HeldTarpits(10)); n != 0 {
		t.Fatalf("nach dem Auflegen noch %d festgehalten", n)
	}
}

// ---------- Befund 2: Redis begrenzt ----------

func TestRedisLargeArgumentStreamed(t *testing.T) {
	big := strings.Repeat("Z", 500000)
	in := fmt.Sprintf("*2\r\n$3\r\nSET\r\n$%d\r\n%s\r\n", len(big), big)
	args, truncated, err := readRESP(bufio.NewReader(strings.NewReader(in)))
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || len(args[1]) != redisKeepPerArg {
		t.Fatalf("Argument nicht gekürzt: truncated=%v len=%d", truncated, len(args[1]))
	}
}

func TestRedisCommandBudget(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("*64\r\n")
	for i := 0; i < 64; i++ {
		fmt.Fprintf(&sb, "$%d\r\n%s\r\n", 100000, strings.Repeat("q", 100000))
	}
	args, _, err := readRESP(bufio.NewReader(strings.NewReader(sb.String())))
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, a := range args {
		total += len(a)
	}
	if total > redisKeepPerCmd {
		t.Fatalf("Befehl behält %d Bytes, erlaubt %d", total, redisKeepPerCmd)
	}
}

func TestRedisRejectsHugeLength(t *testing.T) {
	_, _, err := readRESP(bufio.NewReader(strings.NewReader("*1\r\n$999999999\r\n")))
	if err == nil {
		t.Fatal("riesige Länge muss abgelehnt werden")
	}
}

// ---------- Befund 5: Vertragstest Größenbudget ----------

func TestEventSizeContract(t *testing.T) {
	m := testManager()
	c, done := run(t, m, "dockerapi", "emulate")
	bin := make([]byte, 60<<10)
	for i := range bin {
		bin[i] = byte(i) // nicht druckbar, Backslashes, Anführungszeichen
	}
	path := "/" + strings.Repeat("%22%5C", 3000)
	req := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nX-A: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		path, strings.Repeat("h", 2000), strings.Repeat("\"\\", 2000), strings.Repeat("\"", 5000), len(bin))
	go func() { c.Write([]byte(req)); c.Write(bin) }()
	go io.Copy(io.Discard, c)
	waitDone(t, done, 5*time.Second)

	c2, done2 := run(t, m, "raw", "emulate")
	go func() { c2.Write(bin[:4096]) }()
	waitDone(t, done2, 15*time.Second)

	evs := rawEvents(m)
	if len(evs) < 3 {
		t.Fatalf("zu wenige Ereignisse: %d", len(evs))
	}
	for _, b := range evs {
		if len(b) > maxEventBytes {
			t.Errorf("Ereignis %d Bytes > %d", len(b), maxEventBytes)
		}
		var e struct{ Data json.RawMessage }
		json.Unmarshal(b, &e)
		if len(e.Data) > hiveDataLimit {
			t.Errorf("data %d Bytes > Hive-Limit %d", len(e.Data), hiveDataLimit)
		}
		if bytes.Contains(b, []byte(`"truncated":true`)) && !bytes.Contains(b, []byte(`body_truncated`)) {
			t.Errorf("Inhalt komplett verworfen statt gekürzt: %s", b[:200])
		}
	}
}

// ---------- Befund 22: clip ----------

func TestClip(t *testing.T) {
	if got := clip("ab\xffcdefgh", 5); !strings.HasPrefix(got, "ab") || len([]rune(got)) != 5 {
		t.Errorf("clip mit Binärbyte: %q", got)
	}
	if got := clip("äää", 3); got != "ä" {
		t.Errorf("clip im Zeichen: %q", got)
	}
	if got := clip("kurz", 10); got != "kurz" {
		t.Errorf("clip kurz: %q", got)
	}
}

func TestPrintableBudget(t *testing.T) {
	out := printable(bytes.Repeat([]byte{0}, 10000), 100)
	if len(out) > 100 {
		t.Fatalf("printable zu lang: %d", len(out))
	}
}

// ---------- MySQL ----------

func TestParseMySQLLogin(t *testing.T) {
	p := []byte{0x85, 0xa6, 0x0f, 0x00} // caps inkl. SECURE_CONNECTION, PLUGIN_AUTH
	p = append(p, 0, 0, 0, 1, 33)
	p = append(p, make([]byte, 23)...)
	p = append(p, "root\x00"...)
	p = append(p, 20)
	p = append(p, bytes.Repeat([]byte{0x11}, 20)...)
	p = append(p, "mysql_native_password\x00"...)
	r, ok := parseMySQLLogin(p)
	if !ok || r.User != "root" || len(r.Auth) != 20 || r.Plugin != "mysql_native_password" {
		t.Fatalf("falsch geparst: %+v", r)
	}
}

// ---------- Befund 32: Port-Kollision ----------

func TestNormalizePortCollision(t *testing.T) {
	c := Config{Listeners: []ListenerConfig{{"http", 80, "emulate", true}, {"http", 10080, "emulate", true}}}
	warn := c.Normalize(10000)
	if len(c.Listeners) != 1 || len(warn) == 0 {
		t.Fatalf("Kollision nicht erkannt: %+v %v", c.Listeners, warn)
	}
	c = Config{Tarpit: TarpitConfig{MaxConns: 99999}}
	c.Normalize(0)
	if c.Tarpit.MaxConns != maxTarpitConns {
		t.Fatalf("max_conns nicht begrenzt: %d", c.Tarpit.MaxConns)
	}
}

// ---------- Manager ----------

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestManagerApply(t *testing.T) {
	m := testManager()
	p := freePort(t)
	cfg := Config{Listeners: []ListenerConfig{{"raw", p, "emulate", true}}}
	if !m.Apply(cfg) {
		t.Fatal("erste Konfiguration muss als Änderung gelten")
	}
	ln := m.running[p].ln
	if m.Apply(cfg) {
		t.Fatal("gleiche Konfiguration darf keine Änderung sein")
	}
	cfg.Listeners[0].Mode = "tarpit"
	m.Apply(cfg)
	if m.running[p].ln != ln || m.running[p].cfg.Load().Mode != "tarpit" {
		t.Fatal("Moduswechsel muss ohne Neustart greifen")
	}
	cfg.Listeners[0].Service = "ftp"
	m.Apply(cfg)
	if m.running[p].ln == ln {
		t.Fatal("Dienstwechsel muss den Listener neu starten")
	}
	cfg.Listeners[0].Enabled = false
	m.Apply(cfg)
	if _, ok := m.running[p]; ok {
		t.Fatal("deaktivierter Port läuft noch")
	}
	m.StopAll()
}

// ---------- Drossel ----------

func TestRateLimiter(t *testing.T) {
	r := NewRateLimiter(1, 5)
	n := 0
	for i := 0; i < 50; i++ {
		if r.Allow("1.2.3.4") {
			n++
		}
	}
	if n != 5 {
		t.Fatalf("erlaubt %d statt 5", n)
	}
	if !r.Allow("5.6.7.8") {
		t.Fatal("andere IP darf nicht gedrosselt sein")
	}
}

// ---------- Befund 6: Emitter wiederholt 4xx nicht ----------

func TestEmitterDropsOn4xxRetriesOn5xx(t *testing.T) {
	var calls atomic.Int32
	status := atomic.Int32{}
	status.Store(400)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	em := NewEmitter(&HiveClient{URL: srv.URL, HTTP: srv.Client()}, "t")
	stop := make(chan struct{})
	go em.Run(stop)
	em.Emit(Event{Type: "connect", SrcIP: "1.2.3.4"})
	time.Sleep(2500 * time.Millisecond)
	if calls.Load() != 1 || em.dropped.Load() != 1 {
		t.Fatalf("400: calls=%d dropped=%d (erwartet 1/1)", calls.Load(), em.dropped.Load())
	}
	status.Store(503)
	em.Emit(Event{Type: "connect", SrcIP: "1.2.3.4"})
	time.Sleep(4500 * time.Millisecond)
	if calls.Load() < 3 {
		t.Fatalf("503 muss wiederholt werden, calls=%d", calls.Load())
	}
	close(stop)
}

// ---------- Fuzzing ----------

func FuzzReadRESP(f *testing.F) {
	f.Add([]byte("*2\r\n$4\r\nAUTH\r\n$3\r\npw1\r\n"))
	f.Add([]byte("PING\r\n"))
	f.Add([]byte("*1\r\n$-1\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		readRESP(bufio.NewReader(bytes.NewReader(b)))
	})
}

func FuzzParseMySQLLogin(f *testing.F) {
	f.Add(append(make([]byte, 32), "root\x00\x14aaaaaaaaaaaaaaaaaaaa"...))
	f.Fuzz(func(t *testing.T, b []byte) {
		parseMySQLLogin(b)
	})
}

func FuzzReadLine(f *testing.F) {
	f.Add([]byte("USER x\r\nPASS y\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		br := bufio.NewReaderSize(bytes.NewReader(b), 16)
		for i := 0; i < 5; i++ {
			if _, err := readLine(br, 64); err != nil {
				return
			}
		}
	})
}

func FuzzHTTPRequestParsing(f *testing.F) {
	f.Add([]byte("POST /containers/create HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"Image\":\"a\",\"Cmd\":1}"))
	f.Add([]byte("GET / HTTP/1.1\r\nAuthorization: Basic YTpi\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
		if err != nil {
			return
		}
		body, _ := io.ReadAll(io.LimitReader(req.Body, 4096))
		extractCreds(req, body)
		dockerCommand(req, body)
	})
}

// Gefälschte Absender (UDP) dürfen die Tabelle der Drossel nicht beliebig wachsen lassen:
// Bei voller Tabelle teilen sich neue Adressen einen Eintrag, bekannte behalten ihren.
func TestRateLimiterBounded(t *testing.T) {
	r := NewRateLimiter(1, 5)
	r.max = 100
	if !r.Allow("198.51.100.1") {
		t.Fatal("erste Adresse abgelehnt")
	}
	allowed := 0
	for i := 0; i < 5000; i++ {
		if r.Allow(fmt.Sprintf("203.0.113.%d:%d", i%250, i)) {
			allowed++
		}
	}
	r.mu.Lock()
	n := len(r.buckets)
	r.mu.Unlock()
	if n > r.max+1 {
		t.Fatalf("Tabelle hat %d Einträge, Grenze %d", n, r.max)
	}
	// 99 neue Einträge mit je einem Ereignis, danach nur noch das gemeinsame Kontingent (5)
	if allowed > 99+5+1 {
		t.Fatalf("%d Ereignisse erlaubt: gemeinsames Kontingent greift nicht", allowed)
	}
	if !r.Allow("198.51.100.1") {
		t.Fatal("bekannte Adresse muss ihr eigenes Kontingent behalten")
	}
}

// UDP-Pakete aller Absender zusammen sind begrenzt (Absender fälschbar).
func TestUDPGlobalRate(t *testing.T) {
	m := testManager()
	n := 0
	for i := 0; i < udpEventsBurst+500; i++ {
		if m.udpRate.Allow("") {
			n++
		}
	}
	if n < udpEventsBurst || n > udpEventsBurst+udpEventsPerSec {
		t.Fatalf("erlaubt %d, erwartet etwa %d", n, udpEventsBurst)
	}
}
