package main

// Köder für Produkte, die gerade massenhaft angegriffen werden (Web-Honeypot). Statt einer
// 404-Seite sieht der Angreifer unter den bekannten Pfaden eine glaubwürdige Oberfläche:
// Anmeldeseiten, typische Fehlercodes und Kopfzeilen, bei manchen Lücken sogar eine
// "verwundbare" Antwort. Das Ziel: Er schickt seinen echten Exploit samt Nutzlast (die steht
// dann im Ereignis "request" oder "command") und verliert dabei Zeit.
//
//   fortinet   FortiGate SSL-VPN: /remote/login, /remote/logincheck, /remote/fgt_lang
//              (CVE-2018-13379: das "ausgelesene" Sitzungsfile enthält die Köder-Zugangsdaten)
//   ivanti     Ivanti Connect Secure: /dana-na/…, /api/v1/totp/… (CVE-2023-46805/CVE-2024-21887),
//              Pulse-Secure-Dateilesen (CVE-2019-11510)
//   cisco-asa  Cisco ASA WebVPN: /+CSCOE+/logon.html, /+webvpn+/index.html, CVE-2020-3452
//   hikvision  Hikvision: /SDK/webLanguage (CVE-2021-36260, der Befehl landet als "command"),
//              /ISAPI/…, /Security/users?auth=… (CVE-2017-7921), /doc/page/login.asp
//   onvif      ONVIF-Gerätedienst einer Kamera (SOAP), WS-Security-Anmeldung als Login
//   tomcat     Tomcat Manager: 401 mit Basic-Auth; Werkspasswörter "gelingen", danach nimmt der
//              Manager WAR-Dateien an (Deploy als "command", Aufrufe der Webshell ebenso)
//   java-app   Jira- und Keycloak-artige Java-Anwendung mit Anmeldung und Basic-Auth an der
//              REST-API: Köder für Java4Shell (CVE-2026-114938, Base64 in Kopfzeile oder Body)
//
// Alles ist statisch, nichts wird ausgeführt; kein Sprachmodell (die Seiten müssen bei jedem
// Aufruf gleich aussehen). Anmeldeversuche zeichnet serveHTTP über extractCreds als "login"
// auf, die Anfrage selbst als "request" mit dem Feld "lure". Anmeldungen und Exploits
// beantworten die Köder bewusst langsam, wie ein ausgelastetes Gerät (lureDelay).
//
// Welche Köder laufen, legt die Einstellung "lures" fest: leer = passend zum Geräteprofil
// (profileLures), "all", "off" oder eine Liste wie "tomcat,java-app".

import (
	"fmt"
	"html"
	"math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// lureNames: alle Köder (Reihenfolge = Prüfreihenfolge). Muss zu hive/sensors.go passen.
var lureNames = []string{"fortinet", "ivanti", "cisco-asa", "hikvision", "onvif", "tomcat", "java-app"}

// profileLures: Köder, die ohne eigene Auswahl zum Geräteprofil passen. Das bisherige
// gemischte Profil zeigt alle; ein Heimrouter oder eine Smart-Home-Zentrale keine.
var profileLures = map[string][]string{
	"":             lureNames,
	"linux-server": {"tomcat", "java-app"},
	"dev-server":   {"tomcat", "java-app"},
	"nas":          {"tomcat"},
	"ip-camera":    {"hikvision", "onvif"},
	"router":       {},
	"smart-home":   {},
}

// lureSet bildet die Einstellung auf die eingeschalteten Köder ab; ok = false bei unbekannten Namen.
func lureSet(setting, profile string) (map[string]bool, bool) {
	on := map[string]bool{}
	switch strings.TrimSpace(setting) {
	case "":
		for _, n := range profileLures[profile] {
			on[n] = true
		}
		return on, true
	case "off":
		return on, true
	case "all":
		for _, n := range lureNames {
			on[n] = true
		}
		return on, true
	}
	for _, n := range strings.Split(setting, ",") {
		n = strings.TrimSpace(n)
		if !contains(lureNames, n) {
			return nil, false
		}
		on[n] = true
	}
	return on, true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// lureResp: Antwort eines Köders. hdr["Server"] ersetzt die Kopfzeile des Profils ("" = keine).
type lureResp struct {
	status int
	ctype  string
	body   string
	hdr    map[string]string
}

type lure struct {
	name  string
	match func(s *Session, req *http.Request) bool
	serve func(s *Session, req *http.Request, body []byte) lureResp
}

var lures []lure // in init: die Funktionen verweisen auf lureFor

func init() {
	lures = []lure{
		{"fortinet", func(_ *Session, r *http.Request) bool { return strings.HasPrefix(r.URL.Path, "/remote/") }, serveFortinet},
		{"ivanti", matchIvanti, serveIvanti},
		{"cisco-asa", matchCisco, serveCisco},
		{"hikvision", matchHikvision, serveHikvision},
		{"onvif", func(_ *Session, r *http.Request) bool { return strings.HasPrefix(r.URL.Path, "/onvif/") }, serveONVIF},
		{"tomcat", matchTomcat, serveTomcat},
		{"java-app", matchJavaApp, serveJavaApp},
	}
}

// lureFor: der zuständige, eingeschaltete Köder für diese Anfrage (nil = keiner).
func (s *Session) lureFor(req *http.Request) *lure {
	on := s.m.lureOn()
	for i := range lures {
		if on[lures[i].name] && lures[i].match(s, req) {
			return &lures[i]
		}
	}
	return nil
}

// lureOn: eingeschaltete Köder der laufenden Konfiguration.
func (m *Manager) lureOn() map[string]bool {
	if p := m.lures.Load(); p != nil {
		return *p
	}
	on, _ := lureSet("", "")
	return on
}

// lureSleep und lureDelay: bewusst langsame Antworten (in Tests ohne Warten).
var lureSleep = time.Sleep

func lureDelay(min, max time.Duration) {
	lureSleep(min + time.Duration(rand.Int64N(int64(max-min)+1)))
}

// ---- gemerkte Zustände je Angreifer (geschriebene Dateien, installierte Anwendungen) ----

const (
	lureMemMax = 2000
	lureMemTTL = time.Hour
)

type lureEntry struct {
	val   string
	until time.Time
}

var lureMem = struct {
	sync.Mutex
	m map[string]lureEntry
}{m: map[string]lureEntry{}}

func lureRemember(ip, key, val string) {
	lureMem.Lock()
	defer lureMem.Unlock()
	now := time.Now()
	if len(lureMem.m) >= lureMemMax {
		for k, e := range lureMem.m {
			if now.After(e.until) {
				delete(lureMem.m, k)
			}
		}
		if len(lureMem.m) >= lureMemMax {
			lureMem.m = map[string]lureEntry{}
		}
	}
	lureMem.m[ip+"\x00"+key] = lureEntry{clip(val, 4096), now.Add(lureMemTTL)}
}

func lureRecall(ip, key string) (string, bool) {
	lureMem.Lock()
	defer lureMem.Unlock()
	e, ok := lureMem.m[ip+"\x00"+key]
	if !ok || time.Now().After(e.until) {
		return "", false
	}
	return e.val, true
}

// ---- gemeinsame Bausteine ----

const (
	ctHTML = "text/html; charset=utf-8"
	ctXML  = "application/xml"
	ctJSON = "application/json"
	ctText = "text/plain; charset=utf-8"
)

// java4shellRe: Auslöser für CVE-2026-114938 (wie hive/analyze.go): Base64 aus vollen
// 64er-Blöcken mit angehängtem "=".
var java4shellRe = regexp.MustCompile(`(?:^|[^A-Za-z0-9+/_-])(?:[A-Za-z0-9+/_-]{64})+(?:=|%3D){1,2}(?:$|[^A-Za-z0-9+/_=%-])`)

// java4shell: Auslöser in einer Kopfzeile, der Query oder dem Body.
func java4shell(req *http.Request, body []byte) bool {
	for _, vs := range req.Header {
		for _, v := range vs {
			if java4shellRe.MatchString(v) {
				return true
			}
		}
	}
	return java4shellRe.MatchString(req.URL.RawQuery) || java4shellRe.Match(body)
}

// javaCrash: Antwort eines Java-Servers, dem eine Anfrage "die Luft abdrückt": lange nichts,
// dann ein 500 mit Tomcat-Fehlerseite. Für den Angreifer sieht das nach Wirkung aus.
func javaCrash() lureResp {
	lureDelay(6*time.Second, 12*time.Second)
	return lureResp{500, ctHTML, tomcatError(500, "Internal Server Error", "The server encountered an unexpected condition that prevented it from fulfilling the request."), nil}
}

func basicUser(req *http.Request) (string, string, bool) {
	u, p, ok := req.BasicAuth()
	return u, p, ok
}

// hostFor: Hostname für absolute Angaben in Antworten. Die Host-Kopfzeile des Angreifers nur,
// wenn sie wie ein Hostname aussieht, sonst der eigene.
func hostFor(s *Session, req *http.Request) string {
	h := req.Host
	if h == "" || len(h) > 100 || strings.IndexFunc(h, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == ':')
	}) >= 0 {
		return s.m.Hostname()
	}
	return h
}

func esc(s string) string { return html.EscapeString(s) }

// ---- Fortinet FortiGate SSL-VPN ----

const fortiServer = "xxxxxxxx-xxxxx" // so meldet sich FortiOS

func serveFortinet(s *Session, req *http.Request, _ []byte) lureResp {
	hdr := map[string]string{"Server": fortiServer, "X-Frame-Options": "SAMEORIGIN", "X-XSS-Protection": "1; mode=block"}
	switch p := req.URL.Path; {
	case p == "/remote/login":
		hdr["Set-Cookie"] = "SVPNCOOKIE=; path=/; expires=Sun, 11 Mar 1984 12:00:00 GMT; secure; httponly;"
		return lureResp{200, ctHTML, fortiLogin(req.URL.Query().Get("err") != ""), hdr}
	case p == "/remote/logincheck":
		if req.Method != "POST" {
			return lureResp{405, ctHTML, fortiError(405), hdr}
		}
		lureDelay(2*time.Second, 5*time.Second)
		return lureResp{200, ctText, "ret=0,redir=/remote/login?&err=sslvpn_login_permission_denied&lang=en", hdr}
	case p == "/remote/fgt_lang":
		lang := req.URL.Query().Get("lang")
		if strings.Contains(lang, "..") || strings.Contains(lang, "sslvpn_websession") {
			// CVE-2018-13379: "ausgelesene" Sitzungsdatei mit den Köder-Zugangsdaten (bait.go)
			lureDelay(1*time.Second, 3*time.Second)
			b := bait()
			sess := "var fgt_lang =\n" + "\x00\x00\x00\x01" + strings.Repeat("\x00", 12) + "203.0.113.47\x00\x00\x00\x00" + b.User + strings.Repeat("\x00", 28) +
				b.Pass + strings.Repeat("\x00", 24) + "full-access\x00\x00\x00root\x00\x00\x00\x00\x00\x00\x00\x00"
			return lureResp{200, "application/javascript", sess, hdr}
		}
		return lureResp{200, "application/javascript", fortiLang, hdr}
	case p == "/remote/info":
		return lureResp{200, ctText, "", hdr}
	}
	return lureResp{404, ctHTML, fortiError(404), hdr}
}

const fortiLang = `var fgt_lang = {"sslvpn_login_permission_denied":"Permission denied.","sslvpn_login_invalid_cred":"Error: Your credentials are invalid.",` +
	`"login":"Login","username":"Username","password":"Password","launch_forticlient":"Launch FortiClient","sslvpn_portal":"SSL-VPN Portal"};`

func fortiLogin(failed bool) string {
	msg := ""
	if failed {
		msg = `<div class="error-message">Error: Permission denied.</div>`
	}
	return `<!DOCTYPE html><html lang="en" class="main-app"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSL VPN Portal</title><script src="/remote/fgt_lang?lang=en"></script>
<style>body{font-family:Roboto,Arial,sans-serif;background:#2b2f33;color:#333}.main{width:340px;margin:120px auto;background:#fff;border-radius:3px;padding:24px 28px}
h1{font-size:20px;font-weight:400;margin:0 0 18px}input{width:100%;box-sizing:border-box;padding:8px;margin:4px 0 12px;border:1px solid #bbb}
button{background:#3a7bd5;color:#fff;border:0;padding:9px 18px}.error-message{color:#b5121b;margin-bottom:10px}</style></head>
<body><div class="main"><form method="post" action="/remote/logincheck" name="f"><h1>Please Login</h1>` + msg + `
<input type="hidden" name="ajax" value="1"><input type="hidden" name="just_logged_in" value="1">
<input name="username" id="username" placeholder="Username" autocomplete="off">
<input name="credential" id="credential" type="password" placeholder="Password" autocomplete="off">
<input type="hidden" name="realm" value=""><button type="submit" id="login_button">Login</button>
<p><a href="/remote/login?lang=en">Launch FortiClient</a></p></form></div></body></html>`
}

func fortiError(code int) string {
	return fmt.Sprintf("<html><head><title>%d %s</title></head><body><h1>%s</h1></body></html>", code, http.StatusText(code), http.StatusText(code))
}

// ---- Ivanti Connect Secure ----

func matchIvanti(_ *Session, r *http.Request) bool {
	p := r.URL.Path
	return strings.HasPrefix(p, "/dana-na/") || p == "/dana-na" || strings.HasPrefix(p, "/dana/") || strings.HasPrefix(p, "/dana-cached/") ||
		strings.HasPrefix(p, "/api/v1/totp/") || strings.HasPrefix(p, "/api/v1/configuration/") || strings.HasPrefix(p, "/api/v1/license/")
}

func serveIvanti(s *Session, req *http.Request, _ []byte) lureResp {
	p := req.URL.Path
	hdr := map[string]string{"Server": "", "X-Frame-Options": "SAMEORIGIN", "Cache-Control": "no-store", "Pragma": "no-cache"}
	const welcome = "/dana-na/auth/url_default/welcome.cgi"
	switch {
	case strings.Contains(p, "html5acc/guacamole") && strings.Contains(p, "etc/passwd"):
		// CVE-2019-11510 (Pulse Secure): Dateilesen über den HTML5-Zugang
		lureDelay(500*time.Millisecond, 2*time.Second)
		return lureResp{200, "application/octet-stream", ivantiPasswd, hdr}
	case strings.HasPrefix(p, "/api/v1/totp/user-backup-code/") && strings.Contains(p, ".."):
		// CVE-2023-46805: Umgehung der Anmeldung; CVE-2024-21887: Befehl im Pfad
		lureDelay(1*time.Second, 3*time.Second)
		if i := strings.Index(p, "keys-status/"); i >= 0 {
			if cmd := strings.TrimSpace(p[i+len("keys-status/"):]); cmd != "" {
				s.Command(cmd, map[string]any{"lure": "ivanti", "cve": "CVE-2024-21887"})
			}
			return lureResp{200, ctJSON, `{"status":"ok"}`, hdr}
		}
		if strings.Contains(p, "system/system-information") {
			return lureResp{200, ctJSON, ivantiSysInfo(s.m.Hostname()), hdr}
		}
		return lureResp{200, ctJSON, `{}`, hdr}
	case strings.HasPrefix(p, "/api/v1/"):
		return lureResp{403, ctJSON, `{"code":403,"message":"Forbidden"}`, hdr}
	case p == "/dana-na" || p == "/dana-na/" || p == "/dana-na/auth/" || p == "/dana-na/auth/url_default/":
		hdr["Location"] = welcome
		return lureResp{302, ctHTML, "", hdr}
	case p == welcome:
		hdr["Set-Cookie"] = "DSSIGNIN=url_default; path=/; secure"
		return lureResp{200, ctHTML, ivantiLogin(req.URL.Query().Get("p") == "failed"), hdr}
	case p == "/dana-na/auth/url_default/login.cgi":
		if req.Method == "POST" {
			lureDelay(2*time.Second, 5*time.Second)
		}
		hdr["Location"] = welcome + "?p=failed"
		return lureResp{302, ctHTML, "", hdr}
	case strings.HasPrefix(p, "/dana-cached/") || strings.HasPrefix(p, "/dana-na/css/") || strings.HasPrefix(p, "/dana-na/imgs/"):
		return lureResp{404, ctHTML, ivantiError(404), hdr}
	}
	return lureResp{403, ctHTML, ivantiError(403), hdr}
}

const ivantiPasswd = "root:x:0:0:root:/:/bin/bash\nnfast:x:0:0:nfast:/:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n" +
	"daemon:x:2:2:daemon:/sbin:/sbin/nologin\nnobody:x:99:99:Nobody:/:/sbin/nologin\nnaut:x:500:500:naut:/:/sbin/nologin\n" +
	"postgres:x:102:102:PostgreSQL Server:/var/lib/pgsql:/sbin/nologin\n"

func ivantiSysInfo(host string) string {
	return mustJSON(map[string]any{
		"software-inventory": map[string]any{"software": map[string]string{"build": "1647", "name": "IVE-OS", "type": "operating-system", "version": "22.3R1"}},
		"system-information": map[string]string{"hardware-model": "ISA-V", "host-name": host, "os-name": "ive-sa", "os-version": "22.3R1",
			"serial-number": "0331MBR2X8E1F6Q"},
	})
}

func ivantiLogin(failed bool) string {
	msg := ""
	if failed {
		msg = `<tr><td colspan="2" class="cssSmall" style="color:#c00">Invalid username or password. Please re-enter your user information.</td></tr>`
	}
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Ivanti Connect Secure</title>
<style>body{font-family:Verdana,Arial,sans-serif;font-size:12px;background:#fff;margin:0}#hdr{background:#0d1b2a;color:#fff;padding:14px 20px;font-size:18px}
table{margin:40px 0 0 60px}td{padding:5px}input[type=text],input[type=password]{width:200px}.cssSmall{font-size:11px}</style></head>
<body><div id="hdr">Ivanti Connect Secure</div><form name="frmLogin" method="POST" action="login.cgi" autocomplete="off">
<input type="hidden" name="tz_offset" value=""><input type="hidden" name="realm" value="Users">
<table><tr><td colspan="2"><b>Welcome to Ivanti Connect Secure</b></td></tr>` + msg + `
<tr><td>Username</td><td><input type="text" name="username" size="20"></td></tr>
<tr><td>Password</td><td><input type="password" name="password" size="20"></td></tr>
<tr><td></td><td><input type="submit" name="btnSubmit" value="Sign In"></td></tr></table></form></body></html>`
}

func ivantiError(code int) string {
	return fmt.Sprintf("<html><head><title>%d %s</title></head><body><h2>%s</h2><p>Your request could not be processed.</p></body></html>", code, http.StatusText(code), http.StatusText(code))
}

// ---- Cisco ASA WebVPN ----

func matchCisco(_ *Session, r *http.Request) bool {
	p := r.URL.Path
	return strings.HasPrefix(p, "/+CSCOE+/") || strings.HasPrefix(p, "/+CSCOT+/") || strings.HasPrefix(p, "/+CSCOU+/") || strings.HasPrefix(p, "/+webvpn+/")
}

func serveCisco(_ *Session, req *http.Request, _ []byte) lureResp {
	p := req.URL.Path
	hdr := map[string]string{"Server": "", "Cache-Control": "no-store", "X-Frame-Options": "SAMEORIGIN", "X-XSS-Protection": "1"}
	switch {
	case p == "/+CSCOE+/logon.html":
		hdr["Set-Cookie"] = "webvpnlogin=1; path=/; secure"
		return lureResp{200, ctHTML, ciscoLogin(false), hdr}
	case p == "/+webvpn+/index.html":
		if req.Method == "POST" {
			lureDelay(2*time.Second, 5*time.Second)
			return lureResp{200, ctHTML, ciscoLogin(true), hdr}
		}
		hdr["Location"] = "/+CSCOE+/logon.html"
		return lureResp{302, ctHTML, "", hdr}
	case strings.HasPrefix(p, "/+CSCOT+/") && strings.Contains(req.URL.RawQuery+p, ".."):
		// CVE-2020-3452: Dateien des WebVPN lesen (translation-table, oem-customization)
		lureDelay(500*time.Millisecond, 2*time.Second)
		return lureResp{200, "application/octet-stream", ciscoLua, hdr}
	case strings.HasPrefix(p, "/+CSCOT+/translation-table"):
		return lureResp{200, "application/octet-stream", "msgid \"\"\nmsgstr \"\"\n\"Content-Type: text/plain; charset=UTF-8\\n\"\n", hdr}
	case strings.HasSuffix(p, ".js"):
		return lureResp{200, "application/javascript", "/* webvpn */\n", hdr}
	}
	return lureResp{404, ctHTML, "<html><head><title>404 Not Found</title></head><body><h1>File not found</h1></body></html>", hdr}
}

const ciscoLua = "-- portal_inc.lua\nlocal webvpn = require \"webvpn\"\nlocal ifc = webvpn.get_cookie(\"webvpnLang\") or \"en\"\n" +
	"function lang_redirect() return \"/+CSCOE+/logon.html?\" .. ifc end\n"

func ciscoLogin(failed bool) string {
	msg := ""
	if failed {
		msg = `<tr><td colspan="2" style="color:#c00">Login failed.</td></tr>`
	}
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>SSL VPN Service</title>
<style>body{font-family:Arial,sans-serif;font-size:13px;background:#f3f3f3}.box{width:380px;margin:90px auto;background:#fff;border:1px solid #ccc}
.t{background:#1b4e8f;color:#fff;padding:9px 12px;font-weight:bold}table{margin:14px}td{padding:4px}</style></head>
<body><div class="box"><div class="t">Login</div><form method="post" action="/+webvpn+/index.html" name="unicorn" autocomplete="off">
<table><tr><td colspan="2">Please enter your username and password.</td></tr>` + msg + `
<tr><td>GROUP:</td><td><select name="group_list"><option value="VPN">VPN</option><option value="Remote">Remote</option></select></td></tr>
<tr><td>USERNAME:</td><td><input type="text" name="username"></td></tr>
<tr><td>PASSWORD:</td><td><input type="password" name="password"></td></tr>
<tr><td></td><td><input type="hidden" name="tgroup" value=""><input type="submit" name="Login" value="Login"></td></tr></table></form></div></body></html>`
}

// ---- Hikvision ----

func matchHikvision(s *Session, r *http.Request) bool {
	p := r.URL.Path
	if strings.HasPrefix(p, "/SDK/") || strings.HasPrefix(p, "/ISAPI/") || strings.HasPrefix(p, "/doc/page/") ||
		p == "/Security/users" || strings.HasPrefix(p, "/System/configurationFile") {
		return true
	}
	_, ok := lureRecall(s.SrcIP, "hik:"+p) // Ausgabe eines früheren Exploits (webLib/x)
	return ok
}

// hikCmdRe: Befehl im Feld <language> (CVE-2021-36260), Ausgabe oft nach webLib/<datei>.
var (
	hikLangRe = regexp.MustCompile(`(?is)<language>(.*?)</language>`)
	hikOutRe  = regexp.MustCompile(`>\s*webLib/([A-Za-z0-9._-]{1,32})\s*\)?\s*$`)
)

func serveHikvision(s *Session, req *http.Request, body []byte) lureResp {
	p := req.URL.Path
	hdr := map[string]string{}
	if out, ok := lureRecall(s.SrcIP, "hik:"+p); ok {
		return lureResp{200, ctText, out, hdr}
	}
	switch {
	case p == "/SDK/webLanguage" && (req.Method == "PUT" || req.Method == "POST"):
		m := hikLangRe.FindSubmatch(body)
		if m == nil {
			return lureResp{400, ctXML, hikStatus(4, "Invalid XML Content", "badXmlContent"), hdr}
		}
		inner := html.UnescapeString(strings.TrimSpace(string(m[1])))
		cmd := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(inner, "$("), ")"))
		if strings.HasPrefix(inner, "`") {
			cmd = strings.Trim(inner, "`")
		}
		if inner != "" && (strings.HasPrefix(inner, "$(") || strings.HasPrefix(inner, "`")) {
			s.Command(cmd, map[string]any{"lure": "hikvision", "cve": "CVE-2021-36260"})
			lureDelay(1*time.Second, 3*time.Second)
			// Ausgabe für den nächsten Abruf vorbereiten: Statische Shell, nichts wird ausgeführt
			if o := hikOutRe.FindStringSubmatch(cmd); o != nil {
				line := strings.TrimSpace(cmd[:len(cmd)-len(o[0])])
				out := strings.ReplaceAll(telnetReply(s.m.prof(), s.m.Hostname(), line), "\r\n", "\n")
				if telnetUnknown(strings.ReplaceAll(out, "\n", "\r\n")) {
					out = ""
				}
				lureRemember(s.SrcIP, "hik:/"+o[1], out)
			}
			return lureResp{500, ctXML, hikStatus(6, "Invalid Content", "badParameters"), hdr}
		}
		return lureResp{200, ctXML, hikStatus(1, "OK", "OK"), hdr}
	case p == "/SDK/webLanguage":
		return lureResp{200, ctXML, `<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<Language version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">` + "\n<type>en</type>\n</Language>\n", hdr}
	case p == "/Security/users" || strings.HasPrefix(p, "/System/configurationFile"):
		if req.URL.Query().Get("auth") != "" { // CVE-2017-7921: Zugang per auth=YWRtaW46MTEK
			lureDelay(500*time.Millisecond, 2*time.Second)
			if p == "/Security/users" {
				return lureResp{200, ctXML, hikUsers, hdr}
			}
			return lureResp{200, "application/octet-stream", strings.Repeat("\x00", 16) + "\x8b\x1e\x02\xc4" + randHex(48), hdr}
		}
		return hikUnauthorized(hdr)
	case strings.HasPrefix(p, "/doc/page/"):
		if p == "/doc/page/login.asp" || p == "/doc/page/main.asp" {
			return lureResp{200, ctHTML, hikLogin(s.m.Hostname()), hdr}
		}
		return lureResp{404, ctHTML, errorPage(404, s.m.prof().HTTPServer, p), hdr}
	case strings.HasPrefix(p, "/ISAPI/"):
		if u, _, ok := basicUser(req); ok && u != "" {
			lureDelay(1*time.Second, 3*time.Second)
		}
		return hikUnauthorized(hdr)
	}
	return lureResp{404, ctXML, hikStatus(4, "Invalid Operation", "notSupport"), hdr}
}

func hikUnauthorized(hdr map[string]string) lureResp {
	hdr["WWW-Authenticate"] = `Digest qop="auth", realm="IP Camera(C6421)", nonce="` + randHex(16) + `:` + fmt.Sprint(time.Now().Unix()) + `", stale="FALSE"`
	return lureResp{401, ctXML, `<?xml version="1.0" encoding="UTF-8"?>` + "\n<userCheck>\n<statusValue>401</statusValue>\n<statusString>Unauthorized</statusString>\n</userCheck>\n", hdr}
}

func hikStatus(code int, str, sub string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+"\n"+`<ResponseStatus version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">`+
		"\n<requestURL>/SDK/webLanguage</requestURL>\n<statusCode>%d</statusCode>\n<statusString>%s</statusString>\n<subStatusCode>%s</subStatusCode>\n</ResponseStatus>\n", code, str, sub)
}

const hikUsers = `<?xml version="1.0" encoding="UTF-8"?>
<UserList version="1.0" xmlns="http://www.hikvision.com/ver10/XMLSchema">
<User version="1.0" xmlns="http://www.hikvision.com/ver10/XMLSchema">
<id>1</id>
<userName>admin</userName>
<priority>high</priority>
<ipAddress>0.0.0.0</ipAddress>
<macAddress>00:00:00:00:00:00</macAddress>
<userLevel>Administrator</userLevel>
</User>
</UserList>
`

func hikLogin(host string) string {
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>` + esc(host) + `</title>
<style>body{font-family:Arial,sans-serif;background:#1d1f22;color:#ccc}.login{width:330px;margin:130px auto;background:#2c2f33;padding:26px}
input{width:100%;box-sizing:border-box;margin:6px 0 14px;padding:7px;background:#fff;border:0}button{width:100%;padding:9px;background:#c8102e;color:#fff;border:0}</style></head>
<body><div class="login"><form method="post" action="/ISAPI/Security/sessionLogin" autocomplete="off">
<label>User Name<input name="username"></label><label>Password<input name="password" type="password"></label>
<button type="submit">Login</button></form></div></body></html>`
}

// ---- ONVIF (Kamera) ----

var (
	onvifUserRe = regexp.MustCompile(`(?is)<(?:\w+:)?Username>([^<]{0,128})</`)
	onvifPassRe = regexp.MustCompile(`(?is)<(?:\w+:)?Password[^>]*Type="[^"]*#PasswordText"[^>]*>([^<]{0,128})</`)
)

func serveONVIF(s *Session, req *http.Request, body []byte) lureResp {
	const soap = "application/soap+xml; charset=utf-8"
	hdr := map[string]string{}
	if req.Method != "POST" {
		return lureResp{405, ctHTML, errorPage(405, s.m.prof().HTTPServer, req.URL.Path), hdr}
	}
	b := string(body)
	if u := onvifUserRe.FindStringSubmatch(b); u != nil { // WS-Security: nur Klartext-Passwörter sind ein Login
		if pw := onvifPassRe.FindStringSubmatch(b); pw != nil {
			s.Login(html.UnescapeString(u[1]), html.UnescapeString(pw[1]), map[string]any{"path": pr(req.URL.Path, budgetShort), "lure": "onvif"})
		}
		lureDelay(1*time.Second, 2*time.Second)
	}
	if strings.Contains(b, "GetSystemDateAndTime") {
		t := time.Now().UTC()
		return lureResp{200, soap, onvifEnvelope(fmt.Sprintf(`<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime><tt:DateTimeType>NTP</tt:DateTimeType>`+
			`<tt:DaylightSavings>false</tt:DaylightSavings><tt:TimeZone><tt:TZ>CST-8:00:00</tt:TZ></tt:TimeZone><tt:UTCDateTime><tt:Time><tt:Hour>%d</tt:Hour>`+
			`<tt:Minute>%d</tt:Minute><tt:Second>%d</tt:Second></tt:Time><tt:Date><tt:Year>%d</tt:Year><tt:Month>%d</tt:Month><tt:Day>%d</tt:Day></tt:Date>`+
			`</tt:UTCDateTime></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>`, t.Hour(), t.Minute(), t.Second(), t.Year(), int(t.Month()), t.Day())), hdr}
	}
	return lureResp{400, soap, onvifEnvelope(`<env:Fault><env:Code><env:Value>env:Sender</env:Value><env:Subcode><env:Value>ter:NotAuthorized</env:Value></env:Subcode></env:Code>` +
		`<env:Reason><env:Text xml:lang="en">Sender not Authorized</env:Text></env:Reason></env:Fault>`), hdr}
}

func onvifEnvelope(inner string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:ter="http://www.onvif.org/ver10/error" ` +
		`xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema"><env:Body>` + inner + `</env:Body></env:Envelope>`
}

// ---- Tomcat Manager ----

// tomcatDefaults: Werkspasswörter, die "gelingen". Danach nimmt der Manager WAR-Dateien an:
// Der Angreifer lädt seine Webshell hoch und benutzt sie (alles landet in den Ereignissen).
var tomcatDefaults = map[string]bool{"tomcat:tomcat": true, "tomcat:s3cret": true, "admin:admin": true, "admin:tomcat": true,
	"manager:manager": true, "tomcat:admin": true, "admin:password": true, "role1:role1": true, "both:tomcat": true}

func matchTomcat(s *Session, r *http.Request) bool {
	p := r.URL.Path
	if p == "/manager" || strings.HasPrefix(p, "/manager/") || p == "/host-manager" || strings.HasPrefix(p, "/host-manager/") {
		return true
	}
	_, ok := lureRecall(s.SrcIP, "war:"+tomcatContext(p))
	return ok
}

// tomcatContext: erster Pfadteil ("/shell/cmd.jsp" -> "/shell").
func tomcatContext(p string) string {
	if i := strings.IndexByte(strings.TrimPrefix(p, "/"), '/'); i >= 0 {
		return p[:i+1]
	}
	return p
}

func serveTomcat(s *Session, req *http.Request, body []byte) lureResp {
	p := req.URL.Path
	if java4shell(req, body) {
		return javaCrash()
	}
	if _, ok := lureRecall(s.SrcIP, "war:"+tomcatContext(p)); ok && !strings.HasPrefix(p, "/manager") {
		return tomcatWebshell(s, req, body)
	}
	realm := "Tomcat Manager Application"
	if strings.HasPrefix(p, "/host-manager") {
		realm = "Tomcat Host Manager Application"
	}
	u, pw, hasAuth := basicUser(req)
	if !hasAuth || !tomcatDefaults[u+":"+pw] || strings.HasPrefix(p, "/host-manager") {
		if hasAuth {
			lureDelay(1*time.Second, 3*time.Second) // wie eine Prüfung gegen tomcat-users.xml unter Last
		}
		return lureResp{401, ctHTML, tomcat401(strings.HasPrefix(p, "/host-manager")), map[string]string{"WWW-Authenticate": `Basic realm="` + realm + `"`}}
	}
	ctx := tomcatContextParam(req)
	switch {
	case p == "/manager/text/list":
		return lureResp{200, ctText, tomcatList(s.SrcIP), nil}
	case p == "/manager/text/serverinfo":
		return lureResp{200, ctText, tomcatServerInfo(s.m.prof()), nil}
	case p == "/manager/text/deploy" || p == "/manager/deploy":
		if ctx == "" {
			return lureResp{200, ctText, "FAIL - Invalid context path [] was specified\n", nil}
		}
		s.Command(fmt.Sprintf("tomcat deploy path=%s war=%s size=%d", ctx, req.URL.Query().Get("war"), len(body)), map[string]any{"lure": "tomcat"})
		lureDelay(3*time.Second, 8*time.Second) // Entpacken und Start dauern
		lureRemember(s.SrcIP, "war:"+ctx, "1")
		return lureResp{200, ctText, "OK - Deployed application at context path [" + ctx + "]\n", nil}
	case p == "/manager/text/undeploy":
		return lureResp{200, ctText, "OK - Undeployed application at context path [" + ctx + "]\n", nil}
	case p == "/manager/text/start" || p == "/manager/text/stop" || p == "/manager/text/reload":
		verb := map[string]string{"start": "Started", "stop": "Stopped", "reload": "Reloaded"}[strings.TrimPrefix(p, "/manager/text/")]
		return lureResp{200, ctText, "OK - " + verb + " application at context path [" + ctx + "]\n", nil}
	case strings.HasPrefix(p, "/manager/text/"):
		return lureResp{200, ctText, "FAIL - Unknown command [" + esc(strings.TrimPrefix(p, "/manager/text")) + "]\n", nil}
	case p == "/manager/html/upload" && req.Method == "POST":
		name := "/upload"
		if m := warNameRe.FindSubmatch(body); m != nil {
			name = "/" + string(m[1])
		}
		s.Command(fmt.Sprintf("tomcat deploy path=%s upload size=%d", name, len(body)), map[string]any{"lure": "tomcat"})
		lureDelay(3*time.Second, 8*time.Second)
		lureRemember(s.SrcIP, "war:"+name, "1")
		return lureResp{200, ctHTML, tomcatManagerHTML(s, "OK"), nil}
	case p == "/manager" || p == "/manager/":
		return lureResp{302, ctHTML, "", map[string]string{"Location": "/manager/html"}}
	case strings.HasPrefix(p, "/manager/html") || p == "/manager/status":
		return lureResp{200, ctHTML, tomcatManagerHTML(s, "OK"), map[string]string{"Set-Cookie": "JSESSIONID=" + strings.ToUpper(randHex(16)) + "; Path=/manager; HttpOnly"}}
	}
	return lureResp{404, ctHTML, tomcatError(404, "Not Found", "The requested resource ["+esc(p)+"] is not available"), nil}
}

var warNameRe = regexp.MustCompile(`filename="([A-Za-z0-9._-]{1,64})\.war"`)

func tomcatContextParam(req *http.Request) string {
	c := req.URL.Query().Get("path")
	if c == "" || len(c) > 64 || !strings.HasPrefix(c, "/") || strings.ContainsAny(c, " <>\"'\\") {
		return ""
	}
	return c
}

// tomcatWebshell: Aufruf einer hochgeladenen Anwendung. Der Befehl (cmd=, c=, exec= …) wird
// aufgezeichnet; die Antwort ist leer wie bei einer Webshell, deren Ausgabe nichts liefert.
func tomcatWebshell(s *Session, req *http.Request, body []byte) lureResp {
	vals := req.URL.Query()
	if bv, err := url.ParseQuery(string(body)); err == nil {
		for k, v := range bv {
			vals[k] = v
		}
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch strings.ToLower(k) {
		case "cmd", "c", "command", "exec", "execute", "run", "x", "comment", "pwd":
			if v := vals.Get(k); v != "" {
				s.Command(v, map[string]any{"lure": "tomcat", "webshell": pr(req.URL.Path, budgetShort)})
				lureDelay(1*time.Second, 4*time.Second)
				return lureResp{200, ctHTML, "<pre></pre>\n", nil}
			}
		}
	}
	return lureResp{200, ctHTML, "", map[string]string{"Set-Cookie": "JSESSIONID=" + strings.ToUpper(randHex(16)) + "; Path=" + tomcatContext(req.URL.Path) + "; HttpOnly"}}
}

func tomcatList(ip string) string {
	var b strings.Builder
	b.WriteString("OK - Listed applications for virtual host [localhost]\n/:running:0:ROOT\n/examples:running:0:examples\n/host-manager:running:0:host-manager\n/manager:running:1:manager\n/docs:running:0:docs\n")
	lureMem.Lock()
	var own []string
	for k, e := range lureMem.m {
		if c, ok := strings.CutPrefix(k, ip+"\x00war:"); ok && time.Now().Before(e.until) {
			own = append(own, c)
		}
	}
	lureMem.Unlock()
	sort.Strings(own)
	for _, c := range own {
		b.WriteString(c + ":running:0:" + strings.TrimPrefix(c, "/") + "\n")
	}
	return b.String()
}

func tomcatServerInfo(p deviceProfile) string {
	return "OK - Server info\nTomcat Version: [Apache Tomcat/9.0.83]\nOS Name: [Linux]\nOS Version: [" + p.Kernel + "]\nOS Architecture: [" + p.goArch() +
		"]\nJVM Version: [11.0.21+9-post-Ubuntu-0ubuntu122.04]\nJVM Vendor: [Ubuntu]\n"
}

func tomcatManagerHTML(s *Session, msg string) string {
	var rows strings.Builder
	for _, l := range strings.Split(strings.TrimSpace(tomcatList(s.SrcIP)), "\n")[1:] {
		f := strings.Split(l, ":")
		if len(f) == 4 {
			fmt.Fprintf(&rows, "<tr><td><a href=\"%s/\">%s</a></td><td>%s</td><td>true</td><td>%s</td></tr>\n", esc(f[0]), esc(f[0]), esc(f[3]), esc(f[2]))
		}
	}
	return `<!DOCTYPE html><html><head><title>/manager</title><style>body{font-family:Tahoma,Arial,sans-serif}table{border-collapse:collapse}
td,th{border:1px solid #bbb;padding:3px 8px}th{background:#d2a41c;color:#fff}.title{font-size:20px;font-weight:bold}</style></head>
<body><p class="title">Tomcat Web Application Manager</p><table><tr><td><b>Message:</b></td><td>` + esc(msg) + `</td></tr></table><br>
<table><tr><th>Path</th><th>Display Name</th><th>Running</th><th>Sessions</th></tr>
` + rows.String() + `</table><br>
<form method="post" action="/manager/html/upload" enctype="multipart/form-data"><table><tr><th colspan="2">WAR file to deploy</th></tr>
<tr><td>Select WAR file to upload</td><td><input type="file" name="deployWar"></td></tr><tr><td></td><td><input type="submit" value="Deploy"></td></tr></table></form>
<p>Apache Tomcat/9.0.83</p></body></html>`
}

func tomcat401(host bool) string {
	role, app := "manager-gui", "Manager"
	if host {
		role, app = "admin-gui", "Host Manager"
	}
	return `<!doctype html><html lang="en"><head><title>401 Unauthorized</title><style>body{font-family:Tahoma,Arial,sans-serif}h1{background:#525D76;color:#fff;font-size:22px}</style></head>
<body><h1>401 Unauthorized</h1><p>You are not authorized to view this page. If you have not changed any configuration files, please examine the file
<tt>conf/tomcat-users.xml</tt> in your installation. That file must contain the credentials to let you use this webapp.</p>
<p>For example, to add the <tt>` + role + `</tt> role to a user named <tt>tomcat</tt> with a password of <tt>s3cret</tt>, add the following to the config file listed above.</p>
<pre>&lt;role rolename="` + role + `"/&gt;
&lt;user username="tomcat" password="s3cret" roles="` + role + `"/&gt;</pre>
<p>Note that for Tomcat 7 onwards, the roles required to use the ` + app + ` application were changed.</p></body></html>`
}

func tomcatError(code int, text, desc string) string {
	return fmt.Sprintf(`<!doctype html><html lang="en"><head><title>HTTP Status %d – %s</title><style>body{font-family:Tahoma,Arial,sans-serif}h1{background:#525D76;color:#fff;font-size:22px}</style></head>`+
		`<body><h1>HTTP Status %d – %s</h1><hr class="line" /><p><b>Type</b> Status Report</p><p><b>Description</b> %s</p><hr class="line" /><h3>Apache Tomcat/9.0.83</h3></body></html>`,
		code, text, code, text, desc)
}

// ---- Java-Anwendung: Jira und Keycloak (Köder für Java4Shell) ----

var keycloakRe = regexp.MustCompile(`^(?:/auth)?(/realms/([A-Za-z0-9_-]{1,32})(/.*)?|/admin(/.*)?)$`)

func matchJavaApp(_ *Session, r *http.Request) bool {
	p := r.URL.Path
	return p == "/login.jsp" || strings.HasPrefix(p, "/secure/") || strings.HasPrefix(p, "/rest/") || p == "/jira" || strings.HasPrefix(p, "/jira/") ||
		keycloakRe.MatchString(p)
}

func serveJavaApp(s *Session, req *http.Request, body []byte) lureResp {
	if java4shell(req, body) {
		return javaCrash()
	}
	if m := keycloakRe.FindStringSubmatch(req.URL.Path); m != nil {
		return serveKeycloak(s, req, body, m)
	}
	return serveJira(s, req)
}

func jiraHeaders() map[string]string {
	return map[string]string{"X-AREQUESTID": fmt.Sprintf("%dx%dx1", rand.IntN(1400), rand.IntN(9000000)), "X-Content-Type-Options": "nosniff",
		"X-ASEN": "SEN-L" + fmt.Sprint(10000000+rand.IntN(89999999)), "Cache-Control": "no-cache, no-store, no-transform",
		"Set-Cookie": "JSESSIONID=" + strings.ToUpper(randHex(16)) + "; Path=/; HttpOnly"}
}

func serveJira(s *Session, req *http.Request) lureResp {
	p := strings.TrimPrefix(req.URL.Path, "/jira")
	hdr := jiraHeaders()
	switch {
	case p == "/rest/api/2/serverInfo" || p == "/rest/api/latest/serverInfo":
		return lureResp{200, "application/json;charset=UTF-8", mustJSON(map[string]any{"baseUrl": "http://" + hostFor(s, req), "version": "8.20.10",
			"versionNumbers": []int{8, 20, 10}, "deploymentType": "Server", "buildNumber": 820010, "buildDate": "2022-06-28T00:00:00.000+0000",
			"scmInfo": "b1b5ea2d5c1e8d1bdcb3b3e5e5e5f8a5d34b3c1f", "serverTitle": "Jira"}), hdr}
	case strings.HasPrefix(p, "/rest/auth/1/session") && req.Method == "POST":
		lureDelay(2*time.Second, 4*time.Second)
		return lureResp{401, "application/json;charset=UTF-8", `{"errorMessages":["Login failed"],"errors":{}}`, hdr}
	case strings.HasPrefix(p, "/rest/"):
		if _, _, ok := basicUser(req); ok {
			lureDelay(1*time.Second, 3*time.Second)
			hdr["X-Seraph-LoginReason"] = "AUTHENTICATED_FAILED"
		}
		hdr["WWW-Authenticate"] = `OAuth realm="http%3A%2F%2F` + url.QueryEscape(hostFor(s, req)) + `"`
		return lureResp{401, "application/json;charset=UTF-8", `{"errorMessages":["You are not authenticated. Authentication required to perform this operation."],"errors":{}}`, hdr}
	case p == "/login.jsp" && req.Method == "POST":
		lureDelay(2*time.Second, 5*time.Second)
		hdr["X-Seraph-LoginReason"] = "AUTHENTICATED_FAILED"
		return lureResp{200, ctHTML, jiraLogin(true), hdr}
	case p == "/login.jsp" || p == "/secure/Dashboard.jspa" || p == "" || p == "/":
		return lureResp{200, ctHTML, jiraLogin(false), hdr}
	case strings.HasPrefix(p, "/secure/"):
		hdr["Location"] = "/login.jsp?permissionViolation=true&os_destination=" + url.QueryEscape(clip(p, 200))
		return lureResp{302, ctHTML, "", hdr}
	}
	return lureResp{404, ctHTML, tomcatError(404, "Not Found", "The requested resource is not available"), hdr}
}

func jiraLogin(failed bool) string {
	msg := ""
	if failed {
		msg = `<div class="aui-message error">Sorry, your username and password are incorrect - please try again.</div>`
	}
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Log in - Jira</title><meta name="application-name" content="JIRA" data-name="jira" data-version="8.20.10">
<style>body{font-family:-apple-system,Arial,sans-serif;background:#f4f5f7;color:#172b4d}.box{width:360px;margin:100px auto;background:#fff;padding:28px;border-radius:3px;box-shadow:0 1px 2px rgba(9,30,66,.25)}
input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:7px;margin:4px 0 14px;border:2px solid #dfe1e6;border-radius:3px}
.aui-message.error{color:#bf2600;margin-bottom:12px}button{background:#0052cc;color:#fff;border:0;padding:8px 16px;border-radius:3px}</style></head>
<body><div class="box"><h2>Welcome to Jira</h2>` + msg + `<form id="login-form" method="post" action="/login.jsp">
<label for="login-form-username">Username</label><input type="text" id="login-form-username" name="os_username">
<label for="login-form-password">Password</label><input type="password" id="login-form-password" name="os_password">
<label><input type="checkbox" name="os_cookie" value="true"> Remember my login on this computer</label><br><br>
<input type="hidden" name="atl_token" value="` + strings.ToUpper(randHex(4)) + `-` + randHex(2) + `-` + randHex(2) + `|` + randHex(20) + `|lout">
<button type="submit" id="login-form-submit" name="login">Log In</button></form></div></body></html>`
}

func serveKeycloak(s *Session, req *http.Request, body []byte, m []string) lureResp {
	hdr := map[string]string{"X-Frame-Options": "SAMEORIGIN", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store, must-revalidate, max-age=0"}
	const js = "application/json"
	prefix := ""
	if strings.HasPrefix(req.URL.Path, "/auth/") {
		prefix = "/auth"
	}
	if m[1] == "" { // /admin…
		if rest := m[4]; rest == "" || rest == "/" {
			hdr["Location"] = prefix + "/admin/master/console/"
			return lureResp{302, ctHTML, "", hdr}
		}
		if strings.HasPrefix(m[4], "/master/console") {
			return lureResp{200, ctHTML, keycloakConsole(prefix), hdr}
		}
		if _, _, ok := basicUser(req); ok || req.Header.Get("Authorization") != "" {
			lureDelay(1*time.Second, 2*time.Second)
		}
		return lureResp{401, js, `{"error":"HTTP 401 Unauthorized"}`, hdr}
	}
	realm, rest := m[2], m[3]
	if realm != "master" {
		return lureResp{404, js, `{"error":"Realm does not exist"}`, hdr}
	}
	base := "http://" + hostFor(s, req) + prefix + "/realms/master"
	switch {
	case rest == "" || rest == "/":
		return lureResp{200, js, `{"realm":"master","public_key":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA` + randHex(40) + `","token-service":"` + base + `/protocol/openid-connect","account-service":"` + base + `/account","tokens-not-before":0}`, hdr}
	case rest == "/.well-known/openid-configuration":
		return lureResp{200, js, mustJSON(map[string]any{"issuer": base, "authorization_endpoint": base + "/protocol/openid-connect/auth",
			"token_endpoint": base + "/protocol/openid-connect/token", "userinfo_endpoint": base + "/protocol/openid-connect/userinfo",
			"jwks_uri": base + "/protocol/openid-connect/certs", "grant_types_supported": []string{"authorization_code", "implicit", "refresh_token", "password", "client_credentials"},
			"token_endpoint_auth_methods_supported": []string{"private_key_jwt", "client_secret_basic", "client_secret_post", "client_secret_jwt"}}), hdr}
	case rest == "/protocol/openid-connect/token":
		if req.Method != "POST" {
			return lureResp{405, js, `{"error":"RESTEASY003650: No resource method found for GET, return 405 with Allow header"}`, hdr}
		}
		lureDelay(1*time.Second, 3*time.Second)
		form, _ := url.ParseQuery(string(body)) // der Body ist schon gelesen (serveHTTP)
		if form.Get("grant_type") == "password" {
			return lureResp{401, js, `{"error":"invalid_grant","error_description":"Invalid user credentials"}`, hdr}
		}
		return lureResp{401, js, `{"error":"invalid_client","error_description":"Invalid client or Invalid client credentials"}`, hdr}
	case rest == "/protocol/openid-connect/auth" || rest == "/account" || rest == "/account/":
		hdr["Set-Cookie"] = "AUTH_SESSION_ID=" + randHex(18) + "; Version=1; Path=" + prefix + "/realms/master/; HttpOnly"
		return lureResp{200, ctHTML, keycloakLogin(prefix, false), hdr}
	case strings.HasPrefix(rest, "/login-actions/authenticate"):
		if req.Method == "POST" {
			lureDelay(2*time.Second, 5*time.Second)
		}
		return lureResp{200, ctHTML, keycloakLogin(prefix, true), hdr}
	case rest == "/protocol/openid-connect/certs":
		return lureResp{200, js, `{"keys":[]}`, hdr}
	}
	return lureResp{404, js, `{"error":"Unable to find matching target resource method"}`, hdr}
}

func keycloakLogin(prefix string, failed bool) string {
	msg := ""
	if failed {
		msg = `<div class="alert-error"><span class="kc-feedback-text">Invalid username or password.</span></div>`
	}
	return `<!DOCTYPE html><html class="login-pf"><head><meta charset="utf-8"><meta name="robots" content="noindex, nofollow"><title>Sign in to Keycloak</title>
<style>body{font-family:"Red Hat Text",Arial,sans-serif;background:#1f2a36;color:#151515}#kc-content{width:400px;margin:90px auto;background:#fff;padding:30px 40px;border-top:4px solid #0066cc}
input{width:100%;box-sizing:border-box;padding:7px;margin:4px 0 16px;border:1px solid #bbb}.alert-error{color:#c9190b;margin-bottom:12px}#kc-login{background:#0066cc;color:#fff;border:0;width:100%;padding:9px}</style></head>
<body><div id="kc-header">KEYCLOAK</div><div id="kc-content"><h1 id="kc-page-title">Sign in to your account</h1>` + msg + `
<form id="kc-form-login" action="` + prefix + `/realms/master/login-actions/authenticate?session_code=` + randHex(20) + `&amp;execution=` + randHex(16) + `&amp;client_id=account-console&amp;tab_id=` + randHex(5) + `" method="post">
<label for="username">Username or email</label><input id="username" name="username" type="text" autofocus autocomplete="off">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="off">
<input type="hidden" id="id-hidden-input" name="credentialId"><input name="login" id="kc-login" type="submit" value="Sign In"></form></div></body></html>`
}

func keycloakConsole(prefix string) string {
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Keycloak Administration Console</title></head>
<body><div id="app">Loading the admin console</div><noscript>JavaScript is required to use the Keycloak Administration Console.
<a href="` + prefix + `/realms/master/protocol/openid-connect/auth?client_id=security-admin-console">Sign in</a></noscript></body></html>`
}
