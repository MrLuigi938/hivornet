package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// Doppelt maskierte Antworten: wörtliches \n, \t und \" im HTML werden zu echten Zeichen.
func TestParseWebOutUnescape(t *testing.T) {
	raw := `{"status":200,"content_type":"text/html","body":"<html>\\n<head><title>Login</title></head>\\n\\t<body class=\\\"x\\\">ok</body>\\n</html>"}`
	r, ok := parseWebOut(raw)
	if !ok || r.Out != "<html>\n<head><title>Login</title></head>\n\t<body class=\"x\">ok</body>\n</html>" {
		t.Fatalf("nicht entmaskiert: %v %q", ok, r.Out)
	}
	// echte Zeilenumbrüche vorhanden: \n im Text ist gewollt und bleibt
	raw = `{"status":200,"content_type":"text/html","body":"<pre>\nprintf(\"a\\n\");\n</pre>"}`
	if r, _ := parseWebOut(raw); r.Out != "<pre>\nprintf(\"a\\n\");\n</pre>" {
		t.Errorf("gewolltes \\n verändert: %q", r.Out)
	}
	if got := unescapeBody(`a\\nb\nc`); got != "a\\nb\nc" {
		t.Errorf("Backslash-Folge: %q", got)
	}
	if got := unescapeBody("ohne Folgen"); got != "ohne Folgen" {
		t.Errorf("unverändert erwartet: %q", got)
	}
}

// 404 baut der Honeypot selbst: Das Modell liefert nur den Status, kein eigener Inhalt.
func TestParseWebOut404AndHeaders(t *testing.T) {
	r, ok := parseWebOut(`{"status":404,"content_type":"text/html","body":"<h1>Not Found</h1><hr><center>Apache</center>"}`)
	if !ok || r.Status != 404 || r.Out != "" || r.Headers != nil {
		t.Errorf("404: %v %+v", ok, r)
	}
	if r, ok := parseWebOut(`{"status":404,"content_type":"text/html","body":""}`); !ok || r.Status != 404 {
		t.Errorf("404 mit leerem Inhalt: %v %+v", ok, r)
	}
	r, ok = parseWebOut(`{"status":401,"content_type":"text/html","headers":{"www-authenticate":"Basic realm=\"Tomcat Manager Application\"","Location":"http://203.0.113.7/","Server":"Apache","X-Jenkins":"2.426.3\r\nSet-Cookie: a=b"},"body":"<h1>401</h1>"}`)
	if !ok || r.Status != 401 {
		t.Fatalf("401: %v %+v", ok, r)
	}
	if len(r.Headers) != 1 || r.Headers["WWW-Authenticate"] != `Basic realm="Tomcat Manager Application"` {
		t.Errorf("Kopfzeilen: %+v (nur WWW-Authenticate erlaubt, ohne Zeilenumbruch)", r.Headers)
	}
	if _, ok := parseWebOut(`{"status":200,"content_type":"text/html","body":""}`); ok {
		t.Error("leere 200-Antwort angenommen")
	}
}

func TestWebHints(t *testing.T) {
	for p, want := range map[string]string{
		"/SDK/webLanguage":                         "Hikvision",
		"/ISAPI/Security/userCheck":                "Hikvision",
		"/manager/text/list":                       "Tomcat Manager",
		"/host-manager/html":                       "Tomcat Manager",
		"/remote/fgt_lang":                         "FortiGate",
		"/dana-na/auth/url_default/welcome.cgi":    "Ivanti",
		"/+CSCOE+/logon.html":                      "Cisco ASA",
		"/rest/api/2/serverInfo":                   "Jira",
		"/realms/master/protocol/openid-connect/t": "Keycloak",
		"/auth/realms/master/":                     "Keycloak",
		"/script":                                  "Jenkins",
		"/geoserver/web/":                          "GeoServer",
		"/CFIDE/administrator/index.cfm":           "ColdFusion",
		"/xmlrpc.php":                              "WordPress",
		"/api/index.php/v1/config/application":     "Joomla",
		"/v1.41/containers/json":                   "Docker",
		"/actuator/env":                            "Spring Boot",
	} {
		if h := webHintFor(p); !strings.Contains(h, want) {
			t.Errorf("%s: Hinweis %q, erwartet %s", p, h, want)
		}
	}
	if h := webHintFor("/irgendwas/neues"); h != "" {
		t.Errorf("unbekannter Pfad mit Hinweis: %q", h)
	}
	// Der Hinweis landet in der Anweisung, nicht im Datenteil
	msgs := mimicMessages(mimicReq{Kind: "web", Input: "GET /manager/text/list?x=1 HTTP/1.1\nHost: web01", HTTPServer: "nginx/1.18.0 (Ubuntu)", Host: "web01"}, "abc123")
	if !strings.Contains(msgs[0]["content"], "Tomcat Manager Application") || strings.Contains(msgs[1]["content"], "Tomcat") {
		t.Errorf("Hinweis falsch platziert: %q", msgs[0]["content"])
	}
	if !strings.Contains(msgs[0]["content"], "<<<DATA-abc123>>>") || strings.Contains(msgs[0]["content"], "%!") || !strings.Contains(msgs[0]["content"], "web server") {
		t.Errorf("Anweisung: %q", msgs[0]["content"])
	}
	if !strings.Contains(msgs[0]["content"], `exactly once as \n (never \\n)`) {
		t.Error("Hinweis zur Maskierung fehlt")
	}
}

func TestMimicScannerPath(t *testing.T) {
	for _, p := range []string{"/nmaplowercheck1795074035", "/NmapUpperCheck1700000000", "/nice%20ports%2C/Tri%6Eity.txt%2ebak",
		"/a/1234567890", "/deadbeefcafebabe0123", "/x/aB3xK9qLm2Zp"} {
		if !mimicScannerPath(p) {
			t.Errorf("%s nicht als Scannerpfad erkannt", p)
		}
	}
	for _, p := range []string{"/SDK/webLanguage", "/manager/text/list", "/ISAPI/Streaming/channels/101/picture", "/wp-login.php",
		"/dana-na/auth/url_default/welcome.cgi", "/+CSCOE+/logon.html", "/api/v1/totp/user-backup-code", "/2024/05/index.html", "/HNAP1/"} {
		if mimicScannerPath(p) {
			t.Errorf("%s fälschlich als Scannerpfad erkannt", p)
		}
	}
	if got := webInputPath("GET /a/b?c=d HTTP/1.1\nHost: x"); got != "/a/b" {
		t.Errorf("Pfad: %q", got)
	}
}

// Ende zu Ende: Scannerpfade kosten keinen Modellaufruf, 404 wird gespeichert und nicht neu erfragt,
// doppelt maskierte Antworten kommen sauber an.
func TestMimicWeb404Cached(t *testing.T) {
	h := testHive(t)
	calls := 0
	old := mimicAsk
	t.Cleanup(func() { mimicAsk = old })
	mimicAsk = func(_ context.Context, c AIConfig, msgs []map[string]string) (string, error) {
		calls++
		if strings.Contains(msgs[1]["content"], "/SDK/") {
			return `{"status":200,"content_type":"application/xml","body":"<?xml version=\\\"1.0\\\"?>\\n<Language>\\n<type>en</type>\\n</Language>"}`, nil
		}
		return `{"status":404,"content_type":"text/html","body":"<html><body><h1>404 Not Found</h1><hr><center>Apache/2.4.41</center></body></html>"}`, nil
	}
	x := h.Extras()
	x.AI = AIConfig{BaseURL: "https://openrouter.ai/api/v1", Model: "m", APIKey: "k"}
	x.Mimic = defaultMimic()
	x.Mimic.Enabled = true
	if err := x.Validate(); err != nil {
		t.Fatal(err)
	}
	h.extras.x = x
	ask := func(path string) (int, mimicResp) {
		w := httptest.NewRecorder()
		body, _ := json.Marshal(map[string]string{"kind": "web", "input": "GET " + path + " HTTP/1.1\nHost: web01", "ip": "203.0.113.20", "host": "web01"})
		h.mimic(w, httptest.NewRequest("POST", "/api/sensor/mimic", strings.NewReader(string(body))))
		var r mimicResp
		json.Unmarshal(w.Body.Bytes(), &r)
		return w.Code, r
	}
	if code, r := ask("/nmaplowercheck1795074035"); code != 200 || r.Status != 404 || r.Out != "" || calls != 0 {
		t.Errorf("Scannerpfad: %d %+v, %d Aufrufe", code, r, calls)
	}
	for i := 0; i < 2; i++ {
		if code, r := ask("/gibt/es/nicht.old"); code != 200 || r.Status != 404 || r.Out != "" {
			t.Errorf("404 (%d): %d %+v", i, code, r)
		}
	}
	if calls != 1 {
		t.Errorf("404 nicht gespeichert: %d Aufrufe", calls)
	}
	if _, r := ask("/SDK/webLanguage"); r.Status != 200 || r.Out != "<?xml version=\"1.0\"?>\n<Language>\n<type>en</type>\n</Language>" || r.ContentType != "application/xml" {
		t.Errorf("Hikvision: %+v", r)
	}
}

func TestSensorConfigLures(t *testing.T) {
	for _, v := range []string{"", "all", "off", "tomcat", "tomcat, java-app", "fortinet,ivanti,cisco-asa,hikvision,onvif"} {
		if !validLures(v) {
			t.Errorf("%q abgelehnt", v)
		}
	}
	for _, v := range []string{"quatsch", "tomcat,", "ALL", strings.Repeat("tomcat,", 40)} {
		if validLures(v) {
			t.Errorf("%q angenommen", v)
		}
	}
	c := SensorConfig{Lures: "quatsch", Tarpit: TarpitConfig{IntervalMs: 10000, MaxConns: 10, MaxPerIP: 1}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "Köder") {
		t.Errorf("Validate: %v", err)
	}
	c.Lures = "tomcat"
	if err := c.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}
