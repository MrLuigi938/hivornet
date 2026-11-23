package main

// Web-Antworten des Sprachmodells (Ergänzung zu mimic.go): feste Produkthinweise je Pfadfamilie,
// Erkennung von Zufalls- und Scannerpfaden, Aufbereitung der Antwort (doppelt maskierte
// Zeilenumbrüche, erlaubte Kopfzeilen, einheitliche 404).
//
// Die Auswertung der letzten Antworten zeigte: fast alles waren 404-Seiten, oft im falschen Stil,
// und gerade die Produktpfade (Hikvision /SDK/webLanguage, Tomcat /manager/text/list) wirkten
// nicht echt. Deshalb:
//   - Der Hive gibt dem Modell für bekannte Pfadfamilien einen kurzen, festen Hinweis, welches
//     Produkt dort antwortet und wie (webHints). Das Modell muss weniger raten.
//   - 404 baut nie das Modell: Es meldet nur den Status, der Honeypot liefert seine eigene Seite
//     im Stil des Profil-Webservers. Die Entscheidung landet im Zwischenspeicher.
//   - Zufalls- und Scannerpfade (/nmaplowercheck1795074035) gehen gar nicht ans Modell.

import (
	"regexp"
	"strings"
)

// webHint: Produkt hinter einer Pfadfamilie und wie es typischerweise antwortet. Die Texte
// stehen in der Anweisung an das Modell (vertrauenswürdig), nie im Datenteil.
type webHint struct {
	re   *regexp.Regexp
	hint string
}

func hint(expr, text string) webHint { return webHint{regexp.MustCompile(`(?i)` + expr), text} }

// webHints: erste Übereinstimmung gilt. Pfad ohne Query.
var webHints = []webHint{
	hint(`^/(SDK|ISAPI|PSIA|doc/page|Security|System/configurationFile|onvif-http)(/|$)`,
		`Hikvision IP camera/NVR web server. Answers are XML (content_type application/xml) with <?xml version="1.0" encoding="UTF-8"?> and the namespace http://www.hikvision.com/ver20/XMLSchema. /SDK/webLanguage returns a short <Language> XML with <type>en</type>. /ISAPI/* without credentials answers 401 with header WWW-Authenticate: Digest realm="DS-2CD2143G2-I", qop="auth", nonce="<hex>" and an XML <userCheck><statusValue>401</statusValue><statusString>Unauthorized</statusString></userCheck>. /doc/page/login.asp is an HTML login page with username and password fields.`),
	hint(`^/(manager|host-manager)(/|$)`,
		`Apache Tomcat 9 Manager. Every path below /manager/ and /host-manager/ without valid credentials answers 401 with header WWW-Authenticate: Basic realm="Tomcat Manager Application" (host-manager: realm="Tomcat Host Manager Application") and Tomcat's short HTML page titled "401 Unauthorized" that explains the manager-gui and manager-script roles in conf/tomcat-users.xml. /manager/text/* would answer text/plain starting with "OK - " or "FAIL - ".`),
	hint(`^/remote/`,
		`Fortinet FortiGate SSL-VPN portal. /remote/login is an HTML login page (fields username and credential, posted to /remote/logincheck). /remote/fgt_lang?lang=en returns JavaScript "var fgt_lang = {...};" with UI strings (content_type application/javascript is not allowed, use text/plain). /remote/logincheck answers text/plain "ret=0,redir=/remote/login?&err=sslvpn_login_permission_denied&lang=en".`),
	hint(`^/(dana-na|dana|dana-cached|dana-ws)(/|$)|^/api/v1/(totp|configuration|license)`,
		`Ivanti Connect Secure (formerly Pulse Secure) VPN appliance. /dana-na/auth/url_default/welcome.cgi is an HTML sign-in page (fields username, password, hidden realm "Users", posted to /dana-na/auth/url_default/login.cgi). Protected paths answer 403 with a short HTML page. /api/v1/* answers JSON, without a session 403 {"code":403,"message":"Forbidden"}.`),
	hint(`^/(\+CSCOE\+|\+CSCOT\+|\+CSCOU\+|\+webvpn\+|CSCOE)`,
		`Cisco ASA / AnyConnect WebVPN portal. /+CSCOE+/logon.html is an HTML login page titled "SSL VPN Service" with fields username, password and a group_list select, posted to /+webvpn+/index.html. Other /+CSCOE+/ files return small JavaScript or HTML; unknown files return 404.`),
	hint(`^/(login\.jsp|secure/|rest/api/|rest/auth/|plugins/servlet/|jira/|s/|browse/)`,
		`Atlassian Jira Server 8 (Java, behind the web server). HTML pages carry a JSESSIONID cookie (header Set-Cookie) and the login form posts os_username and os_password to /login.jsp. /rest/api/2/serverInfo answers JSON with baseUrl, version "8.20.10", deploymentType "Server", serverTitle. Other REST calls without login answer 401 JSON {"errorMessages":["You are not authenticated. Authentication required to perform this operation."],"errors":{}}.`),
	hint(`^/(auth/)?(realms|admin/realms|admin/master|resources)/`,
		`Keycloak 21 identity server (Java). /realms/<realm>/protocol/openid-connect/auth is an HTML login page (fields username and password). /realms/<realm>/.well-known/openid-configuration answers JSON. Token endpoint errors are JSON like {"error":"invalid_client","error_description":"Invalid client or Invalid client credentials"}. Unknown realms answer 404 JSON {"error":"Realm does not exist"}.`),
	hint(`^/(jenkins|script|scriptText|computer|asynchPeople|manage|j_acegi_security_check|j_spring_security_check|cli|descriptorByName)(/|$)`,
		`Jenkins 2.4xx (Java, Jetty). Responses carry headers X-Jenkins: 2.426.3 and X-Hudson: 1.395. Without login protected paths answer 403 with an HTML page "Authentication required" and a link to /login; the login form posts j_username and j_password to /j_spring_security_check.`),
	hint(`^/geoserver(/|$)`,
		`GeoServer 2.23 (Java). /geoserver/web/ is an HTML admin page; OGC endpoints (/geoserver/ows, /wfs, /wms) answer XML; without a service parameter they answer an ows:ExceptionReport XML with exceptionCode="MissingParameterValue".`),
	hint(`^/(CFIDE|cf_scripts|cfide)(/|$)|\.cf[mc]$`,
		`Adobe ColdFusion 2021 on IIS-like setups. /CFIDE/administrator/index.cfm is an HTML login page (field cfadminPassword). Unknown .cfm/.cfc files answer 404 with a short ColdFusion error page.`),
	hint(`^/(wp-|xmlrpc\.php|wp-json)`,
		`WordPress 6.x on PHP. /xmlrpc.php with GET answers 405 text/plain "XML-RPC server accepts POST requests only.". /wp-json/ answers JSON. Missing wp-content files answer 404.`),
	hint(`^/(administrator|api/index\.php)(/|$)`,
		`Joomla 4 on PHP. /administrator/ is an HTML login page. /api/index.php/v1/* without a token answers 401 JSON:API {"errors":[{"title":"Forbidden"}]}.`),
	hint(`^/(v1\.\d+/)?(containers|images|_ping|version|info|exec|swarm|services)(/|$)`,
		`Docker Engine API. Answers are JSON (content_type application/json); errors look like {"message":"page not found"}.`),
	hint(`^/actuator(/|$)`,
		`Spring Boot 2.7 actuator (Java). /actuator answers JSON with _links; /actuator/health {"status":"UP"}; sensitive endpoints (env, heapdump, gateway) answer 404 JSON with timestamp, status, error and path.`),
	hint(`^/solr(/|$)`,
		`Apache Solr 8. /solr/ is the HTML admin UI; /solr/admin/* answers JSON with a responseHeader object.`),
	hint(`^/(mgmt/tm|mgmt/shared|tmui)(/|$)`,
		`F5 BIG-IP. /mgmt/* without credentials answers 401 JSON {"code":401,"message":"Authorization failed: no user authentication header or token detected.","errorStack":[],"apiError":3} with header WWW-Authenticate: Basic realm="Enterprise Manager". /tmui/login.jsp is an HTML login page.`),
	hint(`^/(vpn|logon/LogonPoint|citrix|nf/auth)(/|$)`,
		`Citrix NetScaler Gateway. /logon/LogonPoint/index.html is the HTML login page; /vpn/index.html redirects users there with an HTML page.`),
	hint(`^/(global-protect|ssl-vpn|php/)`,
		`Palo Alto Networks GlobalProtect portal. /global-protect/login.esp is an HTML login page (fields user and passwd).`),
	hint(`^/(owa|ecp|autodiscover|ews|mapi|rpc)(/|$)`,
		`Microsoft Exchange Outlook Web App. /owa/ shows an HTML sign-in page (fields username and password, posted to /owa/auth.owa); /ews and /autodiscover answer 401 with header WWW-Authenticate: Basic realm="mail".`),
	hint(`^/(console|wls-wsat|_async)(/|$)`,
		`Oracle WebLogic Server 12c (Java). /console/login/LoginForm.jsp is an HTML login page (fields j_username, j_password).`),
	hint(`^/(HNAP1|hnap1)(/|$)`,
		`D-Link router HNAP SOAP service. Answers are text/xml SOAP envelopes; GET /HNAP1/ returns a DeviceSettings response with ModelName and FirmwareVersion.`),
	hint(`^/(cgi-bin|boaform|goform|GponForm)(/|$)`,
		`Embedded router/camera CGI. Existing CGIs answer short HTML or plain text with a login requirement; anything unknown is a 404.`),
	hint(`^/(phpunit|vendor)(/|$)|/eval-stdin\.php`,
		`PHP application files. vendor/ folders are not reachable: answer 404.`),
}

// webHintFor: Hinweis für einen Pfad ("" = keiner).
func webHintFor(p string) string {
	for _, h := range webHints {
		if h.re.MatchString(p) {
			return h.hint
		}
	}
	return ""
}

// scannerPathRe: typische Prüfpfade von Scannern (nmap, Nikto, Masscan …), lange Zahlen- oder
// Hexfolgen und Segmente, die wie zufällige Kennungen aussehen. Die gleiche Regel steht im
// Honeypot (honeypot/mimic.go), der Hive prüft noch einmal für ältere Sensoren.
var scannerPathRe = regexp.MustCompile(`(?i)nmap(lower|upper)check|nice%20ports|trinity\.txt|[0-9]{8,}|[0-9a-f]{16,}`)

// mimicScannerPath: Pfad (ohne Query) ist Zufall eines Scanners, nie etwas für das Modell.
func mimicScannerPath(p string) bool {
	if scannerPathRe.MatchString(p) {
		return true
	}
	for _, seg := range strings.Split(p, "/") {
		if randomSegment(seg) {
			return true
		}
	}
	return false
}

// randomSegment: mindestens 10 Zeichen nur aus Buchstaben und Ziffern, mit Groß- und
// Kleinbuchstaben und mehreren Ziffern ("aB3xK9qLm2"). Echte Pfade sehen fast nie so aus.
func randomSegment(seg string) bool {
	if len(seg) < 10 {
		return false
	}
	up, low, dig := 0, 0, 0
	for _, r := range seg {
		switch {
		case r >= 'A' && r <= 'Z':
			up++
		case r >= 'a' && r <= 'z':
			low++
		case r >= '0' && r <= '9':
			dig++
		default:
			return false
		}
	}
	return up > 0 && low > 0 && dig >= 2
}

// webInputPath: Pfad ohne Query aus der Eingabe "GET /pfad?x HTTP/1.1\nHost: …".
func webInputPath(input string) string {
	line, _, _ := strings.Cut(input, "\n")
	f := strings.Fields(line)
	if len(f) < 2 {
		return ""
	}
	p, _, _ := strings.Cut(f[1], "?")
	return p
}

// unescapeBody: Manche Modelle maskieren im JSON-Feld body doppelt; nach dem Dekodieren stehen
// dann wörtlich \n, \t und \" im HTML. Entmaskiert wird, wenn kein echter Zeilenumbruch
// vorkommt oder die wörtlichen \n deutlich überwiegen (gemischte Antworten mancher Modelle);
// ein einzelnes "\n" neben echten Umbrüchen ist gewollter Text, etwa in einem Skript.
func unescapeBody(s string) string {
	if !strings.Contains(s, `\n`) && !strings.Contains(s, `\t`) && !strings.Contains(s, `\"`) {
		return s
	}
	lit, real := strings.Count(s, `\n`), strings.Count(s, "\n")+strings.Count(s, "\r")
	if real > 0 && lit <= real*2 {
		return s
	}
	return bodyUnescaper.Replace(s)
}

var bodyUnescaper = strings.NewReplacer(`\\`, `\`, `\r\n`, "\n", `\n`, "\n", `\r`, "\n", `\t`, "\t", `\"`, `"`, `\/`, `/`)

// webHeaderAllow: Kopfzeilen, die das Modell setzen darf (typisch für Produkte, ohne Wirkung
// auf andere Hosts). Server, Location, Refresh, CSP und Längenangaben setzt nur der Honeypot.
var webHeaderAllow = map[string]string{
	"www-authenticate": "WWW-Authenticate", "set-cookie": "Set-Cookie", "x-powered-by": "X-Powered-By",
	"x-frame-options": "X-Frame-Options", "cache-control": "Cache-Control", "x-content-type-options": "X-Content-Type-Options",
	"x-jenkins": "X-Jenkins", "x-hudson": "X-Hudson", "x-aspnet-version": "X-AspNet-Version", "x-arequestid": "X-AREQUESTID",
	"x-ausername": "X-AUSERNAME", "pragma": "Pragma", "expires": "Expires", "x-xss-protection": "X-XSS-Protection",
}

// safeWebHeaders: nur erlaubte Namen, Werte als druckbares ASCII ohne Zeilenumbruch, höchstens 8.
func safeWebHeaders(in map[string]string) map[string]string {
	var out map[string]string
	for k, v := range in {
		name, ok := webHeaderAllow[strings.ToLower(strings.TrimSpace(k))]
		v = strings.TrimSpace(v)
		if !ok || v == "" || len(v) > 256 || strings.IndexFunc(v, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0 {
			continue
		}
		if name == "Set-Cookie" {
			if v = safeSetCookie(v); v == "" {
				continue
			}
		}
		if out == nil {
			out = map[string]string{}
		}
		if len(out) >= 8 {
			break
		}
		out[name] = v
	}
	return out
}

// Cookie des Modells: nur "Name=Wert", neu zusammengesetzt mit Path=/ und HttpOnly. Ohne Domain-
// Angabe und nie mit dem Namen des Sitzungs-Cookies der Web-UI (hv_session) oder einem
// __Host-/__Secure-Präfix: Cookies trennen nicht nach Port, ein Modell-Cookie auf demselben
// Host könnte sonst die Anmeldung an der Hive-UI überdecken oder abmelden.
var (
	cookieNameRe  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	cookieValueRe = regexp.MustCompile(`^[A-Za-z0-9!#$%&'()*+./:<=>?@\[\]^_{|}~-]{0,180}$`)
)

func safeSetCookie(v string) string {
	pair, _, _ := strings.Cut(v, ";")
	name, val, ok := strings.Cut(strings.TrimSpace(pair), "=")
	name, val = strings.TrimSpace(name), strings.TrimSpace(val)
	low := strings.ToLower(name)
	if !ok || !cookieNameRe.MatchString(name) || !cookieValueRe.MatchString(val) || low == cookieName ||
		strings.HasPrefix(low, "__host-") || strings.HasPrefix(low, "__secure-") {
		return ""
	}
	return name + "=" + val + "; Path=/; HttpOnly"
}
