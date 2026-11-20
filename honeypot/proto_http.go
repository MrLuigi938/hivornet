package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	// Speicher je Verbindung (M4 des dritten Audits): vorher 64 + 64 KB; mit 48 Verbindungen je
	// IP reichten 15 bis 25 Adressen für das Speicherlimit. nginx erlaubt 8 KB je Kopfzeile.
	maxHTTPHeader = 16 << 10 // Anfragezeile + Kopfzeilen
	maxHTTPBody   = 32 << 10 // gelesener Body; mehr wird nicht gepuffert
	httpBudgetHdr = 1536     // Kopfzeilen im Ereignis
	httpBudgetBdy = 1536     // Body im Ereignis
)

func handleHTTP(s *Session)      { serveHTTP(s, nil) }
func handleDockerAPI(s *Session) { serveHTTP(s, dockerAPI) }

func handleHTTPS(s *Session) {
	if upgradeTLS(s, s.Conn) {
		serveHTTP(s, nil)
	}
}

// upgradeTLS führt den TLS-Handshake als Server, meldet ClientHello und SNI (für JA3/JA4
// im Hive) und ersetzt s.Conn durch die verschlüsselte Verbindung. src liefert die Bytes
// (s.Conn oder ein Puffer, der schon hineingeschaut hat). false: kein TLS möglich.
func upgradeTLS(s *Session, src io.Reader) bool {
	tc := s.m.tlsConf.Load()
	if tc == nil {
		return false
	}
	// ClientHello vor dem Handshake mitlesen (für JA3/JA4 im Hive), dann normal weiter
	s.ReadDeadline(10 * time.Second)
	br := bufio.NewReaderSize(src, tlsHelloMax)
	hello := peekClientHello(br)
	conn := tls.Server(&readerConn{Conn: s.Conn, r: br}, tc)
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	err := conn.Handshake()
	data := map[string]any{}
	if len(hello) > 0 {
		data["client_hello"] = hex.EncodeToString(hello)
	}
	if st := conn.ConnectionState(); st.ServerName != "" {
		data["sni"] = printable([]byte(st.ServerName), budgetShort)
	}
	if len(data) > 0 {
		s.Emit(Event{Type: "tls", Data: data})
	}
	if err != nil {
		return false
	}
	conn.SetDeadline(time.Time{})
	s.Conn = conn
	return true
}

// readerConn liest aus einem vorgeschalteten Puffer (der den ClientHello schon kennt).
type readerConn struct {
	net.Conn
	r io.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// peekClientHello liefert den ersten TLS-Record (Handshake), ohne ihn zu verbrauchen;
// höchstens tlsHelloMax Bytes.
func peekClientHello(br *bufio.Reader) []byte {
	h, err := br.Peek(5)
	if err != nil || h[0] != 0x16 || h[1] != 3 {
		return nil
	}
	n := min(5+(int(h[3])<<8|int(h[4])), tlsHelloMax)
	b, _ := br.Peek(n)
	return append([]byte(nil), b...)
}

// headerOrder: Namen der Kopfzeilen in der gesendeten Reihenfolge (aus dem Puffer, bevor
// http.ReadRequest sie in eine Map sortiert). Leer, wenn der Kopf nicht ganz im Puffer liegt.
func headerOrder(br *bufio.Reader) string {
	if _, err := br.Peek(1); err != nil {
		return ""
	}
	b, _ := br.Peek(br.Buffered())
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end < 0 {
		return ""
	}
	var names []string
	for i, line := range bytes.Split(b[:end], []byte("\r\n")) {
		if i == 0 {
			continue
		}
		if k, _, ok := bytes.Cut(line, []byte(":")); ok && len(names) < 40 {
			names = append(names, string(k))
		}
	}
	return pr(strings.Join(names, ","), 512)
}

func httpTarpit(s *Session) {
	s.Tarpit([]byte("HTTP/1.1 200 OK\r\n"), func() []byte {
		return []byte("X-" + randWord(4, 10) + ": " + randWord(8, 24) + "\r\n")
	})
}

func pr(s string, n int) string { return printable([]byte(s), n) }

// serveHTTP spielt einen Webserver (api == nil) oder eine HTTP-API nach (Docker, Ollama,
// Elasticsearch, Kubernetes; proto_api.go).
func serveHTTP(s *Session, api *httpAPI) {
	// tarpit: sofort festhalten, ohne auf eine Anfrage zu warten
	if s.Mode == "tarpit" {
		httpTarpit(s)
		return
	}
	cr := &capReader{r: s.Conn}
	br := bufio.NewReaderSize(cr, 4096)
	for i := 0; i < 20; i++ {
		s.ReadDeadline(30 * time.Second)
		cr.n = maxHTTPHeader          // Budget für Anfragezeile und Kopf, pro Anfrage neu
		if i == 0 && s.sniffTLS(br) { // HTTPS-Client am HTTP-Port
			return
		}
		order := headerOrder(br)
		req, err := http.ReadRequest(br)
		if err != nil {
			if err != io.EOF && !errors.Is(err, io.ErrUnexpectedEOF) && !isTimeout(err) {
				// kein gültiges HTTP: rohe Bytes festhalten, soweit noch im Puffer, und wie
				// nginx (bzw. Docker) mit 400 antworten statt still aufzulegen
				if n := br.Buffered(); i == 0 && n > 0 {
					b, _ := br.Peek(min(n, 4096))
					s.Emit(Event{Type: "payload", Data: map[string]any{"text": printable(b, budgetText)}})
				}
				if api != nil {
					s.WriteString("HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request")
				} else {
					writeHTTP(s, "GET", 400, "text/html", errorPage(400, s.m.prof().HTTPServer, ""), nil, nil, true)
				}
			}
			return
		}
		// Body begrenzt lesen; Body.Close() absichtlich NICHT aufrufen (es liest bis zum Ende).
		cr.n = maxHTTPBody + 4096
		body, _ := io.ReadAll(io.LimitReader(req.Body, maxHTTPBody))
		closeAfter := req.Close || req.ProtoMinor == 0 || req.ContentLength > maxHTTPBody
		if one := make([]byte, 1); !closeAfter {
			if n, _ := req.Body.Read(one); n > 0 { // Body länger als gelesen
				closeAfter = true
			}
		}

		info := map[string]any{
			"method":     pr(req.Method, 16),
			"path":       pr(req.URL.RequestURI(), budgetPath),
			"host":       pr(req.Host, budgetShort),
			"user_agent": pr(req.UserAgent(), budgetShort),
			"version":    pr(req.Proto, 16),
		}
		keys := make([]string, 0, len(req.Header))
		for k := range req.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var hdr strings.Builder
		for _, k := range keys {
			hdr.WriteString(k + ": " + strings.Join(req.Header[k], ", ") + "\n")
		}
		info["headers"] = pr(strings.TrimSuffix(hdr.String(), "\n"), httpBudgetHdr)
		if order != "" {
			info["header_order"] = order
		}
		if len(body) > 0 {
			info["body"] = printable(body, httpBudgetBdy)
		}
		if req.ContentLength > maxHTTPBody || len(body) >= maxHTTPBody {
			info["body_truncated"] = true
		}
		var lr *lure // Köder für ein bekanntes Produkt (lures.go)
		if api == nil {
			if lr = s.lureFor(req); lr != nil {
				info["lure"] = lr.name
			}
		}
		s.Emit(Event{Type: "request", Data: info})

		if user, pass, ok := extractCreds(req, body); ok {
			s.Login(user, pass, map[string]any{"path": pr(req.URL.Path, budgetShort)})
		}
		if api != nil && api.command != nil {
			if cmd := api.command(req, body); cmd != "" {
				s.Command(cmd, map[string]any{"path": pr(req.URL.Path, budgetShort)})
			}
		}

		// hybrid: Anfrage ist aufgezeichnet, jetzt festhalten
		if s.Mode == "hybrid" {
			httpTarpit(s)
			return
		}

		var status int
		var ctype, out string
		var extra map[string]string
		switch {
		case api != nil:
			status, ctype, out, extra = api.respond(s, req)
		case lr != nil:
			r := lr.serve(s, req, body)
			status, ctype, out, extra = r.status, r.ctype, r.body, r.hdr
		default:
			status, ctype, out, extra = webResponse(s, req)
		}
		if writeHTTP(s, req.Method, status, ctype, out, extra, api, closeAfter) != nil || closeAfter {
			return
		}
	}
}

// hasCtl: Steuerzeichen außer Tab. In Kopfzeilen nie erlaubt, CR/LF hängt sonst Zeilen an.
func hasCtl(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return true
		}
	}
	return false
}

func writeHTTP(s *Session, method string, status int, ctype, body string, extra map[string]string, api *httpAPI, closing bool) error {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	if api != nil {
		if api.headers != nil {
			b.WriteString(api.headers(s))
		}
	} else {
		sv := s.m.prof().HTTPServer
		if v, ok := extra["Server"]; ok { // Köder eines Geräts mit eigener Kennung ("" = keine)
			sv = v
		}
		if sv != "" {
			b.WriteString("Server: " + sv + "\r\n")
		}
	}
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(http.TimeFormat))
	noBody := status == 204 || status == 304 || (status >= 100 && status < 200)
	if !noBody {
		fmt.Fprintf(&b, "Content-Type: %s\r\nContent-Length: %d\r\n", ctype, len(body))
	}
	keys := make([]string, 0, len(extra))
	for k := range extra {
		if k != "Server" || api != nil {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		// Audit 4: Werte aus Angreiferdaten (Pfade, Parameter) dürfen keine Kopfzeile anhängen.
		if hasCtl(k) || hasCtl(extra[k]) {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, extra[k])
	}
	if closing {
		b.WriteString("Connection: close\r\n\r\n")
	} else {
		b.WriteString("Connection: keep-alive\r\n\r\n")
	}
	if !noBody && method != "HEAD" {
		b.WriteString(body)
	}
	return s.WriteString(b.String())
}

// Feldnamen der Anmeldeformulare, auch der Köder (lures.go): FortiGate "credential",
// Java-Anwendungen "j_password" und "os_password" (Jira). Die eigenen Namen der Java-Formulare
// stehen vorn: Jira schickt daneben auch "login=Log In".
var userKeys = []string{"j_username", "os_username", "username", "user", "login", "log", "email", "uname", "usr", "name", "account"}
var passKeys = []string{"j_password", "os_password", "password", "pass", "pwd", "passwd", "pw", "secret", "credential"}

func pick(vals url.Values, keys []string) (string, bool) {
	for _, k := range keys {
		for vk, vv := range vals {
			if strings.EqualFold(vk, k) && len(vv) > 0 {
				return vv[0], true
			}
		}
	}
	return "", false
}

func extractCreds(req *http.Request, body []byte) (string, string, bool) {
	if a := req.Header.Get("Authorization"); len(a) > 6 && strings.EqualFold(a[:6], "basic ") {
		if dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(a[6:])); err == nil {
			u, p, _ := strings.Cut(string(dec), ":")
			return u, p, true
		}
	}
	vals := req.URL.Query()
	ct := strings.ToLower(req.Header.Get("Content-Type"))
	switch {
	case strings.Contains(ct, "application/json"):
		var m map[string]any
		if json.Unmarshal(body, &m) == nil {
			for k, v := range m {
				if s, ok := v.(string); ok {
					vals.Set(k, s)
				}
			}
		}
	case len(body) > 0:
		if bv, err := url.ParseQuery(string(body)); err == nil {
			for k, v := range bv {
				vals[k] = v
			}
		}
	}
	p, okp := pick(vals, passKeys)
	if !okp {
		return "", "", false
	}
	u, _ := pick(vals, userKeys)
	return u, p, true
}

// ---- normale Webseiten ----

var loginPaths = map[string]string{
	"/": "", "/login": "", "/login.html": "", "/admin": "", "/admin/": "", "/index.php": "",
	"/wp-login.php": "WordPress", "/wp-admin": "WordPress", "/wp-admin/": "WordPress",
	"/phpmyadmin": "phpMyAdmin", "/phpmyadmin/": "phpMyAdmin", "/pma/": "phpMyAdmin",
	"/cgi-bin/luci": "LuCI", "/webui": "", "/user/login": "",
}

// errorPage: Fehlerseite im Stil des Webservers aus dem Geräteprofil (lighttpd und Boa
// sehen anders aus als nginx; eine nginx-Seite unter "Server: lighttpd" verrät den Honeypot).
func errorPage(code int, server, path string) string {
	t := fmt.Sprintf("%d %s", code, http.StatusText(code))
	switch {
	case strings.HasPrefix(server, "lighttpd"):
		return "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n" +
			"         \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n" +
			" <head>\n  <title>" + t + "</title>\n </head>\n <body>\n  <h1>" + t + "</h1>\n </body>\n</html>\n"
	case strings.HasPrefix(server, "Boa"):
		msg := ""
		switch code {
		case 400:
			msg = "Your client has issued a malformed or illegal request.\n"
		case 404:
			msg = "The requested URL " + html.EscapeString(clip(path, 256)) + " was not found on this server.\n"
		}
		return "<HTML><HEAD><TITLE>" + t + "</TITLE></HEAD>\n<BODY><H1>" + t + "</H1>\n" + msg + "</BODY></HTML>\n"
	}
	if code == 405 {
		t = "405 Not Allowed"
	}
	return "<html>\r\n<head><title>" + t + "</title></head>\r\n<body>\r\n<center><h1>" + t + "</h1></center>\r\n<hr><center>" + server + "</center>\r\n</body>\r\n</html>\r\n"
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func webResponse(s *Session, req *http.Request) (int, string, string, map[string]string) {
	path := req.URL.Path
	if path == "" { // Anfrage in absoluter Form ohne Schrägstrich ("GET http://host HTTP/1.1"): Startseite
		path = "/"
	}
	switch req.Method {
	case "GET", "HEAD", "POST":
	default: // nginx liefert statische Seiten nur für GET/HEAD; alles andere: 405
		return 405, "text/html", errorPage(405, s.m.prof().HTTPServer, path), nil
	}
	if ctype, body, ok := baitFile(path, s.m.Hostname()); ok && req.Method != "POST" {
		return 200, ctype, body, nil
	}
	if strings.HasPrefix(path, "/manager/html") || strings.HasPrefix(path, "/host-manager") {
		if req.Header.Get("Authorization") == "" {
			return 401, "text/html", "<h1>401 Unauthorized</h1>", map[string]string{"WWW-Authenticate": `Basic realm="Tomcat Manager Application"`}
		}
		return 403, "text/html", "<h1>403 Access Denied</h1>", nil
	}
	if product, ok := loginPaths[path]; ok {
		failed := req.Method == "POST"
		return 200, "text/html; charset=utf-8", loginPage(s.m.Hostname(), product, path, failed), nil
	}
	if status, ctype, body, hdr, ok := s.mimicWeb(req); ok { // unbekannter Pfad: ggf. vom Sprachmodell (mimic.go)
		return status, ctype, body, hdr
	}
	return 404, "text/html", errorPage(404, s.m.prof().HTTPServer, path), nil
}

func loginPage(host, product, action string, failed bool) string {
	title := host + " – Anmeldung"
	if product != "" {
		title = product + " – " + host
	}
	msg := ""
	if failed {
		msg = `<p class="err">Benutzername oder Passwort ist falsch.</p>`
	}
	return `<!DOCTYPE html><html lang="de"><head><meta charset="utf-8"><title>` + html.EscapeString(title) + `</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:Arial,sans-serif;background:#eef1f4;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
form{background:#fff;padding:32px 36px;border-radius:6px;box-shadow:0 2px 10px rgba(0,0,0,.12);width:300px}
h1{font-size:18px;margin:0 0 20px;color:#333}input{width:100%;box-sizing:border-box;padding:9px;margin:6px 0 14px;border:1px solid #c8ccd0;border-radius:4px}
button{width:100%;padding:10px;background:#2f6db5;color:#fff;border:0;border-radius:4px;cursor:pointer}.err{color:#b00020;font-size:13px}</style></head>
<body><form method="post" action="` + html.EscapeString(action) + `"><h1>` + html.EscapeString(title) + `</h1>` + msg + `
<label>Benutzername<input name="username" autocomplete="username"></label>
<label>Passwort<input name="password" type="password" autocomplete="current-password"></label>
<button type="submit">Anmelden</button></form></body></html>`
}

// ---- Docker-API ----

var dockerVersionPrefix = regexp.MustCompile(`^/v[0-9]+\.[0-9]+`)

func dockerPath(req *http.Request) string {
	return dockerVersionPrefix.ReplaceAllString(req.URL.Path, "")
}

func dockerCommand(req *http.Request, body []byte) string {
	p := dockerPath(req)
	switch {
	case req.Method == "POST" && p == "/containers/create":
		var c struct {
			Image      string
			Cmd        any
			Entrypoint any
			HostConfig struct {
				Binds      []string
				Privileged bool
			}
		}
		json.Unmarshal(body, &c)
		parts := []string{"create image=" + c.Image}
		if c.Entrypoint != nil {
			parts = append(parts, "entrypoint="+joinAny(c.Entrypoint))
		}
		if c.Cmd != nil {
			parts = append(parts, "cmd="+joinAny(c.Cmd))
		}
		if len(c.HostConfig.Binds) > 0 {
			parts = append(parts, "binds="+strings.Join(c.HostConfig.Binds, ","))
		}
		if c.HostConfig.Privileged {
			parts = append(parts, "privileged")
		}
		return strings.Join(parts, " ")
	case req.Method == "POST" && strings.HasSuffix(p, "/exec") && strings.HasPrefix(p, "/containers/"):
		var c struct{ Cmd any }
		json.Unmarshal(body, &c)
		return "exec " + joinAny(c.Cmd)
	case req.Method == "POST" && p == "/images/create":
		return "pull " + req.URL.Query().Get("fromImage") + ":" + req.URL.Query().Get("tag")
	}
	return ""
}

// Schein-Container und -Images: drei Container (zwei laufen), fünf Images, wie /info meldet.
// IDs sind je Prozessstart fest, damit wiederholte Abfragen zusammenpassen.
var dockerIDs = func() []string {
	ids := make([]string, 8)
	for i := range ids {
		ids[i] = randHex(32)
	}
	return ids
}()

func dockerContainers(all bool) string {
	created := time.Now().Add(-time.Duration(redisUptime) * time.Second).Unix()
	type c struct {
		Id, Image, Command, State, Status string
		Names                             []string
		Created                           int64
		Ports                             []map[string]any
	}
	list := []c{
		{dockerIDs[0], "nextcloud:27-apache", "/entrypoint.sh apache2-foreground", "running", fmt.Sprintf("Up %d days", redisUptime/86400), []string{"/nextcloud"}, created,
			[]map[string]any{{"PrivatePort": 80, "PublicPort": 8081, "Type": "tcp", "IP": "0.0.0.0"}}},
		{dockerIDs[1], "mariadb:10.11", "docker-entrypoint.sh mariadbd", "running", fmt.Sprintf("Up %d days", redisUptime/86400), []string{"/nextcloud-db"}, created,
			[]map[string]any{{"PrivatePort": 3306, "Type": "tcp"}}},
	}
	if all {
		list = append(list, c{dockerIDs[2], "restic/restic:0.16.2", "restic backup /data", "exited", "Exited (0) 9 hours ago", []string{"/backup-job"}, created, []map[string]any{}})
	}
	return mustJSON(list)
}

func dockerImages() string {
	var out []map[string]any
	for i, t := range []string{"nextcloud:27-apache", "mariadb:10.11", "restic/restic:0.16.2", "redis:6.2-alpine", "alpine:3.18"} {
		out = append(out, map[string]any{"Id": "sha256:" + dockerIDs[3+i%5] + dockerIDs[(4+i)%8], "RepoTags": []string{t},
			"Created": time.Now().AddDate(0, -2-i, 0).Unix(), "Size": 50_000_000 + i*37_000_000})
	}
	return mustJSON(out)
}

func joinAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		var s []string
		for _, x := range t {
			s = append(s, fmt.Sprint(x))
		}
		return strings.Join(s, " ")
	}
	return fmt.Sprint(v)
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func dockerResponse(s *Session, req *http.Request) (int, string, string, map[string]string) {
	const js = "application/json"
	p := dockerPath(req)
	pr := s.m.prof()
	db := pr.docker()
	switch {
	case p == "/_ping":
		return 200, "text/plain; charset=utf-8", "OK", nil
	case p == "/version":
		return 200, js, mustJSON(map[string]any{
			"Platform": map[string]string{"Name": "Docker Engine - Community"}, "Version": pr.DockerVer, "ApiVersion": db.API,
			"MinAPIVersion": db.MinAPI, "GitCommit": db.Commit, "GoVersion": db.Go, "Os": "linux", "Arch": pr.goArch(),
			"KernelVersion": pr.Kernel, "BuildTime": db.Built,
		}), nil
	case p == "/info":
		return 200, js, mustJSON(map[string]any{
			"ID": strings.ToUpper(randHex(16)), "Containers": 3, "ContainersRunning": 2, "ContainersPaused": 0,
			"ContainersStopped": 1, "Images": 5, "Driver": "overlay2", "Name": s.m.Hostname(),
			"OperatingSystem": pr.OSName, "OSType": "linux", "Architecture": pr.Arch, "NCPU": pr.nCPU(),
			"MemTotal": pr.MemTotal, "ServerVersion": pr.DockerVer, "KernelVersion": pr.Kernel,
		}), nil
	case p == "/containers/json":
		return 200, js, dockerContainers(req.URL.Query().Get("all") == "1" || req.URL.Query().Get("all") == "true"), nil
	case p == "/images/json":
		return 200, js, dockerImages(), nil
	case p == "/volumes":
		return 200, js, `{"Volumes":[{"Driver":"local","Name":"nextcloud_db","Mountpoint":"/var/lib/docker/volumes/nextcloud_db/_data","Scope":"local"}],"Warnings":null}`, nil
	case p == "/networks":
		return 200, js, "[]", nil
	case req.Method == "POST" && p == "/containers/create":
		return 201, js, mustJSON(map[string]any{"Id": randHex(32), "Warnings": []string{}}), nil
	case req.Method == "POST" && strings.HasPrefix(p, "/containers/") && strings.HasSuffix(p, "/exec"):
		return 201, js, mustJSON(map[string]string{"Id": randHex(32)}), nil
	case req.Method == "POST" && strings.HasSuffix(p, "/wait"):
		return 200, js, `{"StatusCode":0}`, nil
	case req.Method == "POST" && (strings.HasSuffix(p, "/start") || strings.HasSuffix(p, "/attach")):
		return 204, js, "", nil
	case req.Method == "POST" && p == "/images/create":
		img := clip(req.URL.Query().Get("fromImage"), 128)
		return 200, js, mustJSON(map[string]string{"status": "Pulling from library/" + img}) + "\r\n" +
			mustJSON(map[string]string{"status": "Status: Downloaded newer image for " + img}), nil
	}
	return 404, js, `{"message":"page not found"}`, nil
}
