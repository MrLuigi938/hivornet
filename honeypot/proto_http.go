package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	maxHTTPHeader = 64 << 10 // Anfragezeile + Kopfzeilen
	maxHTTPBody   = 64 << 10 // gelesener Body; mehr wird nicht gepuffert
	httpBudgetHdr = 1536     // Kopfzeilen im Ereignis
	httpBudgetBdy = 1536     // Body im Ereignis
)

func handleHTTP(s *Session)      { serveHTTP(s, false) }
func handleDockerAPI(s *Session) { serveHTTP(s, true) }

func handleHTTPS(s *Session) {
	tc := s.m.tlsConf.Load()
	if tc == nil {
		return
	}
	conn := tls.Server(s.Conn, tc)
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.Handshake(); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	if st := conn.ConnectionState(); st.ServerName != "" {
		s.Emit(Event{Type: "tls", Data: map[string]any{"sni": printable([]byte(st.ServerName), budgetShort)}})
	}
	s.Conn = conn
	serveHTTP(s, false)
}

func httpTarpit(s *Session) {
	s.Tarpit([]byte("HTTP/1.1 200 OK\r\n"), func() []byte {
		return []byte("X-" + randWord(4, 10) + ": " + randWord(8, 24) + "\r\n")
	})
}

func pr(s string, n int) string { return printable([]byte(s), n) }

func serveHTTP(s *Session, docker bool) {
	// tarpit: sofort festhalten, ohne auf eine Anfrage zu warten
	if s.Mode == "tarpit" {
		httpTarpit(s)
		return
	}
	cr := &capReader{r: s.Conn}
	br := bufio.NewReaderSize(cr, 4096)
	for i := 0; i < 20; i++ {
		s.ReadDeadline(30 * time.Second)
		cr.n = maxHTTPHeader // Budget für Anfragezeile und Kopf, pro Anfrage neu
		req, err := http.ReadRequest(br)
		if err != nil {
			if i == 0 && err != io.EOF {
				// kein gültiges HTTP: rohe Bytes festhalten, soweit noch im Puffer
				if n := br.Buffered(); n > 0 {
					b, _ := br.Peek(min(n, 4096))
					s.Emit(Event{Type: "payload", Data: map[string]any{"text": printable(b, budgetText)}})
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
		if len(body) > 0 {
			info["body"] = printable(body, httpBudgetBdy)
		}
		if req.ContentLength > maxHTTPBody || len(body) >= maxHTTPBody {
			info["body_truncated"] = true
		}
		s.Emit(Event{Type: "request", Data: info})

		if user, pass, ok := extractCreds(req, body); ok {
			s.Login(user, pass, map[string]any{"path": pr(req.URL.Path, budgetShort)})
		}
		if docker {
			if cmd := dockerCommand(req, body); cmd != "" {
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
		if docker {
			status, ctype, out, extra = dockerResponse(s, req)
		} else {
			status, ctype, out, extra = webResponse(s, req)
		}
		if writeHTTP(s, req.Method, status, ctype, out, extra, docker, closeAfter) != nil || closeAfter {
			return
		}
	}
}

func writeHTTP(s *Session, method string, status int, ctype, body string, extra map[string]string, docker, closing bool) error {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	if docker {
		b.WriteString("Server: Docker/24.0.7 (linux)\r\nApi-Version: 1.43\r\nOstype: linux\r\n")
	} else {
		b.WriteString("Server: nginx/1.24.0\r\n")
	}
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(http.TimeFormat))
	noBody := status == 204 || status == 304 || (status >= 100 && status < 200)
	if !noBody {
		fmt.Fprintf(&b, "Content-Type: %s\r\nContent-Length: %d\r\n", ctype, len(body))
	}
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
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

var userKeys = []string{"username", "user", "login", "log", "email", "uname", "usr", "name", "account"}
var passKeys = []string{"password", "pass", "pwd", "passwd", "pw", "secret"}

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

func webResponse(s *Session, req *http.Request) (int, string, string, map[string]string) {
	path := req.URL.Path
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
	return 404, "text/html", "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx/1.24.0</center>\r\n</body>\r\n</html>\r\n", nil
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
	switch {
	case p == "/_ping":
		return 200, "text/plain; charset=utf-8", "OK", nil
	case p == "/version":
		return 200, js, mustJSON(map[string]any{
			"Platform": map[string]string{"Name": "Docker Engine - Community"}, "Version": "24.0.7", "ApiVersion": "1.43",
			"MinAPIVersion": "1.12", "GitCommit": "311b9ff", "GoVersion": "go1.20.10", "Os": "linux", "Arch": "amd64",
			"KernelVersion": "5.15.0-91-generic", "BuildTime": "2023-10-26T09:08:02.000000000+00:00",
		}), nil
	case p == "/info":
		return 200, js, mustJSON(map[string]any{
			"ID": strings.ToUpper(randHex(16)), "Containers": 3, "ContainersRunning": 2, "ContainersPaused": 0,
			"ContainersStopped": 1, "Images": 5, "Driver": "overlay2", "Name": s.m.Hostname(),
			"OperatingSystem": "Ubuntu 22.04.3 LTS", "OSType": "linux", "Architecture": "x86_64", "NCPU": 4,
			"MemTotal": int64(8232407040), "ServerVersion": "24.0.7", "KernelVersion": "5.15.0-91-generic",
		}), nil
	case p == "/containers/json" || p == "/images/json" || p == "/volumes":
		return 200, js, "[]", nil
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
