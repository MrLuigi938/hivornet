package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Gleicher Wert wie in hive/bait_test.go: Honeypot und Hive müssen dieselben Köder ableiten.
func TestBaitDerivation(t *testing.T) {
	b := deriveBait("test-token")
	if b.User != baitFixture.User || b.Pass != baitFixture.Pass || b.DBName != baitFixture.DBName || b.APIKey != baitFixture.APIKey {
		t.Fatalf("Ableitung geändert: %+v", b)
	}
	if deriveBait("anderes-token").Pass == b.Pass {
		t.Fatal("Köder nicht je Installation verschieden")
	}
}

var baitFixture = baitCreds{User: "deploy", Pass: "MySW-bzdBq!9Q7vH", DBName: "files", APIKey: "e5e3f2a21d9c9564f958b082a887a34f"}

// httpDo schickt eine rohe Anfrage an den HTTP-Honeypot und liefert die Antwort.
func httpDo(t *testing.T, svc, raw string) (*http.Response, string) {
	t.Helper()
	m := testManager()
	c, done := run(t, m, svc, "emulate")
	go func() { c.Write([]byte(raw)) }()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("%q: %v", raw, err)
	}
	body, _ := io.ReadAll(resp.Body)
	c.Close()
	waitDone(t, done, 5*time.Second)
	return resp, string(body)
}

func TestHTTPBaitFiles(t *testing.T) {
	setBaitSecret("test-token")
	t.Cleanup(func() { setBaitSecret("") })
	b := bait()
	for path, want := range map[string]string{"/.env": "DB_PASSWORD=" + b.Pass, "/.git/config": b.User + ":" + b.Pass + "@", "/robots.txt": "Disallow: /backup/",
		"/backup/": "db-" + b.DBName + ".sql.gz", "/config.php.bak": b.APIKey} {
		resp, body := httpDo(t, "http", "GET "+path+" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		if resp.StatusCode != 200 || !strings.Contains(body, want) {
			t.Errorf("%s: %d %q", path, resp.StatusCode, body)
		}
	}
	if resp, _ := httpDo(t, "http", "GET /gibtsnicht HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); resp.StatusCode != 404 {
		t.Errorf("404 erwartet: %d", resp.StatusCode)
	}
}

// Wie nginx: OPTIONS ergibt 405, Unsinn ergibt 400.
func TestHTTPLikeNginx(t *testing.T) {
	resp, body := httpDo(t, "http", "OPTIONS / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if resp.StatusCode != 405 || !strings.Contains(body, "405 Not Allowed") || resp.Header.Get("Server") != "nginx/1.24.0" {
		t.Errorf("OPTIONS: %d %q", resp.StatusCode, body)
	}
	resp, body = httpDo(t, "http", "HALLO WELT\r\n\r\n")
	if resp.StatusCode != 400 || !strings.Contains(body, "400 Bad Request") || !strings.Contains(body, "nginx/1.24.0") {
		t.Errorf("Unsinn: %d %q", resp.StatusCode, body)
	}
	resp, _ = httpDo(t, "dockerapi", "HALLO WELT\r\n\r\n")
	if resp.StatusCode != 400 {
		t.Errorf("Docker Unsinn: %d", resp.StatusCode)
	}
}

func TestDockerLists(t *testing.T) {
	_, body := httpDo(t, "dockerapi", "GET /v1.43/containers/json HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.Contains(body, "nextcloud") || strings.Contains(body, "backup-job") {
		t.Errorf("Container: %s", body)
	}
	_, body = httpDo(t, "dockerapi", "GET /containers/json?all=1 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.Contains(body, "backup-job") {
		t.Errorf("alle Container: %s", body)
	}
	_, body = httpDo(t, "dockerapi", "GET /images/json HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if strings.Count(body, "RepoTags") != 5 {
		t.Errorf("Images: %s", body)
	}
}

// Die Thread-ID zählt je Verbindung hoch, wie beim echten Server.
func TestMySQLThreadIDCounts(t *testing.T) {
	m := testManager()
	var ids []uint32
	for i := 0; i < 3; i++ {
		c, done := run(t, m, "mysql", "emulate")
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		hdr := make([]byte, 4)
		io.ReadFull(c, hdr)
		p := make([]byte, int(hdr[0])|int(hdr[1])<<8)
		io.ReadFull(c, p)
		ver := strings.IndexByte(string(p[1:]), 0) + 2
		ids = append(ids, binary.LittleEndian.Uint32(p[ver:]))
		c.Close()
		waitDone(t, done, 5*time.Second)
	}
	if ids[1] != ids[0]+1 || ids[2] != ids[1]+1 {
		t.Fatalf("Thread-IDs %v", ids)
	}
}

func TestMySQLNativeMatch(t *testing.T) {
	salt := []byte("abcdefghij0123456789")
	pw := "geheim"
	h1 := sha1.Sum([]byte(pw))
	h2 := sha1.Sum(h1[:])
	x := sha1.Sum(append(append([]byte{}, salt...), h2[:]...))
	auth := make([]byte, 20)
	for i := range auth {
		auth[i] = h1[i] ^ x[i]
	}
	if !mysqlNativeMatch(salt, auth, pw) || mysqlNativeMatch(salt, auth, "falsch") {
		t.Fatal("Prüfung der MySQL-Antwort falsch")
	}
}

func redisSend(t *testing.T, cmds ...string) string {
	t.Helper()
	m := testManager()
	c, done := run(t, m, "redis", "emulate")
	go func() {
		for _, x := range cmds {
			c.Write([]byte(x + "\r\n"))
		}
		c.Write([]byte("QUIT\r\n"))
	}()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, _ := io.ReadAll(c)
	waitDone(t, done, 5*time.Second)
	return string(b)
}

func TestRedisConfigAndInfo(t *testing.T) {
	out := redisSend(t, "CONFIG GET *")
	if !strings.Contains(out, "dbfilename") || !strings.Contains(out, "protected-mode") || strings.HasPrefix(out, "*0") {
		t.Errorf("CONFIG GET *: %q", out[:min(len(out), 200)])
	}
	out = redisSend(t, "CONFIG GET dir")
	if !strings.HasPrefix(out, "*2\r\n$3\r\ndir\r\n") {
		t.Errorf("CONFIG GET dir: %q", out)
	}
	out = redisSend(t, "INFO server")
	if !strings.Contains(out, "redis_version") || strings.Contains(out, "# Keyspace") {
		t.Errorf("INFO server: %q", out)
	}
	out = redisSend(t, "INFO")
	if !strings.Contains(out, "# Keyspace") || !strings.Contains(out, "# Memory") {
		t.Errorf("INFO: %q", out)
	}
}

func TestFTPAnonymousFakeDir(t *testing.T) {
	setBaitSecret("test-token")
	t.Cleanup(func() { setBaitSecret("") })
	m := testManager()
	c, done := run(t, m, "ftp", "emulate")
	readUntil(t, c, "220 ")
	step := func(cmd, want string) {
		c.Write([]byte(cmd + "\r\n"))
		readUntil(t, c, want)
	}
	step("USER anonymous", "331 ")
	step("PASS a@b.c", "230 Login successful.")
	step("PWD", `257 "/"`)
	step("CWD backup", "250 ")
	step("SIZE config.php.bak", "213 912")
	step("PASV", "500 OOPS")
	step("RETR config.php.bak", "425 ")
	step("STOR x.sh", "425 ")
	step("CWD /gibtsnicht", "550 ")
	step("QUIT", "221 ")
	waitDone(t, done, 5*time.Second)
	evs := events(m)
	var cmds []string
	for _, e := range evs {
		if e.Type == "command" {
			cmds = append(cmds, e.Data["input"].(string))
		}
		if e.Type == "login" && e.Data["accepted"] != true {
			t.Errorf("anonymer Login nicht angenommen: %v", e.Data)
		}
	}
	if len(cmds) != 2 || cmds[1] != "STOR x.sh" {
		t.Fatalf("aufgezeichnete Befehle: %v", cmds)
	}
}

func TestBaitLoginFlagged(t *testing.T) {
	setBaitSecret("test-token")
	t.Cleanup(func() { setBaitSecret("") })
	b := bait()
	m := testManager()
	c, done := run(t, m, "ftp", "emulate")
	readUntil(t, c, "220 ")
	c.Write([]byte("USER " + b.User + "\r\nPASS " + b.Pass + "\r\nQUIT\r\n"))
	readUntil(t, c, "221 ")
	waitDone(t, done, 5*time.Second)
	if l := find(events(m), "login"); l == nil || l.Data["bait"] != true || l.Data["accepted"] != true {
		t.Fatalf("Köder-Login: %+v", l)
	}
}

// Ein gewähltes Profil ändert die Kennungen; ohne Profil bleibt alles wie bisher.
func TestDeviceProfile(t *testing.T) {
	m := testManager()
	c := DefaultConfig()
	if p := m.prof(); p.HTTPServer != "nginx/1.24.0" {
		t.Fatalf("ohne Profil: %q", p.HTTPServer)
	}
	c.Profile = "router"
	m.Apply(c)
	defer m.StopAll()
	if p := m.prof(); p.HTTPServer != "lighttpd/1.4.59" || p.SSHBanner != "SSH-2.0-dropbear_2019.78" {
		t.Fatalf("Profil router: %+v", p)
	}
	c.Profile = "gibtsnicht"
	if w := c.Normalize(0); len(w) == 0 || c.Profile != "" {
		t.Fatal("unbekanntes Profil nicht verworfen")
	}
}
