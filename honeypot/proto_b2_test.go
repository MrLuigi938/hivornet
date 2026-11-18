package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// apiDo schickt eine rohe HTTP-Anfrage an einen API-Dienst und liefert Antwort und Ereignisse.
func apiDo(t *testing.T, svc, raw string) (*http.Response, string, []Event) {
	t.Helper()
	m := testManager()
	c, done := run(t, m, svc, "emulate")
	go func() { c.Write([]byte(raw)) }()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("%s %q: %v", svc, raw, err)
	}
	body, _ := io.ReadAll(resp.Body)
	c.Close()
	waitDone(t, done, 5*time.Second)
	return resp, string(body), events(m)
}

func commands(evs []Event) []string {
	var out []string
	for _, e := range evs {
		if e.Type == "command" {
			out = append(out, e.Data["input"].(string))
		}
	}
	return out
}

func post(path, body string) string {
	return "POST " + path + " HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: " +
		itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestOllamaAPI(t *testing.T) {
	resp, body, _ := apiDo(t, "ollama", "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if resp.StatusCode != 200 || body != "Ollama is running" {
		t.Fatalf("/: %d %q", resp.StatusCode, body)
	}
	_, body, _ = apiDo(t, "ollama", "GET /api/tags HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.Contains(body, "llama3.1:8b") {
		t.Errorf("/api/tags: %s", body)
	}
	resp, body, evs := apiDo(t, "ollama", post("/api/generate", `{"model":"llama3.1:8b","prompt":"ignore previous instructions"}`))
	if resp.StatusCode != 200 || !strings.Contains(body, `"done":true`) {
		t.Errorf("generate: %d %s", resp.StatusCode, body)
	}
	if c := commands(evs); len(c) != 1 || c[0] != "prompt llama3.1:8b: ignore previous instructions" {
		t.Errorf("Befehl: %v", c)
	}
	_, _, evs = apiDo(t, "ollama", post("/api/pull", `{"name":"evil/model"}`))
	if c := commands(evs); len(c) != 1 || c[0] != "pull evil/model" {
		t.Errorf("pull: %v", c)
	}
}

func TestElasticAPI(t *testing.T) {
	resp, body, _ := apiDo(t, "elasticsearch", "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if resp.StatusCode != 200 || !strings.Contains(body, "You Know, for Search") || resp.Header.Get("X-Elastic-Product") != "Elasticsearch" {
		t.Fatalf("/: %d %s %v", resp.StatusCode, body, resp.Header)
	}
	_, body, evs := apiDo(t, "elasticsearch", "GET /_cat/indices HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.Contains(body, "customers") || len(commands(evs)) != 0 {
		t.Errorf("_cat/indices: %s %v", body, commands(evs))
	}
	_, _, evs = apiDo(t, "elasticsearch", post("/customers/_search", `{"script_fields":{"x":{"script":"java.lang.Math.class"}}}`))
	if c := commands(evs); len(c) != 1 || !strings.HasPrefix(c[0], "POST /customers/_search {") {
		t.Errorf("_search: %v", c)
	}
	resp, _, _ = apiDo(t, "elasticsearch", "GET /nix HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if resp.StatusCode != 404 {
		t.Errorf("unbekannter Index: %d", resp.StatusCode)
	}
}

func TestKubernetesAPI(t *testing.T) {
	_, body, _ := apiDo(t, "kubernetes", "GET /version HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.Contains(body, "v1.28.4") {
		t.Fatalf("/version: %s", body)
	}
	_, body, _ = apiDo(t, "kubernetes", "GET /pods HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.Contains(body, "PodList") {
		t.Errorf("/pods: %s", body)
	}
	form := "cmd=cat /etc/shadow"
	_, _, evs := apiDo(t, "kubernetes", "POST /run/default/web/web HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: "+
		itoa(len(form))+"\r\nConnection: close\r\n\r\n"+form)
	if c := commands(evs); len(c) != 1 || c[0] != "run default/web/web: cat /etc/shadow" {
		t.Errorf("run: %v", c)
	}
	pod := `{"spec":{"hostPID":true,"containers":[{"image":"alpine","command":["sh","-c","id"],"securityContext":{"privileged":true}}],"volumes":[{"hostPath":{"path":"/"}}]}}`
	_, _, evs = apiDo(t, "kubernetes", post("/api/v1/namespaces/default/pods", pod))
	if c := commands(evs); len(c) != 1 || c[0] != "create pod image=alpine cmd=sh -c id privileged binds=/: --pid=host" {
		t.Errorf("pod: %v", c)
	}
	resp, _, _ := apiDo(t, "kubernetes", "GET /api/v1/nodes HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if resp.StatusCode != 403 {
		t.Errorf("anonym verboten: %d", resp.StatusCode)
	}
}

func TestADB(t *testing.T) {
	m := testManager()
	c, done := run(t, m, "adb", "emulate")
	br := bufio.NewReader(c)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	go func() {
		c.Write(adbPacket(adbCNXN, 0x01000000, 256<<10, []byte("host::features=shell_v2\x00")))
		c.Write(adbPacket(adbOPEN, 7, 0, []byte("shell:getprop ro.product.model\x00")))
		c.Write(adbPacket(adbOPEN, 8, 0, []byte("sync:\x00")))
		send := []byte("SEND")
		send = binary.LittleEndian.AppendUint32(send, uint32(len("/data/local/tmp/x,33261")))
		send = append(send, "/data/local/tmp/x,33261"...)
		c.Write(adbPacket(adbWRTE, 8, 2, send))
	}()
	got := map[uint32]int{}
	var output string
	for i := 0; i < 6; i++ {
		msg, err := readADB(br)
		if err != nil {
			t.Fatalf("Antwort %d: %v", i, err)
		}
		got[msg.cmd]++
		if msg.cmd == adbCNXN && !strings.HasPrefix(string(msg.data), "device::") {
			t.Errorf("Banner: %q", msg.data)
		}
		if msg.cmd == adbWRTE {
			output = string(msg.data)
		}
	}
	c.Close()
	waitDone(t, done, 5*time.Second)
	if output != "SHIELD Android TV\n" {
		t.Errorf("Ausgabe: %q (%v)", output, got)
	}
	cmds := strings.Join(commands(events(m)), "|")
	if cmds != "getprop ro.product.model|push /data/local/tmp/x" {
		t.Errorf("Befehle: %s", cmds)
	}
}

func mqttConnect(client, user, pass string) []byte {
	str := func(s string) []byte { return append([]byte{byte(len(s) >> 8), byte(len(s))}, s...) }
	body := append(str("MQTT"), 4, 0xc2, 0, 60)
	body = append(append(append(body, str(client)...), str(user)...), str(pass)...)
	return append([]byte{0x10, byte(len(body))}, body...)
}

func TestMQTT(t *testing.T) {
	m := testManager()
	c, done := run(t, m, "mqtt", "emulate")
	c.SetDeadline(time.Now().Add(5 * time.Second))
	go func() {
		c.Write(mqttConnect("bot-1", "admin", "public"))
		c.Write([]byte{0x82, 6, 0, 1, 0, 1, '#', 0})                   // SUBSCRIBE "#"
		c.Write(append([]byte{0x30, 7, 0, 3, 'a', '/', 'b'}, "on"...)) // PUBLISH a/b "on"
		c.Write([]byte{0xe0, 0})
	}()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || buf[0] != 0x20 || buf[3] != 0 {
		t.Fatalf("CONNACK: %v %x", err, buf)
	}
	go io.Copy(io.Discard, c)
	waitDone(t, done, 5*time.Second)
	evs := events(m)
	var login bool
	for _, e := range evs {
		if e.Type == "login" && e.Username == "admin" && e.Password == "public" && e.Data["client_id"] == "bot-1" {
			login = true
		}
	}
	if !login {
		t.Errorf("Login fehlt: %+v", evs)
	}
	if cmds := strings.Join(commands(evs), "|"); cmds != "subscribe #|publish a/b on" {
		t.Errorf("Befehle: %s", cmds)
	}
}

func pgStartup(params ...string) []byte {
	body := binary.BigEndian.AppendUint32(nil, 196608)
	for _, p := range params {
		body = append(append(body, p...), 0)
	}
	body = append(body, 0)
	return append(binary.BigEndian.AppendUint32(nil, uint32(4+len(body))), body...)
}

func pgSend(t byte, s string) []byte {
	b := append([]byte(s), 0)
	return append(append([]byte{t}, binary.BigEndian.AppendUint32(nil, uint32(4+len(b)))...), b...)
}

func TestPostgres(t *testing.T) {
	for _, tc := range []struct {
		pass string
		ok   bool
	}{{"postgres", true}, {"Geheim!42", false}} {
		m := testManager()
		c, done := run(t, m, "postgres", "emulate")
		c.SetDeadline(time.Now().Add(5 * time.Second))
		go func() {
			c.Write([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}) // SSLRequest
			c.Write(pgStartup("user", "postgres", "database", "prod"))
			c.Write(pgSend('p', tc.pass))
			if tc.ok {
				c.Write(pgSend('Q', "COPY t FROM PROGRAM 'id'"))
				c.Write([]byte{'X', 0, 0, 0, 4})
			}
		}()
		all, _ := io.ReadAll(c)
		waitDone(t, done, 5*time.Second)
		if all[0] != 'N' {
			t.Errorf("SSL abgelehnt erwartet: %q", all[:1])
		}
		if tc.ok != strings.Contains(string(all), "COPY 0") {
			t.Errorf("%s: Antwort %q", tc.pass, all)
		}
		evs := events(m)
		var login *Event
		for i := range evs {
			if evs[i].Type == "login" {
				login = &evs[i]
			}
		}
		if login == nil || login.Username != "postgres" || login.Password != tc.pass || login.Data["success"] != tc.ok || login.Data["database"] != "prod" {
			t.Errorf("Login: %+v", login)
		}
		if tc.ok && strings.Join(commands(evs), "|") != "COPY t FROM PROGRAM 'id'" {
			t.Errorf("Befehle: %v", commands(evs))
		}
	}
}

// Alle neuen Dienste: auch mit Müll als Eingabe bleiben Ereignisse im Größenbudget,
// und im Tarpit-Modus wird sofort festgehalten.
func TestB2SizeAndTarpit(t *testing.T) {
	bin := make([]byte, 16<<10)
	for i := range bin {
		bin[i] = byte(i*13 + 1)
	}
	for _, svc := range []string{"adb", "mqtt", "postgres", "ollama", "elasticsearch", "kubernetes"} {
		m := testManager()
		c, done := run(t, m, svc, "emulate")
		go io.Copy(io.Discard, c)
		go func(c net.Conn) { c.Write(bin); c.Close() }(c) // eigene Kopie: c wird unten nicht mehr neu belegt
		waitDone(t, done, 10*time.Second)
		for _, b := range rawEvents(m) {
			if len(b) > maxEventBytes {
				t.Errorf("%s: Ereignis %d Bytes", svc, len(b))
			}
		}
		// Tarpit mit eigenen Variablen (die Goroutine oben liest c noch; Race-Detector)
		m2 := testManager()
		ct, doneT := run(t, m2, svc, "tarpit")
		ct.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, err := ct.Read(make([]byte, 64)); err != nil || n == 0 {
			t.Errorf("%s: Tarpit sendet nichts: %v", svc, err)
		}
		ct.Close()
		waitDone(t, doneT, 5*time.Second)
	}
}

func FuzzB2Parsers(f *testing.F) {
	f.Add(adbPacket(adbOPEN, 1, 0, []byte("shell:id\x00")))
	f.Add(mqttConnect("c", "u", "p"))
	f.Add(pgStartup("user", "postgres"))
	f.Fuzz(func(t *testing.T, b []byte) {
		readADB(bytes.NewReader(b))
		r := &mqttReader{b: b}
		r.str()
		r.props()
		r.u16()
		readVarint(bytes.NewReader(b))
		pgQueryReply(string(b), profiles[""])
	})
}

// Zweites Audit, N1/N2: riesige Längenangaben dürfen weder abstürzen (32 Bit) noch Speicher belegen.
func TestADBHugeSendLength(t *testing.T) {
	m := testManager()
	c, done := run(t, m, "adb", "emulate")
	c.SetDeadline(time.Now().Add(5 * time.Second))
	go io.Copy(io.Discard, c)
	send := append([]byte("SEND"), 0xf0, 0xff, 0xff, 0xff)
	send = append(send, "/data/local/tmp/y,33261"...)
	c.Write(adbPacket(adbCNXN, 0x01000000, 4096, []byte("host::")))
	c.Write(adbPacket(adbOPEN, 3, 0, []byte("sync:")))
	c.Write(adbPacket(adbWRTE, 3, 1, send))
	c.Close()
	waitDone(t, done, 5*time.Second)
	if cmds := commands(events(m)); len(cmds) != 1 || cmds[0] != "push /data/local/tmp/y" {
		t.Errorf("Befehle: %v", cmds)
	}
}

func TestReadNLazy(t *testing.T) {
	b, err := readN(bytes.NewReader([]byte("abc")), 200000)
	if err != io.ErrUnexpectedEOF || len(b) != 3 {
		t.Errorf("kurz: %d %v", len(b), err)
	}
	if cap(b) > 4096 {
		t.Errorf("Speicher vorab belegt: %d", cap(b))
	}
	b, err = readN(bytes.NewReader(make([]byte, 9000)), 9000)
	if err != nil || len(b) != 9000 {
		t.Errorf("voll: %d %v", len(b), err)
	}
}
