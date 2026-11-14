package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// Tests für die Protokolle Telnet, SMTP, VNC und RDP sowie das Dienste-Register.

// readUntil liest vom Client-Ende, bis want im Gelesenen vorkommt.
func readUntil(t *testing.T, c net.Conn, want string) string {
	t.Helper()
	var got []byte
	buf := make([]byte, 512)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for !bytes.Contains(got, []byte(want)) {
		n, err := c.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			t.Fatalf("warte auf %q, bekam %q (%v)", want, got, err)
		}
	}
	return string(got)
}

func find(evs []Event, typ string) *Event {
	for i := range evs {
		if evs[i].Type == typ {
			return &evs[i]
		}
	}
	return nil
}

func TestTelnetLoginAndShell(t *testing.T) {
	m := testManager()
	c, done := run(t, m, "telnet", "emulate")
	readUntil(t, c, "login: ")
	c.Write([]byte{255, 253, 1}) // IAC DO ECHO muss ignoriert werden
	c.Write([]byte("root\r\n"))
	readUntil(t, c, "Password: ")
	c.Write([]byte("xc3511\r\n"))
	readUntil(t, c, "# ")
	c.Write([]byte("/bin/busybox MIRAI\r\n"))
	readUntil(t, c, "MIRAI: applet not found")
	c.Close()
	waitDone(t, done, 5*time.Second)
	evs := events(m)
	if l := find(evs, "login"); l == nil || l.Username != "root" || l.Password != "xc3511" {
		t.Fatalf("Login falsch: %+v", l)
	}
	if cmd := find(evs, "command"); cmd == nil || cmd.Data["input"] != "/bin/busybox MIRAI" {
		t.Fatalf("Befehl falsch: %+v", cmd)
	}
}

func TestTelnetReadLineLimit(t *testing.T) {
	br := bufio.NewReader(strings.NewReader(strings.Repeat("a", 5000) + "\n"))
	if _, err := telnetReadLine(br, 1024); err != errLineTooLong {
		t.Fatalf("erwartet errLineTooLong, bekam %v", err)
	}
	br = bufio.NewReader(bytes.NewReader([]byte{255, 250, 31, 0, 80, 0, 24, 255, 240, 'o', 'k', '\r', 0, 'x', '\n'}))
	if l, _ := telnetReadLine(br, 64); l != "ok" {
		t.Fatalf("Subnegotiation nicht entfernt: %q", l)
	}
	if l, _ := telnetReadLine(br, 64); l != "x" {
		t.Fatalf("zweite Zeile: %q", l)
	}
}

func TestSMTPAuthAndMail(t *testing.T) {
	m := testManager()
	c, done := run(t, m, "smtp", "emulate")
	readUntil(t, c, "220 ")
	c.Write([]byte("EHLO bot\r\n"))
	readUntil(t, c, "250 8BITMIME\r\n")
	c.Write([]byte("AUTH LOGIN\r\n"))
	readUntil(t, c, "334 ")
	c.Write([]byte("aW5mbw==\r\n")) // info
	readUntil(t, c, "334 ")
	c.Write([]byte("Z2VoZWlt\r\n")) // geheim
	readUntil(t, c, "535 ")
	c.Write([]byte("AUTH PLAIN AHVzZXIAcGFzcw==\r\n")) // \0user\0pass
	readUntil(t, c, "535 ")
	c.Write([]byte("MAIL FROM:<a@example.com>\r\n"))
	readUntil(t, c, "250 ")
	c.Write([]byte("DATA\r\n"))
	readUntil(t, c, "354 ")
	c.Write([]byte("Subject: Test\r\n\r\nHallo\r\n.\r\n"))
	readUntil(t, c, "queued as")
	c.Write([]byte("QUIT\r\n"))
	readUntil(t, c, "221 ")
	waitDone(t, done, 5*time.Second)
	evs := events(m)
	var logins []string
	for _, e := range evs {
		if e.Type == "login" {
			logins = append(logins, e.Username+"/"+e.Password)
		}
	}
	if strings.Join(logins, ",") != "info/geheim,user/pass" {
		t.Fatalf("Logins: %v", logins)
	}
	if p := find(evs, "payload"); p == nil || !strings.Contains(p.Data["text"].(string), "Subject: Test") || p.Data["mail"] != true {
		t.Fatalf("Mail nicht aufgezeichnet: %+v", p)
	}
}

func TestSMTPDataLimit(t *testing.T) {
	big := strings.Repeat(strings.Repeat("x", 998)+"\r\n", 200) // 200 KB ohne Endezeile
	head, total, ok := smtpReadData(bufio.NewReader(strings.NewReader(big)), 4096)
	if ok || len(head) != 4096 || total > smtpMaxData+4096 {
		t.Fatalf("ok=%v head=%d total=%d", ok, len(head), total)
	}
}

func TestVNCAuth(t *testing.T) {
	m := testManager()
	c, done := run(t, m, "vnc", "emulate")
	readUntil(t, c, "RFB 003.008\n")
	c.Write([]byte("RFB 003.008\n"))
	buf := make([]byte, 2)
	io.ReadFull(c, buf)
	if buf[0] != 1 || buf[1] != 2 {
		t.Fatalf("Sicherheitstypen: %v", buf)
	}
	c.Write([]byte{2})
	ch := make([]byte, 16)
	io.ReadFull(c, ch)
	c.Write(bytes.Repeat([]byte{0xab}, 16))
	res := make([]byte, 4)
	io.ReadFull(c, res)
	if binary.BigEndian.Uint32(res) != 1 {
		t.Fatalf("SecurityResult: %v", res)
	}
	go io.Copy(io.Discard, c)
	waitDone(t, done, 5*time.Second)
	evs := events(m)
	l := find(evs, "login")
	if l == nil || l.Data["response"] != strings.Repeat("ab", 16) || l.Data["password_hashed"] != true || len(l.Data["challenge"].(string)) != 32 {
		t.Fatalf("VNC-Login: %+v", l)
	}
	if v := find(evs, "client_version"); v == nil || v.Data["version"] != "RFB 003.008" {
		t.Fatalf("Version: %+v", v)
	}
}

func rdpCR(cookie string, protocols int) []byte {
	x := []byte{0, 0xe0, 0, 0, 0, 0, 0}
	if cookie != "" {
		x = append(x, "Cookie: mstshash="+cookie+"\r\n"...)
	}
	if protocols >= 0 {
		x = append(x, 1, 0, 8, 0)
		x = binary.LittleEndian.AppendUint32(x, uint32(protocols))
	}
	x[0] = byte(len(x) - 1)
	out := []byte{3, 0, 0, 0}
	binary.BigEndian.PutUint16(out[2:], uint16(len(x)+4))
	return append(out, x...)
}

func TestParseRDPRequest(t *testing.T) {
	r, ok := parseRDPRequest(rdpCR("admin", 3)[4:])
	if !ok || r.Cookie != "admin" || !r.HasNeg || r.Protocols != 3 {
		t.Fatalf("falsch geparst: %+v", r)
	}
	if rdpProtoNames(3) != "TLS+NLA" || rdpProtoNames(0) != "RDP" {
		t.Fatal("Protokollnamen falsch")
	}
	if _, ok := parseRDPRequest([]byte("GET / HTTP/1.1\r\n")); ok {
		t.Fatal("HTTP darf nicht als RDP gelten")
	}
	if c := rdpConfirm(true, 1); len(c) != 19 || c[3] != 19 || c[4] != 14 || c[15] != 1 {
		t.Fatalf("Connection Confirm falsch: %v", c)
	}
}

func TestRDPClientInfo(t *testing.T) {
	core := []byte{0x01, 0xc0, 0xd8, 0x00}
	core = append(core, 4, 0, 8, 0, 0, 4, 0, 3, 1, 0xca, 3, 0xaa) // Version, Breite, Höhe, Farbtiefe, SAS
	core = binary.LittleEndian.AppendUint32(core, 0x0409)
	core = binary.LittleEndian.AppendUint32(core, 2600)
	name := make([]byte, 32)
	for i, c := range utf16.Encode([]rune("KALI-BOX")) {
		binary.LittleEndian.PutUint16(name[i*2:], c)
	}
	core = append(core, name...)
	p := append([]byte("xxxxDuca\x00\x00"), core...)
	n, build, layout, ok := rdpClientInfo(p)
	if !ok || n != "KALI-BOX" || build != 2600 || layout != 0x409 {
		t.Fatalf("%q %d %x %v", n, build, layout, ok)
	}
	if _, _, _, ok := rdpClientInfo(p[:30]); ok {
		t.Fatal("zu kurzer Block darf nicht gelten")
	}
}

func TestRDPCookieLogin(t *testing.T) {
	m := testManager()
	c, done := run(t, m, "rdp", "emulate")
	go c.Write(rdpCR("Administr", -1))
	cc := make([]byte, 11)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, cc); err != nil || cc[5] != 0xd0 {
		t.Fatalf("Connection Confirm: %v %v", cc, err)
	}
	c.Close()
	waitDone(t, done, 5*time.Second)
	if l := find(events(m), "login"); l == nil || l.Username != "Administr" || l.Data["cookie"] != true {
		t.Fatalf("RDP-Login: %+v", l)
	}
}

// Jedes neue Protokoll muss das Größenbudget auch bei Binärmüll einhalten.
func TestNewProtocolsSizeBudget(t *testing.T) {
	bin := make([]byte, 16<<10)
	for i := range bin {
		bin[i] = byte(i*7 + 3)
	}
	for _, svc := range []string{"telnet", "smtp", "vnc", "rdp"} {
		m := testManager()
		c, done := run(t, m, svc, "emulate")
		go io.Copy(io.Discard, c)
		go func() { c.Write(bin); c.Close() }()
		waitDone(t, done, 10*time.Second)
		for _, b := range rawEvents(m) {
			var e struct{ Data json.RawMessage }
			json.Unmarshal(b, &e)
			if len(b) > maxEventBytes || len(e.Data) > hiveDataLimit {
				t.Errorf("%s: Ereignis %d Bytes, data %d Bytes", svc, len(b), len(e.Data))
			}
		}
	}
}

// Die Dienste stehen im Honeypot (handlers), im Hive (sensors.go) und in der UI
// (app.js, Liste SERVICES). Dieser Test schlägt fehl, wenn ein neuer Dienst irgendwo fehlt.
func TestServiceListsInSync(t *testing.T) {
	for _, f := range []string{"../hive/sensors.go", "../hive/web/app.js"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Skipf("%s nicht lesbar (Build ohne Hive-Quellen): %v", f, err)
		}
		for name := range handlers {
			if !bytes.Contains(b, []byte(`"`+name+`"`)) {
				t.Errorf("Dienst %q fehlt in %s", name, f)
			}
		}
	}
	for _, l := range DefaultConfig().Listeners {
		if handlers[l.Service] == nil {
			t.Errorf("Standardkonfiguration nennt unbekannten Dienst %q", l.Service)
		}
	}
}

func FuzzTelnetReadLine(f *testing.F) {
	f.Add([]byte("root\r\n\xff\xfb\x01admin\r\x00"))
	f.Add([]byte{255, 250, 1, 2, 255, 240, 'a', '\n'})
	f.Fuzz(func(t *testing.T, b []byte) {
		br := bufio.NewReaderSize(bytes.NewReader(b), 16)
		for i := 0; i < 8; i++ {
			l, err := telnetReadLine(br, 64)
			if err != nil {
				return
			}
			if len(l) > 64 {
				t.Fatalf("Zeile länger als erlaubt: %d", len(l))
			}
			telnetReply(l)
		}
	})
}

func FuzzRDP(f *testing.F) {
	f.Add(rdpCR("admin", 3)[4:])
	f.Add([]byte("xxDuca\x01\xc0"))
	f.Fuzz(func(t *testing.T, b []byte) {
		parseRDPRequest(b)
		rdpClientInfo(b)
		readTPKT(bytes.NewReader(b))
		smtpPlain(string(b))
	})
}
