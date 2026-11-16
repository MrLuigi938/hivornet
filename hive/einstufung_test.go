package main

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// attackOf baut einen Angriff aus Ereignissen derselben IP (ohne Datenbank).
func attackOf(evs ...*Event) *Attack {
	var a *Attack
	for i, e := range evs {
		e.TS = time.Unix(1700000000+int64(i), 0)
		if e.SrcIP == "" {
			e.SrcIP = "203.0.113.5"
		}
		if a == nil {
			a = newAttack(e)
		}
		a.add(e)
	}
	a.finish()
	return a
}

func svcCmd(svc, input string) *Event {
	return evAt(time.Time{}, "command", svc, "", 0, map[string]any{"input": input})
}

func loginEv(svc, user, pass string, data map[string]any) *Event {
	e := evAt(time.Time{}, "login", svc, "", 0, data)
	e.Username, e.Password = user, pass
	return e
}

func hasTag(a *Attack, id string) bool {
	return slices.ContainsFunc(a.Tags, func(c Count) bool { return c.Key == id })
}

// Forschungsscanner fragen Redis, FTP und SMTP nur ab: Abtasten, nicht "Befehle ausgeführt".
func TestStufeProtocolChatter(t *testing.T) {
	cases := []struct {
		name  string
		evs   []*Event
		stufe int
	}{
		{"Redis PING/INFO", []*Event{svcCmd("redis", "PING"), svcCmd("redis", "INFO server")}, stufeScan},
		{"FTP AUTH TLS", []*Event{svcCmd("ftp", "AUTH TLS"), svcCmd("ftp", "FEAT")}, stufeScan},
		{"SMTP EHLO", []*Event{svcCmd("smtp", "EHLO scanner.example")}, stufeScan},
		{"FTP mod_copy", []*Event{svcCmd("ftp", "SITE CPFR /etc/passwd")}, stufeVersuch},
		{"SMTP Spam", []*Event{svcCmd("smtp", "MAIL FROM:<a@b.example>")}, stufeVersuch},
		{"Redis-Übernahme", []*Event{svcCmd("redis", "INFO"), svcCmd("redis", "CONFIG SET dir /var/spool/cron")}, stufeBefehle},
		{"Redis CONFIG GET", []*Event{svcCmd("redis", "CONFIG GET *")}, stufeVersuch},
		{"Redis SLAVEOF", []*Event{svcCmd("redis", "SLAVEOF 198.51.100.7 8886")}, stufeBefehle},
		{"Docker create", []*Event{svcCmd("dockerapi", "create image=alpine binds=/:/mnt")}, stufeBefehle},
		{"Cowrie-Shell", []*Event{loginEv("ssh", "root", "x", map[string]any{"success": true}), svcCmd("ssh", "uname -a")}, stufeBefehle},
	}
	for _, c := range cases {
		a := attackOf(c.evs...)
		if a.Stufe != c.stufe {
			t.Errorf("%s: Stufe %d, erwartet %d (counts %v)", c.name, a.Stufe, c.stufe, a.Counts)
		}
	}
	a := attackOf(svcCmd("redis", "PING"), svcCmd("redis", "INFO"))
	if a.Profile == "Redis-Übernahme" || len(a.Commands) != 0 || len(a.ProtoCommands) != 2 {
		t.Errorf("Redis-Abfrage: Art %q, Befehle %v, Protokoll %v", a.Profile, a.Commands, a.ProtoCommands)
	}
	a = attackOf(svcCmd("redis", "CONFIG SET dir /root/.ssh"))
	if a.Profile != "Redis-Übernahme" || len(a.Commands) != 1 {
		t.Errorf("Redis-Übernahme: %q %v", a.Profile, a.Commands)
	}
	// Bei Diensten ohne Schein-Shell zählt ein Befehl erst nach angenommenem Login
	sess := func(e *Event) *Event { e.Session = "s1"; return e }
	a = attackOf(sess(loginEv("ftp", "anon", "x", map[string]any{"accepted": true})), sess(svcCmd("ftp", "STOR x")))
	if a.Stufe != stufeBefehle {
		t.Errorf("Befehl nach angenommenem Login: Stufe %d", a.Stufe)
	}
}

// TLS-ClientHello am Klartext-Port: kein Befehl, keine Verschleierung, Merkmal tls_on_plain.
func TestTLSHelloNotCommand(t *testing.T) {
	hello := `\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\xa1\xb2\xc3\xd4\xe5\xf6\x07\x18\x29\x3a\x4b\x5c\x6d\x7e\x8f\x90`
	for _, svc := range []string{"ftp", "redis"} {
		a := attackOf(svcCmd(svc, hello))
		if a.Stufe != stufeScan || len(a.Commands) != 0 || len(a.ProtoCommands) != 0 {
			t.Errorf("%s: Stufe %d, Befehle %v %v", svc, a.Stufe, a.Commands, a.ProtoCommands)
		}
		if !hasTag(a, "tls_on_plain") || hasTag(a, "obfuscation") {
			t.Errorf("%s: Muster %v", svc, a.Tags)
		}
		if a.Profile != "TLS-Scan" {
			t.Errorf("%s: Art %q", svc, a.Profile)
		}
		for _, k := range topKeys(svcCmd(svc, hello)) {
			if k[0] == "command" || k[1] == "obfuscation" {
				t.Errorf("%s: Zähltabelle %v", svc, k)
			}
		}
	}
	// neues Format: Ereignis "tls" mit plain=true
	ev := evAt(time.Time{}, "tls", "ftp", "", 21, map[string]any{"plain": true, "client_hello": "160301"})
	a := attackOf(ev)
	if !hasTag(a, "tls_on_plain") || a.Stufe != stufeScan {
		t.Errorf("tls-Ereignis: %v Stufe %d", a.Tags, a.Stufe)
	}
	if r := BuildReport("x", []*Event{svcCmd("ftp", hello)}, false); len(r.Commands) != 0 || len(r.Decoded) != 0 {
		t.Errorf("Bericht: Befehle %v, entschlüsselt %v", r.Commands, r.Decoded)
	}
}

// Bots tippen ihre Befehle blind in die Telnet-Anmeldung: keine Zugangsdaten.
func TestTelnetPromptCommands(t *testing.T) {
	for _, c := range [][2]string{{"system", "shell"}, {"sh", "/bin/busybox OhVNe7te"}, {"enable", "system"}, {"root", "/bin/busybox ECCHI"}} {
		e := loginEv("telnet", c[0], c[1], nil)
		if eventKind(e, false) != kindPrompt {
			t.Errorf("%v nicht als Login-Abfrage erkannt", c)
		}
		for _, k := range topKeys(e) {
			if k[0] == "username" || k[0] == "password" || k[0] == "cred" {
				t.Errorf("%v zählt als Zugangsdaten: %v", c, k)
			}
		}
		a := attackOf(loginEv("telnet", c[0], c[1], nil))
		if len(a.Creds) != 0 || a.Stufe != stufeVersuch || len(a.ProtoCommands) == 0 {
			t.Errorf("%v: Zugangsdaten %v, Stufe %d, Eingaben %v", c, a.Creds, a.Stufe, a.ProtoCommands)
		}
	}
	a := attackOf(loginEv("telnet", "sh", "/bin/busybox OhVNe7te", nil))
	if !hasTag(a, "iot_botnet") {
		t.Errorf("Mirai-Probe an der Login-Abfrage nicht erkannt: %v", a.Tags)
	}
	// echte Zugangsdaten bleiben welche, auch bei SSH mit Passwort "shell"
	for _, e := range []*Event{loginEv("telnet", "root", "xc3511", nil), loginEv("telnet", "admin", "shell", nil), loginEv("ssh", "system", "shell", nil)} {
		if eventKind(e, false) == kindPrompt {
			t.Errorf("%s/%s (%s) fälschlich als Befehl", e.Username, e.Password, e.Service)
		}
	}
	r := BuildReport("x", []*Event{loginEv("telnet", "system", "shell", nil)}, false)
	if r.Logins != 0 || len(r.Commands) != 2 || !strings.Contains(r.Commands[0], "Login-Abfrage") {
		t.Errorf("Bericht: Logins %d, Befehle %v", r.Logins, r.Commands)
	}
}
