package main

import (
	"testing"
	"time"
)

// Regel 1b (einstufung.go): Ältere Honeypots meldeten jede Zeile einer HTTP-Anfrage an Redis
// als eigenen Befehl, samt "Host: <öffentliche IP>:6379". Das sind keine Befehle.
func TestForeignLinesNotCommands(t *testing.T) {
	lines := []string{"GET / HTTP/1.1", "Host: 203.0.113.7:6379", "User-Agent: Mozilla/5.0", "Accept: */*", "Accept-Encoding: gzip", `\x00\x9c\x01\x02`}
	for _, svc := range []string{"redis", "ftp", "smtp"} {
		var evs []*Event
		for _, l := range lines {
			evs = append(evs, svcCmd(svc, l))
			for _, k := range topKeys(svcCmd(svc, l)) {
				if k[0] == "command" {
					t.Errorf("%s: %q zählt als Befehl", svc, l)
				}
			}
		}
		a := attackOf(evs...)
		if a.Stufe != stufeScan || len(a.Commands) != 0 || len(a.ProtoCommands) != 0 {
			t.Errorf("%s: Stufe %d, Befehle %v %v", svc, a.Stufe, a.Commands, a.ProtoCommands)
		}
		if !hasTag(a, "http_on_raw") || a.Profile != "Protokoll-Probe" {
			t.Errorf("%s: Muster %v, Art %q", svc, a.Tags, a.Profile)
		}
		if r := BuildReport("x", evs, false); len(r.Commands) != 0 {
			t.Errorf("%s: Bericht-Befehle %v", svc, r.Commands)
		}
	}
	// echte Befehle bleiben Befehle
	for _, c := range [][2]string{{"redis", "GET mykey"}, {"redis", "CONFIG SET dir /tmp"}, {"smtp", "MAIL FROM:<a@b.example>"}, {"smtp", "RCPT TO:<c@d.example>"}, {"ftp", "USER anonymous"}, {"redis", `SET k \\x41`}} {
		if foreignEvent(svcCmd(c[0], c[1])) {
			t.Errorf("Fehlalarm %s %q", c[0], c[1])
		}
	}
	// HTTP-Anfragezeilen an anderen Diensten (Kubernetes-API …) betrifft die Regel nicht
	if foreignEvent(svcCmd("kubernetes", "Host: x")) {
		t.Error("Regel 1b gilt nur für Zeilendienste")
	}
}

// Telnet vor 0.7.6: Anfragezeile als Benutzername, erste Kopfzeile als Passwort.
func TestForeignTelnetLogin(t *testing.T) {
	ev := loginEv("telnet", "GET / HTTP/1.1", "Host: 203.0.113.7:23", nil)
	for _, k := range topKeys(ev) {
		if k[0] == "username" || k[0] == "password" || k[0] == "cred" {
			t.Errorf("Zähltabelle: %v", k)
		}
	}
	a := attackOf(loginEv("telnet", "GET / HTTP/1.1", "Host: 203.0.113.7:23", nil), loginEv("telnet", "User-Agent: x", "Accept: */*", nil))
	if a.Counts["login"] != 0 || a.Stufe != stufeScan || !hasTag(a, "http_on_raw") {
		t.Errorf("counts %v Stufe %d Muster %v", a.Counts, a.Stufe, a.Tags)
	}
	if foreignEvent(loginEv("telnet", "root", "Host: x", nil)) {
		t.Error("echter Benutzername als fremd erkannt")
	}
}

// Honeypot ab 0.7.6: die ganze Anfrage als ein "payload" mit foreign=http.
func TestForeignPayload(t *testing.T) {
	ev := evAt(time.Time{}, "payload", "redis", "", 6379, map[string]any{"text": `GET / HTTP/1.1\r\nHost: 203.0.113.7:6379\r\n\r\n`, "bytes": 40, "foreign": "http"})
	a := attackOf(ev)
	if a.Counts["foreign"] != 1 || a.Stufe != stufeScan || !hasTag(a, "http_on_raw") || a.Profile != "Protokoll-Probe" {
		t.Errorf("counts %v Stufe %d Muster %v Art %q", a.Counts, a.Stufe, a.Tags, a.Profile)
	}
	for _, k := range topKeys(ev) {
		if k[0] == "command" {
			t.Errorf("Zähltabelle: %v", k)
		}
	}
	r := BuildReport("x", []*Event{ev}, false)
	if len(r.Timeline) == 0 {
		t.Fatal("kein Ablauf")
	}
	if c := BuildChain([]*Event{ev}, false); c == nil || len(c.Nodes) == 0 {
		t.Error("keine Kette")
	}
}
