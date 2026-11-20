package main

import (
	"io"
	"strings"
	"testing"
	"time"
)

// Testadresse aus dem Dokumentationsbereich (RFC 5737), wie Scanner sie in den Host-Kopf schreiben.
const scanReq = "GET / HTTP/1.1\r\nHost: 203.0.113.7:6379\r\nUser-Agent: Mozilla/5.0 zgrab/0.x\r\nAccept: */*\r\nAccept-Encoding: gzip\r\n\r\n"

// sendAll schickt die Eingabe und wartet, bis der Dienst die Verbindung beendet.
func sendAll(t *testing.T, m *Manager, svc, input string) []Event {
	t.Helper()
	c, done := run(t, m, svc, "emulate")
	go io.Copy(io.Discard, c)
	go c.Write([]byte(input))
	waitDone(t, done, 5*time.Second)
	c.Close()
	return events(m)
}

// Eine HTTP-Anfrage an einen Zeilendienst ist EIN Ereignis "payload" (foreign=http), keine
// Folge von Befehlen oder Logins je Kopfzeile.
func TestHTTPOnLineServices(t *testing.T) {
	telnetDelay = func() time.Duration { return 0 }
	for _, svc := range []string{"redis", "ftp", "smtp", "telnet", "mysql", "postgres"} {
		evs := sendAll(t, testManager(), svc, scanReq)
		var payloads int
		for _, e := range evs {
			switch e.Type {
			case "command", "login", "request":
				t.Errorf("%s: Kopfzeile als %s gemeldet: %v", svc, e.Type, e.Data)
			case "payload":
				payloads++
				txt, _ := e.Data["text"].(string)
				if e.Data["foreign"] != "http" || !strings.HasPrefix(txt, `GET / HTTP/1.1\r\nHost: 203.0.113.7:6379`) || !strings.Contains(txt, "Accept-Encoding") {
					t.Errorf("%s: Anfrage nicht vollständig: %v", svc, e.Data)
				}
			}
		}
		if payloads != 1 {
			t.Errorf("%s: %d payload-Ereignisse, erwartet 1", svc, payloads)
		}
	}
}

// Binärdaten an Textprotokollen: ein Ereignis statt einzelner "Befehle" wie \x00\x9c…
func TestBinaryOnLineServices(t *testing.T) {
	bin := "\x00\x9c\x01\x02\x03\nzweite Zeile\n\x00\x00"
	for _, svc := range []string{"redis", "ftp", "smtp"} {
		evs := sendAll(t, testManager(), svc, bin)
		n := 0
		for _, e := range evs {
			if e.Type == "command" || e.Type == "login" {
				t.Errorf("%s: Binärdaten als %s: %v", svc, e.Type, e.Data)
			}
			if e.Type == "payload" {
				n++
				if e.Data["foreign"] != "binary" || !strings.HasPrefix(e.Data["text"].(string), `\x00\x9c`) {
					t.Errorf("%s: %v", svc, e.Data)
				}
			}
		}
		if n != 1 {
			t.Errorf("%s: %d payload-Ereignisse, erwartet 1", svc, n)
		}
	}
}

// Echte Befehle bleiben Befehle, auch Redis GET; ein TLS-Handshake nach dem ersten Befehl
// wird ebenfalls erkannt.
func TestForeignNoFalsePositive(t *testing.T) {
	m := testManager()
	evs := sendAll(t, m, "redis", "GET mykey\r\nPING\r\nQUIT\r\n")
	var cmds []string
	for _, e := range evs {
		if e.Type == "command" {
			cmds = append(cmds, e.Data["input"].(string))
		}
		if e.Type == "payload" {
			t.Errorf("Fehlalarm: %v", e.Data)
		}
	}
	if strings.Join(cmds, "|") != "GET mykey|PING|QUIT" {
		t.Errorf("Befehle: %q", cmds)
	}
	for _, line := range []string{"GET / HTTP/1.1", "POST /x HTTP/1.0\r", "PRI * HTTP/2.0"} {
		if !isHTTPRequestLine(line) {
			t.Errorf("nicht erkannt: %q", line)
		}
	}
	for _, line := range []string{"GET mykey", "GET / HTTP", "get / HTTP/1.1", "SET a HTTP/1.1 x"} {
		if isHTTPRequestLine(line) {
			t.Errorf("Fehlalarm: %q", line)
		}
	}
}

func TestTLSAfterFirstCommand(t *testing.T) {
	hello := clientHello(t, "nas.example")
	evs := sendAll(t, testManager(), "redis", "PING\r\n"+string(hello))
	var tlsN, cmdN int
	for _, e := range evs {
		switch e.Type {
		case "tls":
			tlsN++
		case "command":
			cmdN++
		}
	}
	if tlsN != 1 || cmdN != 1 {
		t.Errorf("tls=%d command=%d, erwartet 1/1", tlsN, cmdN)
	}
}
