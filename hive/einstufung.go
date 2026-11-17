package main

// Einstufung von Ereignissen: Welche Befehle zählen als "ausgeführt", was ist nur
// Protokoll-Geplänkel, was ist ein TLS-Handshake am falschen Port, was hat ein Bot
// an der Login-Abfrage eingetippt? Alle Regeln dafür stehen in dieser Datei; Angriffe
// (attacks.go: Stufe, Listen, Art), Bericht (analyze.go), Zähltabelle (store.go: topKeys)
// und Benachrichtigungen (notify.go) fragen nur eventKind.
//
// Regeln (in dieser Reihenfolge):
//
//  1. TLS am Klartext-Port: Ereignis "tls" mit plain=true (Honeypot ab 0.5.3) oder ein
//     älteres "command"/"payload", dessen Text mit \x16\x03 beginnt. Kein Befehl, keine
//     Verschleierung, sondern Merkmal tls_on_plain. Stufe: Abtasten.
//  2. Eingabe an der Login-Abfrage (nur Telnet, Honeypot und Cowrie): Ist der Benutzername
//     ein Befehlswort (enable, system, shell, sh, /bin/busybox …) oder beginnt das Passwort
//     mit busybox, hat ein Bot seine Befehle blind in die Anmeldung getippt. Das sind keine
//     Zugangsdaten; sie erscheinen als "Befehl an der Login-Abfrage". Stufe: Versuche.
//  3. Befehl ausgeführt (Stufe 3) nur
//     a) bei Diensten mit Schein-Shell (ssh, telnet): Dort gibt es Befehle erst nach einem
//        angenommenen Login (Cowrie und Honeypot-Telnet melden vorher keine);
//     b) bei der Docker-API: Der Honeypot meldet dort nur create, exec und pull;
//     c) bei Redis nur verändernde oder gefährliche Befehle (CONFIG SET, SLAVEOF/REPLICAOF,
//        MODULE LOAD, EVAL, SET, FLUSHALL, SAVE …, siehe redisChanging);
//     d) bei ADB, Kubernetes, Ollama und Elasticsearch: gemeldet werden dort nur Befehle mit
//        Wirkung; bei MQTT nur "publish";
//     e) bei jedem anderen Dienst nur, wenn in derselben Sitzung ein Login angenommen wurde.
//  4. Sonst ist ein Befehl Protokoll-Geplänkel vor der Anmeldung: reine Abfragen und
//     Handshakes (PING, INFO, EHLO, FEAT, AUTH TLS …, siehe probeWords) zählen als
//     Abtasten, alles andere (USER/PASS-Folgen, MAIL FROM, unbekannte Befehle) als Versuche.

import (
	"path"
	"regexp"
	"strings"
)

type evKind int

const (
	kindOther    evKind = iota
	kindTLSPlain        // TLS-Handshake auf einem Klartext-Port
	kindPrompt          // Befehle an der Login-Abfrage (Telnet), keine Zugangsdaten
	kindProbe           // Protokoll-Abfrage ohne Wirkung (Abtasten)
	kindProto           // Protokoll-Befehl vor der Anmeldung (Versuche)
	kindExec            // Befehl ausgeführt (Stufe 3)
)

// tlsPrefix: so beginnt ein TLS-Record vom Typ Handshake, wie printable ihn darstellt.
const tlsPrefix = `\x16\x03`

func isTLSText(s string) bool { return strings.HasPrefix(s, tlsPrefix) }

// eventKind ordnet ein Ereignis ein. loggedIn: in der Sitzung wurde ein Login angenommen.
func eventKind(e *Event, loggedIn bool) evKind {
	switch e.Type {
	case "tls":
		if dataBool(e.Data, "plain") {
			return kindTLSPlain
		}
	case "payload":
		if isTLSText(dataString(e.Data, "text")) {
			return kindTLSPlain
		}
	case "login":
		if _, ok := promptLines(e); ok {
			return kindPrompt
		}
	case "command":
		input := dataString(e.Data, "input")
		switch {
		case isTLSText(input):
			return kindTLSPlain
		case commandExecuted(e.Service, input, loggedIn):
			return kindExec
		case probeCommand(input):
			return kindProbe
		}
		return kindProto
	}
	return kindOther
}

// commandExecuted: Regel 3.
func commandExecuted(service, input string, loggedIn bool) bool {
	switch service {
	case "ssh", "telnet", "dockerapi":
		return true
	case "adb": // Shell-Befehle und Datei-Ablagen (proto_iot.go)
		return true
	case "kubernetes", "ollama", "elasticsearch":
		// Nur Anfragen mit Wirkung; Webscanner mit POST an diese Ports sind Versuche (zweites Audit, N6)
		return apiChanging(service, input)
	case "mqtt": // Nachricht veröffentlichen ändert etwas, Abonnieren nicht
		return strings.HasPrefix(input, "publish ")
	case "redis":
		return redisChanging(input)
	case "ftp": // nach dem Login nur Hochladen, Löschen, Umbenennen, SITE
		f := strings.Fields(strings.ToUpper(input))
		return loggedIn && len(f) > 0 && ftpChanging[f[0]]
	}
	return loggedIn
}

// apiChanging: Befehle der HTTP-APIs (honeypot/proto_api.go), die etwas bewirken.
func apiChanging(service, input string) bool {
	switch service {
	case "kubernetes":
		for _, p := range []string{"exec ", "run ", "create pod"} {
			if strings.HasPrefix(input, p) {
				return true
			}
		}
		f := strings.Fields(input) // z. B. "DELETE /api/v1/namespaces/x/pods/y"
		return len(f) > 0 && (f[0] == "DELETE" || f[0] == "PUT" || f[0] == "PATCH")
	case "ollama":
		for _, p := range []string{"prompt ", "pull ", "push ", "create ", "copy ", "delete "} {
			if strings.HasPrefix(input, p) {
				return true
			}
		}
	case "elasticsearch":
		l := strings.ToLower(input)
		if strings.Contains(l, "script") {
			return true // Skript-Lücken (Groovy, Painless)
		}
		f := strings.Fields(input)
		if len(f) < 2 {
			return false
		}
		if f[0] != "PUT" && f[0] != "DELETE" && f[0] != "POST" {
			return false
		}
		// Nur echte schreibende Elasticsearch-Pfade; Webscanner (POST /cgi-bin/…) sind Versuche.
		for _, seg := range strings.Split(strings.ToLower(f[1]), "/") {
			switch seg {
			case "_doc", "_create", "_update", "_bulk", "_reindex", "_delete_by_query", "_update_by_query", "_scripts", "_ingest", "_snapshot", "_settings", "_mapping":
				return true
			}
		}
		// PUT/DELETE auf einen Index ("/name") legt an oder löscht
		return f[0] != "POST" && strings.Count(strings.Trim(f[1], "/"), "/") == 0 && !strings.HasPrefix(strings.Trim(f[1], "/"), "_")
	}
	return false
}

var ftpChanging = map[string]bool{"STOR": true, "APPE": true, "STOU": true, "DELE": true, "MKD": true, "XMKD": true, "RMD": true, "XRMD": true, "RNFR": true, "RNTO": true, "SITE": true}

// Redis-Befehle, die Daten oder Einstellungen ändern oder Code ausführen.
var redisChangingCmds = map[string]bool{
	"SET": true, "SETEX": true, "SETNX": true, "PSETEX": true, "MSET": true, "APPEND": true, "DEL": true, "UNLINK": true,
	"RENAME": true, "HSET": true, "LPUSH": true, "RPUSH": true, "SADD": true, "ZADD": true, "RESTORE": true, "SWAPDB": true,
	"FLUSHALL": true, "FLUSHDB": true, "SLAVEOF": true, "REPLICAOF": true, "EVAL": true, "EVALSHA": true, "EVAL_RO": true,
	"FCALL": true, "SAVE": true, "BGSAVE": true, "BGREWRITEAOF": true, "SYSTEM.EXEC": true, "MIGRATE": true, "DEBUG": true,
	"SHUTDOWN": true,
}

// Unterbefehle, die bei sonst lesenden Redis-Befehlen etwas ändern.
var redisChangingSub = map[string]map[string]bool{
	"CONFIG":   {"SET": true, "RESETSTAT": true, "REWRITE": true},
	"MODULE":   {"LOAD": true, "LOADEX": true, "UNLOAD": true},
	"SCRIPT":   {"LOAD": true, "FLUSH": true},
	"FUNCTION": {"LOAD": true, "DELETE": true, "FLUSH": true, "RESTORE": true},
	"ACL":      {"SETUSER": true, "DELUSER": true, "LOAD": true, "SAVE": true},
}

func redisChanging(input string) bool {
	f := strings.Fields(input)
	if len(f) == 0 {
		return false
	}
	cmd := strings.ToUpper(f[0])
	if redisChangingCmds[cmd] {
		return true
	}
	if subs := redisChangingSub[cmd]; subs != nil && len(f) > 1 {
		return subs[strings.ToUpper(f[1])]
	}
	return false
}

// probeWords: Abfragen und Handshakes von Redis, FTP und SMTP ohne Wirkung.
var probeWords = map[string]bool{
	// Redis
	"PING": true, "INFO": true, "COMMAND": true, "HELLO": true, "ECHO": true, "QUIT": true, "CLIENT": true,
	"SELECT": true, "TIME": true, "ROLE": true, "DBSIZE": true, "LASTSAVE": true,
	// FTP
	"FEAT": true, "SYST": true, "PWD": true, "TYPE": true, "OPTS": true, "PBSZ": true, "PROT": true, "NOOP": true,
	"STAT": true, "HELP": true, "SITE HELP": true, "PASV": true, "EPSV": true, "CLNT": true, "AUTH TLS": true, "AUTH SSL": true,
	// SMTP
	"EHLO": true, "HELO": true, "LHLO": true, "RSET": true, "STARTTLS": true,
}

func probeCommand(input string) bool {
	f := strings.Fields(strings.ToUpper(input))
	if len(f) == 0 {
		return true
	}
	if len(f) > 1 && probeWords[f[0]+" "+f[1]] {
		return true
	}
	if f[0] == "AUTH" || f[0] == "SITE" { // AUTH mit Zugangsdaten, SITE EXEC … sind Versuche
		return false
	}
	return probeWords[f[0]]
}

// Befehlswörter, die Bots an der Telnet-Login-Abfrage eintippen, wenn sie die Anmeldung
// für gelungen halten oder Router-CLIs (enable, system, shell) durchprobieren.
var promptWords = map[string]bool{
	"enable": true, "system": true, "shell": true, "sh": true, "linuxshell": true, "bash": true, "ash": true,
	"start": true, "cd": true, "ping": true, "busybox": true, "echo": true, "cat": true, "wget": true, "tftp": true,
	"curl": true, "exit": true, "ls": true, "ps": true, "uname": true, "chmod": true,
}

func promptWord(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "/bin/") || strings.HasPrefix(s, "/usr/") || strings.HasPrefix(s, "/tmp/") || strings.HasPrefix(s, "./") ||
		strings.ContainsAny(s, ";|&") {
		return true
	}
	return promptWords[path.Base(strings.Fields(s)[0])]
}

// promptLines: Regel 2. Liefert die eingetippten Zeilen (Benutzername, Passwort).
func promptLines(e *Event) ([]string, bool) {
	if e.Type != "login" || e.Service != "telnet" {
		return nil, false
	}
	u, p := strings.TrimSpace(e.Username), strings.TrimSpace(e.Password)
	lp := strings.ToLower(p)
	if !promptWord(u) && !strings.HasPrefix(lp, "/bin/busybox") && !strings.HasPrefix(lp, "busybox ") {
		return nil, false
	}
	var out []string
	for _, s := range []string{u, p} {
		if s != "" {
			out = append(out, s)
		}
	}
	return out, true
}

// ---- Anfragen anderer Protokolle (SIP, DNS) ----

// sipHostRe: Host-Teil einer SIP-Adresse, wenn er eine IP ist. Scanner schreiben dort
// meist die angegriffene Adresse hinein, also die öffentliche IP des Honeypots.
var sipHostRe = regexp.MustCompile(`(?i)(sips?:(?:[^@\s;>]*@)?)(\[[0-9a-f:.]+\]|\d{1,3}(?:\.\d{1,3}){3})`)

// maskSIP ersetzt IP-Adressen in SIP-Adressen durch einen Platzhalter.
func maskSIP(s string) string { return sipHostRe.ReplaceAllString(s, "${1}‹IP›") }

// requestKey: Schlüssel für Listen. Web: Methode (außer GET) und Pfad; SIP: Methode und
// Adresse ohne IP; DNS: Abfragetyp und Name.
func requestKey(e *Event) string {
	p, m := dataString(e.Data, "path"), dataString(e.Data, "method")
	switch e.Service {
	case "sip":
		return strings.TrimSpace(m + " " + maskSIP(p))
	case "dns":
		return strings.TrimSpace(strings.TrimPrefix(m, "DNS ") + " " + p)
	}
	if m != "" && m != "GET" {
		return m + " " + p
	}
	return p
}
