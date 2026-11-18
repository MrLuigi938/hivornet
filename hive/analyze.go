package main

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Muster-Analyse: ordnet Befehle, HTTP-Anfragen und rohe Daten bekannten
// Angriffsmustern zu, erkennt benutzte Werkzeuge und sammelt Spuren (URLs,
// Hashes). Alles regelbasiert und lokal; die Regeln stehen in dieser Datei.
//
// Zwei Verwendungen:
//   - beim Schreiben: topKeys() zählt Muster ("tag") und Werkzeuge ("tool") in
//     top_hourly, damit die Ansicht "Analyse" ohne Tabellen-Scan auskommt;
//   - auf Abruf: BuildReport() fasst die Ereignisse einer IP oder Sitzung zusammen.

// Pattern ist eine Regel. On legt fest, auf welche Texte sie angewendet wird:
// "cmd" (Befehle, Docker-/Redis-Kommandos), "web" (Pfad, Body, Kopfzeilen), "raw" (Payload).
type Pattern struct {
	ID   string
	Name string
	Desc string
	On   string
	Sev  int // 1 = Erkundung, 2 = Zugriffsversuch, 3 = Übernahme/Schadcode
	re   *regexp.Regexp
}

func pat(id, name, desc, on string, sev int, expr string) Pattern {
	return Pattern{id, name, desc, on, sev, regexp.MustCompile(`(?i)` + expr)}
}

// Reihenfolge = Anzeige-Reihenfolge bei gleicher Häufigkeit. Neue Regeln hier anhängen;
// TestPatterns enthält je Regel ein Beispiel.
var patterns = []Pattern{
	pat("download_exec", "Nachladen und Ausführen", "Lädt eine Datei aus dem Netz und startet sie (Dropper).", "cmd", 3,
		`\b(wget|curl|tftp|ftpget|fetch)\b[^\n]*(\|\s*(ba|a)?sh\b|chmod\b|;\s*\./|&&\s*\./|\bsh\s+\S|\bbash\s+\S|\bpython\S*\s+\S)`),
	// Bewusst ohne den Namen des Hash-Verfahrens: Zusammen mit den übrigen Begriffen hält der
	// Windows-Virenscanner das fertige Programm selbst für einen Miner und sperrt Build und Tests
	// auf dem Entwicklungsrechner (docs/ENTWICKLUNG.md, Abschnitt Virenscanner).
	pat("miner", "Krypto-Miner", "Hinweise auf Mining-Software oder Mining-Pools.", "cmd", 3,
		`xmrig|minerd|cpuminer|stratum\+(tcp|ssl)|monero|c3pool|nanopool|kinsing|kdevtmpfsi|\bxmr\b`),
	pat("iot_botnet", "IoT-Botnetz (Mirai-Art)", "Typische Probe- und Ladebefehle von Mirai, Gafgyt und Verwandten.", "cmd", 3,
		`/bin/busybox\s+[A-Z0-9]{4,}\b|\bbusybox\s+(wget|tftp)\b|\b(mirai|gafgyt|mozi|bashlite|sora|ecchi)\b|\.(mips|mpsl|arm[4-7]?|x86|sh4|ppc|m68k|spc)\b`),
	pat("persist_ssh", "SSH-Schlüssel hinterlegen", "Trägt einen eigenen Schlüssel in authorized_keys ein, um dauerhaft Zugang zu behalten.", "cmd", 3,
		`authorized_keys|ssh-(rsa|ed25519)\s+AAAA`),
	pat("persist_cron", "Cron-Persistenz", "Richtet einen wiederkehrenden Auftrag ein.", "cmd", 3,
		`\bcrontab\b|/etc/cron|/var/spool/cron|/etc/rc\.local|systemctl\s+enable`),
	pat("docker_escape", "Docker-Ausbruch", "Container mit eingebundenem Host-Dateisystem oder vollen Rechten.", "cmd", 3,
		`\bbinds=/:|\bprivileged\b|/var/run/docker\.sock|\bnsenter\b|--pid=host`),
	pat("redis_takeover", "Redis-Übernahme", "Schreibt über Redis Dateien auf den Server oder lädt ein Modul.", "cmd", 3,
		`\bconfig\s+set\s+(dir|dbfilename)\b|\b(slaveof|replicaof)\s+\S+\s+\d+|\bmodule\s+load\b|system\.exec`),
	pat("account", "Konto ändern", "Legt Benutzer an oder ändert Passwörter.", "cmd", 3,
		`\b(chpasswd|useradd|adduser|usermod)\b|\bpasswd\b(\s|$)|echo\s+\S*:\S+\s*\|\s*chpasswd`),
	pat("cover_tracks", "Spuren verwischen", "Löscht Verlauf oder Protokolle, sperrt Dateien gegen Änderung.", "cmd", 2,
		`history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|rm\s+-rf?\s+/var/log|\bchattr\b|>\s*/var/log/|\.bash_history`),
	pat("kill_rivals", "Konkurrenz beenden", "Beendet fremde Prozesse, oft andere Schadsoftware.", "cmd", 2,
		`\b(pkill|killall)\b|\bkill\s+-9\b`),
	pat("obfuscation", "Verschleierung", "Versteckt Befehle oder Adressen in Base64, Hex- oder Oktal-Kodierung; Hivornet zeigt den entschlüsselten Inhalt.", "cmd", 2,
		`\bbase64\s+(-d|--decode|-D)\b|\bfrombase64string\b|\batob\(|(\\x[0-9a-f]{2}){4,}|(\\[0-7]{3}){4,}|\bxxd\s+-r\b|\bopenssl\s+(enc\s+)?-?base64\s+-d`),
	pat("recon", "Erkundung", "Fragt System, Hardware und Benutzer ab.", "cmd", 1,
		`\buname\b|/proc/cpuinfo|\b(nproc|lscpu|whoami|uptime|ifconfig|lspci|dmidecode)\b|\bfree\s+-|\bdf\s+-|\bcat\s+/etc/(passwd|issue|os-release)|\bip\s+a(ddr)?\b|\bps\s+(aux|-ef)|^\s*(id|w|ls)\s*$`),
	// Echtheitstests der Shell nach dem Login: Marker mit Zufallshash (check_<hex>_small_math …),
	// Subshell-Sichtbarkeit, Quoting und "echo dGVzdA== | base64 -d" (= "test"). Eine emulierte
	// Shell fällt an einigen davon durch; der Bot merkt sich die IP dann als Honeypot.
	pat("honeypot_check", "Honeypot-Prüfung", "Testet nach dem Login, ob die Shell echt ist (Rechnen, Subshells, Quoting, Marker-Ausgaben); scheitert die Emulation, meidet der Bot das Gerät künftig.", "cmd", 2,
		`\bcheck_[0-9a-f]{16,}_\w+|\bv=outer;\s*\(\s*v=inner\b|printf\s+'%s\\n'\s+'a b;\$\(\)'|\becho\s+'?dGVzdA==|^\s*echo\s+"?\$\(\(\s*\d+\s*[-+*]\s*\d+\s*\)\)"?\s*$`),
	// Versuche, ein Sprachmodell umzusteuern ("ignore previous instructions …"); Regeln in mimicguard.go
	pat("prompt_injection", "KI-Manipulation", "Schickt Anweisungen an ein Sprachmodell (z. B. „ignore previous instructions“), etwa um eine KI-gestützte Shell zu entlarven oder umzusteuern. Solche Eingaben gehen nie ans Modell.", "cmd", 2,
		injectionExpr),
	pat("data_theft", "Daten suchen", "Sucht nach Zugangsdaten, Wallets oder Messenger-Daten.", "cmd", 2,
		`TelegramDesktop|tdata|wallet\.dat|\.aws/credentials|id_rsa\b|\.ssh/|smsd|ttyGSM|\bfind\b[^\n]*(\.pem|\.key|password)`),

	pat("log4shell", "Log4Shell", "JNDI-Zeichenkette für CVE-2021-44228.", "web", 3, `\$\{jndi:|\$\{(lower|upper|env|::-)`),
	pat("web_rce", "Web-RCE-Versuch", "Versucht, über eine bekannte Lücke Befehle auszuführen.", "web", 3,
		`phpunit|eval-stdin|invokefunction|call_user_func|think\\app|/struts|\bcmd=|\bexec=|shell_exec|/cgi-bin/\S*\.\./|allow_url_include|auto_prepend_file|/actuator/(gateway|env)|/solr/admin|\bwget\b|\bcurl\b[^\n]*\bhttp|;\s*(cat|id|uname)\b|%3B(wget|curl|cat)`),
	pat("secret_hunt", "Geheimnis-Suche", "Sucht frei liegende Konfigurationen und Schlüssel (.env, .git, Backups).", "web", 2,
		`/\.env|/\.git/|/\.aws/|wp-config|\.DS_Store|/config\.(json|php|yml)|phpinfo|/backup|\.(sql|bak|zip|tar\.gz)(\?|$)|/server-status|id_rsa`),
	pat("iot_exploit", "Router-/IoT-Exploit", "Zielt auf Verwaltungsseiten von Routern, Kameras und NAS-Geräten.", "web", 3,
		`/boaform|/HNAP1|/GponForm|/goform/|setup\.cgi|/cgi-bin/luci|/tmUnblock|/picsdesc\.xml|/ctrlt/DeviceUpgrade|/shell\?|/UD/act|/setup\.xml|/SDK/webLanguage`),
	pat("traversal", "Pfad-Traversal", "Versucht, über ../ Dateien außerhalb des Web-Ordners zu lesen.", "web", 2,
		`\.\./\.\./|%2e%2e[/%]|\.\.%2f|/etc/passwd|/proc/self/environ|c:\\windows`),
	pat("sqli", "SQL-Injection", "SQL-Fragmente in Parametern.", "web", 2,
		`union(\s|\+|%20)+select|\bor\s+1\s*=\s*1|sleep\(\d+\)|information_schema|'\s*--\s`),
	pat("cms_login", "CMS-Anmeldung", "Anmeldeseiten von WordPress, Joomla, phpMyAdmin und ähnlichen.", "web", 2,
		`wp-login|xmlrpc\.php|/wp-admin|/administrator/|phpmyadmin|/pma/|/manager/html|/user/login`),
	pat("api_probe", "Dienst-Erkundung", "Fragt Versions- und Statusseiten ab.", "web", 1,
		`/version$|/_ping|/actuator/health|/api/v1/|/v2/_catalog|/containers/json|/\.well-known/|/robots\.txt|/favicon\.ico|/sitemap\.xml`),

	// Köder (bait.go): kein Textmuster, sondern Abgleich mit den Köder-Zugangsdaten. Die Regel
	// passt nur auf ihren eigenen Platzhalter und steht hier für Name, Text und Schweregrad.
	pat("bait_used", "Köder benutzt", "Hat Zugangsdaten aus einer Köderdatei des Web-Honeypots (.env, .git/config …) benutzt; hat die Datei also gelesen und gezielt ausprobiert.", "meta", 3, `^hivornet:koeder$`),
	pat("tls_on_plain", "TLS auf Klartext-Port", "TLS-Handshake auf einem Port ohne TLS.", "raw", 1, `^\\x16\\x03`),
	pat("smb_probe", "SMB-Probe", "SMB-Verhandlung (z. B. EternalBlue-Scanner).", "raw", 2, `\\xffSMB|\\xfeSMB`),
	pat("http_on_raw", "HTTP auf fremdem Port", "HTTP-Anfrage an einen Nicht-HTTP-Dienst.", "raw", 1, `^(GET|POST|HEAD|OPTIONS|CONNECT) \S+ HTTP/`),
}

var patternByID = func() map[string]*Pattern {
	m := map[string]*Pattern{}
	for i := range patterns {
		m[patterns[i].ID] = &patterns[i]
	}
	return m
}()

// eventText liefert den Text eines Ereignisses und die Regelgruppe dazu.
func eventText(e *Event) (text, on string) {
	switch e.Type {
	case "command":
		if in := dataString(e.Data, "input"); isTLSText(in) {
			return in, "raw" // TLS am Klartext-Port (einstufung.go): Merkmal tls_on_plain, kein Befehl
		} else {
			return in, "cmd"
		}
	case "tls":
		if dataBool(e.Data, "plain") {
			return tlsPrefix + " TLS-ClientHello", "raw"
		}
	case "login":
		if lines, ok := promptLines(e); ok { // Befehle an der Login-Abfrage
			return strings.Join(lines, "\n"), "cmd"
		}
	case "request":
		t := dataString(e.Data, "path") + "\n" + dataString(e.Data, "body") + "\n" + dataString(e.Data, "headers")
		if dataString(e.Data, "forward_to") != "" {
			return "", ""
		}
		return t, "web"
	case "payload":
		return dataString(e.Data, "text"), "raw"
	case "download":
		return dataString(e.Data, "url"), ""
	}
	return "", ""
}

// matchPatterns liefert die IDs aller Regeln der Gruppe, die auf den Text passen.
func matchPatterns(text, on string) []string {
	if text == "" || on == "" {
		return nil
	}
	var out []string
	for i := range patterns {
		if patterns[i].On == on && patterns[i].re.MatchString(text) {
			out = append(out, patterns[i].ID)
		}
	}
	return out
}

// ---- Werkzeuge ----

// Programme, die als "benutztes Werkzeug" gezählt werden (erstes Wort eines Befehls).
var toolWords = map[string]bool{
	"wget": true, "curl": true, "tftp": true, "ftpget": true, "busybox": true, "chmod": true, "python": true,
	"python3": true, "perl": true, "nc": true, "ncat": true, "nohup": true, "crontab": true, "chattr": true,
	"base64": true, "openssl": true, "scp": true, "ssh": true, "docker": true, "git": true, "tar": true,
	"dd": true, "systemctl": true, "iptables": true, "php": true, "gcc": true, "make": true, "sudo": true,
	"apt": true, "apt-get": true, "yum": true, "dnf": true, "apk": true, "pip": true, "pip3": true, "npm": true,
	"masscan": true, "nmap": true, "zmap": true, "screen": true, "tmux": true, "lscpu": true, "uname": true,
}

var (
	cmdSplit  = regexp.MustCompile(`[;\n|&]+`)
	installRe = regexp.MustCompile(`(?i)\b(?:apt(?:-get)?|yum|dnf|apk|pip3?|npm|opkg)\s+(?:-\S+\s+)*(?:install|add)\s+((?:[\w.+-]+\s*){1,6})`)
	pullRe    = regexp.MustCompile(`(?i)\b(?:docker\s+)?pull\s+([\w./:-]+)|\bcreate image=([\w./:-]+)`)
	// Zieldatei: "-O datei", "-o datei" oder Umleitung "> datei" (nicht "</tag>" oder "2>&1")
	outFileRe   = regexp.MustCompile(`(?:\s-[Oo]|(?:^|\s)>{1,2})\s*([\w./-]{1,80})`)
	uaToolRe    = regexp.MustCompile(`(?i)\b(zgrab|masscan|nmap|censys|shodan|nuclei|sqlmap|nikto|gobuster|dirbuster|wpscan|hydra|python-requests|python-urllib|aiohttp|go-http-client|curl|wget|libwww-perl|okhttp|java|httpx|l9explore|l9tcpid|expanse|internetmeasurement|netcraft|bingbot|googlebot)\b`)
	sshClientRe = regexp.MustCompile(`(?i)^SSH-[\d.]+-([A-Za-z_]+)`)
)

// commandTools liefert Werkzeuge und installierte Pakete aus einer Befehlszeile.
// Installierte Pakete und gezogene Images erscheinen als "installiert: <name>".
func commandTools(line string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] && len(out) < 12 {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, part := range cmdSplit.Split(line, 24) {
		for _, w := range strings.Fields(part) {
			if strings.Contains(w, "=") && !strings.HasPrefix(w, "/") { // VAR=wert vor dem Befehl
				continue
			}
			w = strings.ToLower(path.Base(w))
			if w == "sudo" || w == "nohup" {
				add(w)
				continue // das eigentliche Programm folgt
			}
			if toolWords[w] {
				add(w)
			}
			break
		}
	}
	for _, m := range installRe.FindAllStringSubmatch(line, 4) {
		for _, p := range strings.Fields(m[1]) {
			if !strings.HasPrefix(p, "-") {
				add("installiert: " + clip(p, 48))
			}
		}
	}
	for _, m := range pullRe.FindAllStringSubmatch(line, 4) {
		add("installiert: Image " + clip(m[1]+m[2], 64))
	}
	return out
}

// eventTools liefert die Werkzeuge eines Ereignisses (Befehl, User-Agent, SSH-Client).
func eventTools(e *Event) []string {
	switch e.Type {
	case "command":
		return commandTools(dataString(e.Data, "input"))
	case "request":
		if m := uaToolRe.FindString(dataString(e.Data, "user_agent")); m != "" {
			return []string{"Scanner: " + strings.ToLower(m)}
		}
	case "client_version":
		if m := sshClientRe.FindStringSubmatch(dataString(e.Data, "version")); m != nil {
			return []string{"SSH-Client: " + m[1]}
		}
	}
	return nil
}

// ---- Bericht ----

type Count struct {
	Key   string `json:"key"`
	N     int    `json:"n"`
	Label string `json:"label,omitempty"`
}

type TagHit struct {
	ID      string   `json:"id"`
	Mitre   []string `json:"mitre,omitempty"` // MITRE-ATT&CK-Techniken (cve.go)
	Name    string   `json:"name"`
	Desc    string   `json:"desc"`
	Sev     int      `json:"sev"`
	N       int      `json:"n"`
	Example string   `json:"example"`
}

// Report fasst zusammen, was ein Angreifer (eine IP oder eine Sitzung) getan hat.
type Report struct {
	Subject   string    `json:"subject"`
	Origin    string    `json:"origin"`
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
	Events    int       `json:"events"`
	Sessions  int       `json:"sessions"`
	Services  []Count   `json:"services"`
	Logins    int       `json:"logins"`
	LoginsOK  int       `json:"logins_ok"`
	Creds     []Count   `json:"creds"`
	Tags      []TagHit  `json:"tags"`
	Tools     []Count   `json:"tools"`
	URLs      []string  `json:"urls"`
	Hashes    []string  `json:"hashes"`
	Files     []string  `json:"files"`
	Commands  []string  `json:"commands"`
	Decoded   []string  `json:"decoded"` // entschlüsselte Inhalte (Base64, Hex …)
	Timeline  []string  `json:"-"`       // Ablauf für die KI-Auswertung
	Requests  []Count   `json:"requests"`
	Clients   []string  `json:"clients"`
	CVEs      []Count   `json:"cves"`       // bekannte Lücken (cve.go)
	AIReplies []AIReply `json:"ai_replies"` // Antworten des Sprachmodells an den Angreifer
	TarpitMs  int64     `json:"tarpit_ms"`
	Severity  string    `json:"severity"` // niedrig | mittel | hoch
	Summary   []string  `json:"summary"`
	Truncated bool      `json:"truncated"` // es gab mehr Ereignisse als ausgewertet
}

const (
	reportMaxList     = 40
	reportMaxText     = 400 // Zeichen je Befehl bzw. Beispiel
	reportMaxTimeline = 600 // Zeilen im Ablauf (für die KI-Auswertung)
)

// timelineLine beschreibt ein Ereignis in einer Zeile für den Ablauf. Verbindungsende
// und reine Fingerabdrücke fehlen; entschlüsselte Inhalte stehen dahinter.
func timelineLine(e *Event, kind evKind, text string, revealed []string, loc *time.Location) string {
	var d string
	switch {
	case kind == kindTLSPlain:
		d = "TLS-Handshake auf Klartext-Port (kein Befehl)"
	case kind == kindPrompt:
		lines, _ := promptLines(e)
		d = "Eingabe an der Login-Abfrage (keine Zugangsdaten): " + strings.Join(lines, " ⏎ ")
	case e.Type == "command" && kind != kindExec:
		d = "Protokoll-Befehl vor der Anmeldung: " + text
	}
	switch e.Type {
	case "disconnect", "fingerprint", "tls":
		if d == "" {
			return ""
		}
	case "connect":
		d = "Verbindung"
	case "login":
		switch {
		case d != "":
		case dataString(e.Data, "cookie") != "":
			d = "Login-Versuch (RDP, nur Benutzername) " + e.Username
		case dataBool(e.Data, "password_hashed"):
			d = "Login-Versuch " + e.Username + " / (Passwort nur als Hash übertragen)"
		default:
			d = "Login-Versuch " + e.Username + " / " + e.Password
		}
		if dataBool(e.Data, "success") || dataBool(e.Data, "accepted") {
			d += " → vom Honeypot angenommen"
		}
	case "command":
		if d == "" {
			d = "Befehl: " + text
		}
	case "request":
		d = "Anfrage: " + strings.TrimSpace(dataString(e.Data, "method")+" "+dataString(e.Data, "path"))
		if ua := dataString(e.Data, "user_agent"); ua != "" {
			d += " (User-Agent: " + clip(ua, 120) + ")"
		}
		if b := strings.TrimSpace(dataString(e.Data, "body")); b != "" {
			d += " Body: " + clip(b, 300)
		}
	case "download":
		d = "Download: " + nonEmptyFirst(dataString(e.Data, "url"), dataString(e.Data, "filename"))
		if h := dataString(e.Data, "sha256"); h != "" {
			d += " (SHA-256 " + h + ")"
		}
		if strings.Contains(string(e.Data), `"failed":true`) {
			d += " (fehlgeschlagen)"
		}
	case "client_version":
		d = "Client: " + dataString(e.Data, "version")
	case "payload":
		d = "Daten: " + text
	case "tty":
		d = "Terminal-Mitschnitt vorhanden"
	case "ai_reply":
		d = "Antwort der KI (vom Honeypot ausgeliefert) auf „" + clip(dataString(e.Data, "input"), 200) + "“: " + clip(strings.Join(strings.Fields(dataString(e.Data, "output")), " "), 300)
	default:
		d = e.Type + ": " + text
	}
	d = clip(strings.ReplaceAll(strings.TrimSpace(d), "\n", " "), reportMaxText)
	for _, r := range revealed {
		d += "\n      entschlüsselt: " + clip(strings.ReplaceAll(r, "\n", " ⏎ "), reportMaxText)
	}
	return fmt.Sprintf("%s [%s:%d] %s", e.TS.In(loc).Format("15:04:05"), e.Service, e.DstPort, d)
}

func nonEmptyFirst(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

type counter struct {
	n     map[string]int
	order []string
}

func (c *counter) add(k string) {
	if k == "" {
		return
	}
	if c.n == nil {
		c.n = map[string]int{}
	}
	if c.n[k] == 0 {
		if len(c.order) >= 2000 { // Obergrenze für den Speicher
			return
		}
		c.order = append(c.order, k)
	}
	c.n[k]++
}

// top liefert die häufigsten Einträge; bei Gleichstand in der Reihenfolge des ersten Auftretens.
func (c *counter) top(max int) []Count {
	out := make([]Count, 0, len(c.order))
	for _, k := range c.order {
		out = append(out, Count{Key: k, N: c.n[k]})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].N > out[j].N })
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// keys liefert nie nil: Die UI erwartet im JSON Listen, kein null.
func (c *counter) keys(max int) []string {
	if len(c.order) > max {
		return c.order[:max]
	}
	if c.order == nil {
		return []string{}
	}
	return c.order
}

// BuildReport wertet Ereignisse aus (aufsteigend nach Zeit). subject ist die Überschrift.
func BuildReport(subject string, evs []*Event, truncated bool) *Report {
	r := &Report{Subject: subject, Events: len(evs), Truncated: truncated, Severity: "niedrig", Tags: []TagHit{}, AIReplies: []AIReply{}}
	var services, creds, tools, urls, hashes, files, cmds, reqs, clients, sessions, decoded, cves counter
	loc, _ := time.LoadLocation("Local")
	var lastBody, lastLine string
	repeat := 0
	tags := map[string]*TagHit{}
	okSess := map[string]bool{} // Sitzungen mit angenommenem Login (einstufung.go)
	maxSev := 0
	for _, e := range evs {
		if r.First.IsZero() || e.TS.Before(r.First) {
			r.First = e.TS
		}
		if e.TS.After(r.Last) {
			r.Last = e.TS
		}
		if r.Origin == "" && e.Country != "" {
			r.Origin = strings.Join(nonEmpty(e.City, e.CountryName), ", ")
			if e.ASN != 0 {
				r.Origin += fmt.Sprintf(" · AS%d %s", e.ASN, e.ASOrg)
			}
		}
		sessions.add(e.Session)
		r.TarpitMs += e.TarpitMs
		text, on, revealed := analysisText(e)
		for _, d := range revealed {
			decoded.add(clip(d, reportMaxText*2))
		}
		kind := eventKind(e, okSess[e.Session])
		if line := timelineLine(e, kind, text, revealed, loc); line != "" {
			// gleiche Zeile direkt hintereinander (ohne Uhrzeit) nur einmal, mit Zähler
			body := line[8:]
			if n := len(r.Timeline); n > 0 && lastBody == body {
				repeat++
				r.Timeline[n-1] = lastLine + fmt.Sprintf("  (×%d bis %s)", repeat, e.TS.In(loc).Format("15:04:05"))
			} else if len(r.Timeline) < reportMaxTimeline {
				r.Timeline = append(r.Timeline, line)
				lastBody, lastLine, repeat = body, line, 1
			}
		}
		for _, id := range eventPatterns(e, text, on, revealed) {
			p := patternByID[id]
			t := tags[id]
			if t == nil {
				t = &TagHit{ID: id, Name: p.Name, Desc: p.Desc, Sev: p.Sev, Example: clip(strings.TrimSpace(text), reportMaxText), Mitre: patternMitre[id]}
				tags[id] = t
			}
			t.N++
			maxSev = max(maxSev, p.Sev)
		}
		for _, t := range eventTools(e) {
			tools.add(t)
		}
		for _, c := range eventCVEs(text, on) {
			cves.add(c.CVE)
			maxSev = 3
		}
		for _, u := range allURLs(text, revealed, 8) {
			urls.add(clip(u, 300))
		}
		switch e.Type {
		case "connect":
			services.add(fmt.Sprintf("%s:%d", e.Service, e.DstPort))
		case "login":
			if kind == kindPrompt {
				lines, _ := promptLines(e)
				for _, l := range lines {
					cmds.add("an der Login-Abfrage: " + clip(l, reportMaxText))
				}
				break
			}
			r.Logins++
			if dataBool(e.Data, "success") || dataBool(e.Data, "accepted") {
				r.LoginsOK++
				maxSev = max(maxSev, 2)
				okSess[e.Session] = true
			}
			switch {
			case strings.Contains(string(e.Data), `"password_hashed":true`):
				creds.add(e.Username + " / (gehasht)")
			default:
				creds.add(e.Username + " / " + e.Password)
			}
		case "command":
			if kind == kindTLSPlain {
				break
			}
			if kind != kindExec {
				cmds.add("vor der Anmeldung: " + clip(strings.TrimSpace(text), reportMaxText))
				maxSev = max(maxSev, 1)
				break
			}
			cmds.add(clip(strings.TrimSpace(text), reportMaxText))
			for _, m := range outFileRe.FindAllStringSubmatch(text, 6) {
				if f := m[1]; f != "/dev/null" && f != "-" && !strings.HasPrefix(f, "/dev/") {
					files.add(f)
				}
			}
			maxSev = max(maxSev, 2)
		case "request":
			if fw := dataString(e.Data, "forward_to"); fw != "" {
				reqs.add("Weiterleitung nach " + clip(fw, 200))
			} else {
				if e.Service == "sip" || e.Service == "dns" {
					reqs.add(clip(e.Service+": "+requestKey(e), 200))
				} else {
					reqs.add(clip(dataString(e.Data, "method")+" "+dataString(e.Data, "path"), 200))
				}
			}
		case "download":
			hashes.add(dataString(e.Data, "sha256"))
			files.add(clip(dataString(e.Data, "filename"), 120))
			if !strings.Contains(string(e.Data), `"failed":true`) {
				maxSev = 3
			}
		case "client_version":
			clients.add(clip(dataString(e.Data, "version"), 120))
		case "ai_reply":
			if len(r.AIReplies) < 20 {
				r.AIReplies = append(r.AIReplies, aiReplyFrom(e))
			}
		}
		for _, f := range eventFingerprints(e) {
			clients.add(f)
		}
	}
	r.Sessions = len(sessions.order)
	r.Services, r.Creds, r.Tools = services.top(20), creds.top(reportMaxList), tools.top(reportMaxList)
	r.URLs, r.Hashes, r.Files = urls.keys(reportMaxList), hashes.keys(reportMaxList), files.keys(reportMaxList)
	r.Commands, r.Requests, r.Clients = cmds.keys(80), reqs.top(reportMaxList), clients.keys(12)
	r.Decoded = decoded.keys(reportMaxList)
	r.CVEs = cves.top(reportMaxList)
	for i := range r.CVEs {
		r.CVEs[i].Label = cveByID[r.CVEs[i].Key].Name
	}
	for _, t := range tags {
		r.Tags = append(r.Tags, *t)
	}
	sort.Slice(r.Tags, func(i, j int) bool {
		if r.Tags[i].Sev != r.Tags[j].Sev {
			return r.Tags[i].Sev > r.Tags[j].Sev
		}
		if r.Tags[i].N != r.Tags[j].N {
			return r.Tags[i].N > r.Tags[j].N
		}
		return r.Tags[i].ID < r.Tags[j].ID
	})
	r.Severity = map[int]string{0: "niedrig", 1: "niedrig", 2: "mittel", 3: "hoch"}[maxSev]
	r.Summary = r.summarize()
	return r
}

func nonEmpty(s ...string) []string {
	var out []string
	for _, x := range s {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

func countList(c []Count, max int) string {
	var p []string
	for i, x := range c {
		if i == max {
			p = append(p, fmt.Sprintf("und %d weitere", len(c)-max))
			break
		}
		p = append(p, fmt.Sprintf("%s (%d×)", x.Key, x.N))
	}
	return strings.Join(p, ", ")
}

// summarize schreibt die Kurzfassung in ganzen Sätzen.
func (r *Report) summarize() []string {
	var s []string
	if r.Events == 0 {
		return []string{"Keine Ereignisse gefunden."}
	}
	loc, _ := time.LoadLocation("Local")
	span := r.First.In(loc).Format("02.01.2006 15:04") + " bis " + r.Last.In(loc).Format("02.01.2006 15:04")
	from := ""
	if r.Origin != "" {
		from = " aus " + r.Origin
	}
	s = append(s, fmt.Sprintf("%d Ereignisse in %d Verbindungen%s, %s.", r.Events, r.Sessions, from, span))
	if len(r.Services) > 0 {
		s = append(s, "Angesprochene Dienste: "+countList(r.Services, 8)+".")
	}
	if r.Logins > 0 {
		t := fmt.Sprintf("%d Login-Versuche mit %d verschiedenen Kombinationen", r.Logins, len(r.Creds))
		if r.Logins == 1 {
			t = "1 Login-Versuch"
		}
		if r.LoginsOK > 0 {
			t += fmt.Sprintf("; %d davon hat der Honeypot als erfolgreich gewertet", r.LoginsOK)
		}
		s = append(s, t+".")
	}
	for _, t := range r.Tags {
		s = append(s, fmt.Sprintf("%s (%d×): %s", t.Name, t.N, t.Desc))
	}
	for _, c := range r.CVEs {
		s = append(s, fmt.Sprintf("Versuch, eine bekannte Lücke auszunutzen: %s, %s (%d×).", c.Key, c.Label, c.N))
	}
	if len(r.Tools) > 0 {
		s = append(s, "Benutzte Werkzeuge: "+countList(r.Tools, 12)+".")
	}
	if len(r.Decoded) > 0 {
		s = append(s, fmt.Sprintf("Verschleierte Inhalte entschlüsselt: %d (siehe Liste).", len(r.Decoded)))
	}
	if len(r.URLs) > 0 {
		s = append(s, fmt.Sprintf("Nachlade-Adressen: %d (siehe Liste).", len(r.URLs)))
	}
	if r.TarpitMs > 0 {
		s = append(s, fmt.Sprintf("Im Tarpit festgehalten: %s.", (time.Duration(r.TarpitMs)*time.Millisecond).Round(time.Second)))
	}
	switch r.Severity {
	case "hoch":
		s = append(s, "Einstufung hoch: Es wurde versucht, Schadcode nachzuladen, sich dauerhaft einzunisten oder das System zu übernehmen.")
	case "mittel":
		s = append(s, "Einstufung mittel: Zugriffsversuche oder Befehle, aber kein erkennbarer Schadcode.")
	default:
		s = append(s, "Einstufung niedrig: Scan oder Erkundung ohne weitergehende Aktionen.")
	}
	if r.Truncated {
		s = append(s, "Hinweis: Es gab mehr Ereignisse, als ausgewertet wurden; der Bericht zeigt die neuesten.")
	}
	return s
}

// Text liefert den Bericht als reinen Text (Kopieren, Export, KI-Auswertung).
func (r *Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Angriffsbericht: %s\nEinstufung: %s\n\n", r.Subject, r.Severity)
	for _, l := range r.Summary {
		b.WriteString("- " + l + "\n")
	}
	sec := func(title string, lines []string) {
		if len(lines) == 0 {
			return
		}
		b.WriteString("\n" + title + ":\n")
		for _, l := range lines {
			b.WriteString("  " + l + "\n")
		}
	}
	cl := func(c []Count) []string {
		out := make([]string, len(c))
		for i, x := range c {
			out[i] = fmt.Sprintf("%d× %s", x.N, x.Key)
		}
		return out
	}
	var ex []string
	for _, t := range r.Tags {
		l := t.Name + ": " + t.Example
		if len(t.Mitre) > 0 {
			l += " [MITRE ATT&CK " + strings.Join(t.Mitre, ", ") + "]"
		}
		ex = append(ex, l)
	}
	sec("Beispiele je Muster", ex)
	var cl2 []string
	for _, c := range r.CVEs {
		cl2 = append(cl2, fmt.Sprintf("%s %s (%d×)", c.Key, c.Label, c.N))
	}
	sec("Bekannte Lücken (CVE)", cl2)
	sec("Zugangsdaten", cl(r.Creds))
	sec("Befehle (in Reihenfolge)", r.Commands)
	sec("Entschlüsselte Inhalte (Base64, Hex, URL-Kodierung)", r.Decoded)
	sec("Anfragen", cl(r.Requests))
	sec("Werkzeuge", cl(r.Tools))
	sec("Adressen", r.URLs)
	sec("Dateien", r.Files)
	sec("SHA-256 der Downloads", r.Hashes)
	sec("Clients", r.Clients)
	var ai []string
	for _, x := range r.AIReplies {
		ai = append(ai, fmt.Sprintf("%s %s → %s", x.Kind, x.Input, clip(strings.Join(strings.Fields(x.Output), " "), 300)))
	}
	sec("Antworten der KI (vom Honeypot ausgeliefert, nichts ausgeführt)", ai)
	if len(r.Timeline) > 0 {
		title := "Ablauf (Uhrzeit [Dienst:Port] Ereignis; gleiche Zeilen hintereinander zusammengefasst)"
		if len(r.Timeline) >= reportMaxTimeline {
			title += fmt.Sprintf("; nur die ersten %d Zeilen", reportMaxTimeline)
		}
		sec(title, r.Timeline)
	}
	return b.String()
}
