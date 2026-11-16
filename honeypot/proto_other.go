package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"path"
	"strconv"
	"strings"
	"time"
)

// ---------------- FTP ----------------

// ftpFiles: Schein-Verzeichnis nach dem Login (Köderdateien aus bait.go).
func ftpFiles() map[string][]string {
	b := bait()
	return map[string][]string{
		"/":       {"drwxr-xr-x    2 1001     1001         4096 Nov 03 02:15 backup", "drwxr-xr-x    2 0        0            4096 Sep 21 11:40 pub"},
		"/backup": {"-rw-r--r--    1 1001     1001      4718203 Nov 03 02:15 db-" + b.DBName + ".sql.gz", "-rw-r--r--    1 1001     1001          912 Sep 21 11:42 config.php.bak"},
		"/pub":    {},
	}
}

func ftpPath(cwd, arg string) string {
	if arg == "" {
		return cwd
	}
	if !strings.HasPrefix(arg, "/") {
		arg = cwd + "/" + arg
	}
	return path.Clean(arg)
}

// handleFTP spielt vsftpd nach. Anonym (anonymous/ftp) und mit den Köder-Zugangsdaten
// gelingt die Anmeldung; danach gibt es ein kleines Schein-Verzeichnis. Datenverbindungen
// (PASV/PORT) baut der Honeypot bewusst nicht auf: PORT hieße eine ausgehende Verbindung,
// PASV ein weiterer offener Port, den kein Router weiterleitet. LIST, RETR und STOR werden
// deshalb nur aufgezeichnet und mit der Fehlermeldung von vsftpd beantwortet.
func handleFTP(s *Session) {
	drip := func() []byte { return []byte("220-" + randWord(10, 40) + "\r\n") }
	if s.Mode == "tarpit" {
		s.Tarpit(nil, drip)
		return
	}
	if s.WriteString("220 (vsFTPd 3.0.5)\r\n") != nil {
		return
	}
	br := bufio.NewReader(s.Conn)
	user, cwd, in := "", "/", false
	for i := 0; i < 40; i++ {
		s.ReadDeadline(60 * time.Second)
		if i == 0 && s.sniffTLS(br) {
			return
		}
		line, err := readLine(br, 1024)
		if err != nil {
			return
		}
		cmd, arg, _ := strings.Cut(strings.TrimSpace(line), " ")
		reply := "530 Please login with USER and PASS.\r\n"
		up := strings.ToUpper(cmd)
		if in {
			if r, ok := ftpLoggedIn(s, up, arg, line, &cwd); ok {
				if s.WriteString(r) != nil || up == "QUIT" {
					return
				}
				continue
			}
		}
		switch up {
		case "USER":
			user = arg
			reply = "331 Please specify the password.\r\n"
		case "PASS":
			b := bait()
			lu := strings.ToLower(user)
			in = lu == "anonymous" || lu == "ftp" || user == b.User && arg == b.Pass
			s.Login(user, arg, map[string]any{"accepted": in})
			if s.Mode == "hybrid" {
				s.Tarpit(nil, func() []byte { return []byte("530-" + randWord(10, 40) + "\r\n") })
				return
			}
			reply = "530 Login incorrect.\r\n"
			if in {
				reply = "230 Login successful.\r\n"
			}
		case "QUIT":
			s.WriteString("221 Goodbye.\r\n")
			return
		case "SYST":
			reply = "215 UNIX Type: L8\r\n"
		case "FEAT":
			reply = "211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n"
		case "":
			continue
		default:
			s.Command(printable([]byte(line), 512), nil)
		}
		if s.WriteString(reply) != nil {
			return
		}
	}
}

// ftpLoggedIn beantwortet Befehle nach dem Login. ok=false: wie vor dem Login behandeln.
func ftpLoggedIn(s *Session, cmd, arg, line string, cwd *string) (string, bool) {
	files := ftpFiles()
	switch cmd {
	case "PWD", "XPWD":
		return "257 \"" + *cwd + "\" is the current directory\r\n", true
	case "CWD", "XCWD", "CDUP":
		p := ftpPath(*cwd, arg)
		if cmd == "CDUP" {
			p = path.Dir(*cwd)
		}
		if _, ok := files[p]; ok {
			*cwd = p
			return "250 Directory successfully changed.\r\n", true
		}
		return "550 Failed to change directory.\r\n", true
	case "TYPE":
		return "200 Switching to Binary mode.\r\n", true
	case "SIZE", "MDTM":
		p := ftpPath(*cwd, arg)
		for _, f := range files[path.Dir(p)] {
			if fs := strings.Fields(f); len(fs) == 9 && fs[8] == path.Base(p) && f[0] == '-' {
				if cmd == "SIZE" {
					return "213 " + fs[4] + "\r\n", true
				}
				return "213 20261103021500\r\n", true
			}
		}
		return "550 Could not get file size.\r\n", true
	case "PASV", "EPSV":
		return "500 OOPS: vsf_sysutil_bind\r\n", true
	case "PORT", "EPRT":
		return "500 Illegal PORT command.\r\n", true
	case "LIST", "NLST", "RETR", "STOR", "APPE", "STOU":
		// aufzeichnen, aber ohne Datenverbindung nichts übertragen (siehe handleFTP)
		data := map[string]any{"cwd": *cwd}
		if cmd == "STOR" || cmd == "APPE" || cmd == "STOU" {
			data["upload"] = true
		}
		s.Command(printable([]byte(line), 512), data)
		return "425 Use PORT or PASV first.\r\n", true
	case "DELE", "MKD", "XMKD", "RMD", "XRMD", "RNFR", "RNTO", "SITE":
		s.Command(printable([]byte(line), 512), map[string]any{"cwd": *cwd})
		return "550 Permission denied.\r\n", true
	case "QUIT":
		return "221 Goodbye.\r\n", true
	}
	return "", false
}

// ---------------- Redis ----------------

var redisWrite = map[string]bool{
	"SET": true, "CONFIG": true, "SLAVEOF": true, "REPLICAOF": true, "MODULE": true, "EVAL": true,
	"EVALSHA": true, "FLUSHALL": true, "FLUSHDB": true, "SAVE": true, "BGSAVE": true, "SCRIPT": true,
	"DEBUG": true, "SYSTEM.EXEC": true, "MIGRATE": true,
}

const (
	redisMaxArgs     = 64
	redisMaxArgLen   = 512 << 10 // laut Protokoll angekündigte Länge; wird gestreamt, nicht gepuffert
	redisKeepPerArg  = 4096      // so viel eines Arguments wird behalten
	redisKeepPerCmd  = 64 << 10  // so viel eines Befehls insgesamt
	redisInlineLimit = 16 << 10
)

// readRESP liest einen Befehl. Lange Argumente werden nach redisKeepPerArg Bytes
// verworfen (gelesen, aber nicht gespeichert); truncated meldet das.
func readRESP(br *bufio.Reader) (args []string, truncated bool, err error) {
	line, err := readLine(br, redisInlineLimit)
	if err != nil {
		return nil, false, err
	}
	if line == "" {
		return nil, false, nil
	}
	if line[0] != '*' {
		return strings.Fields(line), false, nil // Inline-Kommando, z. B. per netcat
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil || n < 0 || n > redisMaxArgs {
		return nil, false, errors.New("ungültiges RESP-Array")
	}
	args = make([]string, 0, n)
	kept := 0
	for i := 0; i < n; i++ {
		l, err := readLine(br, 64)
		if err != nil {
			return nil, false, err
		}
		if len(l) < 2 || l[0] != '$' {
			return nil, false, errors.New("ungültiger RESP-String")
		}
		ln, err := strconv.Atoi(l[1:])
		if err != nil || ln < 0 || ln > redisMaxArgLen {
			return nil, false, errors.New("ungültige RESP-Länge")
		}
		keep := min(ln, redisKeepPerArg, redisKeepPerCmd-kept)
		buf := make([]byte, keep)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, false, err
		}
		if rest := int64(ln - keep + 2); rest > 0 { // Rest + CRLF verwerfen
			if _, err := io.CopyN(io.Discard, br, rest); err != nil {
				return nil, false, err
			}
		}
		if keep < ln {
			truncated = true
		}
		kept += keep
		args = append(args, string(buf))
	}
	return args, truncated, nil
}

func bulk(s string) string { return fmt.Sprintf("$%d\r\n%s\r\n", len(s), s) }

// Werte pro Prozessstart variieren, damit nicht jeder Hivornet gleich aussieht.
var (
	redisUptime  = 86400*7 + rand.IntN(86400*60)
	redisMemUsed = 900000 + rand.IntN(4000000)
	redisKeys    = 2 + rand.IntN(40)
)

// redisInfo liefert INFO wie Redis 6.2: ohne Argument bzw. "default"/"all" alle
// Abschnitte, sonst nur den genannten (unbekannt: leer).
func redisInfo(section string) string {
	secs := [][2]string{
		{"server", "# Server\r\nredis_version:6.2.14\r\nredis_git_sha1:00000000\r\nredis_mode:standalone\r\nos:Linux 5.15.0-91-generic x86_64\r\narch_bits:64\r\n" +
			"multiplexing_api:epoll\r\ngcc_version:11.4.0\r\nprocess_id:1123\r\n" +
			fmt.Sprintf("tcp_port:6379\r\nuptime_in_seconds:%d\r\nuptime_in_days:%d\r\n", redisUptime, redisUptime/86400) +
			"hz:10\r\nexecutable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\n"},
		{"clients", "# Clients\r\nconnected_clients:1\r\nblocked_clients:0\r\n"},
		{"memory", "# Memory\r\n" + fmt.Sprintf("used_memory:%d\r\nused_memory_human:%.2fM\r\n", redisMemUsed, float64(redisMemUsed)/1048576) +
			"maxmemory:0\r\nmaxmemory_policy:noeviction\r\nmem_allocator:jemalloc-5.1.0\r\n"},
		{"persistence", "# Persistence\r\nloading:0\r\nrdb_bgsave_in_progress:0\r\nrdb_last_bgsave_status:ok\r\naof_enabled:0\r\n"},
		{"stats", fmt.Sprintf("# Stats\r\ntotal_connections_received:%d\r\ntotal_commands_processed:%d\r\nrejected_connections:0\r\n", redisUptime/97, redisUptime/11)},
		{"replication", "# Replication\r\nrole:master\r\nconnected_slaves:0\r\nmaster_repl_offset:0\r\n"},
		{"cpu", fmt.Sprintf("# CPU\r\nused_cpu_sys:%.2f\r\nused_cpu_user:%.2f\r\n", float64(redisUptime)/2900, float64(redisUptime)/1700)},
		{"keyspace", "# Keyspace\r\n" + fmt.Sprintf("db0:keys=%d,expires=0,avg_ttl=0\r\n", redisKeys)},
	}
	section = strings.ToLower(section)
	var parts []string
	for _, s := range secs {
		if section == "" || section == "default" || section == "all" || section == "everything" || section == s[0] {
			parts = append(parts, s[1])
		}
	}
	return strings.Join(parts, "\r\n")
}

// redisConfig: Werte für CONFIG GET (Auswahl, wie ein Debian-Paket sie mitbringt).
var redisConfig = [][2]string{
	{"dbfilename", "dump.rdb"}, {"requirepass", ""}, {"masterauth", ""}, {"unixsocket", ""}, {"logfile", "/var/log/redis/redis-server.log"},
	{"pidfile", "/run/redis/redis-server.pid"}, {"maxmemory", "0"}, {"maxmemory-policy", "noeviction"}, {"timeout", "0"},
	{"tcp-keepalive", "300"}, {"databases", "16"}, {"maxclients", "10000"}, {"port", "6379"}, {"bind", "* -::*"},
	{"protected-mode", "no"}, {"daemonize", "yes"}, {"supervised", "systemd"}, {"loglevel", "notice"}, {"appendonly", "no"},
	{"appendfilename", "appendonly.aof"}, {"appendfsync", "everysec"}, {"save", "3600 1 300 100 60 10000"},
	{"slave-read-only", "yes"}, {"replica-read-only", "yes"}, {"dir", "/var/lib/redis"}, {"hz", "10"}, {"io-threads", "1"},
}

func redisConfigGet(patterns []string) string {
	var out []string
	seen := map[string]bool{}
	for _, p := range patterns {
		p = strings.ToLower(p)
		for _, kv := range redisConfig {
			if ok, _ := path.Match(p, kv[0]); ok && !seen[kv[0]] {
				seen[kv[0]] = true
				out = append(out, bulk(kv[0]), bulk(kv[1]))
			}
		}
	}
	return fmt.Sprintf("*%d\r\n", len(out)) + strings.Join(out, "")
}

func handleRedis(s *Session) {
	drip := func() []byte { return []byte(randWord(1, 3)) }
	if s.Mode == "tarpit" {
		s.Tarpit([]byte("+"), drip)
		return
	}
	br := bufio.NewReader(s.Conn)
	for i := 0; i < 200; i++ {
		s.ReadDeadline(120 * time.Second)
		if i == 0 && s.sniffTLS(br) {
			return
		}
		args, truncated, err := readRESP(br)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		cmd := strings.ToUpper(args[0])
		sub := ""
		if len(args) > 1 {
			sub = strings.ToUpper(args[1])
		}
		if cmd == "AUTH" {
			user, pass := "default", ""
			if len(args) == 2 {
				pass = args[1]
			} else if len(args) >= 3 {
				user, pass = args[1], args[2]
			}
			s.Login(user, pass, nil)
		} else {
			var data map[string]any
			if truncated {
				data = map[string]any{"truncated": true}
			}
			s.Command(printable([]byte(strings.Join(args, " ")), budgetCommand), data)
		}
		if s.Mode == "hybrid" && redisWrite[cmd] && !(cmd == "CONFIG" && sub == "GET") {
			s.Tarpit([]byte("+"), drip)
			return
		}
		var reply string
		switch cmd {
		case "PING":
			reply = "+PONG\r\n"
			if len(args) > 1 {
				reply = bulk(args[1])
			}
		case "AUTH", "SET", "SELECT", "FLUSHALL", "FLUSHDB", "SAVE", "SLAVEOF", "REPLICAOF", "CLIENT", "EXPIRE", "DEL":
			reply = "+OK\r\n"
		case "BGSAVE":
			reply = "+Background saving started\r\n"
		case "INFO":
			sec := ""
			if len(args) > 1 {
				sec = args[1]
			}
			reply = bulk(redisInfo(sec))
		case "CONFIG":
			if sub == "GET" && len(args) > 2 {
				reply = redisConfigGet(args[2:])
			} else if sub == "GET" {
				reply = "-ERR wrong number of arguments for 'config|get' command\r\n"
			} else {
				reply = "+OK\r\n"
			}
		case "GET", "EVAL", "EVALSHA":
			reply = "$-1\r\n"
		case "KEYS", "COMMAND":
			reply = "*0\r\n"
		case "SCAN":
			reply = "*2\r\n$1\r\n0\r\n*0\r\n"
		case "DBSIZE":
			reply = fmt.Sprintf(":%d\r\n", redisKeys)
		case "MODULE":
			reply = "-ERR Error loading the extension. Please check the server logs.\r\n"
		case "QUIT":
			s.WriteString("+OK\r\n")
			return
		default:
			reply = fmt.Sprintf("-ERR unknown command '%s', with args beginning with: \r\n", printable([]byte(args[0]), 64))
		}
		if s.WriteString(reply) != nil {
			return
		}
	}
}

// ---------------- MySQL ----------------

func mysqlPacket(seq byte, payload []byte) []byte {
	n := len(payload)
	return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}, payload...)
}

// nextMySQLID: Thread-ID der nächsten Verbindung. Ein echter Server zählt sie je
// Verbindung hoch; der Startwert ist zufällig (der Server läuft scheinbar schon länger).
func (m *Manager) nextMySQLID() uint32 {
	if m.mysqlID.Load() == 0 {
		m.mysqlID.CompareAndSwap(0, rand.Uint32N(90000)+1000)
	}
	return m.mysqlID.Add(1)
}

func mysqlHandshake(salt []byte, threadID uint32) []byte {
	p := []byte{10}
	p = append(p, "5.7.44-log"...)
	p = append(p, 0)
	p = binary.LittleEndian.AppendUint32(p, threadID)
	p = append(p, salt[:8]...)
	p = append(p, 0)
	p = binary.LittleEndian.AppendUint16(p, 0xf7ff) // ohne CLIENT_SSL
	p = append(p, 0x21)
	p = binary.LittleEndian.AppendUint16(p, 0x0002)
	p = binary.LittleEndian.AppendUint16(p, 0x81bf) // inkl. PLUGIN_AUTH
	p = append(p, 21)
	p = append(p, make([]byte, 10)...)
	p = append(p, salt[8:20]...)
	p = append(p, 0)
	p = append(p, "mysql_native_password"...)
	p = append(p, 0)
	return mysqlPacket(0, p)
}

func cstr(b []byte, pos int) (string, int) {
	if pos >= len(b) {
		return "", len(b)
	}
	end := pos
	for end < len(b) && b[end] != 0 {
		end++
	}
	return string(b[pos:end]), min(end+1, len(b))
}

type mysqlLogin struct {
	User   string
	Auth   []byte
	DB     string
	Plugin string
	SSL    bool // nur SSL-Anfrage, kein Login
}

// parseMySQLLogin wertet das Handshake-Response-Paket aus (ohne Header).
func parseMySQLLogin(p []byte) (mysqlLogin, bool) {
	var r mysqlLogin
	if len(p) < 32 {
		return r, false
	}
	caps := binary.LittleEndian.Uint32(p[0:4])
	if len(p) == 32 && caps&0x800 != 0 {
		r.SSL = true
		return r, true
	}
	user, pos := cstr(p, 32)
	r.User = user
	switch {
	case caps&0x200000 != 0 || caps&0x8000 != 0: // lenenc bzw. 1-Byte-Länge (für Längen < 251 identisch)
		if pos < len(p) {
			l := int(p[pos])
			pos++
			if l >= 251 { // lenenc mit mehreren Bytes: hier nicht sinnvoll, abbrechen
				return r, true
			}
			end := min(pos+l, len(p))
			r.Auth = p[pos:end]
			pos = end
		}
	default:
		var a string
		a, pos = cstr(p, pos)
		r.Auth = []byte(a)
	}
	if caps&0x8 != 0 {
		r.DB, pos = cstr(p, pos)
	}
	if caps&0x80000 != 0 {
		r.Plugin, _ = cstr(p, pos)
	}
	return r, true
}

func handleMySQL(s *Session) {
	drip := func() []byte { return []byte{byte(rand.IntN(256))} }
	if s.Mode == "tarpit" {
		// Handshake-Paket mit riesiger Länge ankündigen und tröpfchenweise senden
		s.Tarpit([]byte{0xff, 0xff, 0x00, 0x00, 0x0a}, drip)
		return
	}
	salt := make([]byte, 20)
	for i := range salt {
		salt[i] = byte(33 + rand.IntN(90))
	}
	if s.Write(mysqlHandshake(salt, s.m.nextMySQLID())) != nil {
		return
	}
	s.ReadDeadline(30 * time.Second)
	br := bufio.NewReader(s.Conn)
	if s.sniffTLS(br) {
		return
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n < 32 || n > 64<<10 {
		return
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(br, p); err != nil {
		return
	}
	lg, ok := parseMySQLLogin(p)
	if !ok || lg.SSL {
		return
	}
	data := map[string]any{"password_hashed": true}
	if b := bait(); mysqlNativeMatch(salt, lg.Auth, b.Pass) {
		data["bait"] = true // Köder-Passwort, nur als Hash übertragen
	}
	if len(lg.Auth) > 0 {
		data["auth_hex"] = hex.EncodeToString(lg.Auth[:min(len(lg.Auth), 64)])
	}
	if lg.DB != "" {
		data["database"] = printable([]byte(lg.DB), 128)
	}
	if lg.Plugin != "" {
		data["plugin"] = printable([]byte(lg.Plugin), 64)
	}
	s.Login(printable([]byte(lg.User), 256), "", data)
	if s.Mode == "hybrid" {
		s.Tarpit([]byte{0xff, 0xff, 0x00, 0x02, 0xff}, drip)
		return
	}
	using := "NO"
	if len(lg.Auth) > 0 {
		using = "YES"
	}
	msg := fmt.Sprintf("Access denied for user '%s'@'%s' (using password: %s)", clip(lg.User, 64), s.SrcIP, using)
	e := []byte{0xff}
	e = binary.LittleEndian.AppendUint16(e, 1045)
	e = append(e, "#28000"...)
	e = append(e, msg...)
	s.Write(mysqlPacket(2, e))
}

// ---------------- SSH-Tarpit ----------------

func handleSSHTarpit(s *Session) {
	readVersion := func(wait time.Duration) {
		s.ReadDeadline(wait)
		br := bufio.NewReaderSize(s.Conn, 512)
		if line, err := readLine(br, 255); err == nil && strings.HasPrefix(line, "SSH-") {
			s.Emit(Event{Type: "client_version", Data: map[string]any{"version": printable([]byte(line), 255)}})
		}
	}
	drip := func() []byte { return []byte(randWord(8, 32) + "\r\n") }
	switch s.Mode {
	case "emulate":
		if s.WriteString("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n") != nil {
			return
		}
		readVersion(10 * time.Second)
	case "hybrid":
		readVersion(3 * time.Second)
		s.Tarpit(nil, drip)
	default:
		s.Tarpit(nil, drip)
	}
}

// ---------------- generischer Listener ----------------

func handleRaw(s *Session) {
	drip := func() []byte { return []byte{byte(rand.IntN(256))} }
	if s.Mode == "tarpit" {
		s.Tarpit(nil, drip)
		return
	}
	s.ReadDeadline(10 * time.Second)
	br := bufio.NewReaderSize(s.Conn, 4096)
	if s.sniffTLS(br) {
		if s.Mode == "hybrid" {
			s.Tarpit(nil, drip)
		}
		return
	}
	buf := make([]byte, 4096)
	n, _ := io.ReadAtLeast(br, buf, 1)
	if n > 0 {
		s.Emit(Event{Type: "payload", Data: map[string]any{"text": printable(buf[:n], budgetText), "bytes": n}})
	}
	if s.Mode == "hybrid" {
		s.Tarpit(nil, drip)
	}
}
