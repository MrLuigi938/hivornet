package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"
)

// ---------------- FTP ----------------

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
	user := ""
	for i := 0; i < 30; i++ {
		s.ReadDeadline(60 * time.Second)
		line, err := readLine(br, 1024)
		if err != nil {
			return
		}
		cmd, arg, _ := strings.Cut(strings.TrimSpace(line), " ")
		reply := "530 Please login with USER and PASS.\r\n"
		switch strings.ToUpper(cmd) {
		case "USER":
			user = arg
			reply = "331 Please specify the password.\r\n"
		case "PASS":
			s.Login(user, arg, nil)
			if s.Mode == "hybrid" {
				s.Tarpit(nil, func() []byte { return []byte("530-" + randWord(10, 40) + "\r\n") })
				return
			}
			reply = "530 Login incorrect.\r\n"
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

func redisInfo() string {
	return "# Server\r\nredis_version:6.2.14\r\nredis_mode:standalone\r\nos:Linux 5.15.0-91-generic x86_64\r\narch_bits:64\r\n" +
		fmt.Sprintf("tcp_port:6379\r\nuptime_in_seconds:%d\r\nuptime_in_days:%d\r\n", redisUptime, redisUptime/86400) +
		"executable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\n" +
		"\r\n# Clients\r\nconnected_clients:1\r\n\r\n# Memory\r\n" +
		fmt.Sprintf("used_memory:%d\r\nused_memory_human:%.2fM\r\n", redisMemUsed, float64(redisMemUsed)/1048576) +
		"\r\n# Persistence\r\nloading:0\r\nrdb_bgsave_in_progress:0\r\nrdb_last_bgsave_status:ok\r\n" +
		"\r\n# Replication\r\nrole:master\r\nconnected_slaves:0\r\n\r\n# Keyspace\r\n" +
		fmt.Sprintf("db0:keys=%d,expires=0,avg_ttl=0\r\n", redisKeys)
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
			reply = bulk(redisInfo())
		case "CONFIG":
			if sub == "GET" && len(args) > 2 {
				switch strings.ToLower(args[2]) {
				case "dir":
					reply = "*2\r\n" + bulk("dir") + bulk("/var/lib/redis")
				case "dbfilename":
					reply = "*2\r\n" + bulk("dbfilename") + bulk("dump.rdb")
				default:
					reply = "*0\r\n"
				}
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

func mysqlHandshake(salt []byte) []byte {
	p := []byte{10}
	p = append(p, "5.7.44-log"...)
	p = append(p, 0)
	p = binary.LittleEndian.AppendUint32(p, rand.Uint32N(90000)+1000)
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
	if s.Write(mysqlHandshake(salt)) != nil {
		return
	}
	s.ReadDeadline(30 * time.Second)
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(s.Conn, hdr); err != nil {
		return
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n < 32 || n > 64<<10 {
		return
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(s.Conn, p); err != nil {
		return
	}
	lg, ok := parseMySQLLogin(p)
	if !ok || lg.SSL {
		return
	}
	data := map[string]any{"password_hashed": true}
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
	buf := make([]byte, 4096)
	n, _ := io.ReadAtLeast(s.Conn, buf, 1)
	if n > 0 {
		s.Emit(Event{Type: "payload", Data: map[string]any{"text": printable(buf[:n], budgetText), "bytes": n}})
	}
	if s.Mode == "hybrid" {
		s.Tarpit(nil, drip)
	}
}
