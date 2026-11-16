package main

// Köder: Der HTTP-Honeypot liefert unter /.env, /.git/config, /robots.txt und ähnlichen
// Pfaden glaubwürdige Dateien statt 404. Die Zugangsdaten darin sind erfunden und je
// Installation eindeutig: abgeleitet per HMAC aus dem Sensor-Token (das Token selbst lässt
// sich daraus nicht zurückrechnen). Der Hive leitet dieselben Werte ab (hive/bait.go) und
// markiert jede spätere Verwendung bei FTP, MySQL, SMTP, Redis, Telnet oder SSH als
// "Köder benutzt". Damit sieht man, wer die Dateien gelesen und die Daten ausprobiert hat.
//
// Die Ableitung muss in beiden Modulen gleich bleiben; TestBaitDerivation prüft einen
// festen Wert in beiden.

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync/atomic"
)

type baitCreds struct {
	User   string
	Pass   string
	DBName string
	APIKey string
}

const baitAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

var baitUsers = []string{"backup", "nasadmin", "svc_backup", "dbadmin", "deploy", "sync"}

func deriveBait(secret string) baitCreds {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("hivornet-koeder-v1"))
	s := mac.Sum(nil)
	var p strings.Builder
	for _, b := range s[2:16] {
		p.WriteByte(baitAlphabet[int(b)%len(baitAlphabet)])
	}
	pass := p.String()
	pass = pass[:4] + "-" + pass[4:9] + "!" + pass[9:] // wie ein von Hand gewähltes Passwort
	return baitCreds{
		User:   baitUsers[int(s[0])%len(baitUsers)],
		Pass:   pass,
		DBName: []string{"backup", "nas", "files", "app"}[int(s[1])%4],
		APIKey: hex.EncodeToString(s[16:32]),
	}
}

var baitCur atomic.Pointer[baitCreds]

// setBaitSecret wird beim Start mit dem Sensor-Token aufgerufen.
func setBaitSecret(secret string) {
	b := deriveBait(secret)
	baitCur.Store(&b)
}

func bait() baitCreds {
	if b := baitCur.Load(); b != nil {
		return *b
	}
	return deriveBait("")
}

// isBaitPass: Passwort ist das Köder-Passwort (oder der Köder-API-Schlüssel).
func isBaitPass(p string) bool {
	b := bait()
	return p != "" && (p == b.Pass || p == b.APIKey)
}

// mysqlNativeMatch prüft eine mysql_native_password-Antwort gegen ein Passwort:
// SHA1(pw) XOR SHA1(salt + SHA1(SHA1(pw))).
func mysqlNativeMatch(salt, auth []byte, pw string) bool {
	if len(auth) != 20 {
		return false
	}
	h1 := sha1.Sum([]byte(pw))
	h2 := sha1.Sum(h1[:])
	x := sha1.New()
	x.Write(salt)
	x.Write(h2[:])
	h3 := x.Sum(nil)
	for i := range h1 {
		if h1[i]^h3[i] != auth[i] {
			return false
		}
	}
	return true
}

// baitFile liefert den Inhalt einer Köderdatei oder ok=false.
func baitFile(path, host string) (ctype, body string, ok bool) {
	b := bait()
	switch path {
	case "/.env", "/.env.bak", "/.env.old", "/.env.production", "/app/.env", "/backup/.env":
		return "application/octet-stream", "APP_NAME=\"" + host + " Backup\"\nAPP_ENV=production\nAPP_DEBUG=false\nAPP_URL=http://" + host + ".local\n\n" +
			"DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=" + b.DBName + "\nDB_USERNAME=" + b.User + "\nDB_PASSWORD=" + b.Pass + "\n\n" +
			"REDIS_HOST=127.0.0.1\nREDIS_PASSWORD=" + b.Pass + "\nREDIS_PORT=6379\n\n" +
			"MAIL_MAILER=smtp\nMAIL_HOST=127.0.0.1\nMAIL_PORT=25\nMAIL_USERNAME=" + b.User + "\nMAIL_PASSWORD=" + b.Pass + "\n\n" +
			"FTP_HOST=" + host + ".local\nFTP_USER=" + b.User + "\nFTP_PASSWORD=" + b.Pass + "\n\nBACKUP_API_KEY=" + b.APIKey + "\n", true
	case "/.git/config":
		return "application/octet-stream", "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n" +
			"[remote \"origin\"]\n\turl = https://" + b.User + ":" + b.Pass + "@git." + host + ".local/backup/nas-scripts.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n" +
			"[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n", true
	case "/.git/HEAD":
		return "application/octet-stream", "ref: refs/heads/main\n", true
	case "/robots.txt":
		return "text/plain", "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /phpmyadmin/\nDisallow: /.env\n", true
	case "/backup/", "/backup":
		return "text/html", "<html>\r\n<head><title>Index of /backup/</title></head>\r\n<body>\r\n<h1>Index of /backup/</h1><hr><pre><a href=\"../\">../</a>\r\n" +
			"<a href=\"db-" + b.DBName + ".sql.gz\">db-" + b.DBName + ".sql.gz</a>                                 03-Nov-2026 02:15             4718203\r\n" +
			"<a href=\"config.php.bak\">config.php.bak</a>                                     21-Sep-2026 11:42                 912\r\n" +
			"</pre><hr></body>\r\n</html>\r\n", true
	case "/config.php.bak", "/backup/config.php.bak", "/wp-config.php.bak", "/config.php~":
		return "application/octet-stream", "<?php\n// Datenbank\ndefine('DB_NAME', '" + b.DBName + "');\ndefine('DB_USER', '" + b.User + "');\n" +
			"define('DB_PASSWORD', '" + b.Pass + "');\ndefine('DB_HOST', 'localhost');\n$api_key = '" + b.APIKey + "';\n", true
	}
	return "", "", false
}
