package main

// Köder (Gegenstück zu honeypot/bait.go): Der HTTP-Honeypot verteilt in /.env,
// /.git/config usw. erfundene Zugangsdaten, abgeleitet aus dem Sensor-Token. Der Hive
// leitet dieselben Werte ab und erkennt ihre Verwendung: ein Login mit dem Köder-Passwort
// (oder mit data.bait, das der Honeypot bei MySQL aus dem Hash erkennt) oder eine Anfrage
// bzw. ein Befehl, der Passwort oder API-Schlüssel enthält. Das Muster "bait_used" hat
// Schweregrad 3 (Benachrichtigung) und hebt den Angriff mindestens auf die Stufe
// "Login angenommen".
//
// deriveBait muss mit honeypot/bait.go übereinstimmen (TestBaitDerivation in beiden).

import (
	"crypto/hmac"
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
	pass = pass[:4] + "-" + pass[4:9] + "!" + pass[9:]
	return baitCreds{
		User:   baitUsers[int(s[0])%len(baitUsers)],
		Pass:   pass,
		DBName: []string{"backup", "nas", "files", "app"}[int(s[1])%4],
		APIKey: hex.EncodeToString(s[16:32]),
	}
}

var baitCur atomic.Pointer[baitCreds]

func setBaitSecret(secret string) {
	b := deriveBait(secret)
	baitCur.Store(&b)
}

// baitUsed: Das Ereignis verwendet Köder-Zugangsdaten.
func baitUsed(e *Event) bool {
	b := baitCur.Load()
	if b == nil {
		return false
	}
	switch e.Type {
	case "login":
		return dataBool(e.Data, "bait") || e.Password != "" && (e.Password == b.Pass || e.Password == b.APIKey)
	case "request", "command", "payload":
		// nicht in der Antwort des Honeypots, nur in dem, was der Angreifer schickt
		s := string(e.Data)
		return strings.Contains(s, b.Pass) || strings.Contains(s, b.APIKey)
	}
	return false
}

// eventPatterns: erkannte Muster eines Ereignisses (Regeln aus analyze.go, entschlüsselte
// Inhalte, Köder).
func eventPatterns(e *Event, text, on string, revealed []string) []string {
	var ids []string
	if text != "" {
		ids = analyzeText(text, on).ids // revealed ist dort dasselbe (analysisText)
	}
	if baitUsed(e) {
		ids = append(ids, "bait_used")
	}
	return ids
}
