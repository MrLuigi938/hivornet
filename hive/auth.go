package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	cookieName     = "hv_session"
	maxPasswordLen = 72 // bcrypt verarbeitet nicht mehr
	minPasswordLen = 10
	failsPerIP     = 10 // pro 15 Minuten
	failsGlobal    = 60 // pro Minute über alle IPs
)

var (
	dummyOnce sync.Once
	dummyHash []byte
)

type Auth struct {
	st           *Store
	secureCookie bool
	sensorToken  string
	bcryptSem    chan struct{} // höchstens 2 bcrypt-Läufe gleichzeitig (CPU der NAS schonen)

	mu         sync.Mutex
	fails      map[string]*failInfo
	globalN    int
	globalFrom time.Time
}

type failInfo struct {
	n     int
	first time.Time
}

func NewAuth(st *Store, sensorToken string, secure bool) *Auth {
	a := &Auth{st: st, sensorToken: sensorToken, secureCookie: secure, fails: map[string]*failInfo{}, bcryptSem: make(chan struct{}, 2)}
	go func() {
		for range time.Tick(5 * time.Minute) {
			a.mu.Lock()
			for ip, f := range a.fails {
				if time.Since(f.first) > 15*time.Minute {
					delete(a.fails, ip)
				}
			}
			a.mu.Unlock()
		}
	}()
	return a
}

func randToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// In der Datenbank liegt nur der Hash des Tokens; ein Backup verrät keine gültige Sitzung.
func tokenHash(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func validPassword(p string) error {
	switch {
	case len(p) < minPasswordLen:
		return errors.New("das Passwort braucht mindestens 10 Zeichen")
	case len(p) > maxPasswordLen:
		return errors.New("das Passwort darf höchstens 72 Bytes lang sein")
	}
	return nil
}

// EnsureAdmin legt beim ersten Start das Admin-Konto an (oder setzt es mit HIVE_RESET_ADMIN=1 zurück).
func (a *Auth) EnsureAdmin(user, pass string) {
	if user == "" {
		user = "admin"
	}
	var n int
	if err := a.st.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		log.Fatalf("Benutzertabelle: %v", err)
	}
	reset := n > 0 && os.Getenv("HIVE_RESET_ADMIN") == "1" && pass != ""
	if n > 0 && !reset {
		return
	}
	generated := false
	if pass == "" {
		pass = randToken(8)
		generated = true
	}
	if err := validPassword(pass); err != nil {
		log.Fatalf("HIVE_ADMIN_PASSWORD ungültig: %v", err)
	}
	if reset {
		a.st.db.Exec(`DELETE FROM users`)
		a.st.db.Exec(`DELETE FROM auth_sessions`)
	}
	if err := a.SetPassword(user, pass); err != nil {
		log.Fatalf("Admin-Konto anlegen: %v", err)
	}
	switch {
	case reset:
		log.Printf("Admin-Konto %q auf HIVE_ADMIN_PASSWORD zurückgesetzt. HIVE_RESET_ADMIN jetzt wieder entfernen!", user)
	case generated:
		log.Printf("Admin-Konto %q angelegt. Erzeugtes Passwort: %s (bitte in der UI ändern)", user, pass)
	default:
		log.Printf("Admin-Konto %q angelegt", user)
	}
}

func (a *Auth) SetPassword(user, pass string) error {
	if err := validPassword(pass); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = a.st.db.Exec(`INSERT INTO users(username,hash) VALUES(?,?) ON CONFLICT(username) DO UPDATE SET hash=excluded.hash`, user, string(h))
	return err
}

func (a *Auth) Check(user, pass string) bool {
	a.bcryptSem <- struct{}{}
	defer func() { <-a.bcryptSem }()
	var h string
	if err := a.st.db.QueryRow(`SELECT hash FROM users WHERE username=?`, user).Scan(&h); err != nil {
		dummyOnce.Do(func() { dummyHash, _ = bcrypt.GenerateFromPassword([]byte(randToken(8)), bcrypt.DefaultCost) })
		bcrypt.CompareHashAndPassword(dummyHash, []byte(pass)) // gleiche Laufzeit wie bei echtem Konto
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(h), []byte(pass)) == nil
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// attempt zählt einen Versuch VOR dem bcrypt-Lauf (parallele Anfragen kommen nicht durch).
func (a *Auth) attempt(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if time.Since(a.globalFrom) > time.Minute {
		a.globalFrom, a.globalN = time.Now(), 0
	}
	f := a.fails[ip]
	if f == nil || time.Since(f.first) > 15*time.Minute {
		f = &failInfo{first: time.Now()}
		a.fails[ip] = f
	}
	if f.n >= failsPerIP || a.globalN >= failsGlobal {
		return false
	}
	f.n++
	a.globalN++
	return true
}

func (a *Auth) success(ip string) {
	a.mu.Lock()
	delete(a.fails, ip)
	if a.globalN > 0 {
		a.globalN--
	}
	a.mu.Unlock()
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if readJSON(w, r, &req) != nil {
		httpErr(w, 400, "ungültige Anfrage")
		return
	}
	ip := clientIP(r)
	if !a.attempt(ip) {
		httpErr(w, 429, "zu viele Fehlversuche, bitte 15 Minuten warten")
		return
	}
	if len(req.Password) > maxPasswordLen || !a.Check(req.Username, req.Password) {
		time.Sleep(300 * time.Millisecond)
		httpErr(w, 401, "Benutzername oder Passwort falsch")
		return
	}
	a.success(ip)
	tok := randToken(32)
	exp := time.Now().Add(7 * 24 * time.Hour)
	if _, err := a.st.db.Exec(`INSERT INTO auth_sessions(token,username,expires) VALUES(?,?,?)`, tokenHash(tok), req.Username, exp.Unix()); err != nil {
		httpErr(w, 500, "Sitzung konnte nicht angelegt werden")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", Expires: exp, HttpOnly: true,
		Secure: a.secureCookie, SameSite: http.SameSiteStrictMode})
	writeJSON(w, map[string]string{"username": req.Username})
}

func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		a.st.db.Exec(`DELETE FROM auth_sessions WHERE token=?`, tokenHash(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, map[string]bool{"ok": true})
}

// DropOtherSessions meldet alle anderen Sitzungen ab (nach Passwortwechsel).
func (a *Auth) DropOtherSessions(r *http.Request) {
	keep := ""
	if c, err := r.Cookie(cookieName); err == nil {
		keep = tokenHash(c.Value)
	}
	a.st.db.Exec(`DELETE FROM auth_sessions WHERE token != ?`, keep)
}

func (a *Auth) User(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil || len(c.Value) != 64 {
		return ""
	}
	var user string
	var exp int64
	if a.st.db.QueryRowContext(r.Context(), `SELECT username, expires FROM auth_sessions WHERE token=?`, tokenHash(c.Value)).Scan(&user, &exp) != nil {
		return ""
	}
	if time.Now().Unix() > exp {
		return ""
	}
	return user
}

// Require schützt die API für die Web-UI. Schreibende Anfragen brauchen
// zusätzlich einen eigenen Header (Schutz gegen CSRF).
func (a *Auth) Require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Header.Get("X-Requested-With") != "hivornet" {
			httpErr(w, 403, "fehlender Header")
			return
		}
		if a.User(r) == "" {
			httpErr(w, 401, "nicht angemeldet")
			return
		}
		next(w, r)
	}
}

// RequireSensor prüft das gemeinsame Token der Sensoren.
func (a *Auth) RequireSensor(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if a.sensorToken == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(a.sensorToken)) != 1 {
			httpErr(w, 401, "ungültiges Token")
			return
		}
		next(w, r)
	}
}

// ---- Zugriffsschutz für die UI ----

// hostAllowed verhindert DNS-Rebinding: Fremde Domains, die auf eine LAN-IP zeigen,
// werden abgelehnt. Erlaubt sind IP-Adressen, localhost, typische Heimnetz-Namen
// und alles aus HIVE_ALLOWED_HOSTS (kommagetrennt, "*" schaltet die Prüfung ab).
func hostAllowed(host string, extra []string) bool {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	h = strings.ToLower(strings.Trim(h, "[]"))
	if net.ParseIP(h) != nil || h == "localhost" || h == "" {
		return true
	}
	for _, suf := range []string{".local", ".lan", ".home", ".internal", ".home.arpa", ".fritz.box", ".localdomain"} {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	for _, e := range extra {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "*" || e == h || (strings.HasPrefix(e, ".") && strings.HasSuffix(h, e)) {
			return true
		}
	}
	return !strings.Contains(h, ".") // einfacher Rechnername ohne Domain, z. B. "nas"
}

func uiGuard(next http.Handler, ingest *net.IPNet, allowed []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ingest != nil {
			if ip := net.ParseIP(clientIP(r)); ip != nil && ingest.Contains(ip) {
				httpErr(w, 403, "aus dem Sensor-Netz nicht erlaubt")
				return
			}
		}
		if !hostAllowed(r.Host, allowed) {
			httpErr(w, 421, "unbekannter Hostname; in HIVE_ALLOWED_HOSTS eintragen")
			return
		}
		next.ServeHTTP(w, r)
	})
}
