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
	tokens       sensorTokenStore // eigene Tokens je Sensor (sensortokens.go)
	bcryptSem    chan struct{}    // höchstens 2 bcrypt-Läufe gleichzeitig (CPU der NAS schonen)

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
	if pass == "" {
		// Kein Passwort vorgegeben: Das Konto entsteht bei der Ersteinrichtung in der Web-UI (setup.go).
		log.Printf("Noch kein Admin-Konto: Ersteinrichtung in der Web-UI abschließen")
		return
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

// CreateUser legt ein neues Konto mit Rolle in EINEM Schritt an (N1 des dritten Audits: vorher
// entstand das Konto mit der Standardrolle admin, die Rolle kam danach, ein Fehler dabei wurde
// verschluckt). Gibt es den Namen schon, scheitert der Aufruf.
func (a *Auth) CreateUser(user, pass, role string) error {
	if err := validPassword(pass); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = a.st.db.Exec(`INSERT INTO users(username,hash,role) VALUES(?,?,?)`, user, string(h), role)
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

// failKey: Schlüssel der Drossel. IPv6 je /64 (N3 des dritten Audits): Ein Anschluss bekommt
// meist ein ganzes /64, jede Adresse darin hätte sonst eigene zehn Versuche.
func failKey(ip string) string {
	p := net.ParseIP(ip)
	if p == nil || p.To4() != nil {
		return ip
	}
	return p.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// localClient: Adresse aus dem Heimnetz. Sie zählt nicht zur globalen Grenze und wird von ihr
// nicht gesperrt: Viele Fehlversuche aus dem Internet sollen den Betreiber im Heimnetz nicht
// aussperren (N3). Die Grenze je Adresse gilt für sie trotzdem.
func localClient(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && (p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast())
}

// attempt zählt einen Versuch VOR dem bcrypt-Lauf (parallele Anfragen kommen nicht durch).
func (a *Auth) attempt(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if time.Since(a.globalFrom) > time.Minute {
		a.globalFrom, a.globalN = time.Now(), 0
	}
	key, local := failKey(ip), localClient(ip)
	f := a.fails[key]
	if f == nil || time.Since(f.first) > 15*time.Minute {
		f = &failInfo{first: time.Now()}
		a.fails[key] = f
	}
	if f.n >= failsPerIP || !local && a.globalN >= failsGlobal {
		return false
	}
	f.n++
	if !local {
		a.globalN++
	}
	return true
}

func (a *Auth) success(ip string) {
	a.mu.Lock()
	delete(a.fails, failKey(ip))
	if a.globalN > 0 && !localClient(ip) {
		a.globalN--
	}
	a.mu.Unlock()
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	// N2 des dritten Audits: wie bei der Ersteinrichtung und allen anderen schreibenden
	// Anfragen. Sonst schickt eine fremde Webseite aus dem Browser des Betreibers Fehlversuche
	// und sperrt dessen IP. Den Header kann eine fremde Seite nur nach einer CORS-Vorabanfrage
	// setzen, die der Hive nicht erlaubt. (Ein Abgleich von Origin und Host fiele hinter
	// Reverse-Proxys, die Host umschreiben, auf die Nase.)
	if r.Header.Get("X-Requested-With") != "hivornet" {
		httpErr(w, 403, "fehlender Header")
		return
	}
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
	if err := a.startSession(w, r, req.Username); err != nil {
		httpErr(w, 500, "Sitzung konnte nicht angelegt werden")
		return
	}
	writeJSON(w, map[string]string{"username": req.Username})
}

// viaHTTPS: Die Anfrage kam verschlüsselt an, direkt oder über einen Reverse-Proxy, der
// "X-Forwarded-Proto: https" setzt. Dann bekommt das Sitzungs-Cookie das Secure-Flag, auch
// ohne HIVE_COOKIE_SECURE. Ein gefälschter Header schadet nur dem, der ihn schickt: Sein
// Browser schickt das Cookie dann nicht mehr über HTTP.
func viaHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

// startSession legt eine Sitzung an und setzt das Cookie (Anmeldung, Ersteinrichtung).
func (a *Auth) startSession(w http.ResponseWriter, r *http.Request, user string) error {
	tok := randToken(32)
	exp := time.Now().Add(7 * 24 * time.Hour)
	if _, err := a.st.db.Exec(`INSERT INTO auth_sessions(token,username,expires) VALUES(?,?,?)`, tokenHash(tok), user, exp.Unix()); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", Expires: exp, HttpOnly: true,
		Secure: a.secureCookie || viaHTTPS(r), SameSite: http.SameSiteStrictMode})
	return nil
}

func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		a.st.db.Exec(`DELETE FROM auth_sessions WHERE token=?`, tokenHash(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, map[string]bool{"ok": true})
}

// DropOtherSessions meldet die anderen Sitzungen desselben Benutzers ab (nach Passwortwechsel).
func (a *Auth) DropOtherSessions(r *http.Request) {
	user, _ := a.Who(r)
	keep := ""
	if c, err := r.Cookie(cookieName); err == nil {
		keep = tokenHash(c.Value)
	}
	a.st.db.Exec(`DELETE FROM auth_sessions WHERE username = ? AND token != ?`, user, keep)
}

// Who liefert Benutzer und Rolle der Sitzung, sonst leere Werte. Sitzungen gelöschter
// Benutzer gelten nicht mehr (JOIN auf users).
func (a *Auth) Who(r *http.Request) (user, role string) {
	c, err := r.Cookie(cookieName)
	if err != nil || len(c.Value) != 64 {
		return "", ""
	}
	var exp int64
	if a.st.db.QueryRowContext(r.Context(), `SELECT s.username, s.expires, u.role FROM auth_sessions s
		JOIN users u ON u.username = s.username WHERE s.token=?`, tokenHash(c.Value)).Scan(&user, &exp, &role) != nil {
		return "", ""
	}
	if time.Now().Unix() > exp {
		return "", ""
	}
	return user, role
}

func (a *Auth) User(r *http.Request) string {
	u, _ := a.Who(r)
	return u
}

// Require schützt die API für die Web-UI. Schreibende Anfragen brauchen
// zusätzlich einen eigenen Header (Schutz gegen CSRF).
func (a *Auth) Require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Header.Get("X-Requested-With") != "hivornet" {
			httpErr(w, 403, "fehlender Header")
			return
		}
		user, role := a.Who(r)
		if user == "" {
			httpErr(w, 401, "nicht angemeldet")
			return
		}
		if role != "admin" && !viewerAllowed(r) {
			httpErr(w, 403, "Nur Lesezugriff: Das darf nur ein Admin.")
			return
		}
		next(w, r)
	}
}

// viewerAllowed: Was ein Benutzer mit Rolle "viewer" darf. Ansehen ja, ändern nein.
// Ausgenommen sind die Zusatz-Einstellungen (enthalten z. B. das ntfy-Thema, das
// selbst ein Geheimnis ist), die Benutzerverwaltung und die Systemprotokolle.
func viewerAllowed(r *http.Request) bool {
	p := r.URL.Path
	switch {
	case r.Method == "POST" && (p == "/api/password" || p == "/api/logout"):
		return true
	case r.Method != "GET":
		return false
	case strings.HasPrefix(p, "/api/extras"), strings.HasPrefix(p, "/api/users"), strings.HasPrefix(p, "/api/logs"), strings.HasPrefix(p, "/api/abuse"), strings.HasPrefix(p, "/api/share"), strings.HasPrefix(p, "/api/feed"), strings.HasPrefix(p, "/api/sensor-tokens"), strings.HasPrefix(p, "/api/mimic"),
		p == "/api/brute": // Drossel: zeigt eigene Netze und "Nie sperren" (bruteforce.go)
		return false
	// Abfragen bei Dritten mit den Schlüsseln des Admins und teure Auswertungen
	case strings.HasPrefix(p, "/api/lookup/"), strings.HasPrefix(p, "/api/sample"),
		strings.HasPrefix(p, "/api/attackers/") && (strings.HasSuffix(p, "/intel") || strings.HasSuffix(p, "/greynoise")):
		return false
	}
	return true
}

// RequireSensor prüft das gemeinsame Token der Sensoren oder ein eigenes Sensor-Token
// (sensortokens.go); dann ist die Anfrage an diesen Sensor-Namen gebunden.
func (a *Auth) RequireSensor(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if a.sensorToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(a.sensorToken)) == 1 {
			next(w, r)
			return
		}
		if name := a.sensorFor(tok); name != "" {
			next(w, withSensor(r, name))
			return
		}
		httpErr(w, 401, "ungültiges Token")
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

func uiGuard(next http.Handler, ingest *net.IPNet, allowed func() []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ingest != nil {
			if ip := net.ParseIP(clientIP(r)); ip != nil && ingest.Contains(ip) {
				httpErr(w, 403, "aus dem Sensor-Netz nicht erlaubt")
				return
			}
		}
		if !hostAllowed(r.Host, allowed()) {
			httpErr(w, 421, "unbekannter Hostname: über die IP-Adresse öffnen und unter Einstellungen → Zugriff eintragen (oder HIVE_ALLOWED_HOSTS)")
			return
		}
		next.ServeHTTP(w, r)
	})
}
