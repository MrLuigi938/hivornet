package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"errors"
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

// Schnelle Schlüsselableitung für Tests (die Grenzen in readBackup gelten trotzdem).
func fastKDF(t *testing.T) {
	old := backupKDF
	backupKDF.time, backupKDF.memory, backupKDF.threads = 1, 8*1024, 1
	t.Cleanup(func() { backupKDF = old })
}

func TestBackupCryptoRoundtrip(t *testing.T) {
	fastKDF(t)
	data := make([]byte, 3*backupChunk+12345) // mehrere Blöcke
	rand.Read(data[:backupChunk])             // teils nicht komprimierbar
	var buf bytes.Buffer
	if err := writeBackup(&buf, bytes.NewReader(data), "richtiges-passwort", backupMeta{Format: "sqlite", Events: 7}); err != nil {
		t.Fatal(err)
	}
	enc := buf.Bytes()

	meta, r, err := readBackup(bytes.NewReader(enc), "richtiges-passwort")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, data) || meta.Events != 7 {
		t.Fatalf("Rundreise: %v, %d Bytes, %+v", err, len(got), meta)
	}

	readAll := func(b []byte, pass string) error {
		_, r, err := readBackup(bytes.NewReader(b), pass)
		if err != nil {
			return err
		}
		_, err = io.ReadAll(r)
		return err
	}
	if err := readAll(enc, "falsches-passwort"); !errors.Is(err, errBackupAuth) {
		t.Fatalf("falsches Passwort: %v", err)
	}
	// Abgeschnitten: der letzte Block fehlt
	if err := readAll(enc[:len(enc)-200], "richtiges-passwort"); err == nil {
		t.Fatal("abgeschnittene Datei angenommen")
	}
	// Ein Byte mitten im Inhalt geändert
	bad := bytes.Clone(enc)
	bad[len(bad)/2] ^= 1
	if err := readAll(bad, "richtiges-passwort"); err == nil {
		t.Fatal("veränderte Datei angenommen")
	}
	// Metadaten im Kopf geändert (unverschlüsselt, aber mit geprüft)
	bad = bytes.Replace(bytes.Clone(enc), []byte(`"events":7`), []byte(`"events":8`), 1)
	if err := readAll(bad, "richtiges-passwort"); err == nil {
		t.Fatal("veränderter Kopf angenommen")
	}
	if err := readAll([]byte("keine sicherung"), "x"); err == nil || errors.Is(err, errBackupAuth) {
		t.Fatalf("fremde Datei: %v", err)
	}
}

func TestBackupExportImport(t *testing.T) {
	fastKDF(t)
	h := testHive(t)
	h.dbPath = h.st.path
	h.restart = make(chan struct{}, 1)
	h.auth = NewAuth(h.st, "tok", false)
	h.auth.EnsureAdmin("admin", "adminpasswort1")
	ui, _ := h.routes(false, "", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	if err := h.auth.startSession(rec, httptest.NewRequest("GET", "/", nil), "admin"); err != nil {
		t.Fatal(err)
	}
	cookie := rec.Result().Cookies()[0]

	// Daten, die mitkommen sollen
	h.st.SetKV("extras", `{"greynoise_key":"GN-GEHEIM-123","abuseipdb_key":"AB-GEHEIM-456"}`)
	h.st.SetKV("retention_days", "45")
	h.st.SetKV("cowrie_offset", "999999") // gehört zur alten Installation
	w, _ := testWriter(t, h.st)
	w.Submit(&Event{EID: "e1", TS: time.Now(), Sensor: "s", Service: "ssh", Type: "login", SrcIP: "203.0.113.5", DstPort: 22, Username: "root", Password: "toor"})
	w.Stop(5 * time.Second)

	export := func(pass string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/backup/export", strings.NewReader(`{"password":"`+pass+`"}`))
		req.Header.Set("X-Requested-With", "hivornet")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		ui.ServeHTTP(rec, req)
		return rec
	}
	if rec := export("falsch"); rec.Code != 403 {
		t.Fatalf("Export mit falschem Passwort: %d", rec.Code)
	}
	rec = export("adminpasswort1")
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Disposition"), ".hvbak") {
		t.Fatalf("Export: %d %s", rec.Code, rec.Body.String())
	}
	file := rec.Body.Bytes()
	if bytes.Contains(file, []byte("GN-GEHEIM")) || bytes.Contains(file, []byte("toor")) {
		t.Fatal("Geheimnisse unverschlüsselt in der Sicherung")
	}

	imp := func(pass string, data []byte) *httptest.ResponseRecorder {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		mw.WriteField("password", pass)
		fw, _ := mw.CreateFormFile("file", "s.hvbak")
		fw.Write(data)
		mw.Close()
		req := httptest.NewRequest("POST", "/api/backup/import", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("X-Requested-With", "hivornet")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		ui.ServeHTTP(rec, req)
		return rec
	}
	restore := filepath.Join(filepath.Dir(h.dbPath), "restore.db")
	if rec := imp("falsches-passwort", file); rec.Code != 403 {
		t.Fatalf("Import mit falschem Passwort: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(restore); err == nil {
		t.Fatal("restore.db trotz falschem Passwort angelegt")
	}
	if rec := imp("adminpasswort1", file[:len(file)/2]); rec.Code == 200 {
		t.Fatal("halbe Datei angenommen")
	}
	if rec := imp("adminpasswort1", file); rec.Code != 200 {
		t.Fatalf("Import: %d %s", rec.Code, rec.Body.String())
	}
	select {
	case <-h.restart:
	case <-time.After(3 * time.Second):
		t.Fatal("kein Neustart angefordert")
	}

	// Inhalt der wiederhergestellten Datenbank
	db, err := sql.Open("sqlite", "file:"+restore+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	var extras, ret string
	var events, sessions, offsets int
	db.QueryRow(`SELECT v FROM kv WHERE k='extras'`).Scan(&extras)
	db.QueryRow(`SELECT v FROM kv WHERE k='retention_days'`).Scan(&ret)
	db.QueryRow(`SELECT COUNT(*) FROM kv WHERE k='cowrie_offset'`).Scan(&offsets)
	db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&events)
	db.QueryRow(`SELECT COUNT(*) FROM auth_sessions`).Scan(&sessions)
	db.Close()
	if !strings.Contains(extras, "GN-GEHEIM-123") || ret != "45" || events != 1 || sessions != 0 || offsets != 0 {
		t.Fatalf("wiederhergestellt: extras=%q ret=%q events=%d sessions=%d offsets=%d", extras, ret, events, sessions, offsets)
	}

	// Beim nächsten Start: alte Datenbank wird aufgehoben, restore.db übernommen
	h.st.SetKV("retention_days", "7") // Stand nach der Sicherung, steckt nur in der alten Datenbank
	h.st.db.Close()
	applyRestore(h.dbPath)
	if _, err := os.Stat(restore); err == nil {
		t.Fatal("restore.db nicht übernommen")
	}
	old, _ := filepath.Glob(filepath.Join(filepath.Dir(h.dbPath), "backups", "vor-wiederherstellung-*.db"))
	if len(old) != 1 {
		t.Fatalf("alte Datenbank nicht gesichert: %v", old)
	}
	st, err := OpenStore(h.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	if v, _ := st.GetKV("retention_days"); v != "45" {
		t.Fatalf("nach dem Start: retention_days=%q", v)
	}
}

func TestBackupViewerForbidden(t *testing.T) {
	for _, p := range []string{"/api/backup/export", "/api/backup/import"} {
		if viewerAllowed(httptest.NewRequest("POST", p, nil)) {
			t.Fatalf("%s für Nur-Lesen-Benutzer erlaubt", p)
		}
	}
}

func TestCheckRestoreDBRejectsForeign(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fremd.db")
	db, _ := sql.Open("sqlite", "file:"+p)
	db.Exec(`CREATE TABLE x (a)`)
	db.Close()
	if err := checkRestoreDB(p); err == nil {
		t.Fatal("fremde Datenbank angenommen")
	}
}
