package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Ersatz für journalctl: Das Testprogramm ruft sich selbst auf und gibt seine Argumente aus.
func TestHelperJournalctl(t *testing.T) {
	if os.Getenv("HIVE_TEST_JOURNALCTL") != "1" {
		return
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	fmt.Println("2026-11-15T09:00:00+0100 hivornet sh[1]: ARGS " + strings.Join(args, " "))
	os.Exit(0)
}

// fakeJournalctl lässt journal() das Testprogramm statt journalctl aufrufen.
func fakeJournalctl(t *testing.T) {
	t.Helper()
	oldPath, oldArgs := journalctlPath, journalArgsPrefix
	journalctlPath, journalArgsPrefix = os.Args[0], []string{"-test.run=^TestHelperJournalctl$", "--"}
	t.Cleanup(func() { journalctlPath, journalArgsPrefix = oldPath, oldArgs })
	t.Setenv("HIVE_TEST_JOURNALCTL", "1")
}

func logsReq(h *Hive, id, query string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/logs/"+id+query, nil)
	r.SetPathValue("id", id)
	h.logsGet(rec, r)
	return rec
}

func TestLogsDisabledWithoutPi(t *testing.T) {
	h := testHive(t)
	if rec := logsReq(h, "hive", ""); rec.Code != 404 {
		t.Fatalf("ohne HIVE_JOURNAL: %d", rec.Code)
	}
}

func TestLogsJournalAndFile(t *testing.T) {
	h := testHive(t)
	t.Setenv("HIVE_JOURNAL", "1")
	inst := filepath.Join(t.TempDir(), "install.log")
	var lines []string
	for i := 1; i <= 300; i++ {
		lines = append(lines, fmt.Sprintf("Zeile %d", i))
	}
	os.WriteFile(inst, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	t.Setenv("HIVE_INSTALL_LOG", inst)
	fakeJournalctl(t)

	if rec := logsReq(h, "nicht-da", ""); rec.Code != 404 {
		t.Fatalf("unbekannte Quelle: %d", rec.Code)
	}
	rec := logsReq(h, "cowrie-install", "?lines=999999")
	if rec.Code != 200 {
		t.Fatalf("journal: %d %s", rec.Code, rec.Body)
	}
	var out struct{ Text string }
	json.Unmarshal(rec.Body.Bytes(), &out)
	want := "--no-pager --quiet --output=short-iso --lines=2000 --unit=hivornet-cowrie-install.service"
	if !strings.Contains(out.Text, "ARGS "+want) {
		t.Fatalf("journalctl-Aufruf: %q", out.Text)
	}
	// Zeilenzahl ist eine Zahl; alles andere fällt auf 200 zurück und landet nie im Befehl
	rec = logsReq(h, "hive", "?lines=5;rm%20-rf")
	json.Unmarshal(rec.Body.Bytes(), &out)
	if !strings.Contains(out.Text, "--lines=200 --unit=hivornet-hive.service") || strings.Contains(out.Text, "rm") {
		t.Fatalf("Zeilenzahl: %q", out.Text)
	}
	rec = logsReq(h, "install", "?lines=3")
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Text != "Zeile 298\nZeile 299\nZeile 300" {
		t.Fatalf("Datei: %q", out.Text)
	}
}

func TestLogsAdminOnly(t *testing.T) {
	for _, p := range []string{"/api/logs", "/api/logs/hive"} {
		if viewerAllowed(httptest.NewRequest("GET", p, nil)) {
			t.Fatalf("%s für Nur-Lesen-Benutzer erlaubt", p)
		}
	}
}

func TestCowrieInstallWarnings(t *testing.T) {
	h := testHive(t)
	w, err := NewWriter(h.st, func(*Event) {})
	if err != nil {
		t.Fatal(err)
	}
	h.writer = w
	h.cowrie = NewCowrieTail(filepath.Join(t.TempDir(), "fehlt.json"), "test", h.st, func(*Event) {})
	p := filepath.Join(t.TempDir(), "cowrie-install")
	t.Setenv("HIVE_COWRIE_INSTALL_STATUS", p)
	text := func() string {
		var s []string
		for _, w := range h.warnings() {
			s = append(s, w.Text)
		}
		return strings.Join(s, " | ")
	}
	os.WriteFile(p, fmt.Appendf(nil, "running\n%d\nPython-Pakete installieren\n", time.Now().Add(-7*time.Minute).Unix()), 0o644)
	if got := text(); !strings.Contains(got, "Cowrie wird gerade installiert: Python-Pakete installieren (seit 7 Min.)") {
		t.Fatalf("läuft: %s", got)
	}
	if ci := cowrieInstallStatus(); ci == nil || ci.State != "running" {
		t.Fatalf("Stand: %+v", ci)
	}
	os.WriteFile(p, []byte("failed\n1\nSchritt „Cowrie herunterladen“ fehlgeschlagen (Exit-Code 22).\n"), 0o644)
	if got := text(); !strings.Contains(got, "Cowrie-Installation gescheitert: Schritt „Cowrie herunterladen“") {
		t.Fatalf("gescheitert: %s", got)
	}
	os.WriteFile(p, []byte("unsinn\n1\nx\n"), 0o644)
	if cowrieInstallStatus() != nil {
		t.Fatal("unbekannter Zustand angenommen")
	}
}
