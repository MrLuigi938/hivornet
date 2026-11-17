package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallSystemAllowlist(t *testing.T) {
	src, root := t.TempDir(), t.TempDir()
	write := func(base, rel, s string) {
		p := filepath.Join(base, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(s), 0o644)
	}
	write(src, "etc/systemd/system/hivornet-cowrie-config.path", "[Path]\n")
	write(src, "usr/local/sbin/hivornet-cowrie-config", "#!/bin/sh\n")
	write(src, "usr/lib/sysusers.d/hivornet.conf", "u x\n")
	write(src, "etc/hivornet/cowrie.cfg", "überschreibt Einstellungen") // nie übernehmen
	write(src, "etc/systemd/system/sshd.service", "fremd")              // nie übernehmen
	write(src, "usr/local/sbin/hivornet-x.sh", "x")                     // nur ohne Endung
	write(root, "usr/local/sbin/hivornet-update", "alt")
	write(src, "usr/local/sbin/hivornet-update", "alt") // unverändert: nicht neu schreiben
	changed, err := installSystem(src, root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"etc/systemd/system/hivornet-cowrie-config.path": true, "usr/local/sbin/hivornet-cowrie-config": true, "usr/lib/sysusers.d/hivornet.conf": true}
	if len(changed) != len(want) {
		t.Fatalf("geändert: %v", changed)
	}
	for _, c := range changed {
		if !want[c] {
			t.Errorf("unerwartet übernommen: %s", c)
		}
	}
	for _, p := range []string{"etc/hivornet/cowrie.cfg", "etc/systemd/system/sshd.service", "usr/local/sbin/hivornet-x.sh"} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			t.Errorf("%s darf nicht übernommen werden", p)
		}
	}
	// angewendet: Beobachter einschalten, daemon-reload, sysusers
	var calls []string
	applySystem(changed, func(n string, a ...string) error { calls = append(calls, n+" "+strings.Join(a, " ")); return nil }, os.Stderr)
	joined := strings.Join(calls, "\n")
	for _, w := range []string{"systemd-sysusers", "systemctl daemon-reload", "systemctl enable --now hivornet-cowrie-config.path"} {
		if !strings.Contains(joined, w) {
			t.Errorf("fehlt: %s in\n%s", w, joined)
		}
	}
}

func TestEnsureAndWriteCowrieAuth(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cowrie.cfg")
	os.WriteFile(p, []byte("[honeypot]\nhostname = x\n\n[ssh]\nlisten_endpoints = tcp:22\n"), 0o644)
	if ch, err := ensureCowrieAuth(p); err != nil || !ch {
		t.Fatalf("ensure: %v %v", ch, err)
	}
	b, _ := os.ReadFile(p)
	if got := parseCowrieAuth(string(b)); got.Mode != "random" || got.Min != 2 || got.Max != 5 || !strings.Contains(string(b), "[ssh]") {
		t.Fatalf("nach ensure: %+v\n%s", got, b)
	}
	if ch, _ := ensureCowrieAuth(p); ch {
		t.Error("zweites Mal darf nichts ändern")
	}
	writeCowrieAuth(p, string(b), "UserDB", "")
	b, _ = os.ReadFile(p)
	if got := parseCowrieAuth(string(b)); got.Mode != "all" || strings.Count(string(b), "auth_class") != 1 {
		t.Fatalf("UserDB: %+v\n%s", got, b)
	}
	if ch, err := ensureCowrieAuth(filepath.Join(t.TempDir(), "fehlt.cfg")); ch || err != nil {
		t.Error("fehlende Datei: nichts tun")
	}
}

func TestCowrieAuthAPI(t *testing.T) {
	h := testHive(t)
	dir := t.TempDir()
	t.Setenv("HIVE_COWRIE_REQUEST", dir+"/cowrie-request")
	t.Setenv("HIVE_COWRIE_CONFIG_STATUS", dir+"/status")
	old := cowrieCfgPath
	cowrieCfgPath = dir + "/cowrie.cfg"
	defer func() { cowrieCfgPath = old }()
	os.WriteFile(cowrieCfgPath, []byte("[honeypot]\nauth_class = AuthRandom\nauth_class_parameters = 2, 5, 10\n"), 0o644)
	os.WriteFile(dir+"/status", []byte("ok\n1700000000\nAnmeldung nach 2 bis 5 Versuchen je IP\n"), 0o644)

	rec := httptest.NewRecorder()
	h.cowrieAuthGet(rec, httptest.NewRequest("GET", "/api/cowrie/auth", nil))
	if s := rec.Body.String(); !strings.Contains(s, `"platform":"pi"`) || !strings.Contains(s, `"min":2`) || !strings.Contains(s, `"state":"ok"`) {
		t.Fatalf("GET: %s", s)
	}
	put := func(body string) int {
		rec := httptest.NewRecorder()
		h.cowrieAuthPut(rec, httptest.NewRequest("PUT", "/api/cowrie/auth", strings.NewReader(body)))
		return rec.Code
	}
	if put(`{"mode":"random","min":3,"max":7}`) != 200 {
		t.Fatal("gültige Regel abgelehnt")
	}
	if b, _ := os.ReadFile(dir + "/cowrie-request"); string(b) != "random 3 7\n" {
		t.Fatalf("Anfrage: %q", b)
	}
	for _, bad := range []string{`{"mode":"random","min":0,"max":5}`, `{"mode":"random","min":6,"max":3}`, `{"mode":"random","min":2,"max":50}`, `{"mode":"x"}`} {
		if put(bad) != 400 {
			t.Errorf("ungültig angenommen: %s", bad)
		}
	}
	if put(`{"mode":"all"}`) != 200 || !h.cowrieAllChosen() {
		t.Error("jede Kombination")
	}
	if b, _ := os.ReadFile(dir + "/cowrie-request"); string(b) != "userdb\n" {
		t.Fatalf("Anfrage: %q", b)
	}
}
