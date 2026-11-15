package main

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func evAt(ts time.Time, typ, svc, ip string, port int, data map[string]any) *Event {
	e := &Event{TS: ts, Type: typ, Service: svc, SrcIP: ip, DstPort: port, Country: "CN", CountryName: "China", City: "Peking"}
	if data != nil {
		e.Data, _ = json.Marshal(data)
	}
	return e
}

func TestAttacksGrouping(t *testing.T) {
	h := testHive(t)
	w, wait := testWriter(t, h.st)
	now := time.Now()
	t0 := now.Add(-50 * time.Minute)
	// Angriff 1: SSH-Brute-Force mit Erfolg, Befehlen und Download
	a := "203.0.113.10"
	w.Submit(evAt(t0, "connect", "ssh", a, 22, nil))
	for i, pw := range []string{"123456", "admin", "123456"} {
		e := evAt(t0.Add(time.Duration(i+1)*time.Second), "login", "ssh", a, 22, nil)
		e.Username, e.Password = "root", pw
		w.Submit(e)
	}
	ok := evAt(t0.Add(5*time.Second), "login", "ssh", a, 22, map[string]any{"success": true})
	ok.Username, ok.Password = "root", "toor"
	w.Submit(ok)
	w.Submit(evAt(t0.Add(6*time.Second), "command", "ssh", a, 22, map[string]any{"input": "uname -a"}))
	w.Submit(evAt(t0.Add(7*time.Second), "download", "ssh", a, 22, map[string]any{"url": "http://198.51.100.1/x.sh"}))
	// 30 Minuten Pause: neuer Angriff derselben IP (Web-Scanner)
	t1 := t0.Add(30 * time.Minute)
	w.Submit(evAt(t1, "request", "http", a, 80, map[string]any{"path": "/.env", "method": "GET"}))
	w.Submit(evAt(t1.Add(time.Second), "request", "http", a, 80, map[string]any{"path": "/.env", "method": "GET"}))
	// andere IP: Port-Scan, gerade aktiv
	b := "198.51.100.20"
	for i, p := range []int{22, 23, 3306} {
		w.Submit(evAt(now.Add(-time.Duration(3-i)*time.Second), "connect", "ssh", b, p, nil))
	}
	wait()

	get := func(q string) (out struct {
		Attacks []*Attack
		Total   int
		Stufen  []int
	}) {
		rec := httptest.NewRecorder()
		h.attacks(rec, httptest.NewRequest("GET", "/api/attacks?"+q, nil))
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", q, rec.Code, rec.Body)
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		return
	}
	all := get("range=24h")
	if all.Total != 3 || len(all.Attacks) != 3 {
		t.Fatalf("erwartet 3 Angriffe, bekommen %d: %+v", all.Total, all.Attacks)
	}
	scan, web, ssh := all.Attacks[0], all.Attacks[1], all.Attacks[2] // neueste zuerst
	if scan.IP != b || scan.Profile != "Port-Scan" || scan.Stufe != stufeScan || len(scan.Ports) != 3 {
		t.Errorf("Scan falsch: %+v", scan)
	}
	if web.Profile != "Web-Scanner" || web.Stufe != stufeVersuch || len(web.Paths) != 1 || web.Paths[0].N != 2 || web.Tags[0].Key != "secret_hunt" {
		t.Errorf("Web falsch: %+v", web)
	}
	if ssh.Profile != "SSH-Einbruch" || ssh.Stufe != stufeDownload || !ssh.Success || ssh.SuccessCred != "root / toor" ||
		ssh.Creds[0].Key != "root / 123456" || ssh.Creds[0].N != 2 || ssh.CredsDistinct != 3 || ssh.Counts["login"] != 4 ||
		len(ssh.Commands) != 1 || len(ssh.URLs) != 1 || ssh.Country != "CN" {
		t.Errorf("SSH falsch: %+v", ssh)
	}
	if all.Stufen[stufeScan] != 1 || all.Stufen[stufeVersuch] != 1 || all.Stufen[stufeDownload] != 1 {
		t.Errorf("Stufen: %v", all.Stufen)
	}
	if got := get("active=1"); len(got.Attacks) != 1 || got.Attacks[0].IP != b {
		t.Errorf("aktiv: %+v", got.Attacks)
	}
	if got := get("stufe=4"); len(got.Attacks) != 1 || got.Attacks[0].Stufe != 4 {
		t.Errorf("Filter Stufe: %+v", got.Attacks)
	}
	if got := get("q=toor"); len(got.Attacks) != 1 || got.Attacks[0].IP != a {
		t.Errorf("Suche: %+v", got.Attacks)
	}
	if got := get("ip=" + b); len(got.Attacks) != 1 {
		t.Errorf("IP-Filter: %+v", got.Attacks)
	}
	if got := get("service=http"); len(got.Attacks) != 1 || got.Attacks[0].Profile != "Web-Scanner" {
		t.Errorf("Dienst-Filter: %+v", got.Attacks)
	}
	if got := get("limit=1&before=" + strconv.FormatInt(scan.Last, 10)); len(got.Attacks) != 1 || got.Attacks[0].ID != web.ID {
		t.Errorf("Weiterblättern: %+v", got.Attacks)
	}
	rec := httptest.NewRecorder()
	h.attacks(rec, httptest.NewRequest("GET", "/api/attacks?ip=kaputt", nil))
	if rec.Code != 400 {
		t.Errorf("ungültige IP: %d", rec.Code)
	}

	// Verläufe und Vergleich
	rec = httptest.NewRecorder()
	h.series(rec, httptest.NewRequest("GET", "/api/stats/series?range=24h", nil))
	var s struct {
		Series map[string][]int64
		Totals map[string]int64
	}
	json.Unmarshal(rec.Body.Bytes(), &s)
	sum := func(v []int64) (n int64) {
		for _, x := range v {
			n += x
		}
		return
	}
	if len(s.Series["connect"]) != 24 || sum(s.Series["connect"]) != 4 || sum(s.Series["success"]) != 1 || s.Totals["success"] != 1 ||
		s.Totals["ips"] != 2 || s.Totals["login"] != 4 || s.Totals["request"] != 2 {
		t.Errorf("Verlauf: %+v %+v", s.Series, s.Totals)
	}
}

func TestAttackClassify(t *testing.T) {
	mk := func(evs ...*Event) *Attack {
		a := newAttack(evs[0])
		for _, e := range evs {
			a.add(e)
		}
		a.finish()
		return a
	}
	now := time.Now()
	ip := "203.0.113.5"
	cases := []struct {
		a    *Attack
		want string
	}{
		{mk(evAt(now, "command", "telnet", ip, 23, map[string]any{"input": "/bin/busybox ECCHI"})), "IoT-Botnetz (Mirai-Art)"},
		{mk(evAt(now, "command", "redis", ip, 6379, map[string]any{"input": "CONFIG SET dir /var/spool/cron"})), "Redis-Übernahme"},
		{mk(evAt(now, "login", "mysql", ip, 3306, map[string]any{"password_hashed": true})), "MySQL-Brute-Force"},
		{mk(evAt(now, "login", "rdp", ip, 3389, map[string]any{"cookie": "Administr"})), "RDP-Abtastung"},
		{mk(evAt(now, "request", "http", ip, 80, map[string]any{"path": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"})), "Web-Exploit"},
		{mk(evAt(now, "connect", "ssh", ip, 22, nil)), "Verbindungsversuch"},
	}
	for _, c := range cases {
		if c.a.Profile != c.want {
			t.Errorf("erwartet %q, bekommen %q", c.want, c.a.Profile)
		}
	}
	if a := mk(evAt(now, "login", "mysql", ip, 3306, map[string]any{"password_hashed": true})); a.Creds[0].Key != " / (gehasht)" {
		t.Errorf("gehasht: %q", a.Creds[0].Key)
	}
}
