package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsOwnIP(t *testing.T) {
	t.Cleanup(func() { setOwnNets(OwnNets{Private: true}) })
	setOwnNets(OwnNets{Private: true, Nets: []string{"203.0.113.0/24", "198.51.100.7"}})
	for ip, want := range map[string]bool{
		"192.168.178.20": true, "10.1.2.3": true, "172.20.0.5": true, "127.0.0.1": true, "::1": true, "fd00::1": true,
		"100.64.1.1": true, "203.0.113.99": true, "198.51.100.7": true, "198.51.100.8": false, "8.8.8.8": false, "kaputt": false,
	} {
		if got := isOwnIP(ip); got != want {
			t.Errorf("%s: %v", ip, got)
		}
	}
	setOwnNets(OwnNets{Private: false})
	if isOwnIP("192.168.1.1") {
		t.Error("private Adressen trotz Abschaltung eigen")
	}
	setOwnNets(OwnNets{Private: true, InStats: true})
	if !isOwnIP("10.0.0.1") || ownHidden("10.0.0.1") {
		t.Error("in_stats: eigen, aber nicht verborgen")
	}
	x := OwnNets{Nets: []string{"keinnetz"}}
	if x.validate() == nil {
		t.Error("ungültiges Netz angenommen")
	}
}

// Eigene Tests: gespeichert und auf Wunsch sichtbar, aber nicht in Kennzahlen und "Gerade aktiv".
func TestOwnTestsHidden(t *testing.T) {
	setOwnNets(OwnNets{Private: true})
	h := testHive(t)
	w, wait := testWriter(t, h.st)
	now := time.Now()
	w.Submit(evAt(now.Add(-time.Minute), "connect", "redis", "192.168.178.50", 6379, nil))
	w.Submit(evAt(now.Add(-50*time.Second), "command", "redis", "192.168.178.50", 6379, map[string]any{"input": "CONFIG SET dir /tmp"}))
	w.Submit(evAt(now.Add(-40*time.Second), "connect", "ssh", "203.0.113.4", 22, nil))
	wait()
	var n int
	h.st.db.QueryRow(`SELECT COUNT(*) FROM events WHERE src_ip = '192.168.178.50'`).Scan(&n)
	if n != 2 {
		t.Fatalf("eigene Ereignisse nicht gespeichert: %d", n)
	}
	h.st.db.QueryRow(`SELECT COUNT(*) FROM top_hourly WHERE key = '192.168.178.50' OR field = 'command'`).Scan(&n)
	if n != 0 {
		t.Fatalf("eigene Ereignisse in der Zähltabelle: %d", n)
	}
	h.st.db.QueryRow(`SELECT COUNT(*) FROM attackers WHERE ip = '192.168.178.50'`).Scan(&n)
	if n != 0 {
		t.Fatal("eigene Adresse in der Angreiferliste")
	}
	get := func(q string) (out struct {
		Attacks []*Attack
		Own     int
	}) {
		rec := httptest.NewRecorder()
		h.attacks(rec, httptest.NewRequest("GET", "/api/attacks?"+q, nil))
		json.Unmarshal(rec.Body.Bytes(), &out)
		return
	}
	if d := get("active=1"); len(d.Attacks) != 1 || d.Own != 1 || d.Attacks[0].IP != "203.0.113.4" {
		t.Fatalf("Gerade aktiv: %+v", d)
	}
	if d := get("own=1"); len(d.Attacks) != 2 {
		t.Fatalf("own=1 zeigt nicht alle: %d", len(d.Attacks))
	}
	rec := httptest.NewRecorder()
	h.liveStatus(rec, httptest.NewRequest("GET", "/api/stats/live", nil))
	var live struct{ Active int }
	json.Unmarshal(rec.Body.Bytes(), &live)
	if live.Active != 1 {
		t.Fatalf("Live-Anzeige zählt eigene Tests: %d", live.Active)
	}
}

// Neuzählung: alte, vermischte Zähler verschwinden, neue Felder entstehen.
func TestRecountTop(t *testing.T) {
	setOwnNets(OwnNets{Private: true})
	st := testStore(t)
	e := evAt(time.Now(), "login", "snmp", "203.0.113.8", 161, map[string]any{"pdu": "get"})
	e.Username, e.Password = "community", "public"
	if err := e.Sanitize(); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"pdu": "get"})
	st.db.Exec(`INSERT INTO events(ts, service, type, src_ip, username, password, data) VALUES(?,?,?,?,?,?,?)`,
		e.TS.UnixMilli(), "snmp", "login", e.SrcIP, "community", "public", string(b))
	st.db.Exec(`INSERT INTO top_hourly(hour, field, key, label, n) VALUES(?, 'cred', 'community / public', '', 1)`, e.TS.UnixMilli()/3600000)
	st.db.Exec(`DELETE FROM kv WHERE k = ?`, recountKey)
	if !prepareRecount(st) {
		t.Fatal("Neuzählung nicht vorbereitet")
	}
	recountTop(st, 1)
	var n int
	st.db.QueryRow(`SELECT COUNT(*) FROM top_hourly WHERE field = 'cred'`).Scan(&n)
	if n != 0 {
		t.Fatal("alte Zähler nicht entfernt")
	}
	st.db.QueryRow(`SELECT COUNT(*) FROM top_hourly WHERE field = 'snmp' AND key = 'public'`).Scan(&n)
	if n != 1 {
		t.Fatal("SNMP-Community nicht neu gezählt")
	}
	if prepareRecount(st) {
		t.Fatal("Neuzählung läuft zweimal")
	}
}
