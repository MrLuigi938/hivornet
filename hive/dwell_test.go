package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func dr(sess, typ string, sec int64, input string) dwellRow {
	return dwellRow{svc: "ssh", ip: "203.0.113.5", sess: sess, typ: typ, ts: sec * 1000, ok: typ == "login", input: input}
}

func TestDwellCompute(t *testing.T) {
	now := time.Unix(100000, 0)
	rows := []dwellRow{
		// s1: Login ohne Befehl, 8 s
		dr("s1", "login", 10, ""), dr("s1", "disconnect", 18, ""),
		// s2: Login ohne Befehl, 10 s
		dr("s2", "login", 20, ""), dr("s2", "disconnect", 30, ""),
		// s3: Prüfreihe, danach nichts
		dr("s3", "login", 40, ""), dr("s3", "command", 41, "printf '%s\n' 'check_0123456789abcdef_small_math'"),
		dr("s3", "command", 42, "v=outer; (v=inner; printf 'child=%s\n' \"$v\")"), dr("s3", "disconnect", 60, ""),
		// s4: Prüfreihe, danach weiterer Befehl
		dr("s4", "login", 70, ""), dr("s4", "command", 71, "echo; echo 'check_0123456789abcdef_transport_done'"),
		dr("s4", "command", 72, "uname -a"), dr("s4", "disconnect", 100, ""),
		// s5: Befehl vor dem Login zählt nicht, ohne Login-Erfolg wird die Sitzung ignoriert
		dr("s5", "command", 5, "id"), dr("s5", "disconnect", 6, ""),
		// s6: noch offen (zuletzt vor 1 min) wird nicht gewertet
		dr("s6", "login", 99940, ""),
	}
	st := dwellCompute(rows, now)
	if len(st) != 2 {
		t.Fatalf("Zeilen: %+v", st)
	}
	s, all := st[0], st[1]
	if s.Service != "ssh" || all.Service != "" || s != func() DwellStat { a := all; a.Service = "ssh"; return a }() {
		t.Errorf("Dienst und Summe müssen übereinstimmen: %+v / %+v", s, all)
	}
	if s.Logins != 4 || s.NoCmd != 2 {
		t.Errorf("Logins/NoCmd: %+v", s)
	}
	// Dauern: 8, 10, 20, 30 s -> Median 15 s
	if s.MedianDwellMs != 15000 {
		t.Errorf("Median Dauer: %d", s.MedianDwellMs)
	}
	// Befehle 0, 0, 2, 2 -> Median 1, Mittel 1
	if s.MedianCmds != 1 || s.AvgCmds != 1 {
		t.Errorf("Befehle: %v %v", s.MedianCmds, s.AvgCmds)
	}
	if s.CheckSessions != 2 || s.CheckFollow != 1 {
		t.Errorf("Prüfreihe: %+v", s)
	}
}

func TestDwellMerge(t *testing.T) {
	stats := []DwellStat{{Service: "ssh", Logins: 2}, {Logins: 2}}
	rows, total := dwellMerge(stats, map[string][2]int{"ssh": {4, 1}, "telnet": {2, 2}})
	if len(rows) != 2 || rows[0].ReturnIPs != 4 || rows[0].ReturnBack != 1 || rows[1].Service != "telnet" || rows[1].ReturnBack != 2 {
		t.Errorf("Zeilen: %+v", rows)
	}
	if total.ReturnIPs != 6 || total.ReturnBack != 3 {
		t.Errorf("Summe: %+v", total)
	}
}

func TestDwellEndpoint(t *testing.T) {
	h := testHive(t)
	now := time.Now()
	ins := func(typ, sess, ip, data string, ago time.Duration) {
		var d any // wie im Betrieb: ohne Daten NULL
		if data != "" {
			d = data
		}
		if _, err := h.st.db.Exec(`INSERT INTO events(ts,type,service,src_ip,session,data,country) VALUES(?,?,?,?,?,?,'DE')`,
			now.Add(-ago).UnixMilli(), typ, "telnet", ip, sess, d); err != nil {
			t.Fatal(err)
		}
	}
	// Wiederkehr-Gruppe: erster Login vor 20 Tagen, danach zwei weitere Verbindungen (1 Tag später)
	ins("login", "a1", "203.0.113.20", `{"success":true}`, 20*24*time.Hour)
	ins("connect", "a2", "203.0.113.20", ``, 19*24*time.Hour)
	ins("login", "b1", "203.0.113.21", `{"success":true}`, 20*24*time.Hour) // kehrt nicht zurück
	ins("login", "c1", "203.0.113.22", `{"success":false}`, 20*24*time.Hour)
	// Sitzung im Zeitraum
	ins("login", "s1", "203.0.113.30", `{"success":true}`, 3*time.Hour)
	ins("command", "s1", "203.0.113.30", `{"input":"ls"}`, 3*time.Hour-2*time.Second)
	ins("disconnect", "s1", "203.0.113.30", ``, 3*time.Hour-10*time.Second)
	rec := httptest.NewRecorder()
	h.dwell(rec, httptest.NewRequest("GET", "/api/dwell?range=7d", nil))
	if rec.Code != 200 {
		t.Fatalf("Status %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Services []DwellStat `json:"services"`
		Total    DwellStat   `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err, rec.Body.String())
	}
	if len(out.Services) != 1 || out.Services[0].Service != "telnet" {
		t.Fatalf("Dienste: %+v", out.Services)
	}
	s := out.Services[0]
	if s.Logins != 1 || s.NoCmd != 0 || s.MedianDwellMs != 10000 || s.AvgCmds != 1 {
		t.Errorf("Dienst: %+v", s)
	}
	if s.ReturnIPs != 2 || s.ReturnBack != 1 || out.Total.ReturnIPs != 2 {
		t.Errorf("Wiederkehr: %+v", s)
	}
}
