package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestJudgePort(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) int64 { return now.Add(-d).UnixMilli() }
	day := 24 * time.Hour
	cases := []struct {
		name   string
		s      PortStat
		total  int64
		direct bool
		pub    string
		silent bool
		want   string
	}{
		{"SMTP 3 Tage still, Pi", PortStat{Port: 25, Service: "smtp", ActiveSince: ago(3 * day)}, 500, true, "", true,
			"Port 25 (SMTP): seit 3 Tagen keine einzige Verbindung, vermutlich vom Internetanbieter gesperrt (häufig bei 25 und 445) oder im Router nicht auf dieses Gerät weitergeleitet."},
		{"SMB Docker ohne .env", PortStat{Port: 445, Service: "raw", ActiveSince: ago(4 * day)}, 500, false, "", true, "in der .env nicht freigegeben"},
		{"Redis Docker mit NAS-Port", PortStat{Port: 6379, Service: "redis", ActiveSince: ago(3 * day)}, 500, false, "16379", true, "nicht auf NAS-Port 16379 weitergeleitet"},
		{"erst 1 Tag aktiv", PortStat{Port: 25, Service: "smtp", ActiveSince: ago(day)}, 500, true, "", false, ""},
		{"Verbindungen da", PortStat{Port: 25, Service: "smtp", ActiveSince: ago(10 * day), Conns7d: 300, Conns48h: 40, LastConn: ago(time.Hour)}, 500, true, "", false, ""},
		{"seit 3 Tagen nichts mehr", PortStat{Port: 3389, Service: "rdp", ActiveSince: ago(10 * day), Conns7d: 80, LastConn: ago(4 * day)}, 500, true, "", true, "keine Verbindung mehr"},
		{"kaum Verbindungen", PortStat{Port: 445, Service: "raw", ActiveSince: ago(8 * day), Conns7d: 2, Conns48h: 1, LastConn: ago(10 * time.Hour)}, 500, true, "", true, "in 7 Tagen nur 2 Verbindungen"},
		{"seltener Port erst nach 7 Tagen", PortStat{Port: 11434, Service: "ollama", ActiveSince: ago(3 * day)}, 500, true, "", false, ""},
		{"seltener Port nach 8 Tagen", PortStat{Port: 11434, Service: "ollama", ActiveSince: ago(8 * day)}, 500, true, "", true, "Port 11434 (Ollama): seit 8 Tagen"},
		{"gar nichts los: kein Einzelhinweis", PortStat{Port: 25, Service: "smtp", ActiveSince: ago(5 * day)}, 0, true, "", false, ""},
		{"läuft nicht", PortStat{Port: 25, Service: "smtp"}, 500, true, "", false, ""},
	}
	for _, c := range cases {
		s := c.s
		judgePort(&s, now, c.total, c.direct, c.pub)
		if s.Silent != c.silent || !strings.Contains(s.Text, c.want) {
			t.Errorf("%s: still=%v Text %q", c.name, s.Silent, s.Text)
		}
	}
}

// Ende zu Ende: Lebenszeichen merkt sich die laufenden Ports, die Zähltabelle liefert die
// Verbindungen, Warnung und API zeigen den stillen Port.
func TestSilentPortsEndToEnd(t *testing.T) {
	t.Setenv("HIVE_DIRECT_PORTS", "1")
	h := testHive(t)
	cfg := DefaultSensorConfigForTest()
	cfg.Listeners = []ListenerConfig{{Service: "smtp", Port: 25, Mode: "emulate", Enabled: true}, {Service: "redis", Port: 6379, Mode: "emulate", Enabled: true},
		{Service: "rdp", Port: 3389, Mode: "emulate", Enabled: false}}
	b, _ := json.Marshal(cfg)
	h.st.SetKV(configKey(""), string(b))
	now := time.Now()
	start := now.Add(-4 * 24 * time.Hour)
	ls, _ := json.Marshal([]map[string]any{{"port": 25, "running": true}, {"port": 6379, "running": true}})
	h.trackListeners(Heartbeat{Sensor: "pi", Listeners: ls}, start)
	h.trackListeners(Heartbeat{Sensor: "pi", Listeners: ls}, now) // ändert "seit" nicht
	// Redis bekommt laufend Verbindungen, SMTP keine
	for i := 0; i < 90; i++ {
		hour := now.Add(-time.Duration(i)*time.Hour).UnixMilli() / 3600000
		h.st.db.Exec(topUpsert, hour, "port", "6379", "redis")
	}
	stats, err := h.portStats("", now)
	if err != nil || len(stats) != 2 {
		t.Fatalf("%v %+v", err, stats)
	}
	if !stats[0].Silent || stats[0].Port != 25 || stats[1].Silent || stats[1].Conns7d != 90 || stats[1].Conns48h < 47 {
		t.Fatalf("%+v", stats)
	}
	ws := h.silentWarnings(now)
	if len(ws) != 1 || !strings.Contains(ws[0].Text, "Port 25 (SMTP): seit 4 Tagen keine einzige Verbindung") {
		t.Fatalf("Warnungen %+v", ws)
	}
	// Seit-Zeit überlebt einen Neustart des Hive (kv-Tabelle)
	h.ports = portActivity{}
	if s := h.activeSince("pi", 25); s != start.UnixMilli() {
		t.Fatalf("seit %d, erwartet %d", s, start.UnixMilli())
	}
	// Port abgeschaltet: vergessen; wieder an: zählt neu
	ls2, _ := json.Marshal([]map[string]any{{"port": 6379, "running": true}})
	h.trackListeners(Heartbeat{Sensor: "pi", Listeners: ls2}, now)
	if h.activeSince("pi", 25) != 0 || h.activeSince("", 6379) != start.UnixMilli() {
		t.Fatal("abgeschalteter Port nicht vergessen")
	}
	if len(h.silentWarnings(now)) != 0 {
		t.Fatal("Warnung für abgeschalteten Port")
	}
}

// Gar keine Verbindungen auf irgendeinem Port: ein Sammelhinweis statt je Port.
func TestSilentAllPorts(t *testing.T) {
	h := testHive(t)
	cfg := DefaultSensorConfigForTest()
	b, _ := json.Marshal(cfg)
	h.st.SetKV(configKey(""), string(b))
	now := time.Now()
	ls, _ := json.Marshal([]map[string]any{{"port": 6379, "running": true}})
	h.trackListeners(Heartbeat{Sensor: "pi", Listeners: ls}, now.Add(-72*time.Hour))
	ws := h.silentWarnings(now)
	if len(ws) != 1 || !strings.Contains(ws[0].Text, "auf keinem Port") {
		t.Fatalf("%+v", ws)
	}
}
