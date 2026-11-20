package main

// Tests zu den Funden des vierten Sicherheitsaudits (Ende-zu-Ende-Prüfung).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Ein Sensor mit gültigem Token darf mit riesigen Dauern nicht die Summen in hourly und
// attackers überlaufen lassen; vorher scheiterte danach jede Schreib-Transaktion der Stunde.
func TestIngestDurationOverflow(t *testing.T) {
	h := testHive(t)
	w, err := NewWriter(h.st, func(*Event) {})
	if err != nil {
		t.Fatal(err)
	}
	mk := func() *Event {
		e := &Event{TS: time.Now(), Type: "connect", Service: "http", SrcIP: "192.0.2.7", DstPort: 80,
			TarpitMs: math.MaxInt64, DurationMs: math.MaxInt64}
		if err := e.Sanitize(); err != nil {
			t.Fatal(err)
		}
		return e
	}
	a := mk()
	if a.TarpitMs != maxEventMs || a.DurationMs != maxEventMs {
		t.Fatalf("nicht begrenzt: %d %d", a.TarpitMs, a.DurationMs)
	}
	for i := 0; i < 3; i++ {
		if err := w.writeBatch([]*Event{mk(), mk()}); err != nil {
			t.Fatalf("Schreiben scheitert: %v", err)
		}
	}
	neg := &Event{TS: time.Now(), Type: "connect", SrcIP: "192.0.2.7", TarpitMs: -5, DurationMs: math.MinInt64}
	neg.Sanitize()
	if neg.TarpitMs != 0 || neg.DurationMs != 0 {
		t.Fatalf("negativ: %d %d", neg.TarpitMs, neg.DurationMs)
	}
}

// "tty"-Ereignisse kommen nur vom Cowrie-Leser des Hives, nie über /api/ingest.
func TestIngestRejectsTTY(t *testing.T) {
	h := testHive(t)
	w, err := NewWriter(h.st, func(*Event) {})
	if err != nil {
		t.Fatal(err)
	}
	h.writer = w
	body := `{"sensor":"s1","events":[
	 {"type":"tty","src_ip":"192.0.2.8","session":"fremd","data":{"shasum":"` + strings.Repeat("a", 64) + `"}},
	 {"type":"connect","src_ip":"192.0.2.8"}]}`
	rec := httptest.NewRecorder()
	h.ingest(rec, httptest.NewRequest("POST", "/api/ingest", strings.NewReader(body)))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"accepted":1`) {
		t.Fatalf("Antwort %d %s", rec.Code, rec.Body.String())
	}
}

// Lebenszeichen mit erfundenen Namen und riesigen Port-Listen füllen die Port-Tabelle nicht.
func TestHeartbeatListenersBounded(t *testing.T) {
	h := testHive(t)
	var b strings.Builder
	b.WriteString("[")
	for p := 0; p < 30000; p++ {
		if p > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"port":%d,"running":true}`, p)
	}
	b.WriteString("]")
	ls := json.RawMessage(b.String())
	for i := 0; i < 150; i++ {
		body, _ := json.Marshal(Heartbeat{Sensor: fmt.Sprintf("s%d", i), Listeners: ls})
		req := httptest.NewRequest("POST", "/api/sensor/heartbeat", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		h.heartbeat(rec, req)
		if i > 3 {
			break // zwei Bedingungen reichen: Ports je Sensor und Anzahl der Sensoren (unten)
		}
	}
	h.ports.mu.Lock()
	n := len(h.portSinceLocked())
	h.ports.mu.Unlock()
	if n == 0 || n > 5*maxTrackedPorts {
		t.Fatalf("%d Port-Einträge", n)
	}
	// mehr als 100 Sensoren: keine neuen Einträge
	for i := 0; i < 120; i++ {
		h.sensors.Put(Heartbeat{Sensor: fmt.Sprintf("x%d", i)})
	}
	before := n
	h.heartbeat(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(`{"sensor":"neu","listeners":[{"port":22,"running":true}]}`)))
	h.ports.mu.Lock()
	n = len(h.portSinceLocked())
	h.ports.mu.Unlock()
	if n != before {
		t.Fatalf("unbekannter 101. Sensor trägt Ports ein: %d -> %d", before, n)
	}
}

func TestHeartbeatFieldsClipped(t *testing.T) {
	h := testHive(t)
	held := make([]HeldTarpit, 2000)
	for i := range held {
		held[i] = HeldTarpit{IP: "192.0.2.1", Port: 22}
	}
	body, _ := json.Marshal(Heartbeat{Sensor: "s", LastError: strings.Repeat("x", 100000), HeldTarpits: held})
	h.heartbeat(httptest.NewRecorder(), httptest.NewRequest("POST", "/", bytes.NewReader(body)))
	hb := h.sensors.All()[0]
	if len(hb.LastError) > 512 || len(hb.HeldTarpits) > 300 {
		t.Fatalf("nicht gekürzt: %d %d", len(hb.LastError), len(hb.HeldTarpits))
	}
}

// Ersteinrichtung nur aus dem Heimnetz: Ein offen erreichbarer Hive darf nicht von Fremden
// eingerichtet werden.
func TestSetupOnlyFromHomeNet(t *testing.T) {
	h := testHive(t)
	h.auth = NewAuth(h.st, "", false)
	try := func(ip string) int {
		req := httptest.NewRequest("POST", "/api/setup", strings.NewReader(`{"password":"einlangespasswort"}`))
		req.Header.Set("X-Requested-With", "hivornet")
		req.RemoteAddr = ip + ":40000"
		rec := httptest.NewRecorder()
		h.setupRun(rec, req)
		return rec.Code
	}
	for _, ip := range []string{"198.51.100.4", "[2001:db8::5]"} {
		if c := try(ip); c != 403 {
			t.Fatalf("%s: %d", ip, c)
		}
	}
	if !h.auth.NeedsSetup() {
		t.Fatal("Fremder hat eingerichtet")
	}
	for _, ip := range []string{"192.168.1.20", "127.0.0.1", "100.100.1.1", "[fd00::1]"} {
		if !setupAllowed(strings.Trim(ip, "[]")) {
			t.Fatalf("%s abgelehnt", ip)
		}
	}
	if c := try("192.168.1.20"); c != 200 {
		t.Fatalf("Heimnetz: %d", c)
	}
}

// Pi: Die Hive-Datenbank ist für Honeypot und Cowrie unsichtbar.
func TestPiUnitsHideHiveData(t *testing.T) {
	read := func(n string) string {
		b, err := os.ReadFile("../pi/rootfs/etc/systemd/system/" + n)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	hv := read("hivornet-hive.service")
	if !strings.Contains(hv, "StateDirectoryMode=0700") || !strings.Contains(hv, "UMask=0077") {
		t.Error("Hive-Dienst: Datenordner nicht auf 0700/UMask 0077")
	}
	for _, n := range []string{"hivornet-honeypot.service", "hivornet-cowrie.service", "hivornet-cowrie-clean.service"} {
		if !strings.Contains(read(n), "InaccessiblePaths=-/var/lib/hivornet ") {
			t.Errorf("%s: /var/lib/hivornet nicht gesperrt", n)
		}
	}
}
