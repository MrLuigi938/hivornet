package main

// Tests zu den Funden des vierten Sicherheitsaudits (Ende-zu-Ende-Prüfung).

import (
	"math"
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
