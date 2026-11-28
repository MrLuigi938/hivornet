package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// Live-Check 0.9.7: Eine Top-Liste, die länger braucht als die Frist der Anfrage, wird trotzdem
// fertig gerechnet und abgelegt; die nächste Anfrage bekommt sie aus dem Speicher, ohne neu zu
// rechnen (vorher: abgebrochen, verworfen, jede Anfrage begann von vorn).
func TestTopResSlowBuildFinishes(t *testing.T) {
	var c topResCache
	var calls atomic.Int32
	load := func(ctx context.Context) ([]byte, error) {
		calls.Add(1)
		select {
		case <-time.After(150 * time.Millisecond):
			return []byte(`["ok"]`), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	k := topResKey{field: "country", hour: time.Now().UnixMilli()/3600000 - 24*30, limit: 10}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	_, err := c.get(ctx, k, load)
	cancel()
	if !errors.Is(err, errBusy) {
		t.Fatalf("erwartet errBusy, bekommen %v", err)
	}
	// zweite Anfrage, während die erste Berechnung noch läuft: wartet auf dieselbe
	b, err := c.get(t.Context(), k, load)
	if err != nil || string(b) != `["ok"]` {
		t.Fatalf("zweite Anfrage: %q, %v", b, err)
	}
	b, err = c.get(t.Context(), k, load)
	if err != nil || string(b) != `["ok"]` {
		t.Fatalf("aus dem Speicher: %q, %v", b, err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d Berechnungen, erwartet 1", n)
	}
}

// Ein Fehler der Berechnung kommt bei der wartenden Anfrage an und wird nicht abgelegt.
func TestTopResBuildError(t *testing.T) {
	var c topResCache
	boom := errors.New("kaputt")
	k := topResKey{field: "asn", limit: 10}
	if _, err := c.get(t.Context(), k, func(context.Context) ([]byte, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("erwartet Fehler, bekommen %v", err)
	}
	b, err := c.get(t.Context(), k, func(context.Context) ([]byte, error) { return []byte(`[]`), nil })
	if err != nil || string(b) != `[]` {
		t.Fatalf("nach dem Fehler: %q, %v", b, err)
	}
}

// Schnappschuss: Gibt die Anfrage auf, läuft der Aufbau im Hintergrund zu Ende.
func TestSnapWaitBuildsInBackground(t *testing.T) {
	h := testHive(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := h.snapWait(ctx); err != nil && !errors.Is(err, errBusy) { // nil nur, wenn schon fertig
		t.Fatalf("erwartet errBusy, bekommen %v", err)
	}
	h.snap.mu.Lock()
	run := h.snap.run
	h.snap.mu.Unlock()
	if run != nil {
		select {
		case <-run.done:
		case <-time.After(10 * time.Second):
			t.Fatal("Aufbau im Hintergrund nicht fertig")
		}
		if run.err != nil {
			t.Fatal(run.err)
		}
	}
	if list, _, _ := h.snap.get(); list == nil {
		t.Fatal("Schnappschuss nicht aufgebaut")
	}
	if err := h.snapWait(t.Context()); err != nil {
		t.Fatal(err)
	}
}
