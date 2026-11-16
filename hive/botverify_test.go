package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBotVerify(t *testing.T) {
	v := &botVerifierT{cache: map[string]botResult{}, pending: map[string]bool{}, queue: make(chan [2]string, 8),
		lookPTR: func(_ context.Context, ip string) ([]string, error) {
			switch ip {
			case "66.249.66.1":
				return []string{"crawl-66-249-66-1.googlebot.com."}, nil
			case "203.0.113.9":
				return []string{"crawl-1.googlebot.com.evil.example."}, nil
			case "203.0.113.10":
				return []string{"crawl-66-249-66-1.googlebot.com."}, nil // PTR gefälscht, Vorwärts passt nicht
			case "203.0.113.11": // gemietete VM in der Google-Cloud: Vorwärts passt, ist aber kein Googlebot
				return []string{"11.113.0.203.bc.googleusercontent.com."}, nil
			}
			return nil, errors.New("NXDOMAIN")
		},
		lookIP: func(_ context.Context, host string) ([]string, error) {
			switch host {
			case "crawl-66-249-66-1.googlebot.com":
				return []string{"66.249.66.1"}, nil
			case "11.113.0.203.bc.googleusercontent.com":
				return []string{"203.0.113.11"}, nil
			}
			return nil, errors.New("NXDOMAIN")
		}}
	ctx := context.Background()
	for ip, want := range map[string]string{"66.249.66.1": "ok", "203.0.113.9": "fake", "203.0.113.10": "fake", "198.51.100.1": "fake", "203.0.113.11": "fake"} {
		if r := v.check(ctx, ip, "Googlebot"); r.Verdict != want {
			t.Errorf("%s: %q, erwartet %q", ip, r.Verdict, want)
		}
	}
	// Ablauf über die Warteschlange mit Zwischenspeicher
	st := testStore(t)
	v.st = st
	b := claimedBot([]string{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"})
	if b == nil || b.Name != "Googlebot" {
		t.Fatal("Googlebot nicht erkannt")
	}
	if s, _ := v.status("66.249.66.1", b); s != "" {
		t.Fatal("ohne Prüfung schon ein Ergebnis")
	}
	stop := make(chan struct{})
	go v.run(stop)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s, _ := v.status("66.249.66.1", b); s == "ok" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(stop)
	if s, ptr := v.status("66.249.66.1", b); s != "ok" || ptr == "" {
		t.Fatalf("Ergebnis %q %q", s, ptr)
	}
	if data, _, ok := st.lookupGet("ip:66.249.66.1", "rdns", time.Hour); !ok || data == "" {
		t.Fatal("nicht gespeichert")
	}
}
