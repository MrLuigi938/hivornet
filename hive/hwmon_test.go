package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Nachgebautes /proc und /sys wie auf einem Raspberry Pi 4 mit den drei Diensten.
func fakeHW(t *testing.T) (proc, sys string) {
	t.Helper()
	root := t.TempDir()
	proc, sys = filepath.Join(root, "proc"), filepath.Join(root, "sys")
	w := func(p, s string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w(filepath.Join(proc, "stat"), "cpu  1000 0 1000 8000 0 0 0 0 0 0\ncpu0 250 0 250 2000 0 0 0 0 0 0\ncpu1 250 0 250 2000 0 0 0 0 0 0\ncpu2 250 0 250 2000 0 0 0 0 0 0\ncpu3 250 0 250 2000 0 0 0 0 0 0\nintr 1\n")
	w(filepath.Join(proc, "meminfo"), "MemTotal:        3884000 kB\nMemFree:          500000 kB\nMemAvailable:    2884000 kB\nBuffers:          100000 kB\nCached:          1500000 kB\nSwapTotal:        204800 kB\nSwapFree:         204800 kB\n")
	w(filepath.Join(proc, "loadavg"), "0.42 0.35 0.30 1/200 1234\n")
	w(filepath.Join(proc, "uptime"), "86400.50 300000.00\n")
	w(filepath.Join(proc, "device-tree/model"), "Raspberry Pi 4 Model B Rev 1.5\x00")
	w(filepath.Join(proc, "self/status"), "Name:\thive\nVmRSS:\t   65536 kB\n")
	w(filepath.Join(sys, "class/thermal/thermal_zone0/temp"), "51500\n")
	w(filepath.Join(sys, "firmware-throttled"), "0x50000\n")
	cg := filepath.Join(sys, "fs/cgroup/system.slice")
	w(filepath.Join(cg, "hivornet-hive.service/memory.current"), "73400320\n")
	w(filepath.Join(cg, "hivornet-hive.service/memory.max"), "402653184\n")
	w(filepath.Join(cg, "hivornet-cowrie.service/memory.current"), "52428800\n")
	w(filepath.Join(cg, "hivornet-cowrie.service/memory.max"), "max\n")
	return proc, sys
}

func TestHardwareMonitor(t *testing.T) {
	proc, sys := fakeHW(t)
	oldP, oldS, oldT := hwProc, hwSys, hwThrottled
	hwProc, hwSys, hwThrottled = proc, sys, "firmware-throttled"
	t.Cleanup(func() { hwProc, hwSys, hwThrottled = oldP, oldS, oldT })

	h := testHive(t)
	h.hw.sample(time.Now())
	// zweiter Punkt: 600 von 1000 Ticks beschäftigt -> 60 %
	os.WriteFile(filepath.Join(proc, "stat"), []byte("cpu  1300 0 1300 8400 0 0 0 0 0 0\ncpu0 1 0 0 0\ncpu1 1 0 0 0\ncpu2 1 0 0 0\ncpu3 1 0 0 0\n"), 0o644)
	h.hw.sample(time.Now())

	rec := httptest.NewRecorder()
	h.hardwareAPI(rec, httptest.NewRequest("GET", "/api/hardware", nil))
	var s hwSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if !s.Available || s.Cores != 4 || s.CPU != 60 {
		t.Fatalf("CPU: %+v", s)
	}
	if s.MemTotal != 3884000*1024 || s.MemUsed != 1000000*1024 || s.MemCache != 1600000*1024 {
		t.Errorf("Speicher: %d %d %d", s.MemTotal, s.MemUsed, s.MemCache)
	}
	if s.Temp != 51.5 || s.Load[0] != 0.42 || s.UptimeS != 86400 || s.Model != "Raspberry Pi 4 Model B Rev 1.5" || s.HiveRSS != 64<<20 {
		t.Errorf("Werte: %+v", s)
	}
	if s.Throttled != "seit dem Start schon einmal Unterspannung" {
		t.Errorf("Drosselung: %q", s.Throttled)
	}
	if len(s.Services) != 2 || s.Services[0].Name != "hivornet-hive" || s.Services[0].Limit != 384<<20 || s.Services[1].Limit != 0 {
		t.Errorf("Dienste: %+v", s.Services)
	}
	if len(s.History) != 2 || s.History[1].CPU != 60 || s.History[1].Mem < 25 || s.History[1].Mem > 26 {
		t.Errorf("Verlauf: %+v", s.History)
	}
}

func TestHardwareMonitorUnavailable(t *testing.T) {
	oldP := hwProc
	hwProc = filepath.Join(t.TempDir(), "fehlt")
	t.Cleanup(func() { hwProc = oldP })
	h := testHive(t)
	h.hw.sample(time.Now())
	rec := httptest.NewRecorder()
	h.hardwareAPI(rec, httptest.NewRequest("GET", "/api/hardware", nil))
	var s hwSnapshot
	json.Unmarshal(rec.Body.Bytes(), &s)
	if s.Available || s.History == nil {
		t.Fatalf("%+v", s)
	}
}

// Raspberry Pi 3: keine Speicherverwaltung der cgroups (memory.current fehlt), keine
// Firmware-Bits; Speicher je Dienst aus der Statusdatei von hivornet-memstat, Unterspannung
// über rpi_volt.
func TestHardwareMonitorPi3(t *testing.T) {
	root := t.TempDir()
	proc, sys := filepath.Join(root, "proc"), filepath.Join(root, "sys")
	w := func(p, s string) {
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w(filepath.Join(proc, "stat"), "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 1 0 0 0\n")
	w(filepath.Join(proc, "meminfo"), "MemTotal: 948000 kB\nMemAvailable: 650000 kB\n")
	w(filepath.Join(sys, "class/hwmon/hwmon0/name"), "cpu_thermal\n")
	w(filepath.Join(sys, "class/hwmon/hwmon1/name"), "rpi_volt\n")
	w(filepath.Join(sys, "class/hwmon/hwmon1/in0_lcrit_alarm"), "0\n")
	mem := filepath.Join(root, "memory")
	w(mem, fmt.Sprintf("ok\n%d\nArbeitsspeicher der Dienste\nmemcg 0\nhivornet-hive 96468992 402653184\nhivornet-cowrie 81264640 268435456\nunbekannt 1 1\n", time.Now().Unix()))
	oldP, oldS, oldT, oldM := hwProc, hwSys, hwThrottled, hwMemStatus
	hwProc, hwSys, hwThrottled, hwMemStatus = proc, sys, "fehlt", mem
	t.Cleanup(func() { hwProc, hwSys, hwThrottled, hwMemStatus = oldP, oldS, oldT, oldM })

	var m hwMonitor
	m.sample(time.Now())
	s := m.snapshot()
	if len(s.Services) != 2 || s.Services[0].Name != "hivornet-hive" || s.Services[0].Bytes != 96468992 || s.Services[1].Limit != 268435456 {
		t.Fatalf("Dienste: %+v", s.Services)
	}
	if !s.MemLimitsOff {
		t.Error("Speichergrenzen wirkungslos nicht erkannt")
	}
	if s.Throttled != "ok" {
		t.Errorf("rpi_volt: %q", s.Throttled)
	}
	w(filepath.Join(sys, "class/hwmon/hwmon1/in0_lcrit_alarm"), "1\n")
	if got := throttled(); got != "Unterspannung" {
		t.Errorf("Unterspannung: %q", got)
	}
	// veraltete Datei (Zeitgeber steht) zählt nicht
	w(mem, "ok\n1000\nx\nmemcg 0\nhivornet-hive 1 1\n")
	if l, _ := hwServices(); len(l) != 0 {
		t.Errorf("veraltete Statusdatei benutzt: %+v", l)
	}
}
