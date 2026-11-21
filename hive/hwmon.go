package main

// Hardware-Monitor für den Reiter System (GET /api/hardware).
//
// Ein Sammler liest alle 15 Sekunden CPU-Auslastung, Arbeitsspeicher, Temperatur und Last aus
// /proc und /sys (nur lesend, keine neuen Rechte; die Sandbox des Pi-Dienstes erlaubt das) und
// hält die letzte Stunde als Verlauf im Speicher (240 Punkte, wenige KB). Auf dem Pi kommt der
// Speicher je Dienst aus den cgroups der systemd-Dienste hinzu, in Docker der des eigenen
// Containers mit seiner Grenze.
//
// Auf Systemen ohne /proc (Entwicklung unter Windows) meldet die API available=false.

import (
	"bufio"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	hwEvery  = 15 * time.Second
	hwPoints = 240 // eine Stunde
)

// In Tests überschreibbar.
var (
	hwProc = "/proc"
	hwSys  = "/sys"
	// Drosselungs-Bits der Pi-Firmware (relativ zu hwSys; der Doppelpunkt geht unter Windows nicht)
	hwThrottled = "devices/platform/soc/soc:firmware/get_throttled"
	// Statusdatei von hivornet-memstat (Pi, root, jede Minute): Speicher je Dienst
	hwMemStatus = "/var/lib/hivornet-status/memory"
)

type hwPoint struct {
	T    int64   `json:"t"`              // Unix-Millisekunden
	CPU  float64 `json:"cpu"`            // Prozent über alle Kerne
	Mem  float64 `json:"mem"`            // Prozent belegt (ohne Puffer und Cache)
	Temp float64 `json:"temp,omitempty"` // °C
}

type hwService struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Bytes int64  `json:"bytes"`
	Limit int64  `json:"limit,omitempty"` // 0: keine Grenze
}

type hwSnapshot struct {
	Available bool        `json:"available"`
	Model     string      `json:"model,omitempty"`
	Cores     int         `json:"cores"`
	CPU       float64     `json:"cpu"`
	Load      [3]float64  `json:"load"`
	MemTotal  int64       `json:"mem_total"`
	MemUsed   int64       `json:"mem_used"`
	MemCache  int64       `json:"mem_cache"`
	SwapTotal int64       `json:"swap_total"`
	SwapUsed  int64       `json:"swap_used"`
	Temp      float64     `json:"temp,omitempty"`
	TempMax   float64     `json:"temp_max,omitempty"` // höchster Wert der letzten Stunde
	Throttled string      `json:"throttled,omitempty"`
	UptimeS   int64       `json:"uptime_s"`
	HiveRSS   int64       `json:"hive_rss"`
	Services  []hwService `json:"services,omitempty"`
	// Speichergrenzen der Dienste (MemoryMax=) greifen nicht: Speicherverwaltung der cgroups aus
	MemLimitsOff bool         `json:"mem_limits_off,omitempty"`
	DiskTotal    int64        `json:"disk_total,omitempty"`
	DiskFree     int64        `json:"disk_free,omitempty"`
	DB           *dbLimitInfo `json:"db,omitempty"` // Datenbank auf diesem Datenträger (dblimit.go)
	History      []hwPoint    `json:"history"`
	IntervalMs   int64        `json:"interval_ms"`
}

type hwMonitor struct {
	mu       sync.Mutex
	hist     []hwPoint
	last     hwSnapshot
	prevIdle uint64
	prevAll  uint64
}

// cpuTimes: Summe aller und der untätigen Zeiten aus der ersten Zeile von /proc/stat.
func cpuTimes() (idle, all uint64, cores int, ok bool) {
	f, err := os.Open(filepath.Join(hwProc, "stat"))
	if err != nil {
		return 0, 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) == 0 {
			continue
		}
		switch {
		case fs[0] == "cpu":
			for i, v := range fs[1:] {
				n, _ := strconv.ParseUint(v, 10, 64)
				if i >= 8 { // guest-Zeiten stecken schon in user/nice
					break
				}
				all += n
				if i == 3 || i == 4 { // idle, iowait
					idle += n
				}
			}
			ok = true
		case strings.HasPrefix(fs[0], "cpu"):
			cores++
		}
	}
	return idle, all, cores, ok
}

// memInfo liest /proc/meminfo (Werte in Bytes).
func memInfo() map[string]int64 {
	f, err := os.Open(filepath.Join(hwProc, "meminfo"))
	if err != nil {
		return nil
	}
	defer f.Close()
	m := map[string]int64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fs := strings.Fields(v)
		if len(fs) == 0 {
			continue
		}
		n, _ := strconv.ParseInt(fs[0], 10, 64)
		if len(fs) > 1 && fs[1] == "kB" {
			n *= 1024
		}
		m[k] = n
	}
	return m
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.TrimRight(string(b), "\x00"))
}

func readInt(p string) (int64, bool) {
	s := readTrim(p)
	if s == "" || s == "max" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// cpuTemp: höchste Temperatur der Thermal-Zonen in °C (Pi: thermal_zone0).
func cpuTemp() float64 {
	best := 0.0
	zones, _ := filepath.Glob(filepath.Join(hwSys, "class/thermal/thermal_zone*/temp"))
	for _, z := range zones {
		if n, ok := readInt(z); ok && n > 0 && n < 150000 {
			if t := float64(n) / 1000; t > best {
				best = t
			}
		}
	}
	return best
}

// throttled: Unterspannung oder Drosselung auf dem Pi (Firmware-Bits, falls lesbar).
func throttled() string {
	s := readTrim(filepath.Join(hwSys, hwThrottled))
	if s == "" {
		return rpiVolt()
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 32)
	if err != nil {
		return ""
	}
	var p []string
	if v&0x1 != 0 {
		p = append(p, "Unterspannung")
	}
	if v&0x2 != 0 || v&0x4 != 0 {
		p = append(p, "Takt gedrosselt")
	}
	if v&0x8 != 0 {
		p = append(p, "Temperaturgrenze")
	}
	if len(p) == 0 && v&0x50000 != 0 {
		p = append(p, "seit dem Start schon einmal Unterspannung")
	} else if len(p) == 0 && v&0xE0000 != 0 {
		p = append(p, "seit dem Start schon einmal gedrosselt")
	}
	if len(p) == 0 {
		return "ok"
	}
	return strings.Join(p, ", ")
}

// services: Speicher je Hivornet-Dienst (Pi: systemd-cgroups) bzw. des eigenen Containers.
var hwUnits = [][2]string{{"hivornet-hive", "Hive (Web-UI)"}, {"hivornet-honeypot", "Honeypot"}, {"hivornet-cowrie", "Cowrie (SSH/Telnet)"}}

// hwServices: Speicher je Dienst und ob die Speichergrenzen der Dienste wirkungslos sind.
func hwServices() ([]hwService, bool) {
	var out []hwService
	base := filepath.Join(hwSys, "fs/cgroup/system.slice")
	for _, s := range hwUnits {
		dir := filepath.Join(base, s[0]+".service")
		n, ok := readInt(filepath.Join(dir, "memory.current"))
		if !ok {
			continue
		}
		lim, _ := readInt(filepath.Join(dir, "memory.max"))
		out = append(out, hwService{Name: s[0], Label: s[1], Bytes: n, Limit: lim})
	}
	if len(out) == 0 {
		// Raspberry Pi: Speicherverwaltung der cgroups ab Werk aus, memory.current fehlt. Dann
		// schreibt hivornet-memstat (root) die Werte in eine Statusdatei (Pi 3 im Live-Check 0.9.3).
		if l, off, ok := readMemStatus(hwMemStatus); ok {
			return l, off
		}
	}
	if len(out) == 0 && os.Getenv("HIVE_JOURNAL") != "1" { // Docker: eigener Container
		if n, ok := readInt(filepath.Join(hwSys, "fs/cgroup/memory.current")); ok {
			lim, _ := readInt(filepath.Join(hwSys, "fs/cgroup/memory.max"))
			out = append(out, hwService{Name: "container", Label: "Hive-Container", Bytes: n, Limit: lim})
		}
	}
	return out, false
}

// readMemStatus liest die Statusdatei von hivornet-memstat (höchstens 5 Minuten alt).
// Format: "ok", Unix-Zeit, Text, "memcg 0|1", je Dienst "NAME RSS GRENZE".
func readMemStatus(p string) (list []hwService, limitsOff, ok bool) {
	b, err := os.ReadFile(p)
	if err != nil || len(b) > 4096 {
		return nil, false, false
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) < 4 || strings.TrimSpace(lines[0]) != "ok" {
		return nil, false, false
	}
	if at, err := strconv.ParseInt(strings.TrimSpace(lines[1]), 10, 64); err != nil || time.Since(time.Unix(at, 0)) > 5*time.Minute {
		return nil, false, false
	}
	memcg := true
	anyLimit := false
	for _, l := range lines[3:] {
		fs := strings.Fields(l)
		if len(fs) == 2 && fs[0] == "memcg" {
			memcg = fs[1] == "1"
			continue
		}
		if len(fs) != 3 {
			continue
		}
		for _, u := range hwUnits {
			if fs[0] != u[0] {
				continue
			}
			rss, err1 := strconv.ParseInt(fs[1], 10, 64)
			lim, err2 := strconv.ParseInt(fs[2], 10, 64)
			if err1 != nil || err2 != nil || rss < 0 || lim < 0 {
				break
			}
			list = append(list, hwService{Name: u[0], Label: u[1], Bytes: rss, Limit: lim})
			anyLimit = anyLimit || lim > 0
		}
	}
	return list, !memcg && anyLimit, len(list) > 0
}

func selfRSS() int64 {
	f, err := os.Open(filepath.Join(hwProc, "self/status"))
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "VmRSS:"); ok {
			fs := strings.Fields(v)
			if len(fs) > 0 {
				n, _ := strconv.ParseInt(fs[0], 10, 64)
				return n * 1024
			}
		}
	}
	return 0
}

// sample nimmt einen Messpunkt; die CPU-Auslastung ergibt sich aus dem Abstand zum vorigen.
func (m *hwMonitor) sample(now time.Time) {
	idle, all, cores, ok := cpuTimes()
	mi := memInfo()
	if !ok || mi == nil {
		return
	}
	s := hwSnapshot{Available: true, Cores: max(cores, 1), IntervalMs: hwEvery.Milliseconds()}
	s.MemTotal = mi["MemTotal"]
	avail, has := mi["MemAvailable"]
	if !has {
		avail = mi["MemFree"] + mi["Buffers"] + mi["Cached"]
	}
	s.MemUsed = max(s.MemTotal-avail, 0)
	s.MemCache = mi["Buffers"] + mi["Cached"]
	s.SwapTotal, s.SwapUsed = mi["SwapTotal"], max(mi["SwapTotal"]-mi["SwapFree"], 0)
	if fs := strings.Fields(readTrim(filepath.Join(hwProc, "loadavg"))); len(fs) >= 3 {
		for i := range 3 {
			s.Load[i], _ = strconv.ParseFloat(fs[i], 64)
		}
	}
	if fs := strings.Fields(readTrim(filepath.Join(hwProc, "uptime"))); len(fs) > 0 {
		f, _ := strconv.ParseFloat(fs[0], 64)
		s.UptimeS = int64(f)
	}
	s.Model = readTrim(filepath.Join(hwProc, "device-tree/model"))
	if s.Model == "" {
		s.Model = readTrim(filepath.Join(hwSys, "firmware/devicetree/base/model"))
	}
	s.Temp = cpuTemp()
	s.Throttled = throttled()
	s.HiveRSS = selfRSS()
	s.Services, s.MemLimitsOff = hwServices()

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.prevAll > 0 && all > m.prevAll {
		dAll, dIdle := float64(all-m.prevAll), float64(idle-m.prevIdle)
		s.CPU = max(0, min(100, 100*(dAll-dIdle)/dAll))
	} else if len(m.hist) > 0 {
		s.CPU = m.hist[len(m.hist)-1].CPU
	}
	m.prevIdle, m.prevAll = idle, all
	memPct := 0.0
	if s.MemTotal > 0 {
		memPct = 100 * float64(s.MemUsed) / float64(s.MemTotal)
	}
	m.hist = append(m.hist, hwPoint{T: now.UnixMilli(), CPU: round1(s.CPU), Mem: round1(memPct), Temp: round1(s.Temp)})
	if len(m.hist) > hwPoints {
		m.hist = append(m.hist[:0], m.hist[len(m.hist)-hwPoints:]...)
	}
	for _, p := range m.hist {
		s.TempMax = max(s.TempMax, p.Temp)
	}
	s.CPU = round1(s.CPU)
	m.last = s
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }

func (m *hwMonitor) snapshot() hwSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.last
	s.History = append([]hwPoint{}, m.hist...)
	return s
}

// runHW: erster Messpunkt sofort (Ausgangswert für die CPU), der zweite nach 2 Sekunden, damit
// die Seite gleich nach dem Start eine Auslastung zeigt; danach alle 15 Sekunden.
func (h *Hive) runHW(stop <-chan struct{}) {
	h.hw.sample(time.Now())
	select {
	case <-stop:
		return
	case <-time.After(2 * time.Second):
	}
	h.hw.mu.Lock()
	h.hw.hist = h.hw.hist[:0] // der erste Punkt hatte noch keine CPU-Auslastung
	h.hw.mu.Unlock()
	h.hw.sample(time.Now())
	t := time.NewTicker(hwEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			h.hw.sample(time.Now())
		}
	}
}

// hardwareAPI: GET /api/hardware
func (h *Hive) hardwareAPI(w http.ResponseWriter, r *http.Request) {
	s := h.hw.snapshot()
	if s.History == nil {
		s.History = []hwPoint{}
	}
	if total, free := diskTotalFree(h.dbPath); total > 0 {
		s.DiskTotal, s.DiskFree = total, free
	}
	if h.st != nil {
		dl := h.dbLimitInfo()
		s.DB = &dl
	}
	writeJSON(w, s)
}

// rpiVolt: Unterspannung über den Treiber rpi_volt (hwmon), wo die Firmware-Bits nicht lesbar
// sind (z. B. Raspberry Pi 3). in0_lcrit_alarm ist 1, solange die Spannung zu niedrig ist.
func rpiVolt() string {
	dirs, _ := filepath.Glob(filepath.Join(hwSys, "class/hwmon/hwmon*"))
	for _, d := range dirs {
		if readTrim(filepath.Join(d, "name")) != "rpi_volt" {
			continue
		}
		switch readTrim(filepath.Join(d, "in0_lcrit_alarm")) {
		case "1":
			return "Unterspannung"
		case "0":
			return "ok"
		}
	}
	return ""
}
