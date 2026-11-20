package main

// Ist ein Dauer-Brute-Forcer gerade gesperrt? Die Drossel läuft in nftables (Raspberry Pi:
// hivornet-firewall, Docker: tools/firewall.sh auf dem Host). Der Hive hat darauf keinen
// Zugriff und bekommt auch keinen: Auf dem Pi schreibt hivornet-brute-bans.timer (root) jede
// Minute die Sperrliste nach /var/lib/hivornet-status/brute-bans, der Hive liest nur diese Datei.
// Im Docker-Betrieb gibt es keine solche Datei; die UI sagt dann ehrlich "Status je IP unbekannt".
//
// Datei: Zustand (ok|off|failed), Unix-Zeit, Text, danach je Zeile "IP ABLAUF" (Unix-Zeit).

import (
	"bufio"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func bruteBansPath() string {
	if p := os.Getenv("HIVE_BRUTE_BANS"); p != "" {
		return p
	}
	if bruteRequestPath() != "" { // nur auf dem Raspberry Pi
		return "/var/lib/hivornet-status/brute-bans"
	}
	return ""
}

type bruteBanFile struct {
	State string
	At    time.Time
	Text  string
	Bans  map[string]int64 // IP -> Ablauf (ms)
}

const bruteBansMax = 2000

// readBruteBans liest und prüft die Datei streng (höchstens 256 KB, nur gültige IPs).
func readBruteBans(p string) *bruteBanFile {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 256<<10))
	var head []string
	out := &bruteBanFile{Bans: map[string]int64{}}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if len(head) < 3 {
			head = append(head, line)
			continue
		}
		ip, until, ok := strings.Cut(line, " ")
		addr := net.ParseIP(ip)
		sec, err := strconv.ParseInt(until, 10, 64)
		if !ok || addr == nil || err != nil || sec <= 0 || len(out.Bans) >= bruteBansMax {
			continue
		}
		out.Bans[addr.String()] = sec * 1000
	}
	if len(head) < 3 || head[0] != "ok" && head[0] != "off" && head[0] != "failed" {
		return nil
	}
	sec, _ := strconv.ParseInt(head[1], 10, 64)
	out.State, out.At, out.Text = head[0], time.Unix(sec, 0), clip(head[2], 200)
	return out
}

var bruteBanCache struct {
	mu sync.Mutex
	at time.Time
	v  *bruteBanFile
}

func cachedBruteBans() *bruteBanFile {
	p := bruteBansPath()
	if p == "" {
		return nil
	}
	c := &bruteBanCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.at) > 15*time.Second {
		c.v, c.at = readBruteBans(p), time.Now()
	}
	return c.v
}

// bruteLimitInfo: Stand der Drossel für die UI.
type bruteLimitInfo struct {
	Platform   string `json:"platform"` // pi | docker | none
	Enabled    bool   `json:"enabled"`  // in den Einstellungen eingeschaltet
	Rate       int    `json:"rate"`
	Burst      int    `json:"burst"`
	BanMinutes int    `json:"ban_minutes"`
	Known      bool   `json:"known"` // aktuelle Sperrliste je IP liegt vor
	Note       string `json:"note,omitempty"`
}

func (h *Hive) bruteLimit() bruteLimitInfo {
	b := h.Extras().Brute
	out := bruteLimitInfo{Platform: "none", Enabled: b.Limit, Rate: b.Rate, Burst: b.Burst, BanMinutes: b.BanMinutes}
	switch {
	case bruteRequestPath() != "":
		out.Platform = "pi"
	case h.cowrie != nil:
		out.Platform = "docker"
	}
	if !b.Limit {
		return out
	}
	f := cachedBruteBans()
	switch {
	case out.Platform != "pi":
		out.Note = "Die Drossel läuft in der Firewall des Hosts; ob eine IP gerade gesperrt ist, sieht der Hive nicht."
	case f == nil:
		out.Note = "Sperrliste noch nicht vorhanden (hivornet-brute-bans.timer schreibt sie jede Minute)."
	case f.State != "ok":
		out.Note = "Firewall meldet: " + f.Text
	case time.Since(f.At) > 3*time.Minute:
		out.Note = "Sperrliste veraltet (Stand " + f.At.In(hiveLoc()).Format("15:04") + ")."
	default:
		out.Known = true
	}
	return out
}

// bruteBansFor: Ablauf der Sperre (ms) je gerade gesperrter IP aus ips.
func (h *Hive) bruteBansFor(ips []string) map[string]int64 {
	out := map[string]int64{}
	if len(ips) == 0 || !h.Extras().Brute.Limit {
		return out
	}
	f := cachedBruteBans()
	if f == nil || f.State != "ok" {
		return out
	}
	now := time.Now().UnixMilli()
	for _, ip := range ips {
		if until, ok := f.Bans[ip]; ok && until > now {
			out[ip] = until
		}
	}
	return out
}
