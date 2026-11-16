// Hivornet Honeypot: ein Prozess für viele Protokolle, mit Tarpit-Modus.
package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// version wird beim Bauen gesetzt: -ldflags "-X main.version=v0.2.0"
var version = "dev"

const healthFile = "/tmp/hivornet-healthy"

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		// Docker-Healthcheck: gesund, wenn die Hauptschleife in den letzten 60 s gelebt hat.
		fi, err := os.Stat(healthFile)
		if err != nil || time.Since(fi.ModTime()) > 60*time.Second {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "version" {
		println(version)
		return
	}
	log.SetFlags(log.LstdFlags)
	cfgPath := env("HONEYPOT_CONFIG", "/etc/hivornet/honeypot.yml")
	hiveURL := strings.TrimRight(env("HIVE_URL", "http://hive:8089"), "/")
	token := os.Getenv("HIVORNET_TOKEN")
	sensor := env("SENSOR_NAME", "sensor-1")
	bind := os.Getenv("HONEYPOT_BIND") // leer = alle Schnittstellen
	if token == "" {
		log.Fatal("HIVORNET_TOKEN ist nicht gesetzt (siehe .env)")
	}
	lowOffset := 0
	if v, err := strconv.Atoi(os.Getenv("HONEYPOT_LOW_PORT_OFFSET")); err == nil && v >= 0 && v < 60000 {
		lowOffset = v
	}

	base, err := LoadConfigFile(cfgPath)
	if err != nil {
		log.Printf("Konfigurationsdatei nicht lesbar (%v), nutze Standardwerte", err)
		base = DefaultConfig()
	}

	hive := &HiveClient{URL: hiveURL, Token: token, Sensor: sensor, HTTP: &http.Client{Timeout: 15 * time.Second}}
	em := NewEmitter(hive, sensor)
	stop := make(chan struct{})
	emDone := make(chan struct{})
	go func() { em.Run(stop); close(emDone) }()

	setBaitSecret(token) // Köder-Zugangsdaten je Installation (bait.go)
	mgr := NewManager(em, bind, lowOffset)
	mgr.Apply(base)
	log.Printf("Hivornet Honeypot %s gestartet, Sensor %q, Hive %s", version, sensor, hiveURL)

	// Konfiguration aus der Web-UI regelmäßig abholen.
	go func() {
		failing := false
		for {
			cfg, err := hive.FetchConfig()
			switch {
			case err != nil:
				if !failing {
					log.Printf("Konfiguration vom Hive nicht abrufbar: %v", err)
				}
				failing = true
				mgr.Recheck() // fehlgeschlagene Ports und Zertifikat trotzdem prüfen
			case cfg != nil:
				failing = false
				if mgr.Apply(*cfg) {
					log.Printf("Neue Konfiguration vom Hive übernommen")
				}
			default:
				failing = false
				mgr.Apply(base)
			}
			time.Sleep(15 * time.Second)
		}
	}()

	// Prüfen, ob der Container ins Internet verbinden kann. Mit der Netzsperre
	// (tools/firewall.sh) sollte das scheitern; sonst warnt die UI.
	var egressOpen atomic.Int32 // 0 = unbekannt, 1 = gesperrt, 2 = offen
	if probe := env("HONEYPOT_EGRESS_PROBE", "1.1.1.1:443"); probe != "off" {
		go func() {
			for {
				c, err := net.DialTimeout("tcp", probe, 4*time.Second)
				if err == nil {
					c.Close()
					if egressOpen.Swap(2) != 2 {
						log.Printf("WARNUNG: Der Honeypot kann ins Internet verbinden (%s). Netzsperre fehlt, siehe README.", probe)
					}
				} else {
					egressOpen.Store(1)
				}
				time.Sleep(10 * time.Minute)
			}
		}()
	}

	// Lebenszeichen mit aktuellem Zustand für die UI.
	started := time.Now()
	go func() {
		for {
			cfg, listeners := mgr.Status()
			conns, tarpits := mgr.limits.Counts()
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			lastErr, _ := em.lastErr.Load().(string)
			egress := map[int32]string{0: "unbekannt", 1: "gesperrt", 2: "offen"}[egressOpen.Load()]
			hive.Heartbeat(map[string]any{
				"sensor": sensor, "version": version, "uptime_s": int64(time.Since(started).Seconds()),
				"config": cfg, "listeners": listeners, "connections": conns, "tarpits": tarpits, "held_tarpits": mgr.HeldTarpits(300),
				"events_sent": em.sent.Load(), "events_dropped": em.dropped.Load(), "events_throttled": em.throttled.Load(),
				"conns_rejected": mgr.limits.rejected.Load(), "proxied_conns": mgr.proxied.Load(), "egress": egress,
				"last_error": lastErr, "mem_bytes": ms.Sys, "goroutines": runtime.NumGoroutine(),
			})
			os.WriteFile(healthFile, []byte(time.Now().Format(time.RFC3339)), 0o644)
			time.Sleep(10 * time.Second)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("Beende ...")
	mgr.StopAll()
	close(stop)
	select {
	case <-emDone:
	case <-time.After(8 * time.Second):
	}
}
