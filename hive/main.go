// Hivornet Hive: sammelt Ereignisse, ergänzt GeoIP, speichert in SQLite
// und liefert API und Web-UI aus.
package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// version wird beim Bauen gesetzt: -ldflags "-X main.version=v0.2.0"
var version = "dev"

//go:embed web
var webFS embed.FS

type Hive struct {
	st               *Store
	writer           *Writer
	geo              *Geo
	auth             *Auth
	broker           *Broker
	sensors          *Sensors
	cowrie           *CowrieTail
	dbPath           string
	started          time.Time
	defaultRetention int
	maxDBBytes       int64
	minFreeBytes     int64
	cowrieLogDir     string
	cowrieLibDir     string

	volMu sync.Mutex
	vol   map[string]int64
	volAt time.Time

	retMu   sync.Mutex
	retStat RetentionStatus
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envMB(k string, def int64) int64 {
	if v, err := strconv.ParseInt(os.Getenv(k), 10, 64); err == nil && v >= 0 {
		return v << 20
	}
	return def << 20
}

func (h *Hive) retention() RetentionStatus {
	h.retMu.Lock()
	defer h.retMu.Unlock()
	return h.retStat
}

// dirSize summiert Dateigrößen, ohne Symlinks zu folgen (höchstens maxFiles Dateien).
func dirSize(dir string, maxFiles int) int64 {
	var total int64
	n := 0
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || n > maxFiles {
			return nil
		}
		if d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				total += fi.Size()
			}
			n++
		}
		return nil
	})
	return total
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func localAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	return addr
}

// applyRestore ersetzt beim Start die Datenbank durch /data/restore.db, falls vorhanden.
func applyRestore(dbPath string) {
	src := filepath.Join(filepath.Dir(dbPath), "restore.db")
	if _, err := os.Stat(src); err != nil {
		return
	}
	for _, suf := range []string{"-wal", "-shm"} {
		os.Remove(dbPath + suf)
	}
	if err := os.Rename(src, dbPath); err != nil {
		log.Fatalf("Wiederherstellen aus %s: %v", src, err)
	}
	log.Printf("Datenbank aus restore.db wiederhergestellt")
}

func main() {
	dbPath := env("HIVE_DB", "/data/hive.db")
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck": // für Docker (Image ohne Shell)
			resp, err := (&http.Client{Timeout: 3 * time.Second}).Get("http://" + localAddr(env("HIVE_LISTEN", ":8088")) + "/healthz")
			if err != nil || resp.StatusCode != 200 {
				os.Exit(1)
			}
			os.Exit(0)
		case "backup": // docker compose exec hive /hive backup
			st, err := OpenStore(dbPath)
			if err != nil {
				log.Fatalf("Datenbank: %v", err)
			}
			name, err := st.Backup(filepath.Join(filepath.Dir(dbPath), "backups"), 7)
			if err != nil {
				log.Fatalf("Backup: %v", err)
			}
			fmt.Println(name)
			return
		case "version":
			fmt.Println(version)
			return
		}
	}

	os.MkdirAll(filepath.Dir(dbPath), 0o755)
	applyRestore(dbPath)
	st, err := OpenStore(dbPath)
	if err != nil {
		log.Fatalf("Datenbank: %v", err)
	}
	ret, _ := strconv.Atoi(env("HIVE_RETENTION_DAYS", "30"))
	h := &Hive{
		st: st, dbPath: dbPath, started: time.Now(), defaultRetention: ret,
		maxDBBytes: envMB("HIVE_MAX_DB_MB", 2048), minFreeBytes: envMB("HIVE_MIN_FREE_MB", 1024),
		broker:       NewBroker(),
		sensors:      &Sensors{last: map[string]Heartbeat{}},
		geo:          NewGeo(env("HIVE_GEOIP_DIR", filepath.Join(filepath.Dir(dbPath), "geoip"))),
		cowrieLibDir: os.Getenv("HIVE_COWRIE_LIB"),
	}
	if h.writer, err = NewWriter(st, h.broker.Publish); err != nil {
		log.Fatalf("Datenbank: %v", err)
	}
	go h.writer.Run()
	if env("HIVE_GEOIP", "on") != "off" {
		go h.geo.AutoUpdate()
	}

	h.auth = NewAuth(st, os.Getenv("HIVORNET_TOKEN"), os.Getenv("HIVE_COOKIE_SECURE") == "1")
	if h.auth.sensorToken == "" {
		log.Printf("WARNUNG: HIVORNET_TOKEN ist leer, Sensoren können nichts senden")
	}
	h.auth.EnsureAdmin(env("HIVE_ADMIN_USER", "admin"), os.Getenv("HIVE_ADMIN_PASSWORD"))

	if p := os.Getenv("HIVE_COWRIE_LOG"); p != "" {
		h.cowrieLogDir = filepath.Dir(p)
		h.cowrie = NewCowrieTail(p, env("COWRIE_SENSOR_NAME", env("SENSOR_NAME", "sensor-1")), st, func(e *Event) {
			h.geo.Enrich(e)
			for !h.writer.Submit(e) {
				time.Sleep(100 * time.Millisecond)
			}
		})
		go h.cowrie.Run()
	}

	go func() {
		time.Sleep(time.Minute)
		for {
			s := st.Retention(h.policy())
			h.retMu.Lock()
			h.retStat = s
			h.retMu.Unlock()
			time.Sleep(10 * time.Minute)
		}
	}()

	var ingestNet *net.IPNet
	if v := os.Getenv("HIVE_INGEST_SUBNET"); v != "" {
		if _, n, err := net.ParseCIDR(v); err == nil {
			ingestNet = n
		} else {
			log.Printf("HIVE_INGEST_SUBNET ungültig: %v", err)
		}
	}
	var allowedHosts []string
	if v := os.Getenv("HIVE_ALLOWED_HOSTS"); v != "" {
		allowedHosts = strings.Split(v, ",")
	}

	a := h.auth
	// Sensor-API: eigener Listener, nur im internen Docker-Netz erreichbar.
	sensorMux := http.NewServeMux()
	sensorMux.HandleFunc("POST /api/ingest", a.RequireSensor(h.ingest))
	sensorMux.HandleFunc("POST /api/sensor/heartbeat", a.RequireSensor(h.heartbeat))
	sensorMux.HandleFunc("GET /api/sensor/config", a.RequireSensor(h.sensorConfig))

	// Web-UI und ihre API
	ui := http.NewServeMux()
	ui.HandleFunc("POST /api/login", a.Login)
	ui.HandleFunc("POST /api/logout", a.Logout)
	ui.HandleFunc("GET /api/me", h.me)
	ui.HandleFunc("GET /api/stats/summary", a.Require(h.summary))
	ui.HandleFunc("GET /api/stats/timeline", a.Require(h.timeline))
	ui.HandleFunc("GET /api/stats/top", a.Require(h.top))
	ui.HandleFunc("GET /api/stats/map", a.Require(h.mapPoints))
	ui.HandleFunc("GET /api/events", a.Require(h.events))
	ui.HandleFunc("GET /api/export/events", a.Require(h.exportEvents))
	ui.HandleFunc("GET /api/export/blocklist", a.Require(h.blocklist))
	ui.HandleFunc("GET /api/stream", a.Require(h.broker.ServeHTTP))
	ui.HandleFunc("GET /api/attackers/{ip}", a.Require(h.attacker))
	ui.HandleFunc("GET /api/sessions", a.Require(h.sessionsList))
	ui.HandleFunc("GET /api/sessions/{id}", a.Require(h.sessionDetail))
	ui.HandleFunc("GET /api/tarpit", a.Require(h.tarpit))
	ui.HandleFunc("GET /api/settings", a.Require(h.getSettings))
	ui.HandleFunc("PUT /api/settings", a.Require(h.putSettings))
	ui.HandleFunc("POST /api/password", a.Require(h.changePassword))
	ui.HandleFunc("GET /api/system", a.Require(h.system))
	ui.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := st.db.PingContext(r.Context()); err != nil {
			http.Error(w, "db", 503)
			return
		}
		w.Write([]byte("ok"))
	})
	if tok := os.Getenv("HIVE_METRICS_TOKEN"); tok != "" {
		ui.HandleFunc("GET /metrics", (&Auth{sensorToken: tok}).RequireSensor(h.metrics))
	}
	// Die Sensor-API ist zusätzlich auf dem UI-Port erreichbar, wenn kein eigener Port gesetzt ist (lokale Tests).
	sensorAddr := os.Getenv("HIVE_SENSOR_LISTEN")
	if sensorAddr == "" {
		ui.Handle("/api/ingest", sensorMux)
		ui.Handle("/api/sensor/", sensorMux)
	}

	sub, _ := fs.Sub(webFS, "web")
	files := http.FileServer(http.FS(sub))
	if dir := os.Getenv("HIVE_WEB_DIR"); dir != "" { // nur für Entwicklung: UI direkt vom Datenträger
		files = http.FileServer(http.Dir(dir))
	}
	ui.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	}))

	baseCtx, cancelBase := context.WithCancel(context.Background())
	mkServer := func(addr string, hd http.Handler) *http.Server {
		return &http.Server{Addr: addr, Handler: hd, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
			MaxHeaderBytes: 64 << 10, BaseContext: func(net.Listener) context.Context { return baseCtx }}
	}
	servers := []*http.Server{mkServer(env("HIVE_LISTEN", ":8088"), securityHeaders(uiGuard(ui, ingestNet, allowedHosts)))}
	if sensorAddr != "" {
		servers = append(servers, mkServer(sensorAddr, sensorMux))
	}
	for _, srv := range servers {
		go func(srv *http.Server) {
			log.Printf("Hivornet Hive %s lauscht auf %s", version, srv.Addr)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatal(err)
			}
		}(srv)
	}

	// Sauber beenden: keine neuen Anfragen, Warteschlange schreiben, Datenbank schließen.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("Beende ...")
	cancelBase() // beendet offene Live-Streams
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	for _, srv := range servers {
		srv.Shutdown(ctx)
	}
	cancel()
	if h.cowrie != nil {
		h.cowrie.Stop()
	}
	h.writer.Stop(15 * time.Second)
	st.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	st.db.Close()
	log.Printf("Beendet")
}
