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
	maxDBBytes       int64 // HIVE_MAX_DB_MB: Vorgabe der Grenze (dblimit.go)
	maxDBCapBytes    int64 // HIVE_MAX_DB_CAP_MB: harte Obergrenze, 0 = keine
	minFreeBytes     int64
	dbLimMu          sync.Mutex
	cowrieLogDir     string
	cowrieLibDir     string

	volMu sync.Mutex
	vol   map[string]int64
	volAt time.Time

	retMu   sync.Mutex
	retStat RetentionStatus

	extras    extrasCache   // Einstellungen der Zusatzfunktionen (extras.go)
	feed      feedCache     // Blockliste zum Abonnieren (feed.go)
	mimicSt   mimicState    // Sprachmodell-Antworten (mimic.go)
	insightsC insightsCache // Erkenntnisse (insights.go)
	notifier  *Notifier     // Benachrichtigungen (notify.go)
	aiSem     chan struct{} // höchstens eine KI-Auswertung gleichzeitig
	upd       updater       // Update-Prüfung (setup.go)
	restart   chan struct{} // Neustart nach einer Wiederherstellung (backup.go)
	hosts     hostList      // erlaubte Hostnamen der Web-UI (hosts.go)
	probe     *portProbe    // lauschen die Cowrie-Ports? (probe.go)
	abuse     abuseReporter // Meldungen an AbuseIPDB (abusereport.go)
	ports     portActivity  // seit wann welche Ports laufen (silentports.go)
	share     shareState    // URLhaus, Dateien sammeln, MalwareBazaar, DShield (share.go)
	snap      attackSnap    // Angriffe der letzten sieben Tage (attacksnap.go)
	hw        hwMonitor     // Hardware-Monitor (hwmon.go)
	bruteTop  bruteTopCache // Top-Listen ohne Dauer-Brute-Force (brutetop.go)
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
	// Bisherige Datenbank aufheben (backups/vor-wiederherstellung-…), falls etwas schiefgeht.
	if _, err := os.Stat(dbPath); err == nil {
		if old, err := OpenStore(dbPath); err == nil {
			dir := filepath.Join(filepath.Dir(dbPath), "backups")
			os.MkdirAll(dir, 0o700)
			name := filepath.Join(dir, "vor-wiederherstellung-"+time.Now().Format("20060102-150405")+".db")
			if _, err := old.db.Exec(`VACUUM INTO ?`, name); err != nil {
				log.Printf("Alte Datenbank nicht gesichert: %v", err)
			} else {
				log.Printf("Alte Datenbank gesichert: %s", name)
			}
			old.db.Close()
		}
	}
	for _, suf := range []string{"-wal", "-shm"} {
		os.Remove(dbPath + suf)
	}
	if err := os.Rename(src, dbPath); err != nil {
		log.Fatalf("Wiederherstellen aus %s: %v", src, err)
	}
	log.Printf("Datenbank aus restore.db wiederhergestellt")
}

// routes baut die beiden Router: Web-UI mit ihrer API und die Sensor-API.
// sensorOnUI legt die Sensor-Routen zusätzlich auf den UI-Router (nur Entwicklung).
func (h *Hive) routes(sensorOnUI bool, metricsToken string, files http.Handler) (ui, sensor *http.ServeMux) {
	a := h.auth
	// Sensor-API: eigener Listener, nur im internen Docker-Netz erreichbar.
	sensorRoutes := func(m *http.ServeMux) {
		m.HandleFunc("POST /api/ingest", a.RequireSensor(h.ingest))
		m.HandleFunc("POST /api/sensor/heartbeat", a.RequireSensor(h.heartbeat))
		m.HandleFunc("GET /api/sensor/config", a.RequireSensor(h.sensorConfig))
		m.HandleFunc("POST /api/sensor/mimic", a.requireMimic(h.mimic))
	}
	sensor = http.NewServeMux()
	sensorRoutes(sensor)

	// Web-UI und ihre API
	ui = http.NewServeMux()
	ui.HandleFunc("POST /api/login", a.Login)
	ui.HandleFunc("POST /api/logout", a.Logout)
	ui.HandleFunc("GET /api/me", h.me)
	ui.HandleFunc("GET /api/setup", h.setupStatus) // ohne Anmeldung: nur solange kein Konto existiert
	ui.HandleFunc("POST /api/setup", h.setupRun)
	ui.HandleFunc("POST /api/update", a.Require(h.updateRun))
	ui.HandleFunc("POST /api/update/check", a.Require(h.updateCheckNow))
	ui.HandleFunc("PUT /api/update/channel", a.Require(h.updateSetChannel))
	ui.HandleFunc("GET /api/users", a.Require(h.usersList))
	ui.HandleFunc("POST /api/users", a.Require(h.usersCreate))
	ui.HandleFunc("DELETE /api/users/{name}", a.Require(h.usersDelete))
	ui.HandleFunc("GET /api/stats/summary", a.Require(h.summary))
	ui.HandleFunc("GET /api/stats/timeline", a.Require(h.timeline))
	ui.HandleFunc("GET /api/stats/top", a.Require(h.top))
	ui.HandleFunc("GET /api/stats/map", a.Require(h.mapPoints))
	ui.HandleFunc("GET /api/stats/countries", a.Require(h.countryStats))
	ui.HandleFunc("GET /api/stats/series", a.Require(h.series))
	ui.HandleFunc("GET /api/attacks", a.Require(h.attacks))
	ui.HandleFunc("GET /api/stats/live", a.Require(h.liveStatus))
	ui.HandleFunc("GET /api/cowrie/auth", a.Require(h.cowrieAuthGet))
	ui.HandleFunc("PUT /api/cowrie/auth", a.Require(h.cowrieAuthPut))
	ui.HandleFunc("GET /api/brute", a.Require(h.bruteStatus))
	ui.HandleFunc("GET /api/events", a.Require(h.events))
	ui.HandleFunc("GET /api/export/events", a.Require(h.exportEvents))
	ui.HandleFunc("GET /api/export/blocklist", a.Require(h.blocklist))
	ui.HandleFunc("GET /api/feed", a.Require(h.feedSettings))
	ui.HandleFunc("GET /api/sample", a.Require(h.sample))
	ui.HandleFunc("GET /api/mimic/status", a.Require(h.mimicStatus))
	ui.HandleFunc("GET /api/insights", a.Require(h.insights))
	ui.HandleFunc("GET /api/dwell", a.Require(h.dwell)) // Verweildauer nach Login (dwell.go)
	ui.HandleFunc("GET /api/firstseen", a.Require(h.firstSeen))
	ui.HandleFunc("GET /api/searches", a.Require(h.searches))
	ui.HandleFunc("GET /api/exposure", a.Require(h.exposure))
	ui.HandleFunc("POST /api/exposure", a.Require(h.exposure))
	ui.HandleFunc("GET /api/ownip", a.Require(h.ownIPAPI))
	ui.HandleFunc("POST /api/ownip/refresh", a.Require(h.ownIPRefreshAPI))
	ui.HandleFunc("POST /api/searches", a.Require(h.searches))
	ui.HandleFunc("DELETE /api/searches/{name}", a.Require(h.searches))
	ui.HandleFunc("DELETE /api/mimic/cache", a.Require(h.mimicClear))
	ui.HandleFunc("GET /api/sensor-tokens", a.Require(h.sensorTokensAPI))
	ui.HandleFunc("POST /api/sensor-tokens", a.Require(h.sensorTokensAPI))
	ui.HandleFunc("DELETE /api/sensor-tokens/{name}", a.Require(h.sensorTokensAPI))
	ui.HandleFunc("POST /api/sensor-tokens/{name}/trust", a.Require(h.sensorTrust))
	ui.HandleFunc("PUT /api/feed", a.Require(h.feedSettings))
	ui.HandleFunc("GET /feed/blocklist.txt", h.feedBlocklist) // ohne Anmeldung, nur mit Token (feed.go)
	ui.HandleFunc("GET /api/stream", a.Require(h.broker.ServeHTTP))
	ui.HandleFunc("GET /api/attackers/{ip}", a.Require(h.attacker))
	ui.HandleFunc("GET /api/sessions", a.Require(h.sessionsList))
	ui.HandleFunc("GET /api/sessions/{id}", a.Require(h.sessionDetail))
	ui.HandleFunc("GET /api/sessions/{id}/tty", a.Require(h.sessionTTY))
	ui.HandleFunc("GET /api/report", a.Require(h.report))
	ui.HandleFunc("POST /api/report/ai", a.Require(h.reportAI))
	h.aiPlusRoutes(ui, a) // weitere KI-Funktionen (aiplus.go)
	ui.HandleFunc("GET /api/attackers/{ip}/intel", a.Require(h.intel))
	ui.HandleFunc("GET /api/attackers/{ip}/greynoise", a.Require(h.greynoise))
	ui.HandleFunc("GET /api/export/stix", a.Require(h.exportSTIX))
	ui.HandleFunc("GET /api/extras", a.Require(h.getExtras))
	ui.HandleFunc("PUT /api/extras", a.Require(h.putExtras))
	ui.HandleFunc("POST /api/extras/test-notify", a.Require(h.testNotify))
	ui.HandleFunc("GET /api/abuse/log", a.Require(h.abuseLog))
	ui.HandleFunc("GET /api/share/status", a.Require(h.shareStatus))
	ui.HandleFunc("POST /api/share/dshield/check", a.Require(h.dshieldCheckAPI))
	ui.HandleFunc("GET /api/funde", a.Require(h.funde))          // Tab „Funde“ (funde.go)
	ui.HandleFunc("GET /api/funde/file", a.Require(h.fundeFile)) // Fallakte einer Datei
	ui.HandleFunc("GET /api/campaigns", a.Require(h.campaigns))
	ui.HandleFunc("GET /api/analysis/patterns", a.Require(h.patternStats))
	ui.HandleFunc("GET /api/analysis/exploits", a.Require(h.exploitsAPI)) // Exploits nach Produkt (exploits.go)
	ui.HandleFunc("GET /api/cve/info", a.Require(h.cveInfoAPI))           // Lückendetails (cvedb.go)
	ui.HandleFunc("GET /api/cve/status", a.Require(h.cveStatusAPI))
	ui.HandleFunc("POST /api/cve/refresh", a.Require(h.cveRefreshAPI))
	ui.HandleFunc("POST /api/cve/suggest", a.Require(h.suggestAPI)) // KI-Regelvorschläge (cvesuggest.go)
	ui.HandleFunc("GET /api/cve/suggestions", a.Require(h.suggestionsAPI))
	ui.HandleFunc("POST /api/cve/suggestions/{id}/accept", a.Require(h.suggestionDecideAPI))
	ui.HandleFunc("POST /api/cve/suggestions/{id}/discard", a.Require(h.suggestionDecideAPI))
	ui.HandleFunc("DELETE /api/cve/rules/{id}", a.Require(h.customRuleDeleteAPI))
	ui.HandleFunc("GET /api/creds/summary", a.Require(h.credSummary))
	ui.HandleFunc("GET /api/weekly", a.Require(h.weeklyPreview))
	ui.HandleFunc("GET /api/chain", a.Require(h.chain))
	ui.HandleFunc("GET /api/lookup/urlhaus", a.Require(h.lookupURLhaus))
	ui.HandleFunc("GET /api/lookup/malwarebazaar", a.Require(h.lookupBazaar))
	ui.HandleFunc("GET /api/tarpit", a.Require(h.tarpit))
	ui.HandleFunc("GET /api/settings", a.Require(h.getSettings))
	ui.HandleFunc("GET /api/ports/activity", a.Require(h.portActivityAPI))
	ui.HandleFunc("PUT /api/settings", a.Require(h.putSettings))
	ui.HandleFunc("POST /api/password", a.Require(h.changePassword))
	ui.HandleFunc("GET /api/system", a.Require(h.system))
	ui.HandleFunc("GET /api/hardware", a.Require(h.hardwareAPI))
	ui.HandleFunc("POST /api/backup/export", a.Require(h.backupExport))
	ui.HandleFunc("POST /api/backup/import", a.Require(h.backupImport))
	ui.HandleFunc("GET /api/logs", a.Require(h.logsList))
	ui.HandleFunc("GET /api/logs/{id}", a.Require(h.logsGet))
	ui.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := h.st.db.PingContext(r.Context()); err != nil {
			http.Error(w, "db", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	})
	if metricsToken != "" {
		ui.HandleFunc("GET /metrics", (&Auth{sensorToken: metricsToken}).RequireSensor(h.metrics))
	}
	if sensorOnUI {
		// Ohne eigenen Sensor-Port (lokale Tests) liegen die Sensor-Routen mit auf dem UI-Port.
		// Einzeln mit Methode registriert: ein Präfix wie "/api/sensor/" kollidiert mit "GET /".
		sensorRoutes(ui)
	}
	ui.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	}))
	return ui, sensor
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
			selfInstallSystem() // nur als root beim Update durch einen älteren Updater (pisystem.go)
			return
		case "verify-release": // hivornet-update: Signatur von SHA256SUMS prüfen (releasesig.go)
			if len(os.Args) < 4 {
				log.Fatal("Aufruf: hive verify-release SHA256SUMS SHA256SUMS.sig")
			}
			if err := verifyRelease(os.Args[2], os.Args[3]); err != nil {
				log.Fatalf("Signatur: %v", err)
			}
			fmt.Println("Signatur gültig")
			return
		case "sign-release": // Release-Workflow: SHA256SUMS signieren (releasesig.go)
			if len(os.Args) < 4 {
				log.Fatal("Aufruf: HIVORNET_SIGNING_KEY=… hive sign-release SHA256SUMS SHA256SUMS.sig")
			}
			if err := signRelease(os.Args[2], os.Args[3], []byte(os.Getenv("HIVORNET_SIGNING_KEY"))); err != nil {
				log.Fatalf("Signieren: %v", err)
			}
			fmt.Println("signiert")
			return
		case "install-system": // hivornet-update (root): Systemdateien aus dem Paket übernehmen
			if len(os.Args) < 3 {
				log.Fatal("Ordner fehlt")
			}
			if err := cmdInstallSystem(os.Args[2]); err != nil {
				log.Fatalf("Systemdateien: %v", err)
			}
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
		maxDBCapBytes: envMB("HIVE_MAX_DB_CAP_MB", 0),
		broker:        NewBroker(),
		sensors:       &Sensors{last: map[string]Heartbeat{}},
		geo:           NewGeo(env("HIVE_GEOIP_DIR", filepath.Join(filepath.Dir(dbPath), "geoip"))),
		cowrieLibDir:  os.Getenv("HIVE_COWRIE_LIB"),
	}
	h.aiSem = make(chan struct{}, 1)
	h.restart = make(chan struct{}, 1)
	h.loadExtras()
	h.notifier = NewNotifier(func() NotifyConfig { return h.Extras().Notify })
	bgStop := make(chan struct{})
	go h.notifier.Run(bgStop)
	go h.watchWarnings(bgStop)
	go h.checkUpdates(bgStop)
	h.abuse.load(st)
	go h.runAbuseReports(bgStop)
	h.share.load(st)
	go h.runSharing(bgStop)
	botVerifier.mu.Lock()
	botVerifier.st = st
	botVerifier.mu.Unlock()
	go botVerifier.run(bgStop)
	go h.runWeekly(bgStop)
	go h.runAIPlus(bgStop) // Kurzanalysen und KI-Wochenbericht (aiplus.go)
	go h.runSpikes(bgStop) // Spitzen-Warnung (insights.go)
	h.loadCustomRules()    // eigene Regeln aus KI-Vorschlägen (cvesuggest.go), vor Neuzählung und Zwischenspeicher
	go h.warmAnalysis(bgStop)
	go h.warmSnap(bgStop)
	go h.runOwnIP(bgStop) // eigene öffentliche Adresse (ownip.go)
	go h.runHW(bgStop)    // Hardware-Monitor (hwmon.go)
	go h.runCVEDB(bgStop) // KEV-Katalog, NVD und EPSS (cvedb.go)
	upgradeSensorConfigs(st)
	var maxID int64 // vor dem Start des Schreibers: alles bis hierher ist "alt"
	st.db.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM events`).Scan(&maxID)
	if prepareRecount(st) { // neue Zählregeln (0.5.3); ersetzt backfillPatterns
		go recountTop(st, maxID)
	} else {
		go backfillPatterns(st, maxID)
	}
	if h.writer, err = NewWriter(st, func(e *Event) { h.broker.Publish(e); h.notifier.OnEvent(e) }); err != nil {
		log.Fatalf("Datenbank: %v", err)
	}
	if ms, err := strconv.Atoi(os.Getenv("HIVE_FLUSH_MS")); err == nil && ms >= 100 && ms <= 60000 {
		h.writer.Interval = time.Duration(ms) * time.Millisecond
	}
	h.writer.brute = newBruteTracker() // Dauer-Brute-Force verdichten (bruteforce.go)
	h.writer.brute.exempt = func(ip string) bool { return isOwnIP(ip) || h.neverBlock(ip) }
	h.writer.brute.seed = st.bruteSeed
	go h.writer.Run()
	if err := h.syncBruteLimit(); err != nil {
		log.Printf("Drossel für Dauer-Brute-Force nicht angefordert: %v", err)
	}
	if env("HIVE_GEOIP", "on") != "off" {
		go h.geo.AutoUpdate()
	}

	h.auth = NewAuth(st, os.Getenv("HIVORNET_TOKEN"), os.Getenv("HIVE_COOKIE_SECURE") == "1")
	if h.auth.sensorToken == "" {
		log.Printf("WARNUNG: HIVORNET_TOKEN ist leer, Sensoren können nichts senden")
	}
	setBaitSecret(h.auth.sensorToken) // Köder-Zugangsdaten wie der Honeypot (bait.go)
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
	h.probe = newPortProbe(cowrieProbeTargets())
	go h.probe.run(bgStop, func() bool { // erst prüfen, wenn Cowrie fertig installiert ist
		ci := cowrieInstallStatus()
		return h.cowrie != nil && (ci == nil || ci.State == "ok")
	})

	go func() {
		time.Sleep(time.Minute)
		for {
			h.autoGrowDB(time.Now()) // erst erweitern, wenn erlaubt; sonst löscht das Aufräumen
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
	h.hosts.env = envAllowedHosts()
	h.reloadHosts()

	sensorAddr := os.Getenv("HIVE_SENSOR_LISTEN")
	sub, _ := fs.Sub(webFS, "web")
	files := http.FileServer(http.FS(sub))
	if dir := os.Getenv("HIVE_WEB_DIR"); dir != "" { // nur für Entwicklung: UI direkt vom Datenträger
		files = http.FileServer(http.Dir(dir))
	}
	ui, sensorMux := h.routes(sensorAddr == "", os.Getenv("HIVE_METRICS_TOKEN"), files)

	baseCtx, cancelBase := context.WithCancel(context.Background())
	mkServer := func(addr string, hd http.Handler) *http.Server {
		return &http.Server{Addr: addr, Handler: hd, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
			MaxHeaderBytes: 64 << 10, BaseContext: func(net.Listener) context.Context { return baseCtx }}
	}
	servers := []*http.Server{mkServer(env("HIVE_LISTEN", ":8088"), securityHeaders(uiGuard(ui, ingestNet, h.allowedHosts)))}
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
	select {
	case <-sig:
		log.Printf("Beende ...")
	case <-h.restart:
		// Nach einer Wiederherstellung: beenden, systemd bzw. Docker starten neu,
		// beim Start übernimmt applyRestore die neue Datenbank.
		log.Printf("Beende für die Wiederherstellung ...")
	}
	cancelBase() // beendet offene Live-Streams
	close(bgStop)
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
