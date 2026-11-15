# Hivornet – Architektur

Stand: Branch `claude/fable-ueberarbeitung-c18ccc` (nach 0.2.0). Dieses Dokument beschreibt, wie das System aufgebaut ist und wo man es erweitert. Was sich gegenüber 0.2.0 geändert hat und warum, steht in [UEBERARBEITUNG.md](UEBERARBEITUNG.md); das Ereignisformat in [events.md](events.md).

## 1. Komponenten

| Container | Sprache | Aufgabe | Netze | Limit RAM |
|---|---|---|---|---|
| `honeypot` | Go, ein Binary, distroless | Lauscht auf den Honeypot-Ports, spielt 12 Dienste nach, schickt Ereignisse an den Hive | `honeynet`, `ingest` | 192 MB |
| `cowrie` | Python (Fremd-Image 3.1.6, per Digest) | SSH und Telnet mit gefälschter Shell; schreibt `cowrie.json` und TTY-Mitschnitte in Volumes | `honeynet` | 256 MB |
| `hive` | Go, ein Binary, distroless | Nimmt Ereignisse an, ergänzt GeoIP, speichert in SQLite, liefert API und Web-UI, analysiert und benachrichtigt | `admin`, `ingest` | 384 MB |
| `janitor` | BusyBox | Löscht alte Cowrie-Dateien | keines | 16 MB |

Die Limits sind Obergrenzen für den Notfall. Gemessen liegt alles zusammen unter 512 MB (README, Tabelle oben). Die Zusatzfunktionen dieser Überarbeitung belegen keinen nennenswerten Speicher: Die Regeln sind beim Start kompilierte reguläre Ausdrücke, Benachrichtigungen haben eine Warteschlange mit 64 Plätzen, Berichte entstehen auf Abruf aus höchstens 5.000 Ereignissen.

```
Angreifer ──> honeypot ──POST /api/ingest (Netz ingest, Port 8089)──┐
Angreifer ──> cowrie ──cowrie.json, tty/ (Volumes, für den Hive nur lesbar)──┤
                                                                             v
                       ┌──────────────────────── hive ─────────────────────────┐
                       │ Sanitize → GeoIP → Writer (Sammeltransaktion) → SQLite │
                       │                      │                                 │
                       │                      ├─> Broker (SSE)  ──> Browser     │
                       │                      └─> Notifier ──> ntfy/Telegram/Webhook
                       │ API (8088): Statistik, Bericht, Einstellungen          │
                       │   auf Abruf ──> KI-Schnittstelle, AbuseIPDB            │
                       └────────────────────────────────────────────────────────┘
honeypot <── GET /api/sensor/config (alle 15 s) ── hive      honeypot ── Heartbeat (alle 10 s) ──> hive
```

Ausgehende Verbindungen:

- `honeypot` und `cowrie`: keine (Netzsperre `tools/firewall.sh`); der Honeypot prüft das selbst (`HONEYPOT_EGRESS_PROBE`).
- `hive`: GeoIP-Download (`download.db-ip.com`) sowie, nur wenn eingerichtet, Benachrichtigungen, KI-Schnittstelle und AbuseIPDB.

## 2. Honeypot (`honeypot/`)

| Datei | Inhalt |
|---|---|
| `main.go` | Start, Schleifen für Konfiguration (15 s), Heartbeat (10 s), Netzsperren-Prüfung (10 min), sauberes Beenden |
| `config.go` | `Config`, `ListenerConfig`, `TarpitConfig`; `LoadConfigFile`, `Normalize` (Standardwerte, Port-Kollisionen), `BindPort` (Ports < 1024 lauschen auf Port+10000) |
| `manager.go` | `Manager.Apply` startet/stoppt Listener; **`handlers`** ist das Register aller Dienste; `handle` baut die `Session`, setzt Limits, schreibt `connect`/`disconnect` |
| `session.go` | `Session` mit `Emit`, `Login`, `Command`, `Write`, `Tarpit`; Hilfen `clip`, `printable`, `readLine`, `capReader`; Budgets `budgetText` usw.; `selfSignedTLS` |
| `limits.go` | `Limits` (Verbindungen gesamt, je IP, je Port, Tarpit-Plätze), `RateLimiter` (10 Ereignisse/s je IP, Burst 300) |
| `hive.go` | `Event`, `HiveClient` (Senden, Konfiguration, Heartbeat), `Emitter` (Warteschlange nach Bytes, Blöcke ≤ 200/1 MB, 4xx verwerfen, 5xx wiederholen) |
| `proto_http.go` | `http`, `https`, `dockerapi` |
| `proto_other.go` | `ftp`, `redis`, `mysql`, `ssh-tarpit`, `raw` |
| `proto_telnet.go` | `telnet`: Login, Schein-Shell (`telnetReply`), `telnetReadLine` entfernt IAC-Folgen |
| `proto_smtp.go` | `smtp`: AUTH PLAIN/LOGIN, MAIL/RCPT/DATA; `smtpReadData` begrenzt die Mail |
| `proto_vnc.go` | `vnc`: RFB-Handshake bis zur Challenge/Response |
| `proto_rdp.go` | `rdp`: `readTPKT`, `parseRDPRequest` (Cookie, Protokolle), `rdpConfirm`, `rdpClientInfo` |
| `proto_udp.go` | UDP-Dienste `sip`, `snmp`, `dns`: **`udpHandlers`** (Register der UDP-Dienste, je ein Parser `[]byte -> Event`), `serveUDP` (Empfang, Drossel, nie eine Antwort), `berTLV` für SNMP |
| `honeypot_test.go`, `proto_new_test.go` | Tests, Fuzz-Ziele, Vertragstests (`TestEventSizeContract`, `TestNewProtocolsSizeBudget`, `TestServiceListsInSync`) |

Jeder Handler hat die Form `func(*Session)` und kennt drei Modi (`s.Mode`): `emulate` (nachspielen), `tarpit` (sofort `s.Tarpit(...)`), `hybrid` (erst aufzeichnen, dann `s.Tarpit(...)`). Der Handler läuft unter `recover`; Lesefristen setzt er selbst mit `s.ReadDeadline`.

Regeln, die jeder Handler einhalten muss:

1. **Eingaben begrenzen:** nie unbegrenzt lesen (`readLine(br, max)`, `io.ReadFull` mit geprüfter Länge, feste Schleifenzahl).
2. **Ausgaben in Ereignissen begrenzen:** Texte durch `printable(b, budget)` bzw. `pr(s, n)` oder `clip`; nie Rohbytes in `Data`.
3. **Nichts ausführen, nichts schreiben, keine Verbindungen aufbauen.**

## 3. Hive (`hive/`)

| Datei | Inhalt |
|---|---|
| `main.go` | Start, `Hive`-Struktur, `routes()` (alle HTTP-Routen), Server, sauberes Beenden, Unterbefehle `healthcheck`, `backup`, `version` |
| `store.go` | `Event`, `Sanitize`, `migrations`, `OpenStore`, `Writer` (ein Schreiber, Sammeltransaktionen, Duplikaterkennung über `eid`), `topKeys` (Zähltabelle), `Retention`, `Backup` |
| `api.go` | Sensor-Endpunkte (`ingest`, `heartbeat`, `sensorConfig`), Statistik, Ereignisliste (`eventFilter`), Export, Einstellungen des Sensors, `warnings`, `system`, `metrics` |
| `auth.go` | Admin-Konto, Login-Bremse, Sitzungen (nur Hash gespeichert), `Require` (Cookie + CSRF-Header), `RequireSensor` (Token), `uiGuard` (Sensor-Netz aussperren, Host-Prüfung) |
| `sensors.go` | `SensorConfig.Validate`, `knownServices`, Konfiguration je Sensor, `Heartbeat`, `Sensors` |
| `cowrie.go` | `CowrieTail`: liest `cowrie.json` mit Rotation und Wiederaufnahme; `handle` übersetzt Cowrie-Ereignisse |
| `geo.go` | GeoIP (DB-IP Lite), `Enrich`, monatliches Update |
| `sse.go` | `Broker`: Live-Ereignisse an Browser |
| `analyze.go` | **Muster-Analyse:** `patterns` (Regeln), `matchPatterns`, `commandTools`/`eventTools`, `BuildReport`, `Report.Text` |
| `report.go` | `/api/report`, KI-Auswertung (`askAI`, `reportAI`), AbuseIPDB (`intel`), `loadEvents` |
| `notify.go` | `Notifier` (ntfy, Telegram, Webhook; Abklingzeit, Stundenlimit), `watchWarnings`, Testnachricht |
| `extras.go` | `Extras` (Standort, Benachrichtigungen, KI, AbuseIPDB), Geheimnis-Behandlung, Tabelle `lookups` |
| `tty.go` | `parseTTYLog`, `ttyClean`, `/api/sessions/{id}/tty` |
| `users.go` | Benutzerverwaltung (`usersList`, `usersCreate`, `usersDelete`); Rollen `admin` und `viewer`, Regeln in `viewerAllowed` (auth.go) |
| `intel2.go` | GreyNoise-Abfrage (`greynoise`), STIX-2.1-Export (`exportSTIX`, `stixID`, `stixString`) |
| `setup.go` | Ersteinrichtung (`setupStatus`, `setupRun`), einmalige Port-Anpassung (`upgradeSensorConfigs`), Update-Prüfung gegen GitHub (`checkUpdates`, `newestRelease`, `parseSemver`), Update-Auslösung (`updateRun`), Muster-Nachzählen (`backfillPatterns`) |
| `disk_linux.go`, `disk_other.go` | freier Speicher |
| `hive_test.go`, `extra_test.go` | Tests |

### Weg eines Ereignisses

1. `ingest` (oder `CowrieTail.handle`) erzeugt ein `Event`. Geo-Felder vom Sensor werden verworfen.
2. `Event.Sanitize` prüft IP und Typ (`validTypes`), kürzt Felder, kürzt `data` über 16 KB feldweise.
3. `Geo.Enrich` setzt Land, Stadt, Koordinaten, ASN.
4. `Writer.Submit` verwirft Duplikate (`eid`) und stellt ein; ist die Warteschlange voll, bekommt der Sensor 503 und sendet später erneut.
5. `Writer.writeBatch` schreibt in einer Transaktion nach `events`, `hourly`, `attackers` und `top_hourly` (über `topKeys`, inklusive Muster, Werkzeuge, Adressen).
6. Nach dem Commit ruft der Writer `pub` auf: `Broker.Publish` (Live-Feed) und `Notifier.OnEvent`.

### HTTP-Routen (alle in `Hive.routes`)

Sensor-API (Token, Port 8089): `POST /api/ingest`, `POST /api/sensor/heartbeat`, `GET /api/sensor/config`.

Web-UI (Sitzungs-Cookie; schreibende Aufrufe brauchen den Header `X-Requested-With: hivornet`; Benutzer mit Rolle `viewer` dürfen nur lesen, siehe `viewerAllowed` in `auth.go`):

| Route | Zweck |
|---|---|
| `POST /api/login`, `POST /api/logout`, `GET /api/me`, `POST /api/password` | Anmeldung (`me` liefert auch Rolle und Update-Hinweis) |
| `GET/POST /api/setup` | Ersteinrichtung, ohne Anmeldung, nur solange kein Konto existiert |
| `GET/POST /api/users`, `DELETE /api/users/{name}` | Benutzerverwaltung (nur Admin) |
| `POST /api/update` | Update anstoßen (nur wo `HIVE_UPDATE_REQUEST` gesetzt ist) |
| `GET /api/stats/summary`, `/timeline`, `/top?field=…`, `/map` | Kennzahlen; `field`: `country`, `port`, `ip`, `asn`, `service`, `username`, `password`, `cred`, `command`, `path`, `useragent`, `client`, `tag`, `tool`, `url` |
| `GET /api/events` | Liste; Filter `service`, `type`, `country`, `session`, `src_ip`, `sensor`, `dst_port`, `q`, `range`, `hide_noise`, `before`, `limit` |
| `GET /api/export/events`, `/api/export/blocklist`, `/api/export/stix` | Export (CSV/JSON, Blockliste, STIX 2.1) |
| `GET /api/stream` | Live-Ereignisse (SSE) |
| `GET /api/attackers/{ip}`, `…/intel`, `…/greynoise` | Angreifer, AbuseIPDB, GreyNoise |
| `GET /api/sessions`, `/api/sessions/{id}`, `/api/sessions/{id}/tty` | Sitzungen, Mitschnitt |
| `GET /api/report?ip=…` oder `?session=…` (`&format=text`), `POST /api/report/ai` | Angriffsbericht, KI-Auswertung |
| `GET/PUT /api/settings` | Sensor-Konfiguration, Aufbewahrung |
| `GET/PUT /api/extras`, `POST /api/extras/test-notify` | Zusatzfunktionen |
| `GET /api/tarpit`, `GET /api/system`, `GET /healthz`, `GET /metrics` | Tarpit, System, Überwachung |

## 4. Datenbank

SQLite über `modernc.org/sqlite` (ohne cgo), WAL, `auto_vacuum=INCREMENTAL`, höchstens 4 Verbindungen, ein einziger Schreiber für Ereignisse.

**Migrationen:** `migrations` in `hive/store.go` ist eine Liste von SQL-Texten; der Index + 1 ist die Schema-Version in `PRAGMA user_version`. `Store.migrate` führt beim Start alle fehlenden Schritte je in einer Transaktion aus. Bestehende Einträge nie ändern, nur anhängen. Braucht ein Schritt Go-Code (wie das Befüllen der Zähltabelle in Schritt 2), kommt er als `if v+1 == N` in `migrate`.

| Version | Inhalt |
|---|---|
| 1 | Grundschema: `events`, `hourly`, `attackers`, `kv`, `users`, `auth_sessions` |
| 2 | `top_hourly`; Sitzungs-Token nur noch als Hash (alte Sitzungen gelöscht) |
| 3 | `lookups` (Zwischenspeicher für AbuseIPDB, GreyNoise und KI-Auswertung) |
| 4 | Spalte `users.role` (`admin` oder `viewer`, Standard `admin`) |

| Tabelle | Schlüssel | Inhalt | Aufbewahrung |
|---|---|---|---|
| `events` | `id` | alle Ereignisse; `ts` in Millisekunden, `data` als JSON-Text | Frist (`retention_days`) und Größe (`HIVE_MAX_DB_MB`, `HIVE_MIN_FREE_MB`) |
| `hourly` | Stunde, Dienst, Typ, Land | Anzahl, Tarpit-Zeit; ohne IPs | 400 Tage |
| `top_hourly` | Stunde, `field`, `key` | Zähler für Top-Listen und Karte; `label` ist die Beschriftung | Frist |
| `attackers` | `ip` | erste/letzte Sichtung, Zähler, Herkunft | Frist |
| `lookups` | `subject`, `source` | `subject` = `ip:<IP>` oder `session:<ID>`; `source` = `abuseipdb` oder `ai`; `data` = JSON bzw. Text | Frist |
| `kv` | `k` | `sensor_config`, `sensor_config:<name>`, `retention_days`, `cowrie_state`, `extras` | bleibt |
| `users`, `auth_sessions` | | Konten mit Rolle (bcrypt), Sitzungen (SHA-256 des Tokens). Sitzungen gelöschter Benutzer gelten nicht mehr (JOIN in `Auth.Who`) | Sitzungen 7 Tage |

`top_hourly.field`: `country`, `port`, `ip`, `asn`, `service`, `geo` (Karte, Schlüssel „Breite,Länge“), `username`, `password`, `cred`, `command`, `path`, `useragent`, `client`, `tag` (Muster-ID, `label` = Name), `tool`, `url`.

## 5. Web-UI (`hive/web/`)

Reines JavaScript in ES-Modulen, kein Build-Schritt, per `go:embed` im Binary (in der Entwicklung mit `HIVE_WEB_DIR` vom Datenträger).

| Datei | Inhalt |
|---|---|
| `index.html`, `style.css`, `favicon.svg` | Rahmen; Farben als CSS-Variablen für Hell und Dunkel |
| `dom.js` | `h()` baut Elemente und fügt Texte **immer als Textknoten** ein (`safeText` ersetzt Steuerzeichen); `api()`, Formatierung, Tooltip, `store()` |
| `charts.js` | `worldMap` (Punkte, Standort, `attack()` zeichnet die Angriffslinie), `timeline`, `toplist`, `svcName`, `svcColor` |
| `world.js` | Landumrisse (erzeugt von `tools/build_world.py`) |
| `app.js` | Anmeldung, Live-Stream, Router (`routes`, `route()`), Ansichten Dashboard, Live-Feed, Sitzungen, Angreifer, Zugangsdaten, Tarpit, Einstellungen, System |
| `extra.js` | Ansichten Live-Karte und Analyse; Bausteine `reportCard`, `ttyCard`, `intelCard`, `extrasCards` |

Regeln für die UI:

- **Nie `innerHTML`.** Angreiferdaten nur über `h()`/`mount()`. Adressen aus Angreiferdaten werden nicht verlinkt.
- Die CSP (`securityHeaders` in `main.go`) erlaubt nur eigene Skripte und Styles. Inline-`style`-Attribute sind verboten; `h()` setzt Stile über `el.style` (erlaubt).
- Eine Ansicht ist `async function viewX(el, ctx, ...parameter)`. `ctx.live(fn)` abonniert Live-Ereignisse, `ctx.every(ms, fn)` setzt einen Timer; beides räumt der Router beim Verlassen ab.
- `app.js` und `extra.js` importieren sich gegenseitig. Das funktioniert, weil `extra.js` die Namen aus `app.js` nur innerhalb von Funktionen benutzt. Auf oberster Ebene von `extra.js` nichts aus `app.js` verwenden.

## 6. Konfiguration

### Hive (Umgebungsvariablen)

| Variable | Standard | Bedeutung |
|---|---|---|
| `HIVORNET_TOKEN` | – (Pflicht) | gemeinsames Token der Sensoren |
| `HIVE_ADMIN_USER`, `HIVE_ADMIN_PASSWORD`, `HIVE_RESET_ADMIN` | `admin`, leer, `0` | Admin-Konto beim ersten Start bzw. Zurücksetzen |
| `HIVE_LISTEN`, `HIVE_SENSOR_LISTEN` | `:8088`, leer | UI-Port; Sensor-Port. Ohne Sensor-Port liegen die Sensor-Routen mit auf dem UI-Port (nur Entwicklung) |
| `HIVE_INGEST_SUBNET` | leer | aus diesem Netz lehnt die UI Anfragen ab |
| `HIVE_ALLOWED_HOSTS`, `HIVE_COOKIE_SECURE` | leer, `0` | Host-Prüfung, Cookie nur über HTTPS |
| `HIVE_DB`, `HIVE_GEOIP_DIR`, `HIVE_GEOIP` | `/data/hive.db`, `/data/geoip`, `on` | Speicherorte; `off` schaltet den GeoIP-Download ab |
| `HIVE_RETENTION_DAYS`, `HIVE_MAX_DB_MB`, `HIVE_MIN_FREE_MB` | 30, 2048, 1024 | Aufbewahrung |
| `HIVE_FLUSH_MS` | 300 | Schreibintervall des Writers (100–60000). Größer schont SD-Karten |
| `HIVE_COWRIE_LOG`, `HIVE_COWRIE_LIB` | leer | Pfad zu `cowrie.json`; Ordner mit `tty/` und `downloads/` |
| `SENSOR_NAME`, `COWRIE_SENSOR_NAME` | `sensor-1` | Sensorname für Cowrie-Ereignisse |
| `HIVE_METRICS_TOKEN` | leer | schaltet `/metrics` frei |
| `HIVE_UPDATE_CHECK` | `on` | `off` schaltet die Prüfung auf neue Versionen bei GitHub ab |
| `HIVE_UPDATE_REQUEST` | leer | Datei, in die der Hive eine Update-Anforderung legt; nur gesetzt, wo ein Updater läuft (Pi-Image). Fehlt sie, gibt es keinen Update-Knopf |
| `HIVE_UPDATE_STATUS` | leer | Datei, aus der das Ergebnis des letzten Updates gelesen wird (vom Updater geschrieben) |
| `HIVE_DIRECT_PORTS` | leer | `1`: Honeypot lauscht ohne Docker direkt auf den echten Ports; die Einstellungen zeigen „direkt am Gerät" statt der NAS-Portzuordnung |
| `HIVE_WEB_DIR` | leer | UI vom Datenträger statt aus dem Binary (Entwicklung) |
| `PORT_*` | | nur zur Anzeige „Öffentlich“ in den Einstellungen (`publishedPorts` in `api.go`) |

In der UI gespeichert (Tabelle `kv`): Sensor-Konfiguration, Aufbewahrung, **Zusatzfunktionen** (`extras`: Standort, Benachrichtigungen, KI, AbuseIPDB-Schlüssel), sowie die Merker `config_level` (Port-Anpassung lief) und `patterns_backfilled` (Muster nachgezählt). Geheimnisse darin liefert die API nie zurück.

**Ersteinrichtung:** Ist kein Admin-Konto vorhanden und keines per `HIVE_ADMIN_PASSWORD` vorgegeben, legt `EnsureAdmin` keins an; die UI zeigt den Assistenten (`GET/POST /api/setup`, `setup.go`). Wer ihn zuerst ausfüllt, setzt das Passwort – darum gehört die UI nie ins Internet.

### Honeypot

| Variable | Standard | Bedeutung |
|---|---|---|
| `HIVORNET_TOKEN`, `HIVE_URL`, `SENSOR_NAME` | –, `http://hive:8089`, `sensor-1` | Verbindung zum Hive |
| `HONEYPOT_CONFIG` | `/etc/hivornet/honeypot.yml` | Startkonfiguration, bis der Hive eine liefert |
| `HONEYPOT_BIND`, `HONEYPOT_LOW_PORT_OFFSET` | alle Schnittstellen, im Image 10000 | Bindung; Versatz für Ports < 1024 |
| `HONEYPOT_EGRESS_PROBE` | `1.1.1.1:443` | Ziel der Netzsperren-Prüfung; `off` schaltet sie ab |
| `HONEYPOT_LOG_EVENTS` | leer | `1` schreibt Ereignisse zusätzlich nach stdout |

## 7. Erweiterungspunkte

### Neues Protokoll

1. `honeypot/proto_<name>.go` anlegen mit `func handle<Name>(s *Session)`. Alle drei Modi behandeln; Eingaben und Ereignis-Inhalte begrenzen (Abschnitt 2).
2. In `honeypot/manager.go` in `handlers` eintragen. Das ist die einzige Liste im Honeypot.
3. In `hive/sensors.go` zu `knownServices` hinzufügen, in `hive/web/app.js` zu `SERVICES`, in `hive/web/charts.js` zu `SVC_NAME` (und bei Bedarf `SVC_COLOR`). `TestServiceListsInSync` schlägt fehl, wenn Hive oder `app.js` fehlen.
4. Soll der Dienst standardmäßig laufen: `DefaultConfig()` in `honeypot/config.go`, `config/honeypot.yml`, Port in `docker-compose.yml` (bei `honeypot.ports` und als `PORT_…` beim Hive), `.env.example`, `publishedPorts` in `hive/api.go`, Tabelle in der README.
5. Tests: Ablauf über `run(t, m, "<name>", "emulate")` mit `net.Pipe` (Muster in `proto_new_test.go`), den Dienst in `TestNewProtocolsSizeBudget` aufnehmen, für Parser ein Fuzz-Ziel schreiben und in `.github/workflows/ci.yml` eintragen.
6. `tools/attack_sim.py` um einen Testangriff ergänzen; `docs/events.md` ergänzen, falls neue Felder in `data` entstehen.


**UDP-Dienst** statt TCP: Parser `func(p []byte) Event` in `honeypot/proto_udp.go` schreiben und in `udpHandlers` eintragen (nicht in `handlers`). Er darf **nie antworten** (Absender fälschbar, Reflexionsgefahr). Ansonsten dieselben Schritte 3 bis 6; Compose-Ports mit `/udp`. Tests nach dem Muster `TestUDPListenerNeverReplies`, Parser ins Fuzz-Ziel `FuzzUDPParsers` (läuft über alle Einträge von `udpHandlers`).
### Neuer Ereignistyp

1. `validTypes` in `hive/store.go`. Ältere Hives verwerfen unbekannte Typen einzeln (der Rest des Blocks wird angenommen); neue Typen sind also abwärtskompatibel, werden von einem alten Hive aber nicht gespeichert.
2. Erzeugen: im Honeypot per `s.Emit(Event{Type: …, Data: …})` oder in `CowrieTail.handle`.
3. Zählen, falls gewünscht: `topKeys` in `hive/store.go`; für die Analyse `eventText` in `hive/analyze.go`.
4. Anzeigen: `TYPE_NAME` und `describe()` in `hive/web/app.js`.
5. `docs/events.md` ergänzen; Größenbudget beachten (`TestEventSizeContract`).

### Neues Angriffsmuster

1. In `hive/analyze.go` eine Zeile `pat(id, name, beschreibung, gruppe, schweregrad, regex)` an `patterns` anhängen. Gruppe: `cmd`, `web` oder `raw`. Schweregrad 3 löst die Benachrichtigung „Schweres Angriffsmuster“ aus.
2. In `hive/extra_test.go` ein Beispiel in `patternExamples` eintragen; `TestPatterns` verlangt eines je Regel.
3. Achtung Virenscanner: siehe UEBERARBEITUNG.md, Abschnitt Risiken.

### Neue UI-Ansicht

1. `export async function viewX(el, ctx)` schreiben (in `extra.js` oder `app.js`), mit `header("Titel", { range: true })` und `mount(el, …)`.
2. In `app.js`: Eintrag in `NAV` und in `routes` (regulärer Ausdruck auf den Hash), bei `extra.js` zusätzlich im Import.
3. Braucht die Ansicht neue Daten: Handler in `hive/` schreiben und in `Hive.routes` mit `a.Require(...)` registrieren.
4. Im Browser prüfen (Abschnitt 8); die Klammern in verschachtelten `h(...)`-Aufrufen sind die häufigste Fehlerquelle.

### Neues Benachrichtigungsziel

In `Notifier.Send` (`hive/notify.go`) einen weiteren Block nach dem Muster von ntfy anlegen, Felder in `NotifyConfig` (`extras.go`) ergänzen, Geheimnisse in `secretFields` eintragen, Eingabefelder in `extrasCards` (`extra.js`).

### Schemaänderung

SQL an `migrations` anhängen, Tabelle in Abschnitt 4 ergänzen, Test nach dem Muster `TestMigrationFromV01` bzw. `TestMigrationCreatesLookups`.

## 7a. Raspberry-Pi-Image (`pi/`)

Betrieb ohne Docker: zwei systemd-Dienste statt Container, sonst dieselben Programme.

| Datei | Zweck |
|---|---|
| `pi/build_image.py` | baut das Image: lädt das festgelegte Raspberry Pi OS Lite (Adresse und Prüfsumme in `BASE`), packt Programme und `pi/rootfs/` als `payload.tar.gz` (Rechte root, Skripte 0755) und schreibt es mit `user-data`, `vendor-data`, `userconf.txt` und `install.sh` in die **FAT-Bootpartition** (pyfatfs). Die Linux-Partition bleibt unberührt; deshalb kein Root und kein Linux nötig |
| `pi/install.sh` | läuft beim ersten Start über cloud-init (`runcmd`, zusätzlich `vendor-data`), genau einmal (`flock`, Merker `/var/lib/hivornet-installed`): Paket prüfen und entpacken, Benutzer anlegen, Token, SSH maskieren, Hostname `hivornet`, Dienste starten, Paket von der Bootpartition löschen. Protokoll `/var/log/hivornet-install.log` |
| `pi/rootfs/etc/systemd/system/hivornet-hive.service` | Hive als Benutzer `hivornet-hive`, gehärtet, `HIVE_DIRECT_PORTS=1`, SD-schonend |
| `pi/rootfs/etc/systemd/system/hivornet-honeypot.service` | Honeypot als Benutzer `hivornet-pot`, nur `CAP_NET_BIND_SERVICE`, lauscht direkt auf den echten Ports |
| `pi/rootfs/.../hivornet-firstboot` | erzeugt beim ersten Start das Token (Passwort kommt aus der UI-Ersteinrichtung) |
| `pi/rootfs/.../hivornet-firewall` | Netzsperre nach Benutzer (nftables oder iptables, owner-Match) |
| `pi/rootfs/.../hivornet-update{.path,.service,script}` | beobachtet die Update-Anforderung des Hive, lädt die Version von GitHub, prüft `SHA256SUMS`, tauscht die Programme, Rückfall auf die alte Version |
| `pi/rootfs/etc/hivornet/honeypot.yml` | Startkonfiguration mit echten Ports; 22 und 23 gehören Cowrie |
| `pi/rootfs/etc/hivornet/cowrie.cfg` | Cowrie-Einstellungen: absolute Pfade unter `/var/lib/hivornet-cowrie`, Ports 22/23, Download-Grenze |
| `pi/rootfs/usr/local/sbin/hivornet-cowrie-install` | installiert Cowrie beim ersten Start mit Internet (Version und Prüfsumme fest), Wiederholung stündlich über `hivornet-cowrie-install.timer` |
| `hivornet-cowrie.service`, `hivornet-cowrie-clean.timer` | Cowrie als Benutzer `hivornet-cowrie` mit `CAP_NET_BIND_SERVICE`; tägliches Aufräumen nach 14 Tagen |

Updates landen über `release.yml` als `hivornet-<tag>-linux-<arch>.tar.gz` mit `SHA256SUMS` in der GitHub-Veröffentlichung; von dort holt sich der Updater die neue Version. Cowrie wird auf dem Pi beim ersten Start nachinstalliert (Python-Umgebung unter `/opt/hivornet/cowrie-env`); die Netzsperre gilt auch für den Benutzer `hivornet-cowrie`. Ein Update über die UI tauscht nur `hive` und `honeypot` aus, die Cowrie-Version ändert sich nur mit einem neuen Image.

## 8. Entwickeln und Prüfen

```bash
sh tools/check.sh          # gofmt, vet, Tests, Cross-Build amd64/arm64/armv7 für beide Module
sh tools/check.sh quick    # ohne Cross-Build
```

UI lokal ansehen (ohne Docker):

```bash
cd hive && go build -o hive . && HIVE_DB=./data/hive.db HIVORNET_TOKEN=test HIVE_ADMIN_PASSWORD=testpasswort1 \
  HIVE_LISTEN=127.0.0.1:8088 HIVE_WEB_DIR=./web HIVE_GEOIP=off ./hive
```

Danach `http://127.0.0.1:8088` öffnen. Testdaten: `python3 tools/attack_sim.py --no-attacks --demo 300 --hive http://127.0.0.1:8088 --token test`. Ohne GeoIP-Datenbank haben Ereignisse keine Koordinaten; die Karte bleibt dann leer.

Was nur die CI prüft: `staticcheck`, `govulncheck`, Race-Detector, `shellcheck`, `hadolint`, Docker-Build. Auf dem Windows-Entwicklungsrechner gibt es kein Docker.
