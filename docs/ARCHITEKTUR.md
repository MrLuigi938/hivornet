# Hivornet – Architektur

Stand: Version 0.6.1-beta.1, Branch `main`. Dieses Dokument beschreibt, wie das System aufgebaut ist und wo man es erweitert. Änderungen je Version stehen im [CHANGELOG](../CHANGELOG.md), das Ereignisformat in [events.md](events.md), Bauen, CI und Veröffentlichen in [ENTWICKLUNG.md](ENTWICKLUNG.md). [UEBERARBEITUNG.md](UEBERARBEITUNG.md) und [AUDIT.md](AUDIT.md) sind historische Protokolle früherer Versionen.

Zwei Betriebsarten mit denselben Programmen: **Docker** (NAS, Server; Abschnitte 1 bis 6) und **Raspberry Pi ohne Docker** (systemd-Dienste; Abschnitt 7a).

## 1. Komponenten

| Container | Sprache | Aufgabe | Netze | Limit RAM |
|---|---|---|---|---|
| `honeypot` | Go, ein Binary, distroless | Lauscht auf den Honeypot-Ports, spielt 12 Dienste nach, schickt Ereignisse an den Hive | `honeynet`, `ingest` | 192 MB |
| `cowrie` | Python (Fremd-Image 3.1.6, per Digest) | SSH und Telnet mit gefälschter Shell; schreibt `cowrie.json` und TTY-Mitschnitte in Volumes | `honeynet` | 256 MB |
| `hive` | Go, ein Binary, distroless | Nimmt Ereignisse an, ergänzt GeoIP, speichert in SQLite, liefert API und Web-UI, analysiert und benachrichtigt | `admin`, `ingest` | 384 MB |
| `janitor` | BusyBox | Löscht alte Cowrie-Dateien | keines | 16 MB |

Die Limits sind Obergrenzen für den Notfall. Gemessen liegt alles zusammen unter 512 MB. Die Zusatzfunktionen (Analyse, Benachrichtigungen, Berichte) belegen keinen nennenswerten Speicher: Die Regeln sind beim Start kompilierte reguläre Ausdrücke, Benachrichtigungen haben eine Warteschlange mit 64 Plätzen, Berichte entstehen auf Abruf aus höchstens 5.000 Ereignissen.

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
                       │   auf Abruf ──> KI-Schnittstelle, AbuseIPDB, GreyNoise │
                       └────────────────────────────────────────────────────────┘
honeypot <── GET /api/sensor/config (alle 15 s) ── hive      honeypot ── Heartbeat (alle 10 s) ──> hive
```

Ausgehende Verbindungen:

- `honeypot` und `cowrie`: keine (Netzsperre `tools/firewall.sh`, auf dem Pi `hivornet-firewall`); der Honeypot prüft das selbst (`HONEYPOT_EGRESS_PROBE`).
- `hive`: GeoIP-Download (`download.db-ip.com`), Update-Prüfung (`api.github.com`, abschaltbar) sowie, nur wenn eingerichtet oder auf Knopfdruck, Benachrichtigungen, KI-Schnittstelle, AbuseIPDB (Abfrage und, wenn eingeschaltet, automatische Meldung), GreyNoise und abuse.ch (URLhaus, MalwareBazaar). DNS-Auflösung über den Resolver des Systems für die Prüfung angeblicher Suchmaschinen-Bots.

## 2. Honeypot (`honeypot/`)

| Datei | Inhalt |
|---|---|
| `main.go` | Start, Schleifen für Konfiguration (15 s), Heartbeat (10 s), Netzsperren-Prüfung (10 min), sauberes Beenden |
| `config.go` | `Config`, `ListenerConfig`, `TarpitConfig`; `LoadConfigFile`, `Normalize` (Standardwerte, Port-Kollisionen), `BindPort` (Ports < 1024 lauschen auf Port+10000) |
| `manager.go` | `Manager.Apply` startet/stoppt Listener; **`handlers`** ist das Register aller Dienste; `handle` baut die `Session`, setzt Limits, schreibt `connect`/`disconnect` |
| `session.go` | `Session` mit `Emit`, `Login`, `Command`, `Write`, `Tarpit`; Hilfen `clip`, `printable`, `readLine`, `capReader`; Budgets `budgetText` usw.; `selfSignedTLS` |
| `limits.go` | `Limits` (Verbindungen gesamt, je IP, je Port, Tarpit-Plätze), `RateLimiter` (10 Ereignisse/s je IP, Burst 300) |
| `hive.go` | `Event`, `HiveClient` (Senden, Konfiguration, Heartbeat), `Emitter` (Warteschlange nach Bytes, Blöcke ≤ 200/1 MB, 4xx verwerfen, 5xx wiederholen), `marshalEvent` (JSON ohne HTML-Maskierung, damit `&` das Größenbudget nicht sprengt) |
| `proto_http.go` | `http`, `https`, `dockerapi`; `nginxError` (Fehlerseiten wie nginx), Docker-Listen |
| `bait.go` | Köder: `deriveBait` (HMAC aus dem Token, gleich in `hive/bait.go`), `baitFile` (Inhalte für `/.env`, `/.git/config` …), `mysqlNativeMatch`; `Session.Login` setzt `data.bait` |
| `profile.go` | Geräteprofile (`profiles`): Banner und Versionen je Profil; `Manager.prof()`. Leeres Profil = bisheriges Verhalten |
| `proto_other.go` | `ftp` (Schein-Verzeichnis nach Login, keine Datenverbindung), `redis` (`redisInfo` mit Abschnitten, `redisConfigGet`), `mysql` (Thread-ID zählt hoch), `ssh-tarpit`, `raw` |
| `proto_telnet.go` | `telnet`: Login (`telnetAccept`: drittes verschiedenes Werkspasswort je IP gilt), Schein-Shell (`telnetReply`), `telnetReadLine` entfernt IAC-Folgen (maskiertes 0xFF zählt zur Zeilenlänge) |
| `proto_smtp.go` | `smtp`: AUTH PLAIN/LOGIN, MAIL/RCPT/DATA; `smtpReadData` begrenzt die Mail |
| `proto_vnc.go` | `vnc`: RFB-Handshake bis zur Challenge/Response |
| `proto_rdp.go` | `rdp`: `readTPKT`, `parseRDPRequest` (Cookie, Protokolle), `rdpConfirm`, `rdpClientInfo` |
| `proto_udp.go` | UDP-Dienste `sip`, `snmp`, `dns`: **`udpHandlers`** (Register der UDP-Dienste, je ein Parser `[]byte -> Event`), `serveUDP` (Empfang, Drossel, nie eine Antwort), `berTLV` für SNMP |
| `honeypot_test.go`, `proto_new_test.go`, `proto_udp_test.go`, `proxy_test.go` | Tests, Fuzz-Ziele, Vertragstests (`TestEventSizeContract`, `TestNewProtocolsSizeBudget`, `TestServiceListsInSync`); gefundene Fuzz-Eingaben liegen als Regressionstests in `testdata/fuzz/` |

Jeder Handler hat die Form `func(*Session)` und kennt drei Modi (`s.Mode`): `emulate` (nachspielen), `tarpit` (sofort `s.Tarpit(...)`), `hybrid` (erst aufzeichnen, dann `s.Tarpit(...)`). Der Handler läuft unter `recover`; Lesefristen setzt er selbst mit `s.ReadDeadline`.

Regeln, die jeder Handler einhalten muss:

1. **Eingaben begrenzen:** nie unbegrenzt lesen (`readLine(br, max)`, `io.ReadFull` mit geprüfter Länge, feste Schleifenzahl).
2. **Ausgaben in Ereignissen begrenzen:** Texte durch `printable(b, budget)` bzw. `pr(s, n)` oder `clip`; nie Rohbytes in `Data`.
3. **Nichts ausführen, nichts schreiben, keine Verbindungen aufbauen.**

## 3. Hive (`hive/`)

| Datei | Inhalt |
|---|---|
| `main.go` | Start, `Hive`-Struktur, `routes()` (alle HTTP-Routen), Server, sauberes Beenden (auch über `Hive.restart` nach einer Wiederherstellung), `applyRestore` (übernimmt `restore.db` beim Start, hebt die alte Datenbank unter `backups/vor-wiederherstellung-…` auf), Unterbefehle `healthcheck`, `backup`, `version` |
| `store.go` | `Event`, `Sanitize`, `migrations`, `OpenStore`, `Writer` (ein Schreiber, Sammeltransaktionen, Duplikaterkennung über `eid`), `topKeys` (Zähltabelle), `Retention`, `Backup` |
| `api.go` | Sensor-Endpunkte (`ingest`, `heartbeat`, `sensorConfig`), Statistik (auch `countryStats` für den Karten-Hover), Ereignisliste (`eventFilter`), Export, Einstellungen des Sensors, `warnings`, `system`, `metrics` |
| `auth.go` | Admin-Konto, Login-Bremse, Sitzungen (nur Hash gespeichert), `Require` (Cookie + CSRF-Header), `RequireSensor` (Token), `uiGuard` (Sensor-Netz aussperren, Host-Prüfung) |
| `sensors.go` | `SensorConfig.Validate`, `knownServices`, Konfiguration je Sensor, `Heartbeat`, `Sensors` |
| `cowrie.go` | `CowrieTail`: liest `cowrie.json` mit Rotation und Wiederaufnahme; `handle` übersetzt Cowrie-Ereignisse |
| `geo.go` | GeoIP (DB-IP Lite), `Enrich`, monatliches Update |
| `sse.go` | `Broker`: Live-Ereignisse an Browser |
| `analyze.go` | **Muster-Analyse:** `patterns` (Regeln), `matchPatterns`, `commandTools`/`eventTools`, `BuildReport`, `timelineLine` (Ablauf für die KI), `Report.Text` |
| `einstufung.go` | **Einstufung an einer Stelle:** `eventKind` (TLS am Klartext-Port, Eingabe an der Login-Abfrage, Protokoll-Abfrage, Protokoll-Befehl, ausgeführter Befehl), `commandExecuted`, `redisChanging`, `probeCommand`, `promptLines`, `requestKey`/`maskSIP` (SIP/DNS-Schlüssel) |
| `abusereport.go` | **Automatische Meldung an AbuseIPDB:** `abuseVerdict` (wann und mit welchen Kategorien), `abuseComment`/`scrubComment` (ohne Passwörter, IPs, Hostnamen), `abuseRound` alle 5 Minuten über die Angriffe der letzten 30 Minuten, `sendAbuseReport` (`POST /api/v2/report`, Kontingent aus `X-RateLimit-*`, Pause bei 429), Protokoll in `kv` (`abuse_report_log`), Abstand je IP in `lookups` (`abuse_report`, `abuse_report_dry`) |
| `bait.go` | Köder-Zugangsdaten wie im Honeypot ableiten, `baitUsed`, `eventPatterns` (Muster plus `bait_used`) |
| `tlsfp.go` | `parseClientHello`, JA3 und JA4 (TLS-Client, FoxIO-Spezifikation), `headerFingerprint`, `eventFingerprints` |
| `cve.go` | `cveRules` (CVE je Web-Anfrage), `patternMitre`/`mitreNames` (MITRE ATT&CK je Muster) |
| `campaigns.go` | Kampagnen über gleiche Zugangsdatenlisten und Nachlade-Hosts (Union-Find), gleiche Fingerabdrücke; `GET /api/campaigns` |
| `chain.go` | Angriffskette: Knoten je Phase, Kanten (Reihenfolge je Sitzung, Herkunft von Adressen); `GET /api/chain?ip=…|session=…` |
| `botverify.go` | Suchmaschinen-Bots per Rückwärts- und Vorwärtsauflösung prüfen (Hintergrund, 2/s, `lookups`/`rdns`) |
| `abusech.go` | URLhaus und MalwareBazaar auf Knopfdruck (`GET /api/lookup/urlhaus`, `/api/lookup/malwarebazaar`) |
| `weekly.go` | ungewöhnliche Zugangsdaten (`rareCred`), Wochenbericht (`runWeekly`, `GET /api/weekly`) |
| `scanner.go` | Forschungsscanner (Shodan, Censys …) am AS-Namen und User-Agent erkennen: `researchScanner` |
| `ownnet.go` | Eigene Netze (`OwnNets` in den Extras): `isOwnIP`, `ownHidden`; der Writer schreibt eigene Tests nur nach `events`, Notifier und `/api/attacks` blenden sie aus |
| `probe.go` | Prüft auf dem Pi die Cowrie-Ports (`HIVE_COWRIE_PROBE`), Hinweis aus dem Journal; `listenerWarnings` für Honeypot-Ports mit Fehler |
| `deobf.go` | Verschleierung aufdecken: `revealHidden` (Base64 auch verschachtelt, Hex-/Oktal-Escapes, URL-Kodierung; nur lesbarer Text), `analysisText`, `matchAll` (Muster auch im Klartext, Muster `obfuscation`), `allURLs` |
| `attacks.go` | `/api/attacks`: bündelt Ereignisse einer IP zu Angriffen (Lücke unter `attackGap` = 15 Min), `Attack` mit Zählern, Zugangsdaten, Pfaden, Befehlen, Mustern, Zeitstreifen, Stufe (0 Abtasten … 4 Download) und vermuteter Art (`classify`); liest höchstens `attackScanMax` Ereignisse. `/api/stats/series`: Verläufe und Vorperiode für die Kennzahlen |
| `report.go` | `/api/report`, KI-Auswertung (`askAI`, `reportAI`), AbuseIPDB (`intel`), `loadEvents` |
| `notify.go` | `Notifier` (ntfy, Telegram, Webhook; Abklingzeit, Stundenlimit), `webhookBody` (Felder der Meldung plus `content` für Discord), `watchWarnings`, Testnachricht |
| `extras.go` | `Extras` (Standort, Benachrichtigungen, KI, AbuseIPDB, GreyNoise), Geheimnis-Behandlung (`secretFields`), Tabelle `lookups` |
| `tty.go` | `parseTTYLog`, `ttyClean`, `/api/sessions/{id}/tty` |
| `users.go` | Benutzerverwaltung (`usersList`, `usersCreate`, `usersDelete`); Rollen `admin` und `viewer`, Regeln in `viewerAllowed` (auth.go) |
| `intel2.go` | GreyNoise-Abfrage (`greynoise`), STIX-2.1-Export (`exportSTIX`, `stixID`, `stixString`) |
| `setup.go` | Ersteinrichtung (`setupStatus`, `setupRun`), einmalige Port-Anpassung (`upgradeSensorConfigs`), Update-Prüfung gegen GitHub (`checkUpdates` zweimal täglich, `runUpdateCheck`, `newestRelease`; Versionsvergleich `parseSemver`/`newer`/`comparePre` nach Semantic Versioning), Update-Kanal (`updateChannel`, `updateSetChannel`: `stable` oder `pre`), „Jetzt prüfen“ (`updateCheckNow`, höchstens alle 10 s), Update-Auslösung (`updateRun`), Muster-Nachzählen (`backfillPatterns`) |
| `pilogs.go` | Nur Raspberry Pi: Seite Protokolle (`logsList`, `logsGet`: `journalctl` für eine feste Liste von Diensten, Installationsprotokoll als Datei) und Stand der Cowrie-Installation (`cowrieInstallStatus`) |
| `backup.go` | Sicherung über die UI: `backupExport` (Passwort prüfen, `VACUUM INTO`, `prepareSnapshot` entfernt Sitzungen und Cowrie-Lesestand), `writeBackup`/`readBackup` (gzip, AES-256-GCM in 1-MiB-Blöcken, Schlüssel per Argon2id, Kopf als Zusatzdaten), `backupImport` (Multipart: zuerst `password`, dann `file`; `checkRestoreDB`, legt `restore.db` ab, startet neu) |
| `disk_linux.go`, `disk_other.go` | freier Speicher |
| `hive_test.go`, `extra_test.go`, `pilogs_test.go`, `backup_test.go` | Tests |

### Weg eines Ereignisses

1. `ingest` (oder `CowrieTail.handle`) erzeugt ein `Event`. Geo-Felder vom Sensor werden verworfen.
2. `Event.Sanitize` prüft IP und Typ (`validTypes`), kürzt Felder, kürzt `data` über 16 KB feldweise.
3. `Geo.Enrich` setzt Land, Stadt, Koordinaten, ASN.
4. `Writer.Submit` verwirft Duplikate (`eid`) und stellt ein; ist die Warteschlange voll, bekommt der Sensor 503 und sendet später erneut.
5. `Writer.writeBatch` schreibt in einer Transaktion nach `events`, `hourly`, `attackers` und `top_hourly` (über `topKeys`, inklusive Muster, Werkzeuge, Adressen).
6. Nach dem Commit ruft der Writer `pub` auf: `Broker.Publish` (Live-Strom der UI) und `Notifier.OnEvent`.

### HTTP-Routen (alle in `Hive.routes`)

Sensor-API (Token, Port 8089): `POST /api/ingest`, `POST /api/sensor/heartbeat`, `GET /api/sensor/config`.

Web-UI (Sitzungs-Cookie; schreibende Aufrufe brauchen den Header `X-Requested-With: hivornet`; Benutzer mit Rolle `viewer` dürfen nur lesen, siehe `viewerAllowed` in `auth.go`):

| Route | Zweck |
|---|---|
| `POST /api/login`, `POST /api/logout`, `GET /api/me`, `POST /api/password` | Anmeldung (`me` liefert auch Rolle und Update-Hinweis) |
| `GET/POST /api/setup` | Ersteinrichtung, ohne Anmeldung, nur solange kein Konto existiert |
| `GET/POST /api/users`, `DELETE /api/users/{name}` | Benutzerverwaltung (nur Admin) |
| `POST /api/update` | Update anstoßen (nur wo `HIVE_UPDATE_REQUEST` gesetzt ist) |
| `POST /api/update/check`, `PUT /api/update/channel` | sofort bei GitHub prüfen; Update-Kanal setzen (`stable`, `pre`) |
| `GET /api/logs`, `GET /api/logs/{id}?lines=…` | Protokoll-Quellen und Inhalt (nur Pi mit `HIVE_JOURNAL=1`, nur Admin) |
| `POST /api/backup/export`, `POST /api/backup/import` | verschlüsselte Sicherung herunterladen bzw. einspielen (nur Admin, Passwort nötig) |
| `GET /api/stats/summary`, `/timeline`, `/top?field=…`, `/map`, `/countries?today_from=…` | Kennzahlen (`countries`: Angriffe je Land heute und gesamt); `field`: `country`, `port`, `ip`, `asn`, `service`, `username`, `password`, `cred`, `command`, `path`, `useragent`, `client`, `tag`, `tool`, `url` |
| `GET /api/events` | Liste; Filter `service`, `type`, `country`, `session`, `src_ip`, `sensor`, `dst_port`, `from`/`to` (ms), `q`, `range`, `hide_noise`, `before`, `limit` |
| `GET /api/attacks` | Angriffe, neueste Aktivität zuerst; `range` (`1h`, `24h`, `7d`, `30d`, `90d`, `all` = Aufbewahrung), `active=1` (letzte 15 Min), `ip=a,b` (Live-Aktualisierung), `stufe=…`, `service`, `success=1`, `q`, `before` (ms), `limit`; liefert dazu `stufen` (Anzahl je Stufe), `matched`, `truncated` (mehr als 500.000 Ereignisse: nur die neuesten gelesen) |
| `GET /api/stats/live` | Live-Anzeige der Kopfleiste: `active` (IPs mit Ereignis in den letzten 15 Min), `tarpits` |
| `GET /api/stats/series` | Verläufe je Kennzahl (`connect`, `ips`, `login`, `request`, `command`, `download`, `success`), Summen und Summen des Zeitraums davor, `active_tarpits` |
| `GET /api/export/events`, `/api/export/blocklist`, `/api/export/stix` | Export (CSV/JSON, Blockliste, STIX 2.1) |
| `GET /api/stream` | Live-Ereignisse (SSE) |
| `GET /api/attackers/{ip}`, `…/intel`, `…/greynoise` | Angreifer, AbuseIPDB, GreyNoise |
| `GET /api/sessions`, `/api/sessions/{id}`, `/api/sessions/{id}/tty` | Sitzungen, Mitschnitt |
| `GET /api/report?ip=…` oder `?session=…` (`&format=text`), `POST /api/report/ai` | Angriffsbericht, KI-Auswertung |
| `GET/PUT /api/settings` | Sensor-Konfiguration, Aufbewahrung |
| `GET/PUT /api/extras`, `POST /api/extras/test-notify` | Zusatzfunktionen |
| `GET /api/campaigns`, `GET /api/chain`, `GET /api/weekly` | Kampagnen, Angriffskette, Vorschau des Wochenberichts |
| `GET /api/lookup/urlhaus?url=…`, `GET /api/lookup/malwarebazaar?hash=…` | abuse.ch auf Knopfdruck (nur Adressen und Hashes aus den eigenen Daten) |
| `GET /api/abuse/log` | Protokoll der AbuseIPDB-Meldungen, Kontingent, letzter Fehler (nur Admin) |
| `GET /api/tarpit`, `GET /api/system`, `GET /healthz`, `GET /metrics` | Tarpit (mit `held`: gerade festgehaltene Verbindungen aus den Lebenszeichen, Herkunft aus `attackers`), System, Überwachung |

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
| `lookups` | `subject`, `source` | `subject` = `ip:<IP>` oder `session:<ID>`; `source` = `abuseipdb`, `greynoise`, `ai`, `abuse_report`, `abuse_report_dry` (letzte Meldung); `data` = JSON bzw. Text | Frist |
| `kv` | `k` | `sensor_config`, `sensor_config:<name>`, `retention_days`, `cowrie_state`, `cowrie_offset`, `extras`, `update_channel`, `config_level`, `patterns_backfilled` | bleibt |
| `users`, `auth_sessions` | | Konten mit Rolle (bcrypt), Sitzungen (SHA-256 des Tokens). Sitzungen gelöschter Benutzer gelten nicht mehr (JOIN in `Auth.Who`) | Sitzungen 7 Tage |

`top_hourly.field`: `country`, `port`, `ip`, `asn`, `service`, `geo` (Karte, Schlüssel „Breite,Länge“), `username`, `password`, `cred`, `command`, `path`, `useragent`, `client`, `tag` (Muster-ID, `label` = Name), `tool`, `url`, `snmp` (Community-String), `sip` (Methode und Adresse, IP ersetzt), `dns` (Typ und Name). Eigene Tests (`ownnet.go`) werden nicht gezählt. Ab 0.5.3 zählt `recountTop` (setup.go) die Felder aus Logins, Befehlen und Anfragen einmal neu (Merker `top_recounted_053`).

## 5. Web-UI (`hive/web/`)

Reines JavaScript in ES-Modulen, kein Build-Schritt, per `go:embed` im Binary (in der Entwicklung mit `HIVE_WEB_DIR` vom Datenträger).

| Datei | Inhalt |
|---|---|
| `index.html`, `style.css`, `favicon.svg` | Rahmen; Farben als CSS-Variablen für Hell und Dunkel; Logo (Schild mit Stachel) |
| `flags.woff2` | Schrift „Twemoji Country Flags“, damit Flaggen-Emojis auch unter Windows erscheinen |
| `dom.js` | `h()` baut Elemente und fügt Texte **immer als Textknoten** ein (`safeText` ersetzt Steuerzeichen); `api()`, Formatierung, Tooltip (`hideTip`), `flag(cc)`, `store()` (Präfix `hv.`) |
| `charts.js` | `worldMap` (Länder nach Anzahl eingefärbt, Orte als Punkte, Zoom per Mausrad, Verschieben, `REGIONS`, Umschalter Länder/Orte/Beides in `controls`; Hover mit Flagge, Name und Angriffen; `attack()` zeichnet die Angriffslinie), `sparkline`, `timeline`, `toplist`, `svcName`, `svcColor` |
| `attacks.js` | Seite „Angriffe“ (`viewAttacks`), Karte je Angriff (`attackCard`), Zeile für „Gerade aktiv“ (`attackRow`), `liveAttacks` (sammelt IPs aus dem Live-Strom und holt alle 2 s deren Angriffe), Umschalter zur Einzelansicht |
| `world.js` | Landumrisse (`COUNTRIES`) und deutsche Ländernamen (`COUNTRY_NAMES`), erzeugt von `tools/build_world.py`; Länder über der Datumsgrenze sind abgewickelt |
| `app.js` | Anmeldung, Live-Stream, Kopfleiste mit Navigation und Benutzermenü, Router (`routes`, `route()`), Ansichten Dashboard (`viewDashboard`), Einzelne Ereignisse (`viewFeed`, fasst Wiederholungen zusammen), Sitzungen, Angreifer, Zugangsdaten, Tarpit, Einstellungen, System (mit `updateCard`), Protokolle (`viewLogs`, nur Pi) |
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
| `HIVE_ALLOWED_HOSTS`, `HIVE_COOKIE_SECURE` | leer, `0` | Host-Prüfung (ergänzt um die Liste aus der Web-UI), Cookie immer nur über HTTPS (sonst automatisch bei HTTPS-Anmeldung) |
| `HIVE_DB`, `HIVE_GEOIP_DIR`, `HIVE_GEOIP` | `/data/hive.db`, `/data/geoip`, `on` | Speicherorte; `off` schaltet den GeoIP-Download ab |
| `HIVE_RETENTION_DAYS`, `HIVE_MAX_DB_MB`, `HIVE_MIN_FREE_MB` | 30, 2048, 1024 | Aufbewahrung |
| `HIVE_FLUSH_MS` | 300 | Schreibintervall des Writers (100–60000). Größer schont SD-Karten |
| `HIVE_COWRIE_LOG`, `HIVE_COWRIE_LIB` | leer | Pfad zu `cowrie.json`; Ordner mit `tty/` und `downloads/` |
| `HIVE_COWRIE_INSTALL_STATUS` | leer | Stand der Cowrie-Installation (Pi, von `hivornet-cowrie-install` geschrieben) |
| `HIVE_JOURNAL`, `HIVE_INSTALL_LOG` | leer | `1` schaltet die Seite Protokolle frei (Pi; braucht die Gruppe `systemd-journal`); Pfad zum Installationsprotokoll des ersten Starts |
| `SENSOR_NAME`, `COWRIE_SENSOR_NAME` | `sensor-1` | Sensorname für Cowrie-Ereignisse |
| `HIVE_METRICS_TOKEN` | leer | schaltet `/metrics` frei |
| `HIVE_UPDATE_CHECK` | `on` | `off` schaltet die Prüfung auf neue Versionen bei GitHub ab (Entwicklungsversionen ohne Versionsnummer prüfen nie) |
| `HIVE_UPDATE_REQUEST` | leer | Datei, in die der Hive eine Update-Anforderung legt; nur gesetzt, wo ein Updater läuft (Pi-Image). Fehlt sie, gibt es keinen Update-Knopf |
| `HIVE_UPDATE_STATUS` | leer | Datei, aus der das Ergebnis des letzten Updates gelesen wird (vom Updater geschrieben) |
| `HIVE_DIRECT_PORTS` | leer | `1`: Honeypot lauscht ohne Docker direkt auf den echten Ports; die Einstellungen zeigen „direkt am Gerät" statt der NAS-Portzuordnung |
| `HIVE_COWRIE_PROBE` | auf dem Pi `ssh=127.0.0.1:22,telnet=127.0.0.1:23`, sonst aus | Cowrie-Ports, die der Hive jede Minute prüft; `off` schaltet ab |
| `HIVE_WEB_DIR` | leer | UI vom Datenträger statt aus dem Binary (Entwicklung) |
| `PORT_*` | | nur zur Anzeige „Öffentlich“ in den Einstellungen (`publishedPorts` in `api.go`) |

In der UI gespeichert (Tabelle `kv`): Sensor-Konfiguration, Aufbewahrung, Update-Kanal, **Zusatzfunktionen** (`extras`: Standort, Benachrichtigungen, KI, Schlüssel für AbuseIPDB und GreyNoise), sowie die Merker `config_level` (Port-Anpassung lief) und `patterns_backfilled` (Muster nachgezählt). Geheimnisse darin liefert die API nie zurück.

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

In `Notifier.Send` (`hive/notify.go`) einen weiteren Block nach dem Muster von ntfy anlegen, Felder in `NotifyConfig` (`extras.go`) ergänzen, Geheimnisse in `secretFields` eintragen, Eingabefelder in `extrasCards` (`extra.js`) und das Geheimnis in deren `body()` mitschicken (`TestExtrasSecretsSentByUI` prüft das).

### Schemaänderung

SQL an `migrations` anhängen, Tabelle in Abschnitt 4 ergänzen, Test nach dem Muster `TestMigrationFromV01` bzw. `TestMigrationCreatesLookups`.

## 7a. Raspberry-Pi-Image (`pi/`)

Betrieb ohne Docker: zwei systemd-Dienste statt Container, sonst dieselben Programme.

| Datei | Zweck |
|---|---|
| `pi/build_image.py` | baut das Image: lädt das festgelegte Raspberry Pi OS Lite (Adresse und Prüfsumme in `BASE`), packt Programme und `pi/rootfs/` als `payload.tar.gz` (Rechte root, Skripte 0755) und schreibt es mit `user-data`, `vendor-data`, `userconf.txt` und `install.sh` in die **FAT-Bootpartition** (pyfatfs). Die Linux-Partition bleibt unberührt; deshalb kein Root und kein Linux nötig |
| `pi/install.sh` | läuft beim ersten Start über cloud-init (`vendor-data` und `runcmd`; der zweite Anstoß prüft nur noch den Merker), genau einmal (`flock`, Merker `/var/lib/hivornet-installed`): Paket prüfen und entpacken, Benutzer anlegen, Token, SSH maskieren, Hostname `hivornet`, Dienste starten, Paket von der Bootpartition löschen. Protokoll `/var/log/hivornet-install.log` |
| `pi/rootfs/etc/systemd/system/hivornet-hive.service` | Hive als Benutzer `hivornet-hive`, gehärtet, `HIVE_DIRECT_PORTS=1`, SD-schonend; Gruppe `systemd-journal` nur zum Lesen der Protokolle (`HIVE_JOURNAL=1`) |
| `pi/rootfs/etc/systemd/system/hivornet-honeypot.service` | Honeypot als Benutzer `hivornet-pot`, nur `CAP_NET_BIND_SERVICE`, lauscht direkt auf den echten Ports; startet nur mit aktiver Netzsperre (`Requires=hivornet-firewall.service`) |
| `pi/rootfs/.../hivornet-firstboot` | erzeugt beim ersten Start das Token (Passwort kommt aus der UI-Ersteinrichtung) |
| `pi/rootfs/.../hivornet-firewall` | Netzsperre nach Benutzer für `hivornet-pot` und `hivornet-cowrie` (nftables oder iptables, owner-Match); getestet mit Ersatzbefehlen in `pi/test_firewall.sh` |
| `pi/rootfs/.../hivornet-update{.path,.service,script}` | beobachtet die Update-Anforderung des Hive, lädt die Version von GitHub, prüft `SHA256SUMS`, tauscht die Programme, Rückfall auf die alte Version |
| `pi/rootfs/etc/hivornet/honeypot.yml` | Startkonfiguration mit echten Ports; 22 und 23 gehören Cowrie |
| `pi/rootfs/etc/hivornet/cowrie.cfg` | Cowrie-Einstellungen: absolute Pfade unter `/var/lib/hivornet-cowrie`, Ports 22/23, Download-Grenze |
| `pi/rootfs/usr/local/sbin/hivornet-cowrie-install` | installiert Cowrie beim ersten Start mit Internet (Version und Prüfsumme fest), Wiederholung stündlich über `hivornet-cowrie-install.timer`; schreibt seinen Stand nach `/var/lib/hivornet-status/cowrie-install` (Zeile 1 `running`/`ok`/`failed`, Zeile 2 Unix-Zeit, Zeile 3 Schritt bzw. Fehler). In der CI getestet mit `pi/test_cowrie_install.sh` (Debian 13) |
| `pi/rootfs/.../hivornet-cowrie-keycheck` | `ExecStartPre` von `hivornet-cowrie.service` (Benutzer `hivornet-cowrie`): entfernt leere oder beschädigte SSH-Host-Schlüssel unter `state_path`, damit Cowrie sie neu erzeugt (sonst `BadKeyError`, Port 22 bleibt zu) |
| `hivornet-cowrie.service`, `hivornet-cowrie-clean.timer` | Cowrie als Benutzer `hivornet-cowrie` mit `CAP_NET_BIND_SERVICE`, nur mit aktiver Netzsperre; tägliches Aufräumen nach 14 Tagen |
| `pi/verify_image.py` | prüft ein fertiges Image (Bootpartition, Paketinhalt, Rechte, Prozessortyp je Architektur); läuft im Release-Workflow |

Updates landen über `release.yml` als `hivornet-<tag>-linux-<arch>.tar.gz` mit `SHA256SUMS` in der GitHub-Veröffentlichung; von dort holt sich der Updater die neue Version. Cowrie wird auf dem Pi beim ersten Start nachinstalliert (Python-Umgebung unter `/opt/hivornet/cowrie-env`); die Netzsperre gilt auch für den Benutzer `hivornet-cowrie`. Ein Update über die UI tauscht nur `hive` und `honeypot` aus, damit auch die eingebettete Web-UI. Änderungen an systemd-Dateien, Skripten unter `pi/rootfs/`, `/etc/hivornet` oder der Cowrie-Version brauchen ein neues Image.

Auf dem Pi ist die Konsolen-Anmeldung gesperrt (zufälliges Passwort in `userconf.txt`) und SSH aus. Zur Fehlersuche dient die Seite **Protokolle** der Web-UI.

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

Was nur die CI prüft: `staticcheck`, `govulncheck`, Race-Detector, `shellcheck`, `hadolint`, Docker-Build, die Netzsperre des Pi (`pi/test_firewall.sh`) und die Cowrie-Installation des Pi in Debian 13 (`pi/test_cowrie_install.sh`). Auf dem Windows-Entwicklungsrechner gibt es kein Docker; die Web-UI hat keinen eigenen Syntax-Check und wird im Browser geprüft.
