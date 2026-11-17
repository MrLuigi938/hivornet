# Hivornet – zweites unabhängiges Audit

Stand: 17.11.2026, Arbeitsstand `main` (2582a8d) **plus** alle nicht committeten Änderungen (CHANGELOG „Unveröffentlicht“). Es wurde kein Code geändert. Tests und Fuzzing liefen nur in einer Kopie außerhalb des Repos.

## 1. Kurzfazit

**Ein Ausbruch aus dem Honeypot ist nach dieser Prüfung nicht erkennbar.**

- **Kein Code-Pfad führt Angreifereingaben aus.** Das gilt für ADB, MQTT, PostgreSQL, Ollama, Elasticsearch, Kubernetes und die Antworten vom Sprachmodell. Es wird nichts auf die Platte geschrieben, und keine Ausgabe wird interpretiert.
- **Die Netzsperre auf dem Pi ist dicht.** Der Honeypot darf über nftables bzw. iptables nur `127.0.0.1:8089` neu ansprechen. Systemd verbietet ihm zusätzlich AF_UNIX, und die Capabilities sind auf `CAP_NET_BIND_SERVICE` beschränkt.
- **Die Web-UI ist vor dem Sensor-Netz geschützt** (`uiGuard`).
- **XSS ist durch den Aufbau ausgeschlossen.** Es gibt nur Textknoten, eine strenge CSP und kein `innerHTML`.

Vor einer Veröffentlichung müssen trotzdem einige Punkte behoben werden:

1. **Hoch – Build-Fehler:** Der Honeypot lässt sich für **armv7 (32-Bit-Pi)** nicht mehr bauen. Damit scheitern auch der Release-Workflow und der Docker-Build für `linux/arm/v7`.
2. **Mittel – übernommener Sensor:** Ein übernommener Sensor kann **beliebige IP-Adressen** in die Blockliste und in die AbuseIPDB-Meldungen bringen. Das ist neu relevant, weil die Blockliste jetzt die Firewall im Heimnetz steuert.
3. **Mittel – Geheimnisse für die Leserolle:** Die Leserolle kann über Fehlertexte das **ntfy-Thema bzw. das Webhook-Token** lesen.
4. **Mittel – Docker (Vermutung, bitte prüfen):** Die Netzsperre gilt nur für die Bridge `hv-honeynet`. Über das Netz `ingest` könnte der Honeypot-Container Dienste der NAS selbst erreichen.
5. **Mittel – Last auf dem Pi:** Mehrere neue Auswertungen sind auf großen Datenbanken teuer (`/api/firstseen`, Angriffsfamilien, Probenanalyse). Angemeldete Nutzer, auch die Leserolle, können damit den Pi auslasten.

Alles Weitere ist niedrig oder ein Hinweis.

## 2. Was geprüft wurde

| Bereich | Vorgehen |
|---|---|
| Netzsperre, Härtung | `pi/rootfs/usr/local/sbin/hivornet-firewall`, `tools/firewall.sh`, `docker-compose.yml`, Dockerfiles, alle `hivornet-*`-Units, Root-Hilfsdienste (`hivornet-update`, `hivornet-cowrie-config`, `hivornet-firstboot`) gelesen |
| Neue Parser | `proto_iot.go`, `proto_pg.go`, `proto_api.go`, `mimic.go`, Diff von `proto_http.go`, `proto_telnet.go`, `manager.go`, `session.go` (sniffTLS) Zeile für Zeile gelesen. Eigene Fuzz-Ziele für ADB, MQTT, PostgreSQL, Kubernetes, Elasticsearch und Ollama, je 40 s auf amd64 (in einer Kopie). Gezielter 32-Bit-Test mit `GOARCH=386`. |
| Sprachmodell | `hive/mimic.go`, `honeypot/mimic.go`: Grenzen, Zwischenspeicher, Ausgabeweg, SSRF |
| Hive-Endpunkte | Router `hive/main.go`, `auth.go` (Require, viewerAllowed, RequireSensor, uiGuard), `feed.go`, `sample.go`, `sensortokens.go`, `exposure.go`, `query.go`, `insights.go`, `auswertung.go`, `notify.go`, Ingest |
| Web-UI | alle `hive/web/*.js` auf HTML-Senken, `href`-Ziele, Inline-Handler, CSP |
| Daten/Logik | `store.go` (Migrationen, Sanitize), `setup.go` (Neuzählung), `einstufung.go` |
| Werkzeuge | `go vet` und `go test ./...` in `hive/` und `honeypot/`: grün. Cross-Build `GOOS=linux GOARCH=arm GOARM=7` bzw. `arm64` für beide Module. `-race` war nicht möglich, weil cgo in dieser Umgebung fehlt; Nebenläufigkeit wurde deshalb nur durch Lesen geprüft. |

Nicht geprüft: Cowrie selbst (fremdes Projekt), echte Läufe auf Pi oder NAS, Docker-Netzwerkverhalten zur Laufzeit.

## 3. Befunde nach Schwere

### Hoch

**H1 – Honeypot baut nicht für armv7 (32-Bit-Raspberry-Pi)** – `honeypot/proto_api.go:93`

```go
list = append(list, map[string]any{..., "size": 4920753328, ...})
```

- **Ursache:** Die untypisierte Konstante wird in `map[string]any` zu `int`. Auf 32-Bit-Plattformen läuft sie über.
- **Ergebnis von `GOOS=linux GOARCH=arm GOARM=7 go build`:** `cannot use 4920753328 (untyped int constant) as int value in map literal (overflows)`.
- **Folgen:**
  - `release.yml` baut nacheinander amd64, arm64 und armv7. Bei armv7 bricht er mit `set -e` ab, es entsteht **kein Release**.
  - Der Docker-Build für `linux/arm/v7` in `ci.yml` scheitert.
  - `tools/check.sh` schlägt fehl.
  - Ein 32-Bit-Pi könnte nicht mehr aktualisiert werden.
- `go test` auf amd64 bemerkt das nicht.
- **Behebung:** `int64(4920753328)`. Zusätzlich in der CI ein schneller `GOARCH=arm go vet ./...` neben den Tests.

### Mittel

**M1 – Ein übernommener Sensor steuert Blockliste und AbuseIPDB-Meldungen** – `hive/api.go:127-164`, `hive/feed.go:66-100`, `hive/abusereport.go`

- **Was passiert:** `/api/ingest` übernimmt `src_ip`, Typ und Inhalt jedes Ereignisses vom Sensor. Das ist naturgemäß so. `Sanitize` prüft nur die Form.
- **Wer kann senden:** Jeder mit dem gemeinsamen `HIVORNET_TOKEN` oder einem Sensor-Token.
  - Das gemeinsame Token steht in der Umgebung des Honeypot-Prozesses.
  - Bei einer Codeausführung im Honeypot – genau der Fall, gegen den die Netzsperre schützt – liest der Angreifer es aus `/proc/self/environ`. Die Sensor-API darf er laut Firewall erreichen.
  - Entfernte Sensoren auf einem VPS sind noch exponierter.
- **Szenario:**
  1. Der Angreifer schickt Ereignisse vom Typ `login` und `command` mit `src_ip` = 1.1.1.1, der IP der Bank, des VPN-Anbieters o. Ä.
  2. Diese IPs erreichen Stufe 3 und landen spätestens nach 10 Minuten in `/feed/blocklist.txt`.
  3. Die abonnierende Firewall im Heimnetz sperrt sie. Das ist ein Ausfall im echten Netz.
  4. Mit aktivierter Auto-Meldung meldet der Hive die IPs zusätzlich unter dem AbuseIPDB-Konto des Nutzers.
- **Einordnung:** Kein Ausbruch ins Heimnetz, aber eine Wirkung über die Sperre hinweg.
- **Vorschlag:**
  - Je Sensor-Token ein Schalter „darf Blockliste/AbuseIPDB speisen“. Standard: nur der lokale Sensor.
  - Eine unveränderliche Ausnahmeliste: eigene Netze, gängige DNS-Resolver und CDNs, frei erweiterbar.
  - Eine Obergrenze für neue Einträge je Stunde mit Warnung.
  - In der UI deutlich machen, dass die Blockliste nur so vertrauenswürdig ist wie jeder Sensor.

**M2 – Leserolle sieht ntfy-Thema bzw. Webhook-URL im Fehlertext** – `hive/notify.go:243-249, 210`; Ausgabe über `GET /api/system` (`hive/api.go:827`)

```go
msg := err.Error()
if c.TelegramToken != "" { msg = strings.ReplaceAll(msg, c.TelegramToken, "…") }
```

- **Was passiert:** Bei einem Netzwerkfehler (DNS, Zeitüberschreitung, Zertifikat) enthält `*url.Error` die volle Adresse, etwa `Post "https://ntfy.sh/<geheimes-thema>": dial tcp …`. Der Text landet in `lastErr`.
- **Wer sieht es:** `/api/system` ist für die Leserolle freigegeben (`viewerAllowed` sperrt es nicht).
- **Warum das zählt:** `viewerAllowed` sperrt `/api/extras` ausdrücklich, weil das ntfy-Thema ein Geheimnis ist. Über diesen Umweg wird es trotzdem sichtbar, ebenso das Token im Pfad eines Discord- oder Slack-Webhooks.
- **Folge:** Ein Viewer kann Meldungen mitlesen oder fälschen.
- **Behebung:** Bei `*url.Error` nur `.Op` und `.Err` ausgeben, oder NtfyURL und WebhookURL genauso schwärzen wie das Telegram-Token.
- Gefunden von der XSS/Leserollen-Teilprüfung, im Code nachvollzogen.

**M3 – Docker: Die Netzsperre deckt das Netz `ingest` nicht ab** (*Vermutung, zur Laufzeit nicht geprüft*) – `docker-compose.yml` (Netz `ingest`), `tools/firewall.sh:52-56`

- **Ausgangslage:** Der Honeypot-Container hängt an `honeynet` und an `ingest` (`internal: true`). `tools/firewall.sh` sperrt FORWARD und INPUT nur für `-i hv-honeynet`.
- **Schutz nach außen:** `internal: true` verhindert Weiterleitung ins Internet und ins LAN.
- **Lücke:** Je nach Docker-Version trägt die Bridge des internen Netzes auf dem Host trotzdem die Gateway-Adresse (hier 172.30.250.1). Für Pakete an den Host selbst greift dann nur INPUT, und dafür gibt es keine Regel.
- **Folge:** Ein übernommener Honeypot-Container könnte SSH, Weboberfläche oder SMB der NAS über 172.30.250.1 erreichen. Der Pi-Betrieb ist nicht betroffen.
- **Prüfen:**
  - `docker network inspect hivornet_ingest`, Gateway-Eintrag und `ip addr` der Bridge.
  - `docker run --rm --network hivornet_ingest busybox nc -zv 172.30.250.1 22`.
- **Behebung:**
  - In `firewall.sh` zusätzlich `iptables -I INPUT -s 172.30.250.0/24 ! -d 172.30.250.2 -j DROP`. Besser: alles aus dem Subnetz zum Host verwerfen; der Hive ist ein Container und wird nicht über INPUT erreicht.
  - Alternativ dem Netz einen festen Bridge-Namen geben (`com.docker.network.bridge.name: hv-ingest`) und wie `hv-honeynet` behandeln.

**M4 – Teure Auswertungen ohne Schutz gegen Mehrfachlast** (Pi mit 1 GB, Hive `MemoryMax=384M`)

- **a) `/api/firstseen`** – `hive/insights.go:371`
  - **Problem:** Die Zeitgrenze steht nur in `HAVING`. Je Feld (12×) wird also die ganze Laufzeit von `top_hourly` gruppiert, ohne Zwischenspeicher.
  - **Folge:** Bei Monaten Daten dauert das Sekunden; nach 20 s gibt es einen 500er.
  - **Behebung:** Eine Tabelle `first_seen(field,key,hour)` beim Zählen pflegen, oder `NOT EXISTS` mit einem Index `(field,key,hour)`. Dazu das Ergebnis zwischenspeichern.
- **b) Angriffsfamilien** – `hive/insights.go:112-126`
  - **Problem:** Jaccard gegen alle bisherigen Familien ist O(N·F). Bei vielen verschiedenen Befehlsfolgen wird daraus fast O(N²). Der ctx wird in der Schleife nicht geprüft, und es gibt kein „nur einmal gleichzeitig“.
  - **Folge:** Zwei offene Tabs oder ein Zeitraumwechsel rechnen doppelt.
  - **Behebung:** `singleflight`, Obergrenze für Familien, ctx-Prüfung, Zwischenspeicher je Zeitraum.
- **c) `/api/sample`** – `hive/sample.go:154-190`
  - **Problem:** Je Aufruf werden bis zu 16 MB gelesen, dazu kommen eine ebenso große Zeichenkette (`strings.Join`) und `matchPatterns` über bis zu 50.000 Zeichenketten. Das sind grob 40–60 MB und viel CPU. Es gibt keinen Zwischenspeicher und keine Begrenzung der Gleichzeitigkeit; die Leserolle darf aufrufen.
  - **Folge:** Ein Dutzend paralleler Aufrufe reicht für den OOM-Kill des Hive.
  - **Behebung:**
    - Ergebnis je Hash in `lookups` speichern; die Datei ändert sich nie.
    - Semaphore mit 1 gleichzeitigen Aufruf.
    - Kein `Join` über alles, sondern blockweise arbeiten.

### Niedrig

**N1 – ADB: Panic auf 32-Bit bei `SEND` mit großer Länge** – `honeypot/proto_iot.go:172-173`

```go
n := int(binary.LittleEndian.Uint32(m.data[4:8]))
path := string(m.data[8:min(len(m.data), 8+n)])
```

- **Fehler:** Auf armv7 wird `n` bei Werten ≥ 2³¹ negativ, `8+n < 8`, und es folgt `slice bounds out of range [8:7]`. Nachgewiesen mit `GOARCH=386` und einem eigenen Test (nach lokaler Korrektur von H1 in der Kopie).
- **Folge:** Das `recover` in `Manager.handle` (`manager.go:339`) fängt das ab; nur diese Verbindung endet. Kein Absturz, aber ein Fehlerprotokoll je Paket und ein Erkennungsmerkmal.
- **Behebung:** In `uint32`/`int64` rechnen, z. B. `if n > uint32(len(m.data)-8) { n = … }`.

**N2 – Speicher wird vorab nach Angreiferangabe belegt** – `proto_iot.go:53` (ADB bis 256 KiB), `proto_pg.go:183` (64 KiB), `proto_iot.go:268` (MQTT 64 KiB)

- **Was passiert:** `make([]byte, n)` geschieht, **bevor** Daten kommen.
- **Rechnung:** Je IP sind 48 normale Verbindungen erlaubt (32+16, `limits.go`), insgesamt 4.608. Ein Angreifer mit ~16 IPs (oder einem IPv6-Präfix) belegt mit ADB-Köpfen und langsamem Nachschieben 16 × 48 × 256 KiB ≈ 192 MB. Das ist das `mem_limit` bzw. `MemoryMax` des Honeypots, also OOM-Kill und Neustart.
- **Einordnung:** Nur Verfügbarkeit, kein Ausbruch.
- **Behebung:** `io.ReadFull` in Stücke teilen (`io.CopyN` in einen `bytes.Buffer` mit Obergrenze) oder `adbMaxData` auf 64 KiB senken. Pro IP höchstens wenige gleichzeitige „große“ Nachrichten zulassen.

**N3 – Sprachmodell: Kosten nur pro Stunde begrenzt, Ausgabe nicht kleingehalten** – `hive/mimic.go:203` (`max_tokens: 2000`), `validate` (bis 5000/h)

- **Kosten:** Mit den Standardwerten (120/h) sind bis zu 2.880 Aufrufe am Tag möglich. Bei Prompt-Injection wie „gib 500 Zeilen aus“ geht jeder bis 2.000 Ausgabe-Token. Mit einem teuren Modell bei OpenRouter ergibt das spürbare Tageskosten, die ein Angreifer bewusst auslösen kann, indem er die Eingabe variiert und so den Zwischenspeicher umgeht.
- **Ausgaben:** Die Modellausgaben gehen **nur** an den Angreifer zurück. Sie werden nicht ausgeführt und nicht in Ereignissen gespeichert. Auch die UI zeigt sie nicht; sie zeigt nur die Eingabe in `recent`, als Textknoten.
- **Behebung:**
  - Tageslimit bzw. Budget zusätzlich zum Stundenlimit.
  - `max_tokens` 600 für die Shell und 1.500 für Web.
  - Gleichzeitige Modellaufrufe begrenzen (Semaphore).
- **Proxy-Missbrauch:** Ein übernommener Honeypot kann `/api/sensor/mimic` als (gedrosselten) Proxy zum Modell des Nutzers verwenden. Die Grenze je IP lässt sich mit erfundenen `ip`-Werten umgehen; nur die Gesamtgrenze greift.

**N4 – Sprachmodell (Web): Content-Type ungefiltert in die Kopfzeile** – `hive/mimic.go:243-246` → `honeypot/proto_http.go:239`

- **Was passiert:** `parseWebOut` prüft nur den Präfix (`text/` …) und kürzt auf 80 Zeichen. CR/LF bleiben erhalten. `writeHTTP` schreibt den Wert roh in die Kopfzeile.
- **Folge:** Eine per Prompt-Injection erzeugte Antwort wie `text/html\r\nSet-Cookie: …` spaltet die Antwort, die der Angreifer selbst bekommt. Schaden entsteht keiner. Die Antwort kann aber kaputt und damit als Honeypot erkennbar sein, und sie wird so im Zwischenspeicher auch anderen geliefert.
- **Behebung:** Nur `[a-z0-9/+.;= -]` zulassen oder auf eine feste Liste abbilden.

**N5 – `/api/sample` folgt Symlinks und öffnet beliebige Dateiarten** – `hive/sample.go:158`

- **Was passiert:** `os.Open` folgt einem Symlink unter `downloads/`.
- **Szenario:** Ein Angreifer, der **Cowrie selbst** übernimmt (Benutzer `hivornet-cowrie`), legt einen Symlink `<sha256>` an. Er zeigt auf eine Datei, die der Hive lesen darf, oder auf ein FIFO. Die Folgen:
  - URLs und IPs aus dieser Datei erscheinen in der UI.
  - Ein FIFO lässt den Handler hängen.
- **Einordnung:** Setzt einen Cowrie-Ausbruch voraus.
- **Behebung:** `os.Lstat` und nur reguläre Dateien zulassen, bzw. `O_NOFOLLOW|O_NONBLOCK`.

**N6 – Einstufung: Jeder POST an Ollama/Elasticsearch/Kubernetes gilt als „Befehl ausgeführt“** – `hive/einstufung.go:88-91`

- **Was passiert:** Der Kommentar sagt „nie reine Abfragen“. Tatsächlich melden die API-Handler jeden POST/PUT/DELETE als Befehl:
  - `elasticCommand`: auch `POST /_search`
  - `ollamaCommand`: unbekannte Pfade und `/api/show`
  - `k8sCommand`: alles außer GET
- **Folge:** Ein Webscanner mit `POST /cgi-bin/…` auf Port 9200 landet in Stufe 3. Auf Port 80 wäre es Stufe 0–1. Das verfälscht Kennzahlen, Benachrichtigungen und die Mindeststufe der Blockliste.
- **Behebung:** Nur bekannte wirksame Präfixe (`exec `, `run `, `create pod`, `prompt `, `pull`, `push`, `create`, `copy`, `delete`, schreibende ES-Pfade) als Befehl werten, den Rest als Protokoll-Befehl.

**N7 – Neuzählung kann sich bei einem Lesefehler als fertig markieren** – `hive/setup.go:552-569` (ebenso `backfillPatterns` :462-481)

- **Was passiert:** `rows.Err()` wird nicht geprüft, und Scan-Fehler werden mit `continue` übergangen.
- **Folge:** Liefert die erste Abfrage wegen SQLITE_BUSY oder eines E/A-Fehlers keine Zeilen, wird `recountKey` gesetzt. Die Top-Listen bleiben dauerhaft unvollständig.
- **Behebung:** Bei `rows.Err()` bzw. einem Scan-Fehler abbrechen, ohne den Schlüssel zu setzen.

**N8 – Suchsprache** – `hive/query.go`

- **Begriffe ohne Längengrenze** (:82): Ein angemeldeter Nutzer, auch die Leserolle, kann mit `cmd:*a*a*a…` (1.000×) je Angriff Millisekunden und je Anfrage Minuten CPU erzeugen. Behebung: Wert ≤ 200 Zeichen, ≤ 8 `*`.
- **`country:` vergleicht per „enthält“** (:137): `country:de` trifft „Bangladesh“. Behebung: zweistellige Werte exakt mit dem Ländercode vergleichen.
- **Gespeicherte Suchen** (:233-273): Lesen, Ändern und Schreiben laufen ohne Mutex, gleichzeitige POSTs verlieren Einträge.

**N9 – Fehler werden in `auswertung.go` verschluckt** – `hive/auswertung.go:59-117`: Scan- und `rows.Err()`-Fehler werden ignoriert. Bei einer Zeitüberschreitung kommen stillschweigend Nullen oder Teilsummen statt eines Fehlers.

### Hinweise

- **Honeypot-Ports dürfen 8088/8089 belegen** (`hive/sensors.go:52-93`): `Validate` verbietet keine Ports des Hive und auf dem Pi auch nicht die Cowrie-Ports 22/23. Ein versehentlich angelegter Listener auf 8089 könnte beim Neustart des Hive dessen Sensor-Port belegen. Vorschlag: reservierte Ports ablehnen.
- **`ALLOW_DOWNLOADS=1` gilt für alle Container am `hv-honeynet`, nicht nur für Cowrie** (`tools/firewall.sh:47`). Der Kommentar sagt „erlaubt Cowrie“. Damit darf auch der Go-Honeypot auf 80/443 ins Internet. Besser per Quell-IP auf den Cowrie-Container beschränken, oder den Kommentar anpassen.
- **Leserolle verbraucht fremde Kontingente:** `/api/attackers/{ip}/intel`, `/greynoise` und `/api/lookup/*` sind für die Leserolle offen und nutzen die Schlüssel des Admins. Das ist schon länger so; bewusst entscheiden.
- **Updates ohne Signatur und ohne Downgrade-Schutz** (`hivornet-update`): Die Prüfsumme stammt aus derselben Veröffentlichung, und jede gültige Version ist erlaubt. Ein übernommener Hive kann so eine ältere, verwundbare Version anfordern. Vorschlag: nur Versionen ≥ der laufenden zulassen (außer beim Zurückrollen per Konsole); langfristig signierte Releases (minisign/cosign).
- **systemd-Härtung des Honeypots ausbaufähig:** `SystemCallFilter=@system-service`, `MemoryDenyWriteExecute=yes`, `RestrictRealtime=yes`, `ProtectProc=invisible`, `ProcSubset=pid`, `ProtectClock=yes`, `ProtectHostname=yes`, `UMask=077` und `ReadWritePaths=` (leer) würden eine Codeausführung im Go-Prozess weiter einengen. Ob `AF_NETLINK` gebraucht wird, sollte geprüft werden; Go braucht es nur für `net.Interfaces`.
- **Web-UI auf dem Pi auch am eingebauten Anschluss** (`HIVE_LISTEN=:8088`): Die UI ist im Gastnetz für alle Geräte dort erreichbar (Login nötig). Dokumentiert ist „8088 nie weiterleiten“. Optional ließe sich 8088 am eingebauten Anschluss sperren, sobald ein Verwaltungsanschluss existiert.
- **`mimic`-Zwischenspeicher:** Gleichzeitige gleiche Anfragen lösen mehrere Modellaufrufe aus (kein `singleflight`). Das kostet nur wenig.
- **Stichprobe zur Neuzählung beim Update:** Das `DELETE FROM top_hourly WHERE field IN (…)` läuft vor dem Start des Schreibers in einer Transaktion. Bei großen Datenbanken verzögert das den Start. Bis die Neuzählung fertig ist, zeigt „Erstmals gesehen“ alte Werte als neu.
- **`qTokenRe`** (`query.go:34`) kennt nur Kleinbuchstaben. `Service:"zwei worte"` wird deshalb falsch zerlegt. `(?i)` ergänzen.
- **CI:** Ein `innerHTML`-Verbot (grep) für `hive/web/` würde den heute sauberen Stand dauerhaft absichern.

## 4. Antworten auf die Kernfragen

| Frage | Antwort |
|---|---|
| Kann ein Angreifer über einen Honeypot-Dienst Code ausführen? | **Nein.** Kein Handler führt Eingaben aus, ruft Programme auf, lädt etwas nach oder interpretiert Modellausgaben. Speicherfehler sind in Go ausgeschlossen. Panics (siehe N1) beenden nur die Verbindung. |
| Kann er Dateien schreiben? | **Nein.** Docker: `read_only` und nur `tmpfs`. Pi: `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, kein `ReadWritePaths`. |
| Ins Heimnetz oder Internet? | **Pi: nein.** nft/iptables per UID; nur Antworten und `lo:8089`. **Docker:** `hv-honeynet` ist gesperrt; `ingest` ist intern, ein Weg zum NAS-Host über dessen Gateway-Adresse ist aber nicht ausgeschlossen (M3). |
| Sensor-API/Web-UI erreichen? | **Die Sensor-API ja** (gewollt, mit Token). Ein übernommener Honeypot kann damit Ereignisse fälschen (M1) und das Sprachmodell nutzen (N3). **Die Web-UI nein:** `uiGuard` sperrt das Sensor-Netz; auf dem Pi verbietet die Firewall dem Honeypot `:8088`. |
| Gelangen Angreiferdaten als HTML in die UI? | **Nein.** Nur Textknoten (`dom.js`), feste `https://`-Präfixe bzw. `encodeURIComponent` bei Links, CSP ohne `unsafe-inline`. |
| Geheimnisse an die Leserolle? | Bis auf M2 nein. `/api/extras`, `/api/feed`, `/api/sensor-tokens` und `/api/mimic` sind gesperrt. |

## 5. Was gut ist

- **Netzsperre auf dem Pi:** pro UID, mit IPv4 und IPv6 (`inet`-Tabelle). Der Honeypot startet nicht ohne sie (`Requires=`). Der Verwaltungsanschluss ist sauber getrennt, mit Statusdatei für die UI.
- **Root-Hilfsdienste** (`hivornet-update`, `hivornet-cowrie-config`): lesen aus dem Hive-Ordner nur die erste Zeile, lehnen Symlinks ab, prüfen streng per Regex und führen nichts aus. Die Statusdateien liegen in root-eigenen Ordnern.
- **Docker:**
  - `cap_drop: ALL`, `no-new-privileges`, `read_only`, Speicher-, CPU- und PID-Grenzen, distroless `nonroot`, Images per Digest.
  - Der Janitor läuft ohne Netz.
  - Die Web-UI ist standardmäßig an 127.0.0.1 gebunden.
- **Sensor-Tokens:**
  - nur als SHA-256 gespeichert, einmalig angezeigt
  - konstante Vergleichszeit
  - fest an den Namen gebunden (Ingest, Lebenszeichen und Konfiguration übernehmen den gebundenen Namen)
  - höchstens 20 Stück
- **Blockliste:**
  - Token mit 192 Bit, Vergleich in konstanter Zeit, 404 ohne Hinweis
  - eigene und private Netze sind ausgenommen, ebenso Angreifer nur über UDP (fälschbar)
  - Zwischenspeicher mit „nur einmal rechnen“, Obergrenze 100.000
- **Shodan-Abfrage:** Die IP wird geprüft und kanonisiert (`net.ParseIP(...).String()`); private Adressen sind abgelehnt. Antworten sind in Größe und Feldlänge begrenzt. Abfragen gibt es nur per POST mit CSRF-Header als Admin.
- **Probenanalyse:** Der Hash wird streng geprüft (`^[0-9a-f]{64}$`), es gibt kein Pfad-Traversal, und die Datei wird nie ausgeliefert oder ausgeführt.
- **Sprachmodell:**
  - Systemprompt mit klarer Daten/Anweisungs-Trennung
  - Ausgabe gekürzt, Steuerzeichen entfernt (`printableKeepNL`, keine ANSI-Escapes)
  - Grenzen je Stunde und IP
  - Fallback auf statische Antworten
  - Honeypot-seitig 64 KiB Lesegrenze und 13 s Zeitlimit
  - Basis-URL nur durch den Admin einstellbar, also keine SSRF durch Angreifer
- **Neue Parser:**
  - durchgängig Längengrenzen (ADB 256 KiB, MQTT 64 KiB, PG-Startup 10.000 B und Nachrichten 64 KiB, Passwort 4 KiB)
  - Schleifenobergrenzen (300/200/200 Nachrichten), Lese-Deadlines
  - `printable`-Budgets für jedes Ereignisfeld
  - `jsonSafe` für Rückspiegelungen in JSON
  - Der fehlerhaftende `mqttReader` verhindert Out-of-bounds-Lesen.
- **Fuzzing:** Ohne Befund auf amd64 (siehe Anhang).
- **Datenbank:**
  - Alle neuen SQL-Stellen sind parametrisiert. Die Suchsprache läuft nur im Speicher, kein Nutzertext kommt in SQL.
  - Migrationen laufen je in einer Transaktion zusammen mit `user_version` und sind idempotent (`IF NOT EXISTS`).
- **Web-UI:** DOM nur über `h()`/Textknoten. `safeText` entschärft zusätzlich Bidi- und Steuerzeichen. Die CSP ist streng; Downloads mit Angreiferdaten kommen als `attachment` mit nicht-HTML-Typ.
- **Anmeldung:** bcrypt mit Semaphore, Dummy-Hash gegen Timing, Fehlversuchsgrenzen je IP und global. Sitzungstoken werden nur gehasht gespeichert. `SameSite=Strict` plus `X-Requested-With` für schreibende Anfragen, DNS-Rebinding-Schutz über Hostnamen.

## 6. Empfohlene Reihenfolge

1. **H1** (Einzeiler) und ein armv7-`go vet` in der CI.
2. **M2:** Fehlertexte schwärzen.
3. **M3:** in Docker prüfen und ggf. eine INPUT-Regel für das `ingest`-Subnetz ergänzen.
4. **M1:** Vertrauensschalter je Sensor und Ausnahmeliste für die Blockliste und AbuseIPDB.
5. **M4:** Zwischenspeicher und Semaphoren für `/api/sample`, `/api/firstseen` und die Familien.
6. **N1, N2, N4:** kleine Härtungen in den Parsern.
7. **N3:** Tagesbudget und kleineres `max_tokens`.
8. **N5–N9** und die Hinweise.

## Anhang: Fuzzing

Eigene Fuzz-Ziele in einer Kopie von `honeypot/` außerhalb des Repos (Handler direkt ohne `recover`, damit Panics sichtbar werden). Startkorpus: gültige CNXN-, OPEN- und SEND-Pakete, MQTT-5-CONNECT, PostgreSQL-SSLRequest, Kubernetes-`exec` und TLS-Record.

Alle sechs Ziele liefen je 40 Sekunden ohne Panic und ohne Hänger (jeder Durchlauf muss in 3 s enden):

| Ziel | Ausführungen | neue Fälle |
|---|---:|---:|
| ADB | 17.402 | 15 |
| MQTT | 10.981 | 28 |
| PostgreSQL | 20.667 | 43 |
| Kubernetes | 4.569 | 15 |
| Elasticsearch | 6.573 | 10 |
| Ollama | 33.327 | 27 |

Der Durchsatz ist wegen `net.Pipe` und Wartezeiten gering. Das ist eine Stichprobe, kein Beleg für Fehlerfreiheit. Der 32-Bit-Fehler N1 fällt auf amd64 nicht auf und wurde gezielt mit `GOARCH=386` nachgewiesen.

Vorschlag: Die neuen Ziele mit einem 32-Bit-Lauf (`GOARCH=386 go test -run Fuzz…`) in `ci.yml` aufnehmen.

## 7. Umsetzung (17.11.2026, Version 0.7.0-beta.1)

| Befund | Stand |
|---|---|
| H1 armv7-Build | behoben (`int64`); CI prüft `go vet` für armv7 und testet den Honeypot auf 386 |
| M1 gefälschte Ereignisse | behoben: Sensoren mit eigenem Token speisen Blockliste und AbuseIPDB erst nach Freigabe („vertrauen“, Standard aus); öffentliche DNS-Resolver und eine eigene Liste „Nie sperren“ sind immer ausgenommen; höchstens N neue Adressen je Stunde (Standard 300), darüber Zurückhalten mit Systemwarnung (`hive/protect.go`, `feed.go`, `abusereport.go`). Restrisiko: Der lokale Honeypot mit dem gemeinsamen Token kann innerhalb dieser Grenzen weiter fälschen. |
| M2 Fehlertexte | behoben: bei Netzwerkfehlern nur Vorgang und Ursache, Adressen und Pfade geschwärzt |
| M3 Docker `ingest` | behoben (zur Laufzeit ungeprüft): fester Bridge-Name `hv-ingest`, `tools/firewall.sh` sperrt INPUT von dort; `update.sh` legt die Netze bei Bedarf neu an. Nach dem Update `sudo sh tools/firewall.sh` ausführen. |
| M4 Last | behoben: Probenanalyse gespeichert je Hash und nur eine gleichzeitig, Text auf 2 MB begrenzt; „Erstmals gesehen“ 10 Min. gespeichert, Familien 5 Min., beide nie parallel berechnet; Familien höchstens 400, Abbruch bei Zeitüberschreitung |
| N1 ADB 32 Bit | behoben, Test auf 386 |
| N2 Speicher vorab | behoben: `readN` belegt Speicher erst, wenn Daten kommen (ADB, MQTT, PostgreSQL) |
| N3 Kosten Sprachmodell | behoben: Tagesbudget (Standard 1.000), `max_tokens` 600/1.500, höchstens 2 Aufrufe gleichzeitig |
| N4 Content-Type | behoben: feste Liste im Hive, zusätzlich Zeichenprüfung im Honeypot |
| N5 Symlinks | behoben: nur reguläre Dateien (`Lstat` + `SameFile`) |
| N6 Einstufung | behoben: nur wirksame Befehle der APIs zählen als „ausgeführt“ |
| N7 Neuzählung | behoben: Lesefehler brechen ab, ohne als fertig zu markieren |
| N8 Suchsprache | behoben: Längen- und Platzhaltergrenze, Ländercode exakt, Mutex für gespeicherte Suchen, `(?i)` |
| N9 Fehler verschluckt | behoben für die Zugangsdaten-Übersicht |
| Hinweise | umgesetzt: reservierte Ports (8088, 8089, auf dem Pi 22/23), `ALLOW_DOWNLOADS` nur für Cowrie (feste IP), Leserolle ohne Abfragen bei Dritten und ohne Probenanalyse, zusätzliche systemd-Härtung des Honeypots (auf dem Pi ungetestet), CI-Verbot für HTML-Senken. Offen: signierte Updates mit Downgrade-Schutz, 8088 am eingebauten Pi-Anschluss sperren, `singleflight` beim Sprachmodell-Speicher. |
