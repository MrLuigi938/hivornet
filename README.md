# Hivornet

Ein leichtgewichtiges Honeypot-System als Alternative zu T-Pot: viele Protokolle, Angreifer ausbremsen (Tarpit) und Auswertung im Browser. Es läuft mit **3 Containern unter 512 MB RAM** auf einer NAS, einem Raspberry Pi oder einem kleinen Server.

| Container | Aufgabe | RAM (gemessen / Limit) |
|---|---|---|
| `honeypot` | eigener Go-Honeypot: FTP, HTTP, HTTPS, Docker-API, MySQL, Redis, SSH-Tarpit, generische Ports. Jeder Port kann aufzeichnen, ausbremsen oder beides | ca. 15 MB / 192 MB |
| `cowrie` | SSH- und Telnet-Honeypot mit gefälschter Shell (Cowrie 3.1.6) | ca. 80–120 MB / 256 MB |
| `hive` | sammelt alles, ergänzt Land/Stadt/Netzbetreiber, speichert in SQLite und liefert die Web-UI | ca. 20–60 MB / 384 MB |
| `janitor` | räumt alte Cowrie-Logs und Downloads auf (BusyBox, ohne Netzwerk) | < 2 MB / 16 MB |

```
Internet ──> Router-Portweiterleitung ──> NAS
                                          ├─ cowrie   (SSH 22, Telnet 23)  ──cowrie.json (Volume)──┐
                                          └─ honeypot (21, 80, 443, ...)   ──Netz "ingest" :8089───┤
                                                                                                    v
                                Browser im Heimnetz  ──>  hive :8088  (SQLite, GeoIP, Web-UI)
           Netzsperre (tools/firewall.sh): Honeypot-Container dürfen keine neuen Verbindungen aufbauen
```

## Voraussetzungen

- Docker mit Compose v2 (Synology: Paket **Container Manager**, QNAP: **Container Station**, Unraid/TrueNAS: vorhanden)
- 1–2 CPU-Kerne, mindestens 1 GB freier RAM, ca. 3 GB Speicherplatz:
  - GeoIP-Datenbank rund 140 MB
  - Ereignisse höchstens `HIVE_MAX_DB_MB`, Standard 2 GB
- Internetzugang für den Build und das monatliche GeoIP-Update
- Ein Router, in dem du Portweiterleitungen einrichten kannst
- Für die Netzsperre: `iptables` auf dem Host (auf Synology, QNAP und gängigen Linux-Systemen vorhanden)

## Installation

### Variante A: per SSH (empfohlen)

1. Ordner `hivornet` auf die NAS kopieren, z. B. nach `/volume1/docker/hivornet`.
2. Per SSH auf die NAS und dort:
   ```bash
   cd /volume1/docker/hivornet
   sudo sh install.sh
   ```
3. Das Skript:
   - legt `.env` mit zufälligem Token und Admin-Passwort an und bindet die UI an die LAN-IP der NAS;
   - baut die Images und startet alles;
   - entfernt das Startpasswort danach wieder aus `.env`;
   - bietet an, die Netzsperre zu setzen.

   Am Ende zeigt es die Adresse der Web-UI, das Passwort (jetzt notieren) und die nötigen Router-Weiterleitungen.

### Variante B: Synology Container Manager ohne SSH

1. Ordner `hivornet` per File Station nach `/docker/hivornet` hochladen.
2. `.env.example` als `.env` kopieren und darin mindestens drei Werte setzen:
   - `HIVORNET_TOKEN`: lange Zufallszeichenkette
   - `HIVE_ADMIN_PASSWORD`: 10 bis 72 Zeichen
   - `HIVE_BIND`: LAN-IP der NAS
3. Container Manager → **Projekt** → **Erstellen** → Pfad `/docker/hivornet` wählen, die vorhandene `docker-compose.yml` verwenden → Erstellen.
4. Netzsperre einrichten (siehe unten). Ohne SSH geht das über den Aufgabenplaner.

## Netzsperre (Pflicht vor dem Betrieb am Internet)

Ein Honeypot nimmt absichtlich feindlichen Verkehr an. Wird ein Container übernommen, z. B. über eine Lücke in Cowrie, soll der Angreifer von dort **nicht weiterkommen**: nicht ins Heimnetz, nicht zur NAS und nicht ins Internet. Das erledigt `tools/firewall.sh`:

```bash
sudo sh tools/firewall.sh            # setzen
sudo sh tools/firewall.sh status     # anzeigen
sudo sh tools/firewall.sh remove     # entfernen
```

Die Regeln sperren alle **neuen** Verbindungen aus dem Docker-Netz `honeynet` (Bridge `hv-honeynet`). Antworten an Angreifer bleiben erlaubt.

Mit `ALLOW_DOWNLOADS=1` darf Cowrie zusätzlich HTTP/HTTPS ins Internet, nie ins LAN. So bekommst du Schadsoftware-Proben, die Angreifer per `wget` nachladen.

**Nach jedem Neustart der NAS neu setzen:**
- **Synology:** Systemsteuerung → Aufgabenplaner → Erstellen → Ausgelöste Aufgabe → Benutzerdefiniertes Skript, Ereignis „Hochfahren“, Benutzer `root`, Befehl: `sh /volume1/docker/hivornet/tools/firewall.sh`. Da Docker eventuell erst danach startet, zusätzlich eine geplante Aufgabe alle 15 Minuten mit demselben Befehl anlegen; das Skript ist idempotent.
- **Linux mit systemd:** `tools/hivornet-firewall.service` nach `/etc/systemd/system/` kopieren, Pfad anpassen, `sudo systemctl enable --now hivornet-firewall`.

**Kontrolle:** Die Web-UI prüft selbst alle 10 Minuten, ob der Honeypot ins Internet kommt. Unter **System** steht dann „Internet aus dem Container: gesperrt“. Fehlt die Sperre, erscheint eine rote Warnung auf dem Dashboard.

Noch besser ist ein eigenes VLAN oder Gastnetz für die NAS bzw. einen eigenen Pi.

## Router-Portweiterleitung

Die Honeypot-Ports liegen auf der NAS absichtlich auf hohen Nummern, damit sie nicht mit SSH oder der Weboberfläche der NAS kollidieren. Im Router leitest du die **echten** Ports dorthin weiter:

| Extern (Internet) | an NAS-Port | Dienst |
|---|---|---|
| 22 | 10022 | SSH (Cowrie) |
| 23 | 10023 | Telnet (Cowrie) |
| 21 | 10021 | FTP |
| 80 | 10080 | HTTP |
| 443 | 10443 | HTTPS |
| 8080 | 18080 | HTTP (Hybrid) |
| 2375 | 12375 | Docker-API |
| 2222 | 12222 | SSH-Tarpit |
| 3306 | 13306 | MySQL |
| 6379 | 16379 | Redis |
| 5900 | 15900 | Generisch (VNC-Port) |

Du musst nicht alle weiterleiten. Fang ruhig mit 22, 23, 80 und 2222 an.

**Die UI-Ports 8088 und 8089 nie weiterleiten**, und die NAS nie als „Exposed Host“ oder DMZ eintragen. Ist auf deinem Router Port 443 oder 80 schon für etwas anderes belegt (VPN, NAS-Fernzugriff), diese Zeilen weglassen.

## Web-UI

`http://<IP-der-NAS>:8088` im Heimnetz öffnen und mit `admin` und dem Passwort aus der Installation anmelden.

| Ansicht | Inhalt |
|---|---|
| Dashboard | Warnungen, Kennzahlen, Weltkarte mit Live-Angriffen, Verlauf nach Dienst, Top-Länder/Ports/IPs/Netzbetreiber/Zugangsdaten/Befehle |
| Live-Feed | alle Ereignisse in Echtzeit, filterbar; Export als CSV/JSON und Blockliste der Angreifer-IPs |
| Sitzungen | Verbindungen mit Logins oder Befehlen; Cowrie-Sitzungen als Befehlsverlauf |
| Angreifer | alles zu einer IP: Herkunft, Ports, Passwörter, Ereignisse |
| Zugangsdaten | häufigste Benutzernamen, Passwörter, Befehle, HTTP-Pfade, User-Agents, Client-Versionen |
| Tarpit | verschwendete Angreiferzeit, gerade festgehaltene Verbindungen, Spitzenreiter |
| Einstellungen | Ports an/aus, Modus je Port, Tarpit-Tempo, Aufbewahrung, Admin-Passwort; bei mehreren Sensoren je Sensor |
| System | Warnungen, Netzsperre, RAM, Datenbank, GeoIP, Cowrie, Status je Sensor und Port |

Änderungen in den Einstellungen übernimmt der Honeypot **innerhalb von 15 Sekunden ohne Neustart**.

### Modi je Port

- **Aufzeichnen** (`emulate`): spielt den Dienst nach und zeichnet Logins, Befehle und Anfragen auf.
- **Tarpit**: hält die Verbindung sofort fest und sendet alle 10 s ein winziges Datenstück. Das bremst Scanner und Bots aus.
  - Jede gehaltene Verbindung kostet etwa 10–20 KB RAM; höchstens 8.000 gleichzeitig.
  - Standardmäßig wird nach 24 h losgelassen.
- **Hybrid**: zeichnet erst den Login oder die erste Anfrage auf und hält die Verbindung dann fest.

Einen neuen Port in der UI anzulegen genügt nicht ganz: Er muss auch in `docker-compose.yml` unter `honeypot.ports` freigegeben sein. Die Spalte „Öffentlich“ in den Einstellungen zeigt das an.

### Schutz vor Überlastung

Angreifer sollen den Honeypot nicht lahmlegen und die Platte nicht füllen können:
- **Größengrenzen:** HTTP-Kopf 64 KB, Body 64 KB, Redis-Befehl 64 KB, MySQL-Paket 64 KB.
- **Verbindungen:** Limits gesamt, pro IP und pro Port.
- **Drossel:** höchstens 10 Ereignisse pro Sekunde und IP (kurzzeitig 300). Darüber wird nur gezählt.
- **Datenbank:**
  - Aufbewahrung nach Tagen.
  - Höchstgröße `HIVE_MAX_DB_MB` und Mindest-Freiplatz `HIVE_MIN_FREE_MB`; bei Bedarf werden die ältesten Ereignisse vorzeitig gelöscht.
- **Cowrie-Dateien:** werden nach `COWRIE_KEEP_DAYS` gelöscht; Downloads höchstens 10 MB je Datei.

## Testen

Von einem anderen Rechner im Heimnetz (Python 3, keine Zusatzpakete):

```bash
python3 tools/attack_sim.py --host <IP-der-NAS>
```

Das schickt typische Angriffe auf alle Honeypot-Ports: Login-Seiten, Docker-Missbrauch, Redis-Cron-Masche, MySQL-Login, SSH-Tarpit. Danach sieht man sie im Live-Feed (Quelle: deine LAN-IP, Land „LAN“).

Für eine gefüllte Weltkarte ohne echte Angriffe gibt es Demo-Daten. Die Sensor-API ist nur im Docker-Netz erreichbar, deshalb auf der NAS selbst ausführen:

```bash
docker run --rm --network hivornet_ingest -v "$PWD/tools:/t:ro" python:3-alpine \
  python3 /t/attack_sim.py --no-attacks --demo 400 --hive http://hive:8089 --token "$(grep ^HIVORNET_TOKEN= .env | cut -d= -f2)"
```

Demo-Daten landen dauerhaft in der Datenbank, also nur zum Ausprobieren verwenden.

## Sicherheit

Was eingebaut ist:
- **Container ohne Rechte:**
  - Kein Container läuft als Root (Cowrie: UID 999; Go-Dienste: UID 65532).
  - Alle Capabilities sind entzogen (`cap_drop: ALL`, `no-new-privileges`), Dateisysteme nur lesbar, feste Limits für RAM, CPU und Prozesse.
  - Kein Container hat den Docker-Socket oder NAS-Ordner.
  - Alle Images sind per Digest festgelegt.
- **Netztrennung:**
  - Honeypot und Cowrie hängen im Netz `honeynet`, durch die Netzsperre ohne ausgehende Verbindungen.
  - Die Sensor-API des Hive (8089) ist nur im internen Netz `ingest` erreichbar. Die Web-UI (8088) lehnt Anfragen aus diesem Netz ab, und Cowrie hat keinen Weg zum Hive.
- **Was Angreifer erreichen können:**
  - Die Shell in Cowrie ist gefälscht, Angreifer führen nichts wirklich aus.
  - Der Go-Honeypot baut selbst keine Verbindungen nach außen auf; die einzige Ausnahme ist die Prüfung der Netzsperre.
  - Angreiferdaten werden in der UI nie als HTML ausgeführt. Steuerzeichen werden sichtbar ersetzt, CSV-Exporte gegen Formel-Injection geschützt.
- **Web-UI:**
  - Nur an die LAN-IP gebunden.
  - Login mit bcrypt, Sperre nach 10 Fehlversuchen pro IP und 60 pro Minute insgesamt.
  - Sitzungen 7 Tage gültig, in der Datenbank nur als Hash; Passwortwechsel meldet alle anderen Geräte ab.
  - Schutz gegen CSRF und DNS-Rebinding, strenge Content-Security-Policy.
- **Updates:** `sh update.sh` regelmäßig ausführen. Es sichert vorher die Datenbank.

**Cowrie-Downloads:** Dateien, die Angreifer per `wget` laden, landen im Volume `hivornet_cowrie-lib`. Das ist **echte Schadsoftware**, also nicht öffnen, nicht auf andere Rechner kopieren.

Sicherheitslücken bitte wie in [SECURITY.md](SECURITY.md) beschrieben melden.

## Recht und Datenschutz

Kein Ersatz für Rechtsberatung, aber das solltest du wissen:

- **Personenbezogene Daten:** IP-Adressen, Benutzernamen und Passwörter der Angreifer sind nach DSGVO personenbezogen.
  - Rechtsgrundlage ist in der Regel das berechtigte Interesse am Schutz der eigenen Systeme (Art. 6 Abs. 1 lit. f DSGVO).
  - Speichere nur so lange wie nötig. Standard: 30 Tage für Ereignisse **und** Angreifer-IPs (`HIVE_RETENTION_DAYS`); die Stundenstatistik enthält keine IPs.
  - Gib Daten nicht ungeprüft weiter.
  - Exporte und Blocklisten sind ebenfalls personenbezogen.
- **Internetanschluss:** Prüfe die Bedingungen deines Anbieters. Manche untersagen Server-Dienste am Privatanschluss.
- **Haftung:** Wird ein Honeypot übernommen und greift von deinem Anschluss aus andere an, kannst du verantwortlich gemacht werden. Deshalb ist die Netzsperre Pflicht.
- **Schadsoftware:** Gespeicherte Proben nicht weitergeben oder ausführen. Zur Analyse z. B. Hash bei VirusTotal nachschlagen, nicht die Datei hochladen.
- **Nur eigene Systeme testen:** `tools/attack_sim.py` nur gegen die eigene Instanz verwenden.

## Betrieb

```bash
docker compose ps                    # Status (alle Container mit Healthcheck)
docker compose logs -f --tail 50     # Logs
sh update.sh                         # aktualisieren (sichert vorher die Datenbank)
sh tools/backup.sh                   # Datenbank sichern nach ./backups
sh uninstall.sh                      # stoppen, Daten behalten
sh uninstall.sh --purge              # alles inkl. Daten löschen
```

### Backup und Wiederherstellen

`sh tools/backup.sh` erzeugt im laufenden Betrieb eine konsistente Kopie (`VACUUM INTO`) und legt sie unter `./backups/` ab. Lokal bleiben die letzten 14 Sicherungen, im Container die letzten 7.

Wiederherstellen:

```bash
docker compose cp backups/hive-JJJJMMTT-HHMMSS.db hive:/data/restore.db
docker compose restart hive          # der Hive übernimmt restore.db beim Start
```

Auf eine andere Version zurückrollen: `git checkout <Version>`, dann `sh update.sh`. Die Datenbank wird beim Start automatisch auf das passende Schema migriert. Ein Zurückrollen auf eine ältere Version braucht das Backup von vor dem Update.

### Überwachung

- Healthchecks für Hive, Honeypot und Cowrie: `docker compose ps` zeigt `healthy`.
- Warnungen in der UI (Dashboard und System), zum Beispiel:
  - ein Sensor meldet sich nicht;
  - die Netzsperre fehlt;
  - Ereignisse wurden verworfen;
  - der Speicher wird knapp;
  - GeoIP-Download fehlgeschlagen;
  - Cowrie still.
- **Prometheus:** In `.env` `HIVE_METRICS_TOKEN` setzen, dann `GET http://<NAS>:8088/metrics` mit Header `Authorization: Bearer <Token>`.

### UI mit HTTPS (optional)

Die UI spricht nur HTTP und ist für das Heimnetz gedacht. Für HTTPS einen Reverse-Proxy davorsetzen, z. B. den der Synology:
1. Systemsteuerung → Anmeldeportal → Erweitert → Reverse Proxy.
2. Quelle `https://hivornet.nas.lan:8443`, Ziel `http://localhost:8088`.
3. In `.env` setzen:
   - `HIVE_BIND=127.0.0.1`
   - `HIVE_COOKIE_SECURE=1`
   - `HIVE_ALLOWED_HOSTS=hivornet.nas.lan`

## Fehlerbehebung

| Problem | Lösung |
|---|---|
| Alle Angreifer erscheinen mit einer 172.x-IP und „LAN“; Warnung „aus dem eigenen Docker-Netz“ | Docker leitet die Ports über den Userland-Proxy statt per NAT weiter, dabei geht die echte IP verloren. Am besten in der Docker-Konfiguration (`/etc/docker/daemon.json`) `"userland-proxy": false` setzen und Docker neu starten. Notlösung: `network_mode: host` für `honeypot` und `cowrie`. Dann `ports` und `networks` dort entfernen, beim Honeypot `HIVE_URL` auf `http://127.0.0.1:8089` setzen und beim Hive `127.0.0.1:8089:8089` veröffentlichen. Die Netztrennung und die Netzsperre wirken dann nicht mehr. |
| „Port is already allocated“ | Port in `.env` ändern und `docker compose up -d` |
| Warnung „Netzsperre fehlt“ | `sudo sh tools/firewall.sh`; bleibt die Warnung nach 10 Minuten, `sudo sh tools/firewall.sh status` prüfen |
| System: Cowrie-Log „fehlt“ | `COMPOSE_PROFILES=cowrie` in `.env`? Logs prüfen: `docker compose logs cowrie`. Startet Cowrie wegen des schreibgeschützten Dateisystems nicht, in `docker-compose.yml` bei `cowrie` `read_only: false` setzen. |
| GeoIP „Download fehlgeschlagen“ | Der Hive braucht Internet für `download.db-ip.com`. Er versucht es täglich neu. |
| UI meldet „unbekannter Hostname“ | Den Namen, unter dem du die NAS aufrufst, in `HIVE_ALLOWED_HOSTS` eintragen |
| Passwort vergessen | In `.env` `HIVE_ADMIN_PASSWORD` neu setzen und `HIVE_RESET_ADMIN=1`, dann `docker compose up -d hive`. Danach `HIVE_RESET_ADMIN=0` und das Passwort aus `.env` entfernen, noch einmal `docker compose up -d hive`. |

## Entwicklung

```bash
cd hive && go test ./... && go build -o hive . && cd ../honeypot && go test ./... && go build -o honeypot .
# Hive:     HIVE_DB=./data/hive.db HIVORNET_TOKEN=test HIVE_ADMIN_PASSWORD=testpasswort1 HIVE_LISTEN=127.0.0.1:8088 HIVE_WEB_DIR=./web ./hive
# Honeypot: HONEYPOT_CONFIG=../config/honeypot.yml HIVE_URL=http://127.0.0.1:8088 HIVORNET_TOKEN=test HONEYPOT_LOW_PORT_OFFSET=20000 HONEYPOT_BIND=127.0.0.1 ./honeypot
```

- **Sensor-API ohne eigenen Port:** Ohne `HIVE_SENSOR_LISTEN` ist sie auch über den UI-Port erreichbar, praktisch für lokale Tests.
- **UI ohne Neubau:** Mit `HIVE_WEB_DIR` liefert der Hive die UI direkt aus dem Ordner aus.
- **Go-Version:** 1.26 oder neuer.

Das Ereignisformat zwischen Sensor und Hive steht in [docs/events.md](docs/events.md).

**Tests:** Unit-, Fuzz- und Vertragstests in `honeypot/honeypot_test.go` und `hive/hive_test.go`. Fuzzing z. B. mit `go test -run=^$ -fuzz=FuzzReadRESP -fuzztime=60s` im Ordner `honeypot`.

Die CI (`.github/workflows/ci.yml`) prüft bei jedem Push:
- `go vet`, `gofmt`, `staticcheck`, `govulncheck`;
- `go test -race` und kurzes Fuzzing;
- `shellcheck` und `hadolint`;
- den Docker-Build für amd64, arm64 und armv7.

Ein Git-Tag `v*` baut die Images und legt sie in der GitHub Container Registry ab.

## Grenzen und Ausblick

Hivornet ist ein Sensor für Massenscans und Login-Versuche mit guter Übersicht, kein Werkzeug für Malware-Analyse oder Forschung. Gegenüber T-Pot fehlt bewusst:

- **Weniger und einfachere Honeypots:** über 20 spezialisierte bei T-Pot, hier 8 einfache Emulationen plus Cowrie. Kein Dateisystem, keine Nutzlast-Ausführung, kein Malware-Fang über SMB.
- **Keine Netzwerk-Erkennung:** kein Suricata, p0f oder Fatt.
- **Feste Auswertungen:** keine frei definierbaren Abfragen wie in Kibana.
- **Kein UDP, kein IPv6:** Die Docker-Netze sind nur IPv4; Angriffe über IPv6 sieht Hivornet nicht.
- **Erkennbar:** Server-Kennungen und Antworten sind fest bzw. einfach gehalten. Geübte Scanner können den Honeypot erkennen.
- **Mehrere Sensoren:** Sie können eigene Konfigurationen haben, teilen sich aber ein Token. Die Sensor-API hat kein TLS und ist nur für das interne Docker-Netz gedacht.
- **Cowrie nur teilweise ausgewertet:** TTY-Mitschnitte und Sitzungsparameter werden gespeichert, aber nicht in der UI angezeigt.

Mögliche nächste Schritte:
- **Benachrichtigungen** (ntfy, Telegram, E-Mail) bei erfolgreichem Login oder Download.
- **Datenabgleich:** AbuseIPDB und GreyNoise, STIX/MISP-Export, weitere Protokolle (SMB, RDP, SMTP, UDP).
- **Konten und Betrieb:** Mehrbenutzer mit Leserolle und zweitem Faktor, eigenes Raspberry-Pi-Image.

## Lizenzen und Quellen

- Hivornet: [MIT-Lizenz](LICENSE)
- IP-Geodaten: [DB-IP.com](https://db-ip.com) Lite, CC BY 4.0
- Weltkarte: [world-atlas](https://github.com/topojson/world-atlas) (ISC), Daten von Natural Earth
- [Cowrie](https://github.com/cowrie/cowrie), BSD-Lizenz
