# Hivornet

Ein leichtgewichtiges Honeypot-System als Alternative zu T-Pot: viele Protokolle, Angreifer ausbremsen (Tarpit) und Auswertung im Browser. Es läuft mit **3 Containern unter 512 MB RAM** auf einer NAS, einem Raspberry Pi oder einem kleinen Server.

| Container | Aufgabe | RAM (gemessen / Limit) |
|---|---|---|
| `honeypot` | eigener Go-Honeypot: FTP, HTTP, HTTPS, Docker-API, MySQL, Redis, SMTP, Telnet, RDP, VNC, SSH-Tarpit, generische Ports. Jeder Port kann aufzeichnen, ausbremsen oder beides | ca. 15 MB / 192 MB |
| `cowrie` | SSH- und Telnet-Honeypot mit gefälschter Shell (Cowrie 3.1.6) | ca. 80–120 MB / 256 MB |
| `hive` | sammelt alles, ergänzt Land/Stadt/Netzbetreiber, speichert in SQLite, erkennt Angriffsmuster, benachrichtigt und liefert die Web-UI | ca. 20–60 MB / 384 MB |
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
2. `.env.example` als `.env` kopieren und darin mindestens zwei Werte setzen:
   - `HIVORNET_TOKEN`: lange Zufallszeichenkette
   - `HIVE_BIND`: LAN-IP der NAS
3. Container Manager → **Projekt** → **Erstellen** → Pfad `/docker/hivornet` wählen, die vorhandene `docker-compose.yml` verwenden → Erstellen.
4. Web-UI unter `http://<LAN-IP>:8088` öffnen und beim ersten Aufruf das Admin-Passwort festlegen (statt es vorab in `.env` einzutragen).
5. Netzsperre einrichten (siehe unten). Ohne SSH geht das über den Aufgabenplaner.

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
| 5900 | 15900 | VNC |
| 25 | 10025 | SMTP |
| 2323 | 12323 | Telnet (Go-Honeypot) |
| 3389 | 13389 | RDP |
| 5060/udp | 15060/udp | SIP (nur aufzeichnen) |
| 161/udp | 10161/udp | SNMP (nur aufzeichnen) |
| 53/udp | 10053/udp | DNS (nur aufzeichnen, standardmäßig aus) |

Du musst nicht alle weiterleiten. Fang ruhig mit 22, 23, 80 und 2222 an.

**Die UI-Ports 8088 und 8089 nie weiterleiten**, und die NAS nie als „Exposed Host“ oder DMZ eintragen. Ist auf deinem Router Port 443 oder 80 schon für etwas anderes belegt (VPN, NAS-Fernzugriff), diese Zeilen weglassen.

## Web-UI

`http://<IP-der-NAS>:8088` im Heimnetz öffnen. Beim allerersten Aufruf – solange noch kein Konto besteht – fragt die UI nach einem Passwort für den Benutzer `admin` und dem Standort für die Karte; danach bist du angemeldet. Deshalb die UI nie ins Internet weiterleiten: Wer sie zuerst erreicht, legt das Passwort fest.

| Ansicht | Inhalt |
|---|---|
| Dashboard | Warnungen, Kennzahlen, Weltkarte mit Live-Angriffen, Verlauf nach Dienst, Top-Länder/Ports/IPs/Netzbetreiber/Zugangsdaten/Befehle |
| Live-Karte | große Karte: Jede neue Verbindung zeichnet eine Linie vom Ursprung zum Honeypot; Laufliste, Angriffe pro Minute |
| Live-Feed | alle Ereignisse in Echtzeit, filterbar; Export als CSV/JSON, Blockliste der Angreifer-IPs und STIX 2.1 (für MISP, OpenCTI) |
| Sitzungen | Verbindungen mit Logins oder Befehlen; Ablauf, Angriffsbericht und bei Cowrie der Terminal-Mitschnitt zum Abspielen |
| Analyse | erkannte Angriffsmuster, benutzte und installierte Programme, Scanner, Nachlade-Adressen |
| Angreifer | alles zu einer IP: Herkunft, Angriffsbericht, Reputation (AbuseIPDB, GreyNoise), Ports, Passwörter, Ereignisse |
| Zugangsdaten | häufigste Benutzernamen, Passwörter, Befehle, HTTP-Pfade, User-Agents, Client-Versionen |
| Tarpit | verschwendete Angreiferzeit, gerade festgehaltene Verbindungen, Spitzenreiter |
| Einstellungen | Ports an/aus, Modus je Port, Tarpit-Tempo, Aufbewahrung, Admin-Passwort; bei mehreren Sensoren je Sensor. Dazu Standort für die Karte, Benachrichtigungen, KI-Auswertung, AbuseIPDB |
| System | Warnungen, Netzsperre, RAM, Datenbank, GeoIP, Cowrie, Status je Sensor und Port |

Änderungen in den Einstellungen übernimmt der Honeypot **innerhalb von 15 Sekunden ohne Neustart**.

### Angriffsbericht und Analyse

Auf der Seite eines Angreifers und einer Sitzung steht ein **Angriffsbericht**: Einstufung (niedrig, mittel, hoch), eine Kurzfassung in Sätzen, die erkannten Muster mit Beispiel, benutzte Werkzeuge, Zugangsdaten, Nachlade-Adressen, Dateien und die Befehle in Reihenfolge. „Als Text speichern“ liefert ihn als Datei.

Die Muster erkennt der Hive nach festen Regeln, ohne fremde Dienste. Beispiele: Nachladen und Ausführen, Krypto-Miner, IoT-Botnetz, SSH-Schlüssel hinterlegen, Cron-Persistenz, Docker-Ausbruch, Log4Shell, Geheimnis-Suche (`.env`, `.git`). Die Ansicht **Analyse** zeigt, wie oft welches Muster und welches Programm vorkam. Gezählt wird ab dem Update auf diese Version.

**KI-Auswertung (optional):** Unter Einstellungen lässt sich ein Sprachmodell eintragen, das einen Bericht auf Knopfdruck in Worte fasst. Es funktioniert jede OpenAI-kompatible Schnittstelle:

| Variante | Adresse | Hinweis |
|---|---|---|
| Ollama auf einem Rechner im Heimnetz | `http://<Rechner>:11434/v1` | Daten bleiben im Haus. Ollama muss im Netz lauschen (`OLLAMA_HOST=0.0.0.0`). |
| LM Studio | `http://<Rechner>:1234/v1` | wie oben |
| OpenRouter | `https://openrouter.ai/api/v1` | braucht einen API-Schlüssel und kostet je Anfrage; IP-Adressen, Zugangsdaten und Befehle der Angreifer verlassen dabei dein Netz |

Die Auswertung stammt von einem Sprachmodell und kann Fehler enthalten. Der Bericht darüber ist die Grundlage.

### Weitere Benutzer

Unter **Einstellungen → Benutzer** legt ein Admin weitere Konten an. Rolle **„Nur ansehen“** sieht alle Auswertungen, kann aber nichts ändern, keine KI-Auswertung starten und die Zusatz-Einstellungen (Benachrichtigungs-Ziele, Schlüssel) nicht sehen. Ein zweiter Faktor fehlt noch.

### UDP-Dienste

SIP (5060), SNMP (161) und DNS (53) laufen über UDP und **antworten nie**. Bei UDP lässt sich die Absenderadresse fälschen; jede Antwort könnte jemand nutzen, um Dritte mit unseren Paketen zu überfluten. Scanner verraten trotzdem, was sie suchen: SIP-Scanner ihre Software und Zielnummer, SNMP-Scanner den Community-String (erscheint als Login), DNS-Scanner die Abfrage. Absender-IPs bei UDP können gefälscht sein.

### Benachrichtigungen

Unter Einstellungen → Benachrichtigungen trägst du ein Ziel ein und wählst die Anlässe:

- **ntfy:** App installieren, ein langes, zufälliges Thema abonnieren und dessen Adresse eintragen, z. B. `https://ntfy.sh/<dein-thema>`. Bei ntfy.sh kann jeder mitlesen, der den Themennamen kennt.
- **Telegram:** Bot beim BotFather anlegen, Token und Chat-ID eintragen.
- **Webhook:** bekommt JSON mit `title`, `text`, `kind`, `ip`, `time`.

„Speichern und Testnachricht senden“ prüft die Einrichtung. Je Angreifer und Anlass kommt höchstens eine Meldung in 10 Minuten, insgesamt höchstens so viele pro Stunde wie eingestellt (Standard 20).

Token und Schlüssel speichert der Hive in seiner Datenbank und zeigt sie nie wieder an. Sie stehen damit auch in den Backups.

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
- **Cowrie-Dateien:** werden nach `COWRIE_KEEP_DAYS` gelöscht; Downloads höchstens 10 MB je Datei. Danach sind auch die Terminal-Mitschnitte in der UI nicht mehr abrufbar.

## Testen

Von einem anderen Rechner im Heimnetz (Python 3, keine Zusatzpakete):

```bash
python3 tools/attack_sim.py --host <IP-der-NAS>
```

Das schickt typische Angriffe auf alle Honeypot-Ports: Login-Seiten, Docker-Missbrauch, Redis-Cron-Masche, MySQL-Login, SSH-Tarpit, Telnet-Bot, SMTP-Anmeldung, VNC und RDP. Danach sieht man sie im Live-Feed (Quelle: deine LAN-IP, Land „LAN“).

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
  - Der Hive verbindet nur zu Adressen, die du selbst einträgst (Benachrichtigungen, KI, AbuseIPDB), und zum GeoIP-Download. Angreifer können diese Adressen nicht beeinflussen.
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
  - Gib Daten nicht ungeprüft weiter. Das betrifft auch die KI-Auswertung über einen Dienst im Internet und die Abfrage bei AbuseIPDB: Beide schicken Angreiferdaten an Dritte und sind deshalb abgeschaltet, bis du sie einrichtest.
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

### Raspberry Pi (fertiges Image)

Für den Raspberry Pi gibt es ein fertiges Image – kein Docker, keine Konsole. Aufspielen, einstecken, im Browser einrichten:

1. Auf der [Releases-Seite](https://github.com/MrLuigi938/hivornet/releases) die passende Datei laden: `hivornet-pi-arm64-*.img.xz` für Pi 3, 4, 5 und Zero 2 W, `hivornet-pi-armv7-*.img.xz` für ältere Modelle.
2. Mit dem [Raspberry Pi Imager](https://www.raspberrypi.com/software/) oder [balenaEtcher](https://etcher.balena.io/) auf eine SD-Karte (ab 8 GB) schreiben. Im Imager: Gerät wählen, bei „Betriebssystem“ ganz unten **„Eigenes Image“** und die `.img.xz`-Datei; die Frage nach **Anpassungen** (Benutzer, WLAN, SSH) mit **„Nein“** beantworten. Hivornet richtet sich selbst ein; Anpassungen des Imagers würden diese Einrichtung ersetzen.
3. Karte in den Pi, **LAN-Kabel** anstecken (WLAN ist nicht eingerichtet), Strom dran. Beim ersten Start vergrößert der Pi die Partition, startet einmal neu und installiert Hivornet. Das dauert **zwei bis fünf Minuten**.
4. Am Rechner im selben Netz **`http://hivornet.local:8088`** öffnen. Beim ersten Aufruf vergibst du dein Passwort und den Standort für die Karte – danach bist du sofort drin.
5. Im Router die Honeypot-Ports **1:1** an den Pi weiterleiten (extern 22 → Pi 22 usw.). Die Ports 8088 und 8089 nie weiterleiten, den Pi nie als „Exposed Host“ eintragen.

Findet dein Rechner `hivornet.local` nicht (kein mDNS), sieh die IP-Adresse des Pi im Router nach und öffne `http://<IP>:8088`.

**Updates:** Erscheint eine neue Version, zeigt die Fußzeile einen Hinweis mit Knopf **„Jetzt aktualisieren"**. Der Pi lädt die neue Version selbst, prüft die Signatur und startet neu; schlägt etwas fehl, kehrt er zur alten Version zurück. Eine neue SD-Karte ist nur für größere Sprünge nötig (wenn sich die Systemdienste ändern; steht dann in den Release-Hinweisen).

Welche Ports im Router: Die Liste steht in der Web-UI unter **Einstellungen → Ports und Modi** (Spalte „Öffentlich“ zeigt „direkt am Gerät“). Für den Anfang genügen 21, 22, 23, 80, 443 und 3389. UDP-Ports (5060, 161) nur bei Interesse; sie zeichnen nur auf.

**Klappt etwas nicht?** Bildschirm an den Pi anschließen: Nach der Installation steht dort die Adresse der Web-UI. Das Installationsprotokoll liegt auf dem Pi unter `/var/log/hivornet-install.log`. Ein Konsolen-Benutzer ist absichtlich gesperrt (eigenes Image mit `--password` bauen, wenn du einen brauchst); SSH ist aus, weil Port 22 dem Honeypot gehört.

**Eigenes Image bauen** (z. B. zum Testen aus diesem Branch). Das Skript ändert nur die Bootpartition eines offiziellen Raspberry Pi OS Lite und braucht weder Linux noch Root, nur Python 3 und openssl:

```bash
pip install pyfatfs==1.1.0
cd hive && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../dist/arm64/hive . && cd ..
cd honeypot && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../dist/arm64/honeypot . && cd ..
python3 pi/build_image.py --arch arm64 --version v0.3.0 --bin dist/arm64 --out dist
```

Das Basis-Image (Raspberry Pi OS Lite „trixie“ vom 06.10.2026) wird geladen und an der Prüfsumme erkannt; ein neueres trägt man in `BASE` in `pi/build_image.py` ein. In der CI passiert dasselbe bei jedem Tag (`.github/workflows/release.yml`, auch von Hand über „Run workflow“).

Hinweise zum Betrieb: Das Pi-Image hat **kein Cowrie** (das braucht Python und viel RAM). SSH und Telnet übernehmen der SSH-Tarpit und der Telnet-Honeypot des Go-Dienstes; es gibt dort also keine echte Fake-Shell und keine TTY-Mitschnitte. Das Image schont die SD-Karte von sich aus (`HIVE_FLUSH_MS=5000`) und begrenzt die Datenbank auf 1 GB. **Auf echter Pi-Hardware ist das Image noch nicht erprobt.**

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
- **Alle Prüfungen in einem Aufruf:** `sh tools/check.sh` (gofmt, vet, Tests, Cross-Build für amd64, arm64 und armv7).

Wie das System aufgebaut ist und wie man ein Protokoll, ein Angriffsmuster oder eine Ansicht ergänzt, steht in [docs/ARCHITEKTUR.md](docs/ARCHITEKTUR.md); das Ereignisformat zwischen Sensor und Hive in [docs/events.md](docs/events.md).

**Tests:** Unit-, Fuzz- und Vertragstests in `honeypot/*_test.go` und `hive/*_test.go`. Fuzzing z. B. mit `go test -run=^$ -fuzz=FuzzReadRESP -fuzztime=60s` im Ordner `honeypot`.

Die CI (`.github/workflows/ci.yml`) prüft bei jedem Push:
- `go vet`, `gofmt`, `staticcheck`, `govulncheck`;
- `go test -race` und kurzes Fuzzing;
- `shellcheck` und `hadolint`;
- den Docker-Build für amd64, arm64 und armv7.

Ein Git-Tag `v*` baut die Images und legt sie in der GitHub Container Registry ab.

## Grenzen und Ausblick

Hivornet ist ein Sensor für Massenscans und Login-Versuche mit guter Übersicht, kein Werkzeug für Malware-Analyse oder Forschung. Gegenüber T-Pot fehlt bewusst:

- **Weniger und einfachere Honeypots:** über 20 spezialisierte bei T-Pot, hier 15 einfache Emulationen (davon 3 über UDP, nur aufzeichnend) plus Cowrie. Kein Dateisystem, keine Nutzlast-Ausführung, SMB nur als Rohdaten auf Port 445. RDP ohne NLA: erfasst wird nur der Benutzername aus dem Verbindungs-Cookie.
- **Keine Netzwerk-Erkennung:** kein Suricata, p0f oder Fatt.
- **Feste Auswertungen:** keine frei definierbaren Abfragen wie in Kibana. Die Angriffsmuster sind einfache Regeln und können danebenliegen.
- **UDP nur aufzeichnend, kein IPv6:** UDP-Dienste antworten nie (siehe oben). Die Docker-Netze sind nur IPv4; Angriffe über IPv6 sieht Hivornet nicht.
- **Erkennbar:** Server-Kennungen und Antworten sind fest bzw. einfach gehalten. Geübte Scanner können den Honeypot erkennen.
- **Mehrere Sensoren:** Sie können eigene Konfigurationen haben, teilen sich aber ein Token. Die Sensor-API hat kein TLS und ist nur für das interne Docker-Netz gedacht.

Mögliche nächste Schritte:
- **Weitere Protokolle:** SMB mit Anmeldedialog, RDP mit NLA.
- **Datenabgleich:** Benachrichtigung per E-Mail.
- **Konten:** zweiter Faktor für die Anmeldung.

## Lizenzen und Quellen

- Hivornet: [MIT-Lizenz](LICENSE)
- IP-Geodaten: [DB-IP.com](https://db-ip.com) Lite, CC BY 4.0
- Weltkarte: [world-atlas](https://github.com/topojson/world-atlas) (ISC), Daten von Natural Earth
- [Cowrie](https://github.com/cowrie/cowrie), BSD-Lizenz
