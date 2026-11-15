<p align="center"><img src="docs/logo.svg" alt="Hivornet-Logo" width="120"></p>

# Hivornet

> [!WARNING]
> **Hivornet ist derzeit eine Beta.** Die Software läuft und wird getestet, aber Funktionen, Konfiguration und Datenformat können sich noch ändern, und Fehler sind möglich.
>
> - **Updates:** Updates können ein Neuaufspielen oder eine neue `.env` erfordern; das steht dann im [CHANGELOG](CHANGELOG.md).
> - **Getestet:** Raspberry Pi und Docker-Betrieb auf NAS sind bisher nur in kleinem Umfang erprobt.
> - **Netz:** Am besten in einem eigenen Netz (VLAN/Gastnetz) und immer mit Netzsperre betreiben.
> - **Fehler melden:** Rückmeldungen und Fehlerberichte gerne als Issue; Sicherheitslücken wie in [SECURITY.md](SECURITY.md) beschrieben.

Hivornet ist ein leichtgewichtiges Honeypot-System für zu Hause und kleine Netze. Es lockt Angreifer aus dem Internet auf gefälschte Dienste, zeichnet auf, was sie versuchen, und bremst sie auf Wunsch aus. Alles läuft mit **unter 512 MB RAM** auf einer NAS, einem Raspberry Pi oder einem kleinen Server.

- **Viele Dienste:** SSH und Telnet mit gefälschter Shell (Cowrie), FTP, HTTP/HTTPS, Docker-API, MySQL, Redis, SMTP, RDP, VNC und weitere. SIP, SNMP und DNS laufen über UDP und zeichnen nur auf.
- **Ausbremsen (Tarpit):** Pro Port wählbar: Angreifer bekommen endlos winzige Datenstücke, und ihr Scanner hängt fest.
- **Auswertung im Browser:**
  - Weltkarte mit Live-Angriffen und Ländern;
  - Live-Feed, Sitzungen mit Terminal-Mitschnitt, Angriffsberichte;
  - erkannte Angriffsmuster, Zugangsdaten und Befehle.
- **Benachrichtigungen und Abgleich:** ntfy, Telegram oder Webhook; Reputation über AbuseIPDB und GreyNoise; Export als CSV, JSON, Blockliste und STIX.
- **Sicher eingerichtet:**
  - Netzsperre für die Honeypots, Dienste ohne Root-Rechte;
  - Updates per Knopf (Raspberry Pi), Backups.

## Installation

Zwei Wege: das **fertige Raspberry-Pi-Image** (am einfachsten) oder **Docker** auf einer NAS oder einem Linux-Server.

### Raspberry Pi (fertiges Image)

Kein Docker, keine Konsole: aufspielen, einstecken, im Browser einrichten. Geeignet für Pi 3, 4, 5 und Zero 2 W (64 Bit) sowie ältere Modelle (32 Bit).

1. Auf der [Releases-Seite](https://github.com/MrLuigi938/hivornet/releases) die passende Datei laden: `hivornet-pi-arm64-*.img.xz` für Pi 3, 4, 5 und Zero 2 W, `hivornet-pi-armv7-*.img.xz` für ältere Modelle.
2. Mit dem [Raspberry Pi Imager](https://www.raspberrypi.com/software/) oder [balenaEtcher](https://etcher.balena.io/) auf eine SD-Karte (ab 8 GB) schreiben. Im Imager: Gerät wählen, bei „Betriebssystem“ ganz unten **„Eigenes Image“** und die `.img.xz`-Datei. Die Frage nach **Anpassungen** (Benutzer, WLAN, SSH) mit **„Nein“** beantworten; Hivornet richtet sich selbst ein.
3. Karte in den Pi, **LAN-Kabel** anstecken (WLAN ist nicht eingerichtet), Strom dran. Beim ersten Start vergrößert der Pi die Partition, startet einmal neu und installiert Hivornet. Nach **zwei bis fünf Minuten** ist die Web-UI erreichbar.
4. Am Rechner im selben Netz **`http://hivornet.local:8088`** öffnen. Beim ersten Aufruf vergibst du dein Passwort und den Standort für die Karte, danach bist du angemeldet. Findet dein Rechner `hivornet.local` nicht, sieh die IP-Adresse des Pi im Router nach und öffne `http://<IP>:8088`.
5. Im Router die Honeypot-Ports **1:1** an den Pi weiterleiten (extern 22 → Pi 22 usw., siehe [Router-Portweiterleitung](#router-portweiterleitung)).

**Cowrie (SSH und Telnet mit gefälschter Shell)** installiert der Pi nach dem ersten Start im Hintergrund nach. Das braucht Internet und dauert auf einem Pi 3 etwa 10 bis 20 Minuten; die übrigen Dienste laufen schon vorher. Klappt es nicht (z. B. ohne Internet), versucht der Pi es stündlich erneut. Bis dahin zeigt die Seite **System** einen Hinweis.

Auf dem Pi gehören die Ports 22 und 23 Cowrie, 2222 dem SSH-Tarpit und 2323 dem Telnet-Honeypot. Die Netzsperre ist auf dem Pi schon eingerichtet. Die Datenbank ist auf 1 GB begrenzt, und der Pi schreibt gebündelt, um die SD-Karte zu schonen.

### Docker auf NAS oder Linux-Server

**Voraussetzungen:**
- Docker mit Compose v2 (Synology: Paket **Container Manager**, QNAP: **Container Station**, Unraid/TrueNAS: vorhanden)
- 1–2 CPU-Kerne, mindestens 1 GB freier RAM, ca. 3 GB Speicherplatz (GeoIP-Datenbank rund 140 MB, Ereignisse höchstens `HIVE_MAX_DB_MB`, Standard 2 GB)
- Internetzugang für den Build und das monatliche GeoIP-Update
- Für die Netzsperre: `iptables` auf dem Host (auf Synology, QNAP und gängigen Linux-Systemen vorhanden)

**Variante A: per SSH (empfohlen)**

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

**Variante B: Synology Container Manager ohne SSH**

1. Ordner `hivornet` per File Station nach `/docker/hivornet` hochladen.
2. `.env.example` als `.env` kopieren und darin mindestens zwei Werte setzen:
   - `HIVORNET_TOKEN`: lange Zufallszeichenkette
   - `HIVE_BIND`: LAN-IP der NAS
3. Container Manager → **Projekt** → **Erstellen** → Pfad `/docker/hivornet` wählen, die vorhandene `docker-compose.yml` verwenden → Erstellen.
4. Web-UI unter `http://<LAN-IP>:8088` öffnen und beim ersten Aufruf das Admin-Passwort festlegen.
5. Netzsperre einrichten (siehe unten). Ohne SSH geht das über den Aufgabenplaner.

So arbeiten die Container zusammen:

```
Internet ──> Router-Portweiterleitung ──> NAS
                                          ├─ cowrie   (SSH 22, Telnet 23)  ──cowrie.json (Volume)──┐
                                          └─ honeypot (21, 80, 443, ...)   ──Netz "ingest" :8089───┤
                                                                                                    v
                                Browser im Heimnetz  ──>  hive :8088  (SQLite, GeoIP, Web-UI)
           Netzsperre (tools/firewall.sh): Honeypot-Container dürfen keine neuen Verbindungen aufbauen
```

| Container | Aufgabe | RAM (gemessen / Limit) |
|---|---|---|
| `honeypot` | Go-Honeypot für alle Dienste außer SSH/Telnet; jeder Port kann aufzeichnen, ausbremsen oder beides | ca. 15 MB / 192 MB |
| `cowrie` | SSH- und Telnet-Honeypot mit gefälschter Shell (Cowrie 3.1.6) | ca. 80–120 MB / 256 MB |
| `hive` | sammelt alles, ergänzt Land/Stadt/Netzbetreiber, speichert in SQLite, erkennt Angriffsmuster, benachrichtigt und liefert die Web-UI | ca. 20–60 MB / 384 MB |
| `janitor` | räumt alte Cowrie-Logs und Downloads auf (BusyBox, ohne Netzwerk) | < 2 MB / 16 MB |

## Netzsperre (Pflicht vor dem Betrieb am Internet)

Ein Honeypot nimmt absichtlich feindlichen Verkehr an. Wird ein Honeypot übernommen, z. B. über eine Lücke in Cowrie, soll der Angreifer von dort **nicht weiterkommen**: nicht ins Heimnetz, nicht zur NAS und nicht ins Internet. Antworten an Angreifer bleiben erlaubt.

Auf dem **Raspberry Pi** ist die Netzsperre eingebaut und immer aktiv. Im **Docker-Betrieb** setzt sie `tools/firewall.sh`:

```bash
sudo sh tools/firewall.sh            # setzen
sudo sh tools/firewall.sh status     # anzeigen
sudo sh tools/firewall.sh remove     # entfernen
```

Die Regeln sperren alle **neuen** Verbindungen aus dem Docker-Netz `honeynet` (Bridge `hv-honeynet`). Mit `ALLOW_DOWNLOADS=1` darf Cowrie zusätzlich HTTP/HTTPS ins Internet, nie ins LAN. So bekommst du Schadsoftware-Proben, die Angreifer per `wget` nachladen.

**Nach jedem Neustart der NAS neu setzen:**
- **Synology:** Systemsteuerung → Aufgabenplaner → Erstellen → Ausgelöste Aufgabe → Benutzerdefiniertes Skript, Ereignis „Hochfahren“, Benutzer `root`, Befehl: `sh /volume1/docker/hivornet/tools/firewall.sh`. Da Docker eventuell erst danach startet, zusätzlich eine geplante Aufgabe alle 15 Minuten mit demselben Befehl anlegen; das Skript ist idempotent.
- **Linux mit systemd:** `tools/hivornet-firewall.service` nach `/etc/systemd/system/` kopieren, Pfad anpassen, `sudo systemctl enable --now hivornet-firewall`.

**Kontrolle:** Die Web-UI prüft alle 10 Minuten, ob der Honeypot ins Internet kommt. Unter **System** steht dann „Internet aus dem Container: gesperrt“. Fehlt die Sperre, erscheint eine rote Warnung auf dem Dashboard.

Noch besser ist ein eigenes VLAN oder Gastnetz für die NAS bzw. den Pi.

## Router-Portweiterleitung

Auf dem **Raspberry Pi** lauschen die Dienste direkt auf den echten Ports; im Router leitest du sie 1:1 weiter (extern 22 → Pi 22). Auf der **NAS** liegen sie absichtlich auf hohen Nummern, damit sie nicht mit SSH oder der Weboberfläche der NAS kollidieren:

| Extern (Internet) | an NAS-Port | Dienst |
|---|---|---|
| 22 | 10022 | SSH (Cowrie) |
| 23 | 10023 | Telnet (Cowrie) |
| 21 | 10021 | FTP |
| 25 | 10025 | SMTP |
| 80 | 10080 | HTTP |
| 443 | 10443 | HTTPS |
| 2222 | 12222 | SSH-Tarpit |
| 2323 | 12323 | Telnet (Go-Honeypot) |
| 2375 | 12375 | Docker-API |
| 3306 | 13306 | MySQL |
| 3389 | 13389 | RDP |
| 5900 | 15900 | VNC |
| 6379 | 16379 | Redis |
| 8080 | 18080 | HTTP (Hybrid) |
| 5060/udp | 15060/udp | SIP (nur aufzeichnen) |
| 161/udp | 10161/udp | SNMP (nur aufzeichnen) |
| 53/udp | 10053/udp | DNS (nur aufzeichnen, standardmäßig aus) |

Du musst nicht alle weiterleiten. Für den Anfang genügen 22, 23, 80, 443 und 3389. Welche Ports aktiv sind, zeigt die Web-UI unter **Einstellungen → Ports und Modi**.

**Die UI-Ports 8088 und 8089 nie weiterleiten**, und das Gerät nie als „Exposed Host“ oder DMZ eintragen. Ist auf deinem Router Port 443 oder 80 schon für etwas anderes belegt (VPN, NAS-Fernzugriff), diese Zeilen weglassen.

## Web-UI

`http://<IP-des-Geräts>:8088` im Heimnetz öffnen. Beim allerersten Aufruf, solange noch kein Konto besteht, fragt die UI nach einem Passwort für den Benutzer `admin` und dem Standort für die Karte. Deshalb die UI nie ins Internet weiterleiten: Wer sie zuerst erreicht, legt das Passwort fest.

| Ansicht | Inhalt |
|---|---|
| Dashboard | Warnungen, Kennzahlen, Weltkarte mit Ländern und Live-Angriffen, Verlauf nach Dienst, Top-Länder/Ports/IPs/Netzbetreiber/Zugangsdaten/Befehle |
| Live-Karte | große Karte: Jede neue Verbindung zeichnet eine Linie vom Ursprung zum Honeypot; Laufliste, Angriffe pro Minute |
| Live-Feed | alle Ereignisse in Echtzeit, filterbar; Export als CSV/JSON, Blockliste der Angreifer-IPs und STIX 2.1 (für MISP, OpenCTI) |
| Sitzungen | Verbindungen mit Logins oder Befehlen; Ablauf, Angriffsbericht und bei Cowrie der Terminal-Mitschnitt zum Abspielen |
| Analyse | erkannte Angriffsmuster, benutzte und installierte Programme, Scanner, Nachlade-Adressen |
| Angreifer | alles zu einer IP: Herkunft, Angriffsbericht, Reputation (AbuseIPDB, GreyNoise), Ports, Passwörter, Ereignisse |
| Zugangsdaten | häufigste Benutzernamen, Passwörter, Befehle, HTTP-Pfade, User-Agents, Client-Versionen |
| Tarpit | verschwendete Angreiferzeit, gerade festgehaltene Verbindungen, Spitzenreiter |
| Einstellungen | Ports an/aus, Modus je Port, Tarpit-Tempo, Aufbewahrung, Admin-Passwort, Benutzer; dazu Standort für die Karte, Benachrichtigungen, KI-Auswertung, AbuseIPDB |
| System | Warnungen, Updates, Netzsperre, RAM, Datenbank, GeoIP, Cowrie, Status je Sensor und Port |

Auf der Weltkarte zeigt das Überfahren eines Landes Flagge, Namen und die Angriffe von heute und insgesamt. Änderungen in den Einstellungen übernimmt der Honeypot **innerhalb von 15 Sekunden ohne Neustart**.

### Modi je Port

- **Aufzeichnen** (`emulate`): spielt den Dienst nach und zeichnet Logins, Befehle und Anfragen auf.
- **Tarpit**: hält die Verbindung sofort fest und sendet alle 10 s ein winziges Datenstück. Das bremst Scanner und Bots aus.
  - Jede gehaltene Verbindung kostet etwa 10–20 KB RAM; höchstens 8.000 gleichzeitig.
  - Standardmäßig wird nach 24 h losgelassen.
- **Hybrid**: zeichnet erst den Login oder die erste Anfrage auf und hält die Verbindung dann fest.

Im Docker-Betrieb muss ein neu angelegter Port zusätzlich in `docker-compose.yml` unter `honeypot.ports` freigegeben sein. Die Spalte „Öffentlich“ in den Einstellungen zeigt das an.

### Angriffsbericht und Analyse

Auf der Seite eines Angreifers und einer Sitzung steht ein **Angriffsbericht**: Einstufung (niedrig, mittel, hoch), eine Kurzfassung in Sätzen, die erkannten Muster mit Beispiel, benutzte Werkzeuge, Zugangsdaten, Nachlade-Adressen, Dateien und die Befehle in Reihenfolge. „Als Text speichern“ liefert ihn als Datei.

Die Muster erkennt Hivornet nach festen Regeln, ohne fremde Dienste. Beispiele: Nachladen und Ausführen, Krypto-Miner, IoT-Botnetz, SSH-Schlüssel hinterlegen, Cron-Persistenz, Docker-Ausbruch, Log4Shell, Geheimnis-Suche (`.env`, `.git`). Die Ansicht **Analyse** zeigt, wie oft welches Muster und welches Programm vorkam.

**KI-Auswertung (optional):** Unter Einstellungen lässt sich ein Sprachmodell eintragen, das einen Bericht auf Knopfdruck in Worte fasst. Es funktioniert jede OpenAI-kompatible Schnittstelle:

| Variante | Adresse | Hinweis |
|---|---|---|
| Ollama auf einem Rechner im Heimnetz | `http://<Rechner>:11434/v1` | Daten bleiben im Haus. Ollama muss im Netz lauschen (`OLLAMA_HOST=0.0.0.0`). |
| LM Studio | `http://<Rechner>:1234/v1` | wie oben |
| OpenRouter | `https://openrouter.ai/api/v1` | braucht einen API-Schlüssel und kostet je Anfrage; IP-Adressen, Zugangsdaten und Befehle der Angreifer verlassen dabei dein Netz |

Die Auswertung stammt von einem Sprachmodell und kann Fehler enthalten. Der Bericht darüber ist die Grundlage.

### Benachrichtigungen

Unter **Einstellungen → Benachrichtigungen** trägst du ein Ziel ein und wählst die Anlässe:

- **ntfy:** App installieren, ein langes, zufälliges Thema abonnieren und dessen Adresse eintragen, z. B. `https://ntfy.sh/<dein-thema>`. Bei ntfy.sh kann jeder mitlesen, der den Themennamen kennt.
- **Telegram:** Bot beim BotFather anlegen, Token und Chat-ID eintragen.
- **Webhook:** bekommt JSON mit `title`, `text`, `kind`, `ip`, `time`.

„Speichern und Testnachricht senden“ prüft die Einrichtung. Je Angreifer und Anlass kommt höchstens eine Meldung in 10 Minuten, insgesamt höchstens so viele pro Stunde wie eingestellt (Standard 20). Token und Schlüssel speichert Hivornet in seiner Datenbank und zeigt sie nie wieder an; sie stehen damit auch in den Backups.

### Weitere Benutzer

Unter **Einstellungen → Benutzer** legt ein Admin weitere Konten an. Die Rolle **„Nur ansehen“** sieht alle Auswertungen, kann aber nichts ändern, keine KI-Auswertung starten und die Zusatz-Einstellungen (Benachrichtigungs-Ziele, Schlüssel) nicht sehen.

### UDP-Dienste

SIP (5060), SNMP (161) und DNS (53) laufen über UDP und **antworten nie**. Bei UDP lässt sich die Absenderadresse fälschen; jede Antwort könnte jemand nutzen, um Dritte mit unseren Paketen zu überfluten. Scanner verraten trotzdem, was sie suchen: SIP-Scanner ihre Software und Zielnummer, SNMP-Scanner den Community-String (erscheint als Login), DNS-Scanner die Abfrage. Absender-IPs bei UDP können gefälscht sein.

## Updates

Unter **System → Updates** siehst du die installierte Version und ob es eine neuere gibt. Geprüft wird automatisch zweimal täglich, mit **„Jetzt prüfen“** sofort.

- **Kanal:** **Stabil** bekommt nur fertige Versionen. **Vorabversionen** bekommt zusätzlich Pre-Releases mit neuen Funktionen, die noch Fehler enthalten können.
- **Raspberry Pi:** Mit **„Jetzt aktualisieren“** lädt der Pi die neue Version selbst, prüft die Prüfsumme und startet neu. Schlägt etwas fehl, kehrt er zur alten Version zurück. Eine neue SD-Karte ist nur nötig, wenn das in den Release-Hinweisen steht.
- **Docker:** `sh update.sh` holt den neuen Stand, sichert vorher die Datenbank und baut neu.

## Betrieb

**Docker:**

```bash
docker compose ps                    # Status (alle Container mit Healthcheck)
docker compose logs -f --tail 50     # Logs
sh update.sh                         # aktualisieren (sichert vorher die Datenbank)
sh tools/backup.sh                   # Datenbank sichern nach ./backups
sh uninstall.sh                      # stoppen, Daten behalten
sh uninstall.sh --purge              # alles inkl. Daten löschen
```

**Backup und Wiederherstellen:** `sh tools/backup.sh` erzeugt im laufenden Betrieb eine konsistente Kopie und legt sie unter `./backups/` ab. Lokal bleiben die letzten 14 Sicherungen, im Container die letzten 7. Wiederherstellen:

```bash
docker compose cp backups/hive-JJJJMMTT-HHMMSS.db hive:/data/restore.db
docker compose restart hive          # der Hive übernimmt restore.db beim Start
```

**Raspberry Pi:** Vor jedem Update über die UI sichert der Pi die Datenbank selbst (unter `/var/lib/hivornet/backups`).

**Überwachung:**
- **Healthchecks:** für Hive, Honeypot und Cowrie; `docker compose ps` zeigt `healthy`.
- **Warnungen in der UI** (Dashboard und System), z. B.:
  - ein Sensor meldet sich nicht;
  - die Netzsperre fehlt;
  - Ereignisse wurden verworfen;
  - der Speicher wird knapp;
  - der GeoIP-Download ist fehlgeschlagen;
  - Cowrie ist still.
- **Prometheus:** In `.env` `HIVE_METRICS_TOKEN` setzen, dann `GET http://<Gerät>:8088/metrics` mit Header `Authorization: Bearer <Token>`.

**UI mit HTTPS (optional):** Die UI spricht nur HTTP und ist für das Heimnetz gedacht. Für HTTPS einen Reverse-Proxy davorsetzen, z. B. den der Synology:
1. Systemsteuerung → Anmeldeportal → Erweitert → Reverse Proxy.
2. Quelle `https://hivornet.nas.lan:8443`, Ziel `http://localhost:8088`.
3. In `.env` setzen: `HIVE_BIND=127.0.0.1`, `HIVE_COOKIE_SECURE=1`, `HIVE_ALLOWED_HOSTS=hivornet.nas.lan`.

## Testen

Von einem anderen Rechner im Heimnetz (Python 3, keine Zusatzpakete):

```bash
python3 tools/attack_sim.py --host <IP-des-Geräts>
```

Das schickt typische Angriffe auf alle Honeypot-Ports: Login-Seiten, Docker-Missbrauch, Redis-Cron-Masche, MySQL-Login, SSH-Tarpit, Telnet-Bot, SMTP-Anmeldung, VNC und RDP. Danach sieht man sie im Live-Feed (Quelle: deine LAN-IP, Land „LAN“). Gegen einen Raspberry Pi mit `--offset 0`, weil dort die echten Ports gelten.

Für eine gefüllte Weltkarte ohne echte Angriffe gibt es Demo-Daten (Docker, auf der NAS selbst ausführen):

```bash
docker run --rm --network hivornet_ingest -v "$PWD/tools:/t:ro" python:3-alpine \
  python3 /t/attack_sim.py --no-attacks --demo 400 --hive http://hive:8089 --token "$(grep ^HIVORNET_TOKEN= .env | cut -d= -f2)"
```

Demo-Daten landen dauerhaft in der Datenbank, also nur zum Ausprobieren verwenden.

## Sicherheit

- **Ohne Rechte:**
  - Kein Dienst läuft als Root.
  - Docker: alle Capabilities entzogen (`cap_drop: ALL`, `no-new-privileges`), Dateisysteme nur lesbar, feste Limits für RAM, CPU und Prozesse, kein Zugriff auf den Docker-Socket oder NAS-Ordner.
  - Raspberry Pi: eigene Systembenutzer je Dienst mit systemd-Härtung.
  - Alle Images und der Cowrie-Quelltext sind per Prüfsumme festgelegt.
- **Netztrennung:**
  - Honeypots haben durch die Netzsperre keine ausgehenden Verbindungen.
  - Die Sensor-API des Hive (8089) ist nur intern erreichbar. Die Web-UI (8088) lehnt Anfragen aus dem Sensor-Netz ab.
- **Was Angreifer erreichen können:**
  - Die Shell in Cowrie ist gefälscht, Angreifer führen nichts wirklich aus.
  - Der Go-Honeypot baut selbst keine Verbindungen nach außen auf; die einzige Ausnahme ist die Prüfung der Netzsperre.
  - Hivornet verbindet nur zu Adressen, die du selbst einträgst (Benachrichtigungen, KI, AbuseIPDB), zum GeoIP-Download und zur Update-Prüfung bei GitHub. Angreifer können diese Adressen nicht beeinflussen.
  - Angreiferdaten werden in der UI nie als HTML ausgeführt. Steuerzeichen werden sichtbar ersetzt, CSV-Exporte gegen Formel-Injection geschützt.
- **Web-UI:**
  - Nur im Heimnetz erreichbar.
  - Login mit bcrypt, Sperre nach 10 Fehlversuchen pro IP und 60 pro Minute insgesamt.
  - Sitzungen 7 Tage gültig, in der Datenbank nur als Hash; Passwortwechsel meldet alle anderen Geräte ab.
  - Schutz gegen CSRF und DNS-Rebinding, strenge Content-Security-Policy.

**Cowrie-Downloads:** Dateien, die Angreifer per `wget` laden, landen auf dem Gerät (Docker: Volume `hivornet_cowrie-lib`, Pi: `/var/lib/hivornet-cowrie/lib/downloads`). Das ist **echte Schadsoftware**: nicht öffnen und nicht auf andere Rechner kopieren.

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
- **Schadsoftware:** Gespeicherte Proben nicht weitergeben oder ausführen. Zur Analyse z. B. den Hash bei VirusTotal nachschlagen, nicht die Datei hochladen.
- **Nur eigene Systeme testen:** `tools/attack_sim.py` nur gegen die eigene Instanz verwenden.

## Fehlerbehebung

| Problem | Lösung |
|---|---|
| Pi: Web-UI nach 10 Minuten nicht erreichbar | Bildschirm an den Pi anschließen: Nach der Installation steht dort die Adresse. Das Installationsprotokoll liegt auf dem Pi unter `/var/log/hivornet-install.log`. Eine Konsolen-Anmeldung und SSH sind absichtlich aus (Port 22 gehört Cowrie). Ist die Web-UI erreichbar, zeigt die Seite **Protokolle** alle Hivornet-Protokolle. |
| Pi: System meldet „Cowrie-Log nicht gefunden“ | Cowrie wird nach dem ersten Start installiert; das braucht Internet und dauert etwa 10 bis 20 Minuten. Ohne Internet versucht es der Pi stündlich erneut. |
| Alle Angreifer erscheinen mit einer 172.x-IP und „LAN“; Warnung „aus dem eigenen Docker-Netz“ | Docker leitet die Ports über den Userland-Proxy statt per NAT weiter, dabei geht die echte IP verloren. In der Docker-Konfiguration (`/etc/docker/daemon.json`) `"userland-proxy": false` setzen und Docker neu starten. |
| „Port is already allocated“ | Port in `.env` ändern und `docker compose up -d` |
| Warnung „Netzsperre fehlt“ | `sudo sh tools/firewall.sh`; bleibt die Warnung nach 10 Minuten, `sudo sh tools/firewall.sh status` prüfen |
| Docker: Cowrie-Log „fehlt“ | `COMPOSE_PROFILES=cowrie` in `.env`? Logs prüfen: `docker compose logs cowrie`. |
| GeoIP „Download fehlgeschlagen“ | Hivornet braucht Internet für `download.db-ip.com` und versucht es täglich neu. |
| UI meldet „unbekannter Hostname“ | Den Namen, unter dem du das Gerät aufrufst, in `HIVE_ALLOWED_HOSTS` eintragen |
| „Jetzt prüfen“ meldet „Repository nicht öffentlich“ | GitHub ist nicht erreichbar oder das Repository nicht öffentlich. Später erneut versuchen. |
| Passwort vergessen (Docker) | In `.env` `HIVE_ADMIN_PASSWORD` neu setzen und `HIVE_RESET_ADMIN=1`, dann `docker compose up -d hive`. Danach `HIVE_RESET_ADMIN=0` und das Passwort aus `.env` entfernen, noch einmal `docker compose up -d hive`. |

## Mitentwickeln

Bauen, Tests, CI, Veröffentlichung und eigenes Pi-Image: [docs/ENTWICKLUNG.md](docs/ENTWICKLUNG.md). Aufbau des Systems: [docs/ARCHITEKTUR.md](docs/ARCHITEKTUR.md).

## Lizenzen und Quellen

- Hivornet: [MIT-Lizenz](LICENSE)
- IP-Geodaten: [DB-IP.com](https://db-ip.com) Lite, CC BY 4.0
- Weltkarte: [world-atlas](https://github.com/topojson/world-atlas) (ISC), Daten von Natural Earth
- Ländernamen und ISO-Codes: [i18n-iso-countries](https://github.com/michaelwittig/node-i18n-iso-countries) (MIT)
- Flaggen: Schrift „Twemoji Country Flags“ aus [country-flag-emoji-polyfill](https://github.com/talkjs/country-flag-emoji-polyfill) (MIT), Grafiken von [Twemoji](https://github.com/jdecked/twemoji) (CC BY 4.0)
- [Cowrie](https://github.com/cowrie/cowrie), BSD-Lizenz
