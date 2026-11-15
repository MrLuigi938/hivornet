# Changelog

Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionen nach [Semantic Versioning](https://semver.org/lang/de/).

## [0.4.0-beta.3] – 2026-11-15

### Behoben
- Update-Prüfung: Vorabversionen gleicher Nummer wurden nicht verglichen; 0.4.0-beta.2 galt auf 0.4.0-beta.1 nicht als neuer („Du hast die neueste Version“). Vergleich jetzt nach Semantic Versioning (beta.2 < beta.11 < rc.1 < fertig).
- Einstellungen: Der GreyNoise-Schlüssel wurde beim Speichern nicht mitgeschickt und ging verloren.
- Webhook: Die Meldung enthält zusätzlich das Feld `content`, damit Discord-Webhooks sie annehmen (vorher „400 Bad Request“). Lehnt ein Ziel ab, zeigt die Fehlermeldung einen Auszug seiner Antwort.

## [0.4.0-beta.2] – 2026-11-15

### Sicherheit
- Raspberry Pi: Die Netzsperre (`hivornet-firewall`) brach beim Start ab, weil der Cowrie-Benutzer im Skript nicht gesetzt war. Dadurch scheiterte die Erstinstallation: Honeypot und Cowrie wurden nicht eingerichtet, und nach einem Neustart wäre der Honeypot ohne Sperre gestartet. Behoben; Honeypot und Cowrie starten jetzt grundsätzlich nur, wenn die Netzsperre aktiv ist (`Requires=`). Ein neuer CI-Test führt das Skript mit Ersatzbefehlen für nft und iptables aus.

### Behoben
- Release-Workflow: Die Veröffentlichung lädt nur noch die eigenen Artefakte (die Build-Protokolle von Docker ließen den Download scheitern).

## [0.4.0-beta.1] – 2026-11-15

### Sicherheit
- Telnet-Honeypot: Maskierte 0xFF-Bytes (`IAC IAC`) zählten nicht zur Zeilenlänge; eine Zeile ohne Zeilenende konnte unbegrenzt wachsen. Gefunden vom Fuzzing in der CI.
- Ereignisse werden ohne HTML-Maskierung kodiert (`&` statt `&`). Angreiferdaten voller `&`, `<` oder `>` sprengten sonst das Größenbudget und gingen verloren.

### Geändert
- **Neuer Name: Hivornet.** Umbenannt sind Programmname, Oberfläche, Umgebungsvariablen (`HIVORNET_TOKEN`, `HIVORNET_VERSION`), Docker-Projekt und Volumes (`hivornet_*`), Image- und Paketnamen, Pi-Dienste und -Pfade (`/opt/hivornet`, `/etc/hivornet`, `hivornet-*.service`), Firewall-Ketten (`HIVORNET-OUT`), die Docker-Bridge (`hv-honeynet`), Sitzungs-Cookie und Browser-Speicher. Bestehende Installationen von 0.3.0 werden nicht automatisch übernommen: Pi neu aufspielen, im Docker-Betrieb `.env` mit den neuen Variablennamen anlegen.
- Raspberry Pi: **Cowrie** (SSH und Telnet mit gefälschter Shell, Terminal-Mitschnitte) wird jetzt beim ersten Start mit Internet nachinstalliert und lauscht auf Port 22 und 23; der SSH-Tarpit bleibt auf 2222, der Telnet-Honeypot auf 2323. Netzsperre und tägliches Aufräumen gelten auch für Cowrie.
- README für die Veröffentlichung neu geordnet; Entwicklerthemen stehen jetzt in `docs/ENTWICKLUNG.md`.
- Neues Logo: Sicherheits-Schild mit gestreiftem Stachel (`hive/web/favicon.svg`, `docs/logo.svg`).
- Updates: Auf der System-Seite lässt sich der Kanal wählen (nur fertige Versionen oder auch Vorabversionen), und „Jetzt prüfen“ fragt sofort bei GitHub nach. Tags mit Bindestrich (`v0.4.0-beta.1`) werden als Pre-Release veröffentlicht.

### Behoben
- Weltkarte: Waagerechte Streifen über die ganze Karte bei Ländern, die über die Datumsgrenze reichen (Russland, Fidschi). Die Umrisse werden jetzt abgewickelt und am Kartenrand umgebrochen.
- Honeypot: Die Warnung „Verbindungen aus dem eigenen Docker-Netz“ war ohne Docker (Raspberry Pi) ein Fehlalarm für Zugriffe aus dem Heimnetz. Gezählt wird nur noch die Gateway-Adresse eines Docker-Netzes, und nur im Docker-Image.

### Neu
- Weltkarte mit Ländergrenzen. Beim Überfahren wird das Land hervorgehoben, mit Flagge, deutschem Namen und den Angriffen heute und insgesamt (`GET /api/stats/countries`); live mitgezählt.
- Flaggen auch an den Länderkürzeln in Listen und Tabellen (eingebettete Schrift, funktioniert auch unter Windows).

## [0.3.0] – 2026-11-14

Überarbeitung nach 0.2.0; Einzelheiten in `docs/UEBERARBEITUNG.md`, Aufbau in `docs/ARCHITEKTUR.md`. Die Datenbank wird beim ersten Start auf Schema-Version 4 gebracht. Bestehende Installationen bekommen die neuen Dienste automatisch in ihre Port-Konfiguration ergänzt (Port 5900 wird von `raw` zu `vnc`; SMTP, Telnet und RDP kommen auf freie Ports dazu).

### Neu
- **Vier weitere Protokolle im Honeypot:**
  - Telnet mit Schein-Shell (zeigt die Befehle von IoT-Bots).
  - SMTP mit Anmeldung und Mail-Annahme ohne Weiterleitung.
  - VNC bis zur Authentifizierung.
  - RDP mit Benutzername aus dem Verbindungs-Cookie und Client-Angaben.
- **Analyse:** Der Hive erkennt 23 Angriffsmuster (z. B. Nachladen und Ausführen, Krypto-Miner, SSH-Schlüssel hinterlegen, Log4Shell), benutzte und installierte Programme, Scanner und Nachlade-Adressen. Neue Ansicht „Analyse“.
- **Angriffsbericht** je Angreifer-IP und je Sitzung: Einstufung, Kurzfassung, Muster mit Beispiel, Werkzeuge, Zugangsdaten, Adressen, Dateien, Befehle; auch als Textdatei.
- **KI-Auswertung (optional):** fasst einen Bericht auf Knopfdruck in Worte, über eine OpenAI-kompatible Schnittstelle (lokal mit Ollama oder LM Studio, oder OpenRouter).
- **Live-Karte:** Jede neue Verbindung zeichnet eine Linie vom Ursprung zum Honeypot; eigene Ansicht mit Laufliste und Zählern. Der Standort ist einstellbar.
- **Terminal-Mitschnitte von Cowrie** in der Sitzungsansicht, auch zum Abspielen.
- **Benachrichtigungen** über ntfy, Telegram oder Webhook bei erfolgreichem Login, Download, schwerem Angriffsmuster, erstem Befehl einer Sitzung und kritischen Warnungen; mit Abklingzeit und Stundenlimit.
- **Reputation:** Abfrage bei AbuseIPDB auf Knopfdruck (24 Stunden zwischengespeichert), Links zu GreyNoise, Shodan und VirusTotal.
- **Live-Feed:** Filter nach Land und Port; Ereigniszeilen lassen sich mit der Tastatur aufklappen.
- **Fertiges Raspberry-Pi-Image (ohne Docker):** SD-Karte schreiben, einstecken, im Browser unter `http://hivornet.local:8088` einrichten. Gehärtete systemd-Dienste, Netzsperre, Token beim ersten Start. Gebaut mit `pi/build_image.py` (ändert nur die Bootpartition, kein Linux und kein Root nötig; Installation beim ersten Start per cloud-init) und in der Release-Pipeline.
- **UDP-Dienste SIP, SNMP und DNS:** zeichnen nur auf und antworten nie (kein Missbrauch für Reflexionsangriffe). SNMP-Community-Strings erscheinen als Login.
- **Weitere Benutzer mit Leserolle:** Admins legen unter Einstellungen Konten an; „Nur ansehen“ sieht alle Auswertungen, ändert nichts.
- **GreyNoise-Abfrage** auf Knopfdruck (Community-API, optional mit Schlüssel), wie AbuseIPDB 24 Stunden zwischengespeichert.
- **STIX-2.1-Export** von Angreifer-IPs, Nachlade-Adressen und Datei-Hashes (für MISP, OpenCTI, Firewalls).
- **Ersteinrichtung in der Web-UI:** Ist kein Admin-Passwort vorgegeben, fragt die UI beim ersten Aufruf nach Passwort und Standort. Kein erzeugtes Startpasswort mehr.
- **Update-Prüfung:** Der Hive sieht zweimal täglich bei GitHub nach einer neueren Version; die Fußzeile weist darauf hin. Wo ein Updater läuft (Pi-Image), gibt es den Knopf „Jetzt aktualisieren" mit Prüfsumme und Rückfall auf die alte Version (`HIVE_UPDATE_CHECK`, `HIVE_UPDATE_REQUEST`).
- **Fußzeile** mit Name, Version und Urheber.
- **Betrieb:** `HIVE_FLUSH_MS` bündelt Schreibvorgänge (schont SD-Karten); `HIVE_DIRECT_PORTS` für den Betrieb ohne Docker; `tools/check.sh` führt alle Prüfungen in einem Aufruf aus.
- **Dokumentation:** `docs/ARCHITEKTUR.md`, `docs/UEBERARBEITUNG.md`.

### Geändert
- Telnet verhält sich wie ein echtes Gerät: je Konto genau ein (geräteabhängiges) Werkspasswort, sonst „Login incorrect" nach kurzer Pause, höchstens drei Versuche. Dazu eine glaubwürdigere BusyBox-Shell (`echo -e`, `/proc/cpuinfo`, `ps`, `uname -a`).
- Angriffsmuster werden für ältere Ereignisse einmalig nachgezählt, damit die Ansicht „Analyse" auch die Vergangenheit abdeckt.
- Port 5900 ist in der Startkonfiguration jetzt `vnc` statt `raw`.
- Nach einem Passwortwechsel werden nur noch die anderen Sitzungen desselben Benutzers abgemeldet.
- Datenbank-Schema-Version 4 (Rollen für Benutzer).
- Neue öffentliche Ports in `docker-compose.yml` und `.env.example`: `PORT_SMTP` (10025), `PORT_TELNET_ALT` (12323), `PORT_RDP` (13389).
- Die Liste der Dienste steht im Honeypot nur noch an einer Stelle; ein Test gleicht Hive und UI dagegen ab.
- Ereignisformat ergänzt (abwärtskompatibel): Typ `tty`, neue Felder in `data` (siehe `docs/events.md`).

### Behoben
- Der Hive stürzte beim Start ab, wenn `HIVE_SENSOR_LISTEN` nicht gesetzt war (Entwicklungsmodus aus der README).

## [0.2.0] – 2026-11-14

Umsetzung des Audits (`docs/AUDIT.md`). Datenbanken aus 0.1.0 werden beim ersten Start automatisch migriert. Bestehende Sitzungen werden dabei ungültig: Einmal neu anmelden.

### Sicherheit
- **Speichergrenzen gegen Absturz durch einzelne Verbindungen:** HTTP-Kopf und Body je 64 KB, Redis-Befehle 64 KB (lange Argumente werden gestreamt), Body wird nicht mehr bis zum Ende gelesen.
- **Netzsperre:** `tools/firewall.sh` und systemd-Unit; der Honeypot prüft selbst, ob er ins Internet kommt, und die UI warnt.
- **Getrennte Listener im Hive:** Sensor-API auf Port 8089 nur im internen Netz, Web-UI auf 8088 lehnt das Sensor-Netz ab. Die UI wird standardmäßig an die LAN-IP gebunden.
- **Images per Digest festgelegt:** Cowrie 3.1.6, Go, distroless, BusyBox.
- **Cowrie gehärtet:** nur lesbares Dateisystem, Download-Limit 10 MB.
- **Login und Sitzungen:**
  - Die Login-Bremse zählt vor dem bcrypt-Lauf, höchstens 2 parallele bcrypt-Läufe und eine globale Grenze.
  - Sitzungs-Token liegen nur als Hash in der Datenbank.
  - Passwortwechsel meldet andere Geräte ab; Passwortlänge 10–72 Zeichen.
- **Schutz gegen DNS-Rebinding:** Prüfung des Host-Headers, `HIVE_ALLOWED_HOSTS`.
- **Startpasswort:** wird nach der Installation aus `.env` entfernt; `.env` wird mit Rechten 600 angelegt.
- **Darstellung von Angreiferdaten:** Steuer- und Richtungszeichen werden in der UI sichtbar ersetzt; CSV-Export ist gegen Formel-Injection geschützt.

### Behoben
- Große Payloads wurden im Hive komplett verworfen: Jetzt gilt ein festes Größenbudget pro Ereignis, und der Hive kürzt feldweise.
- **Emitter:**
  - Blöcke nach Anzahl und Bytes begrenzt.
  - Keine Endlosschleife bei 4xx; Wiederholung mit wachsender Pause bei 5xx.
  - Duplikaterkennung über Ereignis-IDs.
- **Schreiber im Hive:**
  - Fehler werden geprüft (kein Absturz mehr) und Blöcke dreimal versucht.
  - Verworfene Ereignisse werden gezählt und angezeigt.
- **Cowrie-Leser:**
  - Erkennt die Datei am Fingerabdruck der ersten Zeile und liest nach einer Rotation die alte Datei zu Ende.
  - Überlange Zeilen werden übersprungen.
- Tarpit-Modus bei HTTP hält jetzt sofort fest (vorher erst nach der ersten Anfrage).
- Docker-API-Antworten sind gültiges JSON; `HEAD`- und 204-Antworten ohne Body.
- Suche mit Backslash; UTF-8-Kürzung schneidet nicht mehr vor einem Binärbyte ab.
- GeoIP: Prüf-Reader wird geschlossen; Rückgriff auf den Vormonat funktioniert auch am Monatsende.
- UI: Schnelles Wechseln der Ansichten zeichnet nicht mehr über die neue Ansicht; abgelaufene Sitzung führt zur Anmeldung statt zu „getrennt“.
- Port-Kollision durch den Versatz (z. B. 80 und 10080) wird erkannt.
- TLS-Zertifikat des HTTPS-Honeypots wird vor Ablauf erneuert.

### Neu
- **Aufbewahrung:**
  - Nach Größe (`HIVE_MAX_DB_MB`, `HIVE_MIN_FREE_MB`) zusätzlich zur Frist.
  - Angreifer-IPs werden nach derselben Frist gelöscht.
  - Aufräum-Dienst `janitor` für Cowrie-Dateien (`COWRIE_KEEP_DAYS`).
- **Drossel und Limits:** höchstens 10 Ereignisse pro Sekunde und IP (kurzzeitig 300); Verbindungslimit pro Port; Tarpit standardmäßig nach 24 h beendet und auf 8.000 begrenzt.
- **Schnelle Top-Listen und Karte:** über Zähltabellen statt Tabellen-Scans; alle Abfragen mit Zeitlimit.
- **Export:** CSV und JSON sowie Blockliste der Angreifer-IPs.
- **Mehrere Sensoren:** eigene Konfiguration je Sensor.
- **Überwachung:**
  - Warnungen in Dashboard und System.
  - Healthchecks für alle Container.
  - Prometheus-Endpunkt `/metrics` (`HIVE_METRICS_TOKEN`).
  - Erkennung, wenn echte Angreifer-IPs durch den Userland-Proxy verloren gehen.
- **Betrieb:**
  - Sauberes Beenden: Die Warteschlange wird geschrieben.
  - Backup im laufenden Betrieb (`tools/backup.sh`, `hive backup`), Wiederherstellen über `restore.db`.
  - `update.sh` sichert vor dem Update.
- **Datenbank:** Schema-Version mit automatischen Migrationen.
- **Cowrie:** HASSH-Fingerabdrücke werden ausgewertet.
- **Tests:** Unit-, Fuzz- und Vertragstests.
- **Projekt:**
  - CI (vet, gofmt, staticcheck, govulncheck, race, Fuzzing, shellcheck, hadolint, Multi-Arch-Build).
  - Release-Images in der GitHub Container Registry, Dependabot.
  - LICENSE, SECURITY.md, `docs/events.md`.
  - Abschnitte zu Recht und Datenschutz in der README.

## [0.1.0] – 2026-11-13

Erste Version: Go-Honeypot mit 8 Protokollen und Tarpit-/Hybrid-Modus, Cowrie, Hive mit SQLite, GeoIP und Web-UI, Installationsskripte.
