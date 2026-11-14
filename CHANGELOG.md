# Changelog

Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionen nach [Semantic Versioning](https://semver.org/lang/de/).

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
