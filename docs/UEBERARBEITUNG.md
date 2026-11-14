# HoneyLite – Überarbeitung nach 0.2.0

Branch: `claude/fable-ueberarbeitung-c18ccc`, Ausgangspunkt `main` @ `60bc36b` (Version 0.2.0).
Dieses Dokument ist Plan und Protokoll zugleich. Es richtet sich an die nächste Sitzung, die an dem Branch weiterarbeitet. Den Aufbau des Systems beschreibt [ARCHITEKTUR.md](ARCHITEKTUR.md).

## 1. Ausgangslage

Version 0.2.0 hat alle 47 Audit-Befunde abgearbeitet. Der Unterbau ist solide: Grenzen, Netztrennung, Tests und Migrationen sind vorhanden. Was fehlt, steht im Audit unter „Priorität 3 – Funktionsumfang“ und in der README unter „Grenzen und Ausblick“:

- Nur 8 einfache Emulationen. Die am häufigsten gescannten Dienste nach SSH und HTTP (Telnet auf 2323, RDP, VNC, SMTP, SMB) landen im generischen `raw`-Handler oder gar nicht.
- Cowrie schreibt TTY-Mitschnitte, die UI zeigt sie nicht.
- Niemand erfährt von einem erfolgreichen Login, ohne die UI zu öffnen.
- Kein Abgleich mit Reputationsdiensten.
- Die Liste der Dienste steht an sieben Stellen von Hand (Honeypot, Hive, UI, Compose, `.env`, Simulator). Ein neues Protokoll ist dadurch fehleranfällig.

## 2. Plan, sortiert nach Nutzen und Aufwand

Nutzen und Aufwand sind Einschätzungen (hoch/mittel/niedrig). Der Status wird in Abschnitt 3 je Punkt fortgeschrieben.

| Nr. | Punkt | Nutzen | Aufwand | Entscheidung |
|---|---|---|---|---|
| P1 | Neue Protokolle: Telnet, VNC, RDP, SMTP | hoch | mittel | umsetzen |
| P2 | Dienste-Register: eine Quelle im Honeypot, Abgleichtest gegen Hive und UI | mittel | niedrig | umsetzen |
| P3 | TTY-Mitschnitte von Cowrie in der Sitzungsansicht | hoch | mittel | umsetzen |
| P4 | Benachrichtigungen (ntfy, Telegram, Webhook) | hoch | mittel | umsetzen |
| P5 | Abgleich mit AbuseIPDB (auf Abruf, mit Zwischenspeicher), Links zu GreyNoise/Shodan | mittel | mittel | umsetzen |
| P6 | Filter im Live-Feed (Land, Port, Sensor), Tastaturbedienung der Tabellen | mittel | niedrig | umsetzen |
| P7 | Schonung von SD-Karten: einstellbares Schreibintervall, Abschnitt Raspberry Pi | mittel | niedrig | umsetzen |
| P8 | SMB (Negotiate, NTLM-Benutzername) | mittel | hoch | offen |
| P9 | RDP mit NLA/CredSSP (Benutzername aus NTLM) | mittel | hoch | offen |
| P10 | GreyNoise-Abgleich per API | niedrig | mittel | offen |
| P11 | UDP-Dienste (SIP, SNMP, DNS) | mittel | hoch | offen |
| P12 | Mehrbenutzer, Leserolle, zweiter Faktor | niedrig | hoch | offen |
| P13 | Fertiges Raspberry-Pi-Image | mittel | hoch | offen |
| P14 | `proto_other.go` in eine Datei je Protokoll teilen | niedrig | niedrig | verworfen |
| P15 | STIX/MISP-Export | niedrig | mittel | offen |

Begründungen für die Auswahl:

- **P1 vor allem anderen:** Ein Honeypot ist so nützlich wie die Dienste, die er anbietet. Die vier Protokolle sind mit je 100–200 Zeilen machbar, brauchen keinen zusätzlichen Speicher und passen in das vorhandene Muster (`func(*Session)`, drei Modi).
- **P8 und P9 zurückgestellt:** Beide brauchen einen NTLM-Dialog (SPNEGO bzw. CredSSP in ASN.1). Das sind einige hundert Zeilen binäres Protokoll, die sich ohne echten Client auf dem Entwicklungsrechner nicht verlässlich prüfen lassen. Lieber sauber offen lassen als halb richtig einbauen.
- **P14 verworfen:** Reines Verschieben von Code macht den Diff groß und erschwert den Vergleich mit `main`. Neue Protokolle bekommen eigene Dateien; die alten bleiben, wo sie sind.

## 3. Umsetzung je Punkt

(wird während der Arbeit ergänzt)
