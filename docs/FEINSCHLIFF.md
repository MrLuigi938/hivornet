# Feinschliff in vier Paketen – Übergabe

Branch `claude/feinschliff-pakete-bcc796`, Ausgangspunkt `main` @ `fb017f0` (Version 0.5.2-beta.1). Nicht gepusht, nicht gemergt, kein Tag. Die Versionsnummer ist nicht vergeben; das CHANGELOG führt alles unter „Unveröffentlicht“. Grundlage waren die Auswertung der Pi-Instanz des Nutzers und ein Blick von außen (siehe Aufgabe in der Sitzung).

Prüfen des ganzen Branches:

```bash
sh tools/check.sh        # gofmt, vet, Tests, Cross-Build amd64/arm64/armv7 – auf dem Entwicklungsrechner grün
```

UI lokal (ARCHITEKTUR.md, Abschnitt 8): Hive mit `HIVE_WEB_DIR=./web` starten, Honeypot mit `HONEYPOT_LOW_PORT_OFFSET=20000 HONEYPOT_BIND=127.0.0.1 HONEYPOT_EGRESS_PROBE=off` dazu, Testdaten per `POST /api/ingest`.

Was nur die CI prüfen kann (kein Docker, kein WSL2 auf dem Entwicklungsrechner): `shellcheck` (neues Skript `hivornet-cowrie-keycheck`, geänderter `pi/test_cowrie_install.sh`), `staticcheck`, `govulncheck`, Race-Detector, Fuzzing, Docker-Build, `pi/test_cowrie_install.sh` in Debian 13 (mit dem neuen Fall „leere Schlüsseldatei“), `pi/verify_image.py` (erwartet die neue Datei).

---

## Paket 1 – Fehler und Einstufung

| Commit | Inhalt |
|---|---|
| `782d920` | Cowrie-SSH: `hivornet-cowrie-keycheck` als `ExecStartPre` |
| `1360aef` | Warnung, wenn Cowrie-Ports oder Honeypot-Ports nicht lauschen |
| `6740ad5` | Einstufung an einer Stelle, TLS am Klartext-Port, Eingaben an der Login-Abfrage |
| `3d8613d`, `1b7033c` | Getrennte Top-Listen, eigene Netze, Neuzählung, Doku |

**Entscheidungen**

- **SSH-Reparatur nur mit neuem Image.** Der Hive (Benutzer `hivornet-hive`) darf `/var/lib/hivornet-cowrie/lib` nicht ändern; `hivornet-update` tauscht nur `hive` und `honeypot`. Technisch führt der Updater das neue Programm als root aus (`hive version`), aber darüber Reparaturen einzuschleusen wäre eine versteckte Rechteausweitung – bewusst nicht gemacht. Weg für den Nutzer: Sicherung exportieren, neues Image, Sicherung einspielen (README, Fehlerbehebung). Die Web-UI erkennt den Fehler jetzt und sagt das.
- **Keycheck läuft als `hivornet-cowrie`** (gleicher Benutzer wie Cowrie, keine neuen Rechte) und entfernt jedes Paar, von dem eine Hälfte leer ist oder nicht mit `-----BEGIN` bzw. `ssh-`/`ecdsa-`/`sk-` beginnt.
- **Port-Prüfung** nur auf dem Pi standardmäßig (`HIVE_DIRECT_PORTS=1` mit Cowrie); im Docker-Betrieb erreicht der Hive das Cowrie-Netz nicht. Prüfverbindungen kommen von Loopback und werden im Cowrie-Leser verworfen.
- **Einstufung** (`hive/einstufung.go`, Regeln im Kopfkommentar): „Befehle ausgeführt“ nur bei Schein-Shell (ssh, telnet), Docker-API, verändernden Redis-Befehlen, bei FTP nur verändernden Befehlen nach Login, sonst nur nach angenommenem Login. Reine Abfragen (PING, INFO, EHLO, AUTH TLS …) = Abtasten, übriges Geplänkel = Versuche.
- **TLS am Klartext-Port**: Der Honeypot meldet jetzt `tls` mit `plain: true` und `client_hello` (Hex, höchstens 3 KB); ältere `command`-Einträge mit `\x16\x03` erkennt der Hive ebenso. Der Hive prüft hier nicht mehr auf Verschleierung.
- **Befehle an der Login-Abfrage** erkennt der Hive (wirkt auch für Cowrie-Telnet und alte Daten).
- **Eigene Netze**: werden nur in `events` geschrieben (nicht `hourly`, `top_hourly`, `attackers`); der Filter gilt ab dem Speichern. „Trotzdem zählen“ schaltet das ab.
- **Neuzählung** der Top-Listen beim ersten Start (`recountTop`, Merker `top_recounted_053`): Felder aus Logins, Befehlen und Anfragen werden vor dem Start des Writers gelöscht und im Hintergrund neu gezählt. Felder aus Verbindungen (Land, Port, IP) bleiben unverändert, eigene Tests darin bleiben also bis zum Ablauf der Aufbewahrung enthalten.

**Risiken / offen**

- Die Kennzahl „Befehle“ im Dashboard zählt weiter alle `command`-Ereignisse (Tabelle `hourly`), auch Redis-PING. Die Stufen sind korrekt; die Kennzahl wäre ein kleiner Folgeschritt (eigener Typ in `hourly`).
- Cowrie-Dateinamen der Schlüssel (`ssh_host_*_key[.pub]`) sind nur gegen die Doku von Cowrie 3.1.6 geprüft; der CI-Test bricht mit einer Liste des Ordners ab, falls sie anders heißen.

**So prüfen**: `go test ./...` in `hive` (u. a. `TestStufeProtocolChatter`, `TestTLSHelloNotCommand`, `TestTelnetPromptCommands`, `TestPortProbe*`, `TestOwnTestsHidden`, `TestRecountTop`) und `honeypot` (`TestTLSOnPlainPorts`). Im Browser: Angriffe (Filter „Eigene Tests zeigen“, Karten mit „Protokoll-Befehle“), Zugangsdaten (Listen SNMP, SIP, DNS), Einstellungen → Eigene Netze, System → Cowrie (Ports).

---

## Paket 2 – Automatische Meldung an AbuseIPDB

| Commit | Inhalt |
|---|---|
| `23983e2` | `hive/abusereport.go`, `hive/scanner.go`, UI in den Einstellungen |

API nachgeschlagen (docs.abuseipdb.com, www.abuseipdb.com/categories): `POST https://api.abuseipdb.com/api/v2/report`, Kopf `Key`, Felder `ip`, `categories`, `comment`, `timestamp`; 429 bei gleicher IP innerhalb 15 Minuten und bei erschöpftem Tageskontingent (Standard 1.000); Kopfzeilen `X-RateLimit-*`, `Retry-After`; Kommentare ohne personenbezogene Daten.

**Entscheidungen**

- Standardmäßig aus, beim Einschalten zuerst Probemodus. Prüfung alle 5 Minuten über die Angriffe der letzten 30 Minuten.
- Gemeldet nur: Login-Versuche (auch Befehle an der Login-Abfrage), Web-Exploits (`web_rce`, `log4shell`, `iot_exploit`, `traversal`, `sqli`, jede CVE), ausgeführte Befehle, Downloads. Geheimnis-Suche (.env) nur auf Wunsch.
- Nie: private/eigene Adressen, Angriffe nur über UDP, Forschungsscanner (abschaltbar) und per DNS bestätigte Suchmaschinen-Bots.
- Kommentar Englisch, nur erzeugte Sätze, Benutzernamen (nur `[A-Za-z0-9_.-]{1,24}`), Muster, CVE-Nummern, Ports; alle IPs und die Hostnamen aller Sensoren und des Hive werden ersetzt; höchstens 1.000 Zeichen.
- Abstand je IP einstellbar (Standard 24 h, mindestens 1 h), Tageslimit (Standard 50). Protokoll in `kv` (`abuse_report_log`, 200 Einträge), Abstand je IP in `lookups`.

**Risiken / offen**: Gegen die echte API nicht geprüft (nur `httptest`). Die Liste der Forschungsscanner erkennt am AS-Namen der GeoIP-Datenbank; ohne GeoIP greift nur der User-Agent.

**So prüfen**: `TestAbuseVerdict`, `TestAbuseCommentPrivacy`, `TestAbuseReportRound`. In der UI: Einstellungen → AbuseIPDB → Probemodus einschalten, nach 5 Minuten das Protokoll ansehen.

---

## Paket 3 – Tarnung

| Commit | Inhalt |
|---|---|
| `4c6ad97` | Köderdateien, Telnet je IP, nginx-Verhalten, MySQL, Redis, FTP, Docker |
| `5cbd6d1` | Geräteprofile, Doku |

**Entscheidungen**

- **Köder** (`honeypot/bait.go`, `hive/bait.go`): Zugangsdaten per HMAC-SHA256 aus dem Sensor-Token abgeleitet (Token nicht zurückrechenbar, je Installation verschieden, Hive und Honeypot leiten gleich ab; `TestBaitDerivation` prüft denselben festen Wert in beiden Modulen). Verwendung → Muster `bait_used` (Schweregrad 3, Benachrichtigung, Stufe mindestens „Login angenommen“, Art „Köder benutzt“). MySQL erkennt der Honeypot am Hash (`mysqlNativeMatch`).
- **Telnet**: Je IP gilt das dritte verschiedene Werkspasswort und bleibt dann (Speicher begrenzt auf 20.000 IPs). Das alte hostnamenabhängige Passwort entfällt.
- **FTP**: anonyme Anmeldung und Köder-Zugang angenommen, Schein-Verzeichnis. **Keine Datenverbindung**: PORT wäre eine ausgehende Verbindung (verboten), PASV ein weiterer Port, den kein Router weiterleitet. LIST/RETR/STOR werden aufgezeichnet und mit `425` beantwortet, PASV mit der vsftpd-Fehlermeldung `500 OOPS: vsf_sysutil_bind`. Daher liefert `RETR` die Köderdateien **nicht** aus – hier bewusst kleiner als gefordert.
- **Geräteprofile** (`honeypot/profile.go`): Linux-Server, NAS, Router/Kamera; leeres Profil = bisheriges Verhalten (keine Änderung bestehender Installationen). „Profil übernehmen“ in der UI schaltet passende Dienste ein und setzt den Hostnamen; gespeichert wird erst mit „Speichern“.

**Risiken / offen**

- Fehlerseiten haben bei allen Profilen das Layout von nginx (nur die Versionszeile wechselt); bei `lighttpd` sähe die echte Seite anders aus.
- Cowrie (SSH 22, Telnet 23 auf dem Pi) kennt die Profile nicht; Hostname und Banner von Cowrie stehen in `/etc/hivornet/cowrie.cfg` (neues Image nötig).
- Das Router-Profil meldet vsFTPd 2.3.4 (die Version mit der bekannten Hintertür) – zieht Angreifer an, ist aber auffällig. Bei Bedarf ändern.

**So prüfen**: `honeypot`: `TestHTTPBaitFiles`, `TestHTTPLikeNginx`, `TestDockerLists`, `TestMySQLThreadIDCounts`, `TestRedisConfigAndInfo`, `TestFTPAnonymousFakeDir`, `TestBaitLoginFlagged`, `TestTelnetRejectsLikeRealDevice`, `TestDeviceProfile`; `hive`: `TestBaitUsedRaisesAttack`. Von Hand geprüft: Profil „Router“ gespeichert → nach 15 s `Server: lighttpd/1.4.59`, `.env` mit Hostname `router`; FTP-Login mit den Köderdaten aus `/.env` → Angriff „Köder benutzt“.

---

## Paket 4 – Analyse

| Commit | Inhalt |
|---|---|
| `5658fa0` | JA3/JA4, HTTP-Kopfzeilen, HASSH; CVE-Erkennung; MITRE ATT&CK |
| `3203b47` | Kampagnen |
| `a58c257` | Suchmaschinen-Bots per DNS prüfen |
| `be0a249` | URLhaus und MalwareBazaar auf Knopfdruck |
| `6f45657` | Ungewöhnliche Zugangsdaten, Wochenbericht |
| `4a5fd5c`, `174ef1d` | Angriffskette (Wunsch des Nutzers während der Arbeit), als frei beweglicher Graph |

**Entscheidungen**

- **JA3/JA4** rechnet der Hive aus den Rohdaten (auch rückwirkend für gespeicherte `client_hello`). JA4 nach der FoxIO-Spezifikation (nur der TLS-Client-Teil, BSD-3-Clause); geprüft gegen einen selbst gebauten ClientHello und einen echten Go-Client, **nicht** gegen die Referenzimplementierung.
- **HTTP-Kopfzeilen-Reihenfolge** wird aus dem Puffer gelesen, bevor `http.ReadRequest` sie sortiert; liegt der Kopf nicht ganz im ersten Puffer (4 KB), fehlt sie.
- **Kampagnen**: Verkettet nur über gleiche Zugangsdatenliste (≥ 3 verschiedene, gleiche Menge) und gleichen Nachlade-Host. Fingerabdrücke werden getrennt gezeigt, weil verbreitete Werkzeuge sonst alles zusammenwerfen.
- **CVE**: 16 eindeutig erkennbare Lücken; ein Treffer heißt „versucht“, nicht „verwundbar“.
- **Bot-Prüfung**: einzige neue ausgehende Verbindung des Hive ist DNS über den Resolver des Systems (höchstens 2 Prüfungen/s, 30 Tage zwischengespeichert).
- **abuse.ch** (API nachgeschlagen): beide APIs brauchen einen kostenlosen `Auth-Key`. Abgefragt werden nur Adressen und Hashes, die in den eigenen Daten vorkommen; nie ein Upload.
- **Ungewöhnliche Zugangsdaten**: eingebettete Liste (~350 Wörter) gängiger Passwörter, Standardkonten und IoT-Werkspasswörter; kurze Zahlen und Benutzername = Passwort gelten als gewöhnlich.
- **Wochenbericht**: montags ab 8 Uhr Ortszeit, nur einmal je ISO-Woche (`kv weekly_last`), Vorschau in den Einstellungen.
- **Angriffskette** (`hive/chain.go`, `chainView` in `extra.js`): Knoten in sechs Phasen, Kanten aus der Reihenfolge je Sitzung und der Herkunft von Adressen/Dateien. Darstellung als Bubbles mit eigener kleiner Kräfte-Simulation (keine Bibliothek, CSP). Verschieben, Zoomen (Mausrad, Knöpfe), Bubbles umsetzen (Doppelklick gibt frei), Einpassen, Neu anordnen; Auswahl hebt Verbindungen hervor und zeigt Beispiele, Zeiten, MITRE, CVE. Höchstens 60 Knoten (darüber Sammelknoten je Phase), 5.000 Ereignisse.

**Risiken / offen**

- Angriffskette: Das Mausrad zoomt innerhalb der Fläche und scrollt dort die Seite nicht; Touch-Zoom per zwei Fingern gibt es nicht (Knöpfe +/−). Bei sehr vielen Knoten wird es eng; der Sammelknoten „weitere“ fängt das ab.
- Kampagnen und Angriffskette werden auf Abruf aus den Rohdaten berechnet; auf einem Pi 3 mit vielen Ereignissen kann der Aufruf für 30/90 Tage einige Sekunden dauern.
- URLhaus, MalwareBazaar und die Bot-Prüfung sind nur gegen `httptest` bzw. Ersatzfunktionen getestet; bei der lokalen UI-Prüfung lief die DNS-Prüfung echt (eine gefälschte Googlebot-IP wurde erkannt).

**So prüfen**: `TestJA3JA4`, `TestTLSFingerprintRealClient`, `TestCVERules`, `TestEveryPatternHasMitre`, `TestBuildCampaigns`, `TestBotVerify`, `TestAbuseChLookups`, `TestRareCred`, `TestWeeklyDue`, `TestWeeklyText`, `TestBuildChain`, honeypot `TestHTTPSClientHelloCaptured`. Im Browser: Angreifer-Seite → Angriffskette (ziehen, zoomen, Bubble anklicken), Analyse → Kampagnen, CVE, Fingerabdrücke; Bericht → Knöpfe „URLhaus“/„MalwareBazaar“; Einstellungen → Benachrichtigungen → Vorschau des Wochenberichts.

---

## Gemeinsame Hinweise

- Ereignisformat nur ergänzt: `tls.plain`, `tls.client_hello`, `tls.bytes`, `tls.truncated`, `request.header_order`, `login.bait`, `login.accepted` auch bei FTP, `command.cwd`/`upload` bei FTP (docs/events.md).
- Neue Zählfelder in `top_hourly`: `snmp`, `sip`, `dns`, `ja3`, `ja4`, `hassh`, `httpfp`, `cve`. Neue `kv`-Schlüssel: `top_recounted_053`, `abuse_report_log`, `weekly_last`. Neue `lookups`-Quellen: `abuse_report`, `abuse_report_dry`, `rdns`, `urlhaus`, `malwarebazaar`. Keine Schemaänderung.
- Virenscanner: Die neuen Regeln (CVE-Pfade, Köderdateien) haben Build und Tests unter Windows nicht gestört.
- Größenbudget: neue Ereignisse geprüft (`TestTLSOnPlainTruncated`, `TestTLSOnPlainPorts` gegen `maxEventBytes`).
