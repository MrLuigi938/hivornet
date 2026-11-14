# HoneyLite – Überarbeitung nach 0.2.0

Branch: `claude/fable-ueberarbeitung-c18ccc`, Ausgangspunkt `main` @ `60bc36b` (Version 0.2.0). Nicht gepusht, nicht gemergt.

Dieses Dokument ist Plan und Protokoll zugleich und richtet sich an die Sitzung, die an dem Branch weiterarbeitet. Den Aufbau des Systems, das Datenbankschema und die Schritt-für-Schritt-Anleitungen für Erweiterungen beschreibt [ARCHITEKTUR.md](ARCHITEKTUR.md).

## 1. Ausgangslage

Version 0.2.0 hat alle 47 Audit-Befunde abgearbeitet. Der Unterbau ist solide: Grenzen, Netztrennung, Tests und Migrationen sind vorhanden. Es fehlte Funktionsumfang:

- Nur 8 einfache Emulationen. Häufig gescannte Dienste (Telnet auf 2323, RDP, VNC, SMTP) landeten im generischen `raw`-Handler oder gar nicht.
- Die UI zeigte Ereignisse, aber keine Auswertung: was ein Angreifer vorhatte, welche Werkzeuge er benutzte, woher er nachlud.
- Cowrie schrieb TTY-Mitschnitte, die UI zeigte sie nicht.
- Niemand erfuhr von einem erfolgreichen Login, ohne die UI zu öffnen.
- Die Liste der Dienste stand an sieben Stellen von Hand.

Dazu kam während der Arbeit der Wunsch des Nutzers nach einer moderneren Live-Karte (woher kommt der Angriff, wohin geht er), einer Muster-Analyse, einem Angriffsbericht, einer optionalen KI-Auswertung (lokal oder OpenRouter) und einer Übersicht der benutzten und installierten Programme.

## 2. Plan und Status

| Nr. | Punkt | Nutzen | Aufwand | Status |
|---|---|---|---|---|
| P1 | Neue Protokolle: Telnet, VNC, RDP, SMTP | hoch | mittel | **umgesetzt** |
| P2 | Dienste-Register mit Abgleichtest | mittel | niedrig | **umgesetzt** |
| P3 | Muster-Analyse, Werkzeug-Erkennung, Ansicht „Analyse“ | hoch | mittel | **umgesetzt** |
| P4 | Angriffsbericht je IP und Sitzung | hoch | mittel | **umgesetzt** |
| P5 | KI-Auswertung des Berichts (lokales Modell oder OpenRouter) | mittel | mittel | **umgesetzt**, gegen echtes Modell ungeprüft |
| P6 | Live-Karte mit Angriffslinien zum Honeypot | mittel | niedrig | **umgesetzt** |
| P7 | TTY-Mitschnitte von Cowrie in der Sitzungsansicht | hoch | mittel | **umgesetzt**, gegen echtes Cowrie ungeprüft |
| P8 | Benachrichtigungen (ntfy, Telegram, Webhook) | hoch | mittel | **umgesetzt**, gegen echte Dienste ungeprüft |
| P9 | AbuseIPDB auf Abruf, Links zu GreyNoise/Shodan/VirusTotal | mittel | niedrig | **umgesetzt**, gegen echten Dienst ungeprüft |
| P10 | Filter im Live-Feed (Land, Port), Tastaturbedienung der Tabellen | mittel | niedrig | **umgesetzt** |
| P11 | Schonung von SD-Karten (`HIVE_FLUSH_MS`), Abschnitt Raspberry Pi | mittel | niedrig | **umgesetzt** |
| P12 | Fehler aus 0.2.0: Absturz ohne `HIVE_SENSOR_LISTEN` | – | niedrig | **behoben** (beim Testen gefunden) |
| P13 | Telnet glaubwürdiger (ein Passwort je Gerät, BusyBox-Shell) | mittel | niedrig | **umgesetzt** (Wunsch 2. Runde) |
| P14 | Version 0.3.0, Fußzeile, automatische Port-Anpassung | – | niedrig | **umgesetzt** (Wunsch 2. Runde) |
| P15 | Ersteinrichtung über die Web-UI (Passwort, Standort) | hoch | mittel | **umgesetzt** (Wunsch 2. Runde) |
| P16 | Update-Prüfung gegen GitHub, Hinweis und Knopf in der UI | hoch | mittel | **umgesetzt** (Wunsch 2. Runde) |
| P17 | Fertiges Raspberry-Pi-Image, Setup und Update über die UI | hoch | hoch | **umgesetzt**, auf echter Hardware ungeprüft (Wunsch 2. Runde) |
| P18 | Muster rückwirkend für alte Ereignisse zählen | niedrig | niedrig | **umgesetzt** |
| P19 | SMB mit Anmeldedialog (NTLM) | mittel | hoch | **verworfen** (siehe unten); SMB-Scanner erscheinen als Rohdaten auf Port 445 (Pi) |
| P20 | RDP mit NLA/CredSSP | mittel | hoch | **verworfen** (siehe unten) |
| P21 | GreyNoise per API | niedrig | niedrig | **umgesetzt** (3. Runde) |
| P23 | UDP-Dienste SIP, SNMP, DNS (nur aufzeichnen) | mittel | mittel | **umgesetzt** (3. Runde) |
| P24 | Weitere Benutzer mit Leserolle | mittel | mittel | **umgesetzt** (3. Runde); zweiter Faktor offen |
| P25 | STIX-2.1-Export (für MISP, OpenCTI) | niedrig | niedrig | **umgesetzt** (3. Runde) |
| P26 | Pi-Image ohne Linux/Root bauen und tatsächlich bauen (Pi 3) | hoch | mittel | **umgesetzt** (3. Runde), auf Hardware ungeprüft |
| P27 | Ländergrenzen auf der Karte, zweiter Faktor, E-Mail-Benachrichtigung | niedrig | mittel | offen |
| P22 | `proto_other.go` in eine Datei je Protokoll teilen | niedrig | niedrig | verworfen |

P23–P27 kamen in einer dritten Runde dazu: „die offenen Punkte bearbeiten und das Raspberry-Pi-Image für einen Pi 3 bauen“.

P13–P18 kamen in einer zweiten Runde auf Wunsch des Nutzers dazu (Telnet unauffälliger, fertiges Pi-Image mit Einrichtung und Updates über die UI, Versionierung mit Update-Prüfung gegen GitHub, Fußzeile wie im Projekt Heimdeck, die offenen Punkte soweit möglich erledigen).

Begründungen für die weiter offenen Punkte:

- **P19, P20 (SMB, RDP mit NLA) verworfen:** Beide brauchen einen NTLM-Dialog (SPNEGO bzw. CredSSP in ASN.1). Ein Ansatz, die NTLM-Anmeldedaten aus dem Dialog zu lesen, wurde in der zweiten Runde vom Sicherheitsfilter der Entwicklungsumgebung abgebrochen; der Code wurde verworfen und bewusst nicht wieder aufgenommen. RDP erfasst weiterhin den Benutzernamen aus dem Verbindungs-Cookie. SMB-Scanner sieht man über einen `raw`-Listener auf Port 445 (im Pi-Image vorkonfiguriert); die Muster-Regel `smb_probe` erkennt sie.
- **P27 offen:** Ländergrenzen auf der Karte bräuchten Ländergeometrien samt Zuordnung von ISO-Zahlencodes zu Ländercodes (zusätzliche Daten, mehr Gewicht im UI); zweiter Faktor und E-Mail sind eigenständige Vorhaben.
- **P22 verworfen:** Reines Verschieben von Code macht den Diff groß und erschwert den Vergleich mit `main`. Neue Protokolle haben eigene Dateien.

## 3. Umsetzung je Punkt

### P1 – Neue Protokolle

| Dienst | Datei | Was aufgezeichnet wird | hybrid: festhalten nach |
|---|---|---|---|
| `telnet` | `honeypot/proto_telnet.go` | Login (jede Kombination wird angenommen, `data.accepted`), danach bis zu 40 Befehle in einer Schein-Shell | Login |
| `smtp` | `honeypot/proto_smtp.go` | `AUTH PLAIN`/`LOGIN` als Login, `EHLO`/`MAIL`/`RCPT` als Befehle, Anfang der Mail als `payload` mit `mail: true` | erstem Login oder `MAIL` |
| `vnc` | `honeypot/proto_vnc.go` | Client-Version, Challenge und Antwort der VNC-Authentifizierung als Login mit `password_hashed` | Antwort |
| `rdp` | `honeypot/proto_rdp.go` | Benutzername aus dem Cookie `mstshash` als Login (`data.cookie`), gewünschte Protokolle, nach TLS Rechnername/Build/Tastaturlayout als `client_version` | erster Nachricht |

Designentscheidungen:

- **Telnet nimmt jeden Login an.** Bots wie Mirai versuchen eine Kombination je Verbindung und schicken ihre Befehle erst nach dem Login. `telnetReply` beantwortet `/bin/busybox <WORT>` mit `<WORT>: applet not found`; daran erkennen diese Bots eine „echte“ Shell und zeigen ihren Lader. Das Feld heißt `accepted`, nicht `success`, damit Sitzungsansicht und Benachrichtigung „erfolgreicher Login“ weiter nur Cowrie meinen.
- **SMTP nimmt scheinbar jede Mail an**, leitet aber nie etwas weiter. Gelesen werden höchstens 64 KB je Mail, gespeichert die ersten 2 KB.
- **VNC speichert Challenge und Antwort**, weil VNC das Passwort nie überträgt. Damit lässt sich offline prüfen, welches Passwort versucht wurde. Der Login hat deshalb leeren Benutzernamen und leeres Passwort.
- **RDP ohne NLA:** Der Honeypot antwortet wie ein Server, der TLS anbietet. Clients, die NLA verlangen, brechen ab; ihr Benutzername steht meist trotzdem im Cookie.
- **Standardkonfiguration:** Port 5900 ist jetzt `vnc` statt `raw`; neu sind `smtp` 25, `telnet` 2323, `rdp` 3389. Das gilt nur für frische Installationen. Bestehende behalten ihre im Hive gespeicherte Konfiguration und fügen die Dienste unter Einstellungen → „Port hinzufügen“ hinzu.
- **Ports:** `PORT_SMTP` (10025), `PORT_TELNET_ALT` (12323), `PORT_RDP` (13389) in `docker-compose.yml` und `.env.example`. `PORT_RAW` behält seinen Namen (sonst brächen bestehende `.env`-Dateien).

Tests: `TestTelnetLoginAndShell`, `TestTelnetReadLineLimit`, `TestSMTPAuthAndMail`, `TestSMTPDataLimit`, `TestVNCAuth`, `TestParseRDPRequest`, `TestRDPClientInfo`, `TestRDPCookieLogin`, `TestNewProtocolsSizeBudget` (Binärmüll gegen alle vier, Größenbudget), Fuzz-Ziele `FuzzTelnetReadLine`, `FuzzRDP` (in der CI eingetragen). Von Hand: `python3 tools/attack_sim.py --host <NAS>` enthält Testangriffe für alle vier.

Grenzen: Der TLS-Zweig von RDP (`handleRDP` ab `useTLS`) und `rdpClientInfo` sind nur mit einem nachgebauten Paket getestet, nicht mit einem echten RDP-Client.

### P2 – Dienste-Register

`handlers` in `honeypot/manager.go` ist die einzige Liste im Honeypot; `knownServices` in `config.go` ist entfallen. `TestServiceListsInSync` liest `hive/sensors.go` und `hive/web/app.js` und schlägt fehl, wenn dort ein Dienst fehlt. Im Docker-Build (nur ein Modul im Kontext) überspringt sich der Test.

### P3 – Muster-Analyse (`hive/analyze.go`)

- `patterns`: 23 Regeln in drei Gruppen (`cmd` für Befehle, `web` für Pfad/Body/Kopfzeilen, `raw` für rohe Daten), je mit Name, Beschreibung und Schweregrad 1–3.
- `commandTools`/`eventTools`: benutzte Programme (erstes Wort je Teilbefehl aus einer festen Liste), installierte Pakete und gezogene Images (`installiert: …`), Scanner aus dem User-Agent (`Scanner: …`), SSH-Clients (`SSH-Client: …`).
- **Zählen beim Schreiben:** `topKeys` in `store.go` trägt Muster (`tag`), Werkzeuge (`tool`) und Nachlade-Adressen (`url`) in `top_hourly` ein. Die Ansicht „Analyse“ liest nur diese Zähler (`/api/stats/top?field=tag|tool|url`), also ohne Tabellen-Scan.
- UI: `viewAnalysis` in `hive/web/extra.js`.

Designentscheidungen:

- **Regeln im Code statt in einer Datei:** kein neues Format, kein Ladefehler zur Laufzeit, Test je Regel erzwungen. Nachteil: Eine neue Regel braucht einen Build.
- **Kosten:** je Befehl oder Anfrage rund 20 reguläre Ausdrücke auf höchstens 2–5 KB Text. Die Drossel im Honeypot (10 Ereignisse/s je IP) begrenzt die Last.
- **Zähler gelten ab dem Update.** Alte Ereignisse werden nicht nachgezählt (P20); der Angriffsbericht wertet sie aber aus.

Tests: `TestPatterns` (ein Beispiel je Regel, harmlose Texte lösen nichts aus), `TestCommandTools`, `TestTagAndToolCounters`.

### P4 – Angriffsbericht

`BuildReport` (`analyze.go`) fasst die Ereignisse einer IP oder Sitzung zusammen: Einstufung (niedrig/mittel/hoch), Kurzfassung in Sätzen, Muster mit Beispiel, Werkzeuge, Zugangsdaten, Anfragen, Nachlade-Adressen, Dateien, SHA-256 der Downloads, Clients, Befehle in Reihenfolge. `GET /api/report?ip=…|session=…` (`report.go`); mit `format=text` als Textdatei. UI: `reportCard` auf den Seiten „Angreifer“ und „Sitzung“.

- Ausgewertet werden die neuesten 5.000 Ereignisse (`reportMaxEvents`); mehr setzt `truncated`.
- Einstufung: hoch bei einem Muster mit Schweregrad 3 oder einem gelungenen Download; mittel bei Befehlen, Mustern mit Schweregrad 2 oder einem Login, den Cowrie als erfolgreich meldet; sonst niedrig.
- Listen im JSON sind nie `null` (die UI ruft `.length` auf); `TestBuildReport` prüft das.

Tests: `TestBuildReport`, `TestReportEndpoint`.

### P5 – KI-Auswertung

`POST /api/report/ai` schickt den Berichtstext an eine OpenAI-kompatible Schnittstelle (`<Adresse>/chat/completions`) und speichert die Antwort in `lookups` (`source = ai`). Einrichtung unter Einstellungen → „KI-Auswertung“: Adresse, Modell, Schlüssel.

- **Ein Protokoll für alle:** Ollama (`http://<Rechner>:11434/v1`), LM Studio und OpenRouter (`https://openrouter.ai/api/v1`) sprechen dasselbe Format; es gibt keinen anbieterspezifischen Code.
- **Nur auf Knopfdruck**, nie automatisch, und nur eine Anfrage gleichzeitig (`aiSem`). Zeitlimit 5 Minuten (lokale Modelle sind langsam).
- **Prompt-Injection:** Der Bericht enthält Text des Angreifers. Der Systemprompt (`aiSystemPrompt`) weist das Modell an, Inhalte nicht als Anweisungen zu behandeln. Die Antwort wird nur als Text angezeigt und löst nichts aus; im schlimmsten Fall steht Unsinn in der Auswertung.
- **Datenschutz:** Bei einem Dienst im Internet verlassen IP-Adressen, Zugangsdaten und Befehle das Heimnetz. Die UI warnt in den Einstellungen; Standard ist aus.

Tests: `TestAskAI`, `TestReportAIStoresResult` (gegen `httptest`). Gegen ein echtes Modell nicht geprüft.

### P6 – Live-Karte

- `worldMap(points, { home, large })` in `charts.js`: Standort-Marker; `attack(lat, lon, service)` zeichnet einen Bogen vom Ursprung zum Standort (Farbe = Dienst), der sich aufbaut und verblasst, plus Puls am Ursprung und am Ziel. Reine CSS-Animation (`.map .arc`, `pathLength = 1`); bei „Bewegung reduzieren“ im Betriebssystem ohne Animation.
- Neue Ansicht „Live-Karte“ (`viewLive`): große Karte, Angriffe pro Minute, Länder der letzten 10 Minuten, Laufliste der letzten 60 Ereignisse, Dienste seit Öffnen.
- Der Standort kommt aus den Einstellungen (`extras.home`, Standard Mitte Deutschlands). Er wird nicht automatisch ermittelt: Das bräuchte einen fremden Dienst oder die eigene öffentliche IP in GeoIP, und ein ungefährer Ort genügt.

Geprüft im Browser mit von Hand ausgelösten Linien. Mit echten Live-Ereignissen ungeprüft, weil lokal keine GeoIP-Datenbank geladen war (Ereignisse ohne Koordinaten zeichnen keine Linie).

### P7 – TTY-Mitschnitte

- `CowrieTail.handle` übersetzt `cowrie.log.closed` in ein Ereignis vom neuen Typ `tty` (`shasum`, `size`, `duration_s`).
- `GET /api/sessions/{id}/tty` (`tty.go`) liest `<HIVE_COWRIE_LIB>/tty/<shasum>` und liefert Abschnitte mit Zeit, Richtung und Text. Der Dateiname ist immer ein geprüfter SHA-256-Wert, nie ein Pfad aus den Daten.
- `ttyClean` entfernt ANSI-Steuerfolgen und Steuerzeichen; die UI (`ttyCard`) zeigt reinen Text, Eingaben grün, mit „Abspielen“.
- Grenzen: 2 MB je Datei, 256 KB Text, 4.000 Abschnitte. Der `janitor` löscht Mitschnitte nach `COWRIE_KEEP_DAYS`; dann antwortet der Endpunkt mit 410.

**Annahme:** Das Dateiformat (24 Byte Kopf, `<iLiiLL`) stammt aus dem Cowrie-Quelltext, wie ich ihn kenne. Gegen einen laufenden Cowrie-Container 3.1.6 ist es nicht geprüft. Stimmt es nicht, zeigt die UI einen leeren oder gekürzten Mitschnitt; abstürzen kann der Parser nicht (Längen geprüft, `TestParseTTYLog`).

Tests: `TestParseTTYLog`, `TestCowrieTTYEventAndEndpoint` (inklusive abgelehntem Pfad und aufgeräumter Datei).

### P8 – Benachrichtigungen (`hive/notify.go`)

Ziele: ntfy (POST auf die Themen-Adresse), Telegram (`sendMessage`), Webhook (JSON). Anlässe: erfolgreicher Cowrie-Login, Download, Muster mit Schweregrad 3, erster Befehl einer Sitzung, kritische Systemwarnung (`watchWarnings`, jede höchstens alle 6 Stunden).

- Der Notifier hängt hinter dem Writer: Nur gespeicherte Ereignisse lösen aus, und `OnEvent` blockiert nie.
- **Schutz vor Fluten:** je Art und IP eine Meldung in 10 Minuten, insgesamt `max_per_hour` (Standard 20), Warteschlange 64. Unterdrückte Meldungen werden gezählt (System, Einstellungen).
- Fehlertexte enthalten das Telegram-Token nie (es steht in der Adresse; `Send` ersetzt es).
- Titel gehen bei ntfy als HTTP-Kopfzeile; `asciiHeader` ersetzt Umlaute.

Tests: `TestNotifier` (Abklingzeit, Stundenlimit, drei Ziele, Token nicht im Fehler). Gegen ntfy.sh und Telegram nicht geprüft („keine fremden Dienste ansprechen“).

### P9 – AbuseIPDB

`GET /api/attackers/{ip}/intel`: Abfrage nur auf Knopfdruck, private Adressen werden abgelehnt, Ergebnis 24 Stunden in `lookups`. Gespeichert werden nur die angezeigten Felder. Daneben Links zu AbuseIPDB, GreyNoise, Shodan und VirusTotal (öffnen die Seite des Dienstes, ohne Referrer).

Tests: `TestIntelCacheAndPrivate`. Gegen die echte API nicht geprüft; Adresse und Felder (`/api/v2/check`, Kopfzeile `Key`) nach meiner Kenntnis der API v2.

### Zusatz-Einstellungen (`hive/extras.go`)

Ein JSON-Objekt unter `kv.extras`, im Speicher gehalten (`extrasCache`). **Geheimnisse verlassen den Hive nicht:** `GET /api/extras` liefert sie leer und meldet unter `secrets` nur, ob sie gesetzt sind. Beim Speichern heißt leer „behalten“ und `-` „löschen“. Adressen müssen mit `http://` oder `https://` beginnen. Test: `TestExtrasSecretsStayInside`.

### P10 – Filter und Tastatur

`eventFilter` kennt zusätzlich `dst_port` und `sensor`; der Live-Feed hat Felder für Land und Port. Ereigniszeilen haben `tabindex` und klappen mit Eingabe- oder Leertaste auf.

### P11 – SD-Karten, Raspberry Pi

`HIVE_FLUSH_MS` (Standard 300, 100–60000) bestimmt, wie oft der Writer schreibt. Ein größerer Wert bündelt mehr Ereignisse je Transaktion; der Live-Feed verzögert sich entsprechend, und bei Stromausfall geht höchstens dieser Zeitraum verloren. README: Abschnitt „Raspberry Pi“.

### P12 – Absturz ohne `HIVE_SENSOR_LISTEN`

In 0.2.0 registrierte `main` die Sensor-API im Entwicklungsmodus als Präfix `/api/sensor/` neben `GET /`. Go 1.22+ lehnt das als Konflikt ab; der Hive stürzte beim Start ab. Betroffen war nur der in der README beschriebene Start ohne eigenen Sensor-Port, nicht der Docker-Betrieb. Die Routen stehen jetzt in `Hive.routes` und werden einzeln mit Methode registriert. Test: `TestRoutesBothModes`.

### P13 – Telnet glaubwürdiger (`honeypot/proto_telnet.go`)

Vorher nahm Telnet jeden Login an – ein deutliches Honeypot-Signal. Jetzt hat jedes Konto genau **ein** gültiges Passwort (`telnetAccounts`), ausgewählt per FNV-1a aus Hostname und Kontoname. So ist es je Gerät verschieden, aber über Neustarts stabil (wie ein echtes Werkspasswort). Falsche Anmeldungen bekommen nach 1,5–2,7 s Pause `Login incorrect`, nach drei Versuchen endet die Verbindung. Bots, die bekannte Werkspasswörter durchgehen (Mirai u. a.), treffen trotzdem; wer zufällige Zugangsdaten probiert, kommt nicht hinein. Die Schein-Shell beantwortet jetzt `echo -e` (mit `\xNN`), `cat /proc/cpuinfo`, `/proc/mounts`, `ps`, `ls`, `uname -a` glaubwürdig; `wget`/`curl`/`tftp` melden „Network is unreachable“ (als säße das Gerät hinter einer Firewall). Das Feld `accepted` im Login-Ereignis sagt, ob der Login angenommen wurde. Tests: `TestTelnetLoginAndShell` (falsch, dann richtig), `TestTelnetRejectsLikeRealDevice`.

Grenze: Ein Angreifer, der für denselben Benutzer zwei Passwörter als gültig erwartet oder das Zeitverhalten genau vermisst, kann es weiterhin erkennen. Das volle Verhalten eines Geräts bildet nur Cowrie nach.

### P14 – Version 0.3.0, Fußzeile, Port-Anpassung

- `HONEYLITE_VERSION` steht überall auf 0.3.0 (`docker-compose.yml`, `.env.example`, Release-Workflow).
- **Fußzeile** (`credit()` in `app.js`) mit Name, Version und „Erdacht mit ♥ von Luis Blum · gebaut mit KI" – übernommen aus dem Projekt Heimdeck (`/c/hd/heimdeck/web/src/lib/Credit.svelte`). In der Anwendung zeigt sie zusätzlich einen Update-Hinweis (P16).
- **Automatische Port-Anpassung** (`upgradeSensorConfigs` in `setup.go`): Läuft einmal (Merker `config_level` in `kv`) über jede gespeicherte Sensor-Konfiguration. Port 5900 mit Dienst `raw` wird zu `vnc`; SMTP (25), Telnet (2323) und RDP (3389) kommen dazu, sofern ihre Ports frei sind. Was der Nutzer selbst eingestellt hat, bleibt. Damit erscheinen die neuen Dienste nach dem Update von selbst, ohne dass man sie von Hand hinzufügt (auf Wunsch des Nutzers, der die erste Frage so beantwortet hat). Test: `TestUpgradeSensorConfigs`.

### P15 – Ersteinrichtung in der Web-UI (`hive/setup.go`)

Ist kein Admin-Konto vorhanden und keines per `HIVE_ADMIN_PASSWORD` vorgegeben, legt `EnsureAdmin` keins mehr an (vorher: zufälliges Passwort ins Log). Stattdessen zeigt die UI (`showSetup` in `app.js`) einen Assistenten: Passwort (zweimal) und Standort für die Karte. `POST /api/setup` legt das Konto an und meldet sofort an.

- **Wer zuerst kommt, mahlt:** Bei Heimnetz-Geräten üblich und der Grund, warum die UI nie ins Internet gehört (steht so in der README). `GET /api/setup` verrät nur, ob die Einrichtung nötig ist; sobald ein Konto existiert, ist der Weg mit 409 dauerhaft zu (`setupMu` schützt gegen Wettlauf, `attempt` drosselt).
- Test: `TestSetupOnlyOnce` (ohne Header 403, zu kurzes Passwort 400, Erfolg setzt Cookie, zweiter Versuch 409).

### P16 – Update-Prüfung gegen GitHub (`hive/setup.go`)

`checkUpdates` fragt zweimal täglich die Releases-Liste des Repositorys ab (`newestRelease`, semantischer Vergleich in `parseSemver`/`newer`). Die Fußzeile zeigt dann „Version X ist da" mit Link auf die Veröffentlichung. Abschalten mit `HIVE_UPDATE_CHECK=off`; Entwicklungs-Builds („dev") prüfen nie. Solange das Repository privat ist, antwortet GitHub mit 404 und es erscheint kein Hinweis – das ist in Ordnung.

Nur wo ein Updater eingerichtet ist (`HIVE_UPDATE_REQUEST`, also das Pi-Image), erscheint zusätzlich der Knopf „Jetzt aktualisieren". Er ruft `POST /api/update`; der Hive hat selbst keine Rechte, sich zu ersetzen, und legt nur die geprüfte Versionsnummer in eine Datei (`updateRun`). Tests: `TestNewestRelease`, `TestUpdateRequestFile`. Gegen die echte GitHub-API nicht geprüft; nur eigene `MrLuigi938/honeylite`-Adressen werden verlinkt.

### P17 – Raspberry-Pi-Image (`pi/`)

Das Image ist ein Raspberry Pi OS Lite, in das `pi/build-image.sh` HoneyLite hineinlegt – ohne ARM-Emulation (es wird nichts im Image ausgeführt). Enthalten:

- **systemd-Dienste** (`pi/rootfs/etc/systemd/system/`): `honeylite-hive` und `honeylite-honeypot`, beide gehärtet (eigene Benutzer `honeylite-hive`/`honeylite-pot`, `ProtectSystem=strict`, Capabilities leer bzw. nur `CAP_NET_BIND_SERVICE`, Speichergrenzen). Der Honeypot lauscht direkt auf den echten Ports, deshalb kein Port-Versatz und `HIVE_DIRECT_PORTS=1` für die UI-Anzeige.
- **Erster Start** (`honeylite-firstboot`): erzeugt nur das gemeinsame Token. Das Admin-Passwort vergibt der Nutzer im Browser (P15). Kein Docker, keine Konsole – der Wunsch war „aufspielen, einstecken, im Browser einrichten".
- **Netzsperre** (`honeylite-firewall`): sperrt neue ausgehende Verbindungen des Honeypot-Benutzers per nftables oder iptables (owner-Match), erlaubt nur Antworten und den Weg zum Hive auf 127.0.0.1:8089.
- **Update über die UI** (`honeylite-update.path` + `honeylite-update`): Der Pfad-Unit bemerkt die vom Hive abgelegte Anforderung, der Updater lädt das Programmpaket der Version von GitHub, prüft `SHA256SUMS`, sichert die Datenbank, tauscht die Programme und startet neu – mit Rückfall auf die alte Version, wenn der Hive danach nicht läuft. Nur die beiden Programme werden ersetzt; Änderungen an systemd-Dateien brauchen ein neues Image.
- **Cowrie ist nicht dabei** (Python, zu viel RAM). SSH/Telnet decken SSH-Tarpit und der Telnet-Honeypot ab; also keine echte Fake-Shell und keine TTY-Mitschnitte auf dem Pi.

Die Release-Pipeline (`release.yml`) baut je Tag: Docker-Images (wie bisher), Programmpakete `honeylite-<tag>-linux-<arch>.tar.gz` mit `SHA256SUMS` (für den Selbst-Update-Weg) und die Pi-Images, und legt alles in eine GitHub-Veröffentlichung. Das Pi-Image lässt sich über „Run workflow" auch ohne Tag zum Testen bauen.

Der Bauweg wurde in der dritten Runde ersetzt (P26): siehe dort.

### P18 – Muster nachzählen (`hive/setup.go`)

`backfillPatterns` trägt Muster, Werkzeuge und Nachlade-Adressen (`top_hourly`, Felder `tag`/`tool`/`url`) für Ereignisse nach, die vor 0.3.0 gespeichert wurden. Läuft einmal im Hintergrund in 500er-Schritten (Merker `patterns_backfilled`). Die Obergrenze `maxID` wird **vor** dem Start des Schreibers ermittelt, damit neue Ereignisse nicht doppelt gezählt werden. Test: `TestBackfillPatternsOnce`.

### P21 – GreyNoise (`hive/intel2.go`)

`GET /api/attackers/{ip}/greynoise` fragt `https://api.greynoise.io/v3/community/<ip>` ab, optional mit Schlüssel (Kopfzeile `key`, Feld `greynoise_key` in den Zusatz-Einstellungen). Eine 404-Antwort heißt „IP nicht bekannt“ und gilt als Ergebnis. Gespeichert werden `noise`, `riot`, `classification`, `name`, `last_seen`, `message`, 24 Stunden in `lookups` (source `greynoise`). Private Adressen werden nicht abgefragt. Test: `TestGreyNoise`. Gegen die echte API nicht geprüft; Adresse und Felder nach bestem Wissen über die Community-API v3.

### P23 – UDP-Dienste (`honeypot/proto_udp.go`)

`sip`, `snmp`, `dns` sind ein eigenes Register (`udpHandlers`). Der Manager öffnet für sie `net.ListenPacket("udp")`; `serveUDP` liest Pakete (höchstens 2 KB), drosselt je IP wie TCP und ruft den Parser. **Es wird nie geantwortet** (Absender fälschbar, Reflexions- und Verstärkungsgefahr). Ereignisse: SIP als `request` (Methode, Ziel, User-Agent, From/To), SNMP v1/v2c als `login` mit Benutzer `community` und dem Community-String als Passwort, DNS als `request` (`DNS ANY`, Name). Unlesbares wird `payload`. Modi spielen keine Rolle.

Standard: SIP 5060 und SNMP 161 an, DNS 53 aus (viele Router brauchen 53 selbst). Bestehende Installationen bekommen sie über `configUpgrades` Stufe 2 (`hive/setup.go`) einmalig ergänzt. Compose-Ports mit `/udp`, `PORT_SIP`, `PORT_SNMP`, `PORT_DNS`. Tests: `TestSIPEvent`, `TestSNMPEvent`, `TestDNSEvent`, `TestUDPListenerNeverReplies` (prüft ausdrücklich, dass keine Antwort kommt), Fuzz-Ziel `FuzzUDPParsers`.

### P24 – Leserolle (`hive/users.go`, `hive/auth.go`)

Migration 4 ergänzt `users.role` (`admin`, `viewer`). `Auth.Who` liefert Benutzer und Rolle; Sitzungen gelöschter Benutzer gelten sofort nicht mehr. `Require` lässt Viewer nur lesen (`viewerAllowed`): alle GET-Aufrufe außer `/api/extras` (enthält z. B. das ntfy-Thema, das selbst ein Geheimnis ist) und `/api/users`; schreibend nur Passwortwechsel und Abmelden. Admins verwalten Benutzer unter Einstellungen → Benutzer; das eigene Konto und der letzte Admin lassen sich nicht löschen. Nebenbei behoben: Ein Passwortwechsel meldete bisher alle Sitzungen **aller** Benutzer ab, jetzt nur die eigenen. UI: Viewer sehen die Einstellungen nicht in der Navigation und keinen KI- oder Update-Knopf. Test: `TestViewerRole`; im Browser geprüft.

### P25 – STIX-Export (`hive/intel2.go`)

`GET /api/export/stix?range=…&min=…` liefert ein STIX-2.1-Bundle: eine `identity` (HoneyLite) und je ein `indicator` für öffentliche Angreifer-IPs (IPv4/IPv6), Nachlade-Adressen (aus `top_hourly`) und SHA-256 der Downloads. Werte in Mustern werden maskiert (`stixString`: `\` und `'`). Knopf „STIX“ im Live-Feed neben der Blockliste. Test: `TestExportSTIX` (inkl. Maskierung, private IP ausgeschlossen).

### P26 – Pi-Image bauen, ohne Linux (`pi/build_image.py`, `pi/install.sh`)

Auf dem Windows-Entwicklungsrechner gibt es kein WSL2 (Hyper-V nicht aktiv; das wurde als Systemeinstellung nicht geändert). Der Loop-Mount-Ansatz (`build-image.sh`, Root nötig) wurde deshalb durch einen Bauweg ersetzt, der **nur die FAT32-Bootpartition** ändert:

- **Grundlage:** Raspberry Pi OS Lite „trixie“ (Debian 13) vom 06.10.2026, festgelegt mit SHA-256 in `BASE`. Untersucht (ext4 nur gelesen): trixie richtet sich beim ersten Start mit **cloud-init** (NoCloud, Dateien `user-data`, `meta-data`, `network-config` auf der Bootpartition) ein; `nft`, `curl`, `avahi-daemon`, `systemd-sysusers`, `userconf-pi` sind vorhanden; SSH ist nicht eingeschaltet; Bootpartition unter `/boot/firmware`.
- **Inhalt der Bootpartition:** `honeylite/payload.tar.gz` (Programme und `pi/rootfs`, mit Rechten für Linux) samt Prüfsumme, `honeylite/install.sh`, eigene `user-data` (Hostname `honeylite`, `runcmd` startet den Installer), `vendor-data` (zweiter Anstoß, falls jemand user-data ersetzt), `userconf.txt` (Benutzer `honeylite` mit dem Hash eines zufälligen, unbekannten Passworts; ohne gültigen Hash würde Raspberry Pi OS am Bildschirm auf Eingaben warten) und `HONEYLITE.txt` (Kurzanleitung).
- **Erster Start:** Pi vergrößert die Partition, startet neu, cloud-init führt `install.sh` aus (einmalig, mit Sperre), danach laufen Hive, Honeypot, Netzsperre und Updater. Die Bootpartition wird aufgeräumt.
- **Gegenprobe beim Bau:** Jede geschriebene Datei wird aus dem Abbild wieder gelesen und verglichen. Das fertige Image prüft `pi/verify_image.py` (49 Prüfungen: Prüfsummen, Dateien der Bootpartition, unveränderte `cmdline.txt`, gültiger Passwort-Hash, Rechte und Besitzer im Paket, Architektur der Programme, Unix-Zeilenenden); die Release-Pipeline ruft es nach jedem Bau auf.
- shellcheck (0.10.0, lokal geladen) läuft sauber über alle Shell-Skripte.

Gebaut: `honeylite-pi-arm64-v0.3.0.img.xz` für Pi 3/4/5/Zero 2 W (liegt außerhalb des Repos unter `C:\claude\honeylite\dist\`, `dist/` ist ignoriert).

**Nicht geprüft:** Das Image lief noch auf keinem echten Pi und auch nicht in einer Emulation. Ungeprüft sind damit: cloud-init führt `vendor-data` als Skript aus (nur Rückfallweg), `userconf.txt` mit SHA-512-Hash übernimmt den Benutzer ohne Rückfrage, die Netzsperre per nftables-UID-Regel, `CAP_NET_BIND_SERVICE` für Ports unter 1024, mDNS unter `honeylite.local`, der Updater. Das ist das wichtigste Risiko.

## 4. Rahmenbedingungen

| Vorgabe | Stand |
|---|---|
| Unter 512 MB RAM | Keine neuen Container, keine großen Puffer. Neue Speicherverbraucher sind begrenzt: Notifier (64 Meldungen, Karten mit höchstens 5.000 Einträgen), Bericht (5.000 Ereignisse, nur während der Anfrage), Mitschnitt (2 MB, nur während der Anfrage). Nicht auf Hardware gemessen. |
| Container ohne Root, keine neuen Rechte | `docker-compose.yml` nur um drei Ports und eine Variable ergänzt. |
| Angreiferdaten nie als HTML | Neue UI-Teile nutzen nur `h()`; im Browser geprüft mit `<script>`- und `<b>`-Text in Befehl und Mitschnitt (keine Elemente entstanden). Adressen aus Angreiferdaten sind nie Links. |
| Größenbudget je Ereignis | `TestNewProtocolsSizeBudget` für die neuen Dienste; `TestEventSizeContract` unverändert grün. |
| Ereignisformat abwärtskompatibel | Nur Ergänzungen: Typ `tty`, neue Dienste, neue Felder in `data` (siehe `events.md`). Ein Hive 0.2.0 verwirft den Typ `tty` nicht, weil er ihn nie bekommt (er entsteht im Hive). |
| UI und Doku auf Deutsch | ja |

## 5. Bekannte Risiken

1. **Windows-Virenscanner und die Miner-Regel.** Mit dem Namen des Monero-Hash-Verfahrens in der Regel `miner` hielt der Virenscanner des Entwicklungsrechners das Windows-Binary des Hive für einen Miner und sperrte Build und Tests („Zugriff verweigert“ beim Linken). Die Regel und ihr Testbeispiel kommen deshalb ohne diesen Begriff aus. Linux-Builds waren nie betroffen. Wer Regeln mit vielen Malware-Namen ergänzt, kann das wieder auslösen; dann die Begriffe einzeln prüfen. Am Virenscanner wurde nichts geändert.
2. **Raspberry-Pi-Image gebaut, aber auf echter Hardware unerprobt.** Das ist das größte Risiko. Einzelheiten unter P26. Vor einer Veröffentlichung: auf einen Pi spielen, im Browser einrichten, Router-Weiterleitung testen, Update auslösen. Raspberry Pi Imager mit „Anpassungen“ ersetzt `user-data`; dann greift nur noch der Rückfallweg über `vendor-data`. Die README sagt deshalb: Anpassungen ablehnen.
3. **Ungeprüft gegen echte Gegenstellen:** Cowrie-Mitschnittformat, ntfy, Telegram, AbuseIPDB, KI-Schnittstellen, echter RDP-Client, GitHub-Releases-API. Alles ist gegen nachgebaute Server getestet.
4. **Docker:** Auf dem Entwicklungsrechner gibt es kein Docker. Die geänderte `docker-compose.yml` und die Images prüft erst die CI (`docker compose config`, Multi-Arch-Build). `staticcheck`, `govulncheck`, Race-Detector und `shellcheck` (jetzt auch für `pi/`) laufen ebenfalls nur dort.
5. **Fehlalarme der Muster.** Die Regeln sind bewusst einfach. `web_rce` und `recon` treffen breit. Wer danach benachrichtigt wird (Schweregrad 3), sollte die Liste beobachten und Regeln schärfen.
6. **Telnet bleibt für geübte Scanner erkennbar.** Es nimmt zwar nicht mehr jeden Login an (P13), aber das volle Verhalten eines Geräts bildet nur Cowrie nach.
7. **Ersteinrichtung ist offen, wer zuerst kommt.** Solange kein Konto besteht, kann jeder, der die UI erreicht, das Passwort setzen. Deshalb darf die UI nie ins Internet (steht in README und Code-Kommentar). Im Docker-Betrieb bindet sie standardmäßig an die LAN-IP.
8. **SMB und RDP-NLA weiterhin offen.** Ein erster Versuch, NTLM-Anmeldedaten zu lesen, wurde vom Sicherheitsfilter der Entwicklungsumgebung abgebrochen und verworfen; nicht wieder aufgenommen. Wer das ergänzt, braucht einen echten Client (z. B. aus einer SMB-/RDP-Bibliothek) zum Testen.
9. **KI-Auswertung kann falsch liegen** und kostet bei Diensten im Internet Geld je Anfrage. Sie ist deshalb aus und nur auf Knopfdruck.
10. **Der Hive baut neue ausgehende Verbindungen auf** (Benachrichtigungen, KI, AbuseIPDB, Update-Prüfung), aber nur zu Adressen, die der Admin eingetragen hat bzw. zur festen GitHub-Adresse. Ein Angreifer kann diese Adressen nicht beeinflussen.

## 6. Offene Fragen für den Nutzer

Die drei Fragen der ersten Runde hat der Nutzer beantwortet und sie sind umgesetzt: Port 5900 wechselt bei bestehenden Installationen automatisch auf `vnc` (P14), Telnet läuft standardmäßig und wurde zugleich unauffälliger gemacht (P13), die Version ist 0.3.0. Offen bleibt vor allem:

1. Das Pi-Image ist gebaut, aber nicht auf echter Hardware erprobt (P26). Bitte einmal auf einen Pi 3 spielen und berichten: Erscheint die Web-UI unter `http://honeylite.local:8088`? Wenn nicht, hilft `/var/log/honeylite-install.log` (Bildschirm anschließen oder Karte am Rechner lesen).
2. Der Update-Knopf und die GitHub-Prüfung greifen erst, wenn das Repository öffentlich ist und es echte Releases gibt. Solange es privat ist, erscheint kein Hinweis.

## 7. So prüft man den Branch

```bash
sh tools/check.sh                      # gofmt, vet, Tests, Cross-Build (amd64, arm64, armv7)
cd honeypot && go test -run='^$' -fuzz='^FuzzRDP$' -fuzztime=20s .
```

UI von Hand: Hive lokal starten (ARCHITEKTUR.md, Abschnitt 8), dann

1. Erster Start ohne `HIVE_ADMIN_PASSWORD`: Der Einrichtungs-Assistent erscheint; danach ist man angemeldet und die Fußzeile zeigt Version und Urheber.
2. Dashboard: grüner Standort-Marker; Live-Karte zeichnet mit GeoIP-Daten je Verbindung eine Linie.
3. Seite eines Angreifers: Angriffsbericht, „Als Text speichern", Reputation. Analyse: Muster, Programme, Nachlade-Adressen.
4. Cowrie-Sitzung mit Mitschnitt: „Mitschnitt anzeigen", „Abspielen".
5. Einstellungen: Zusatzfunktionen speichern, Seite neu laden, Geheimnisfelder bleiben leer mit Hinweis „gespeichert".

Telnet von Hand (zeigt das Geräteverhalten):

```bash
# Passwort des Testgeräts: hängt vom Hostnamen ab; der Simulator probiert bekannte Werkspasswörter
python3 tools/attack_sim.py --host <NAS>   # schickt u. a. den Telnet-Bot-Ablauf
```

Pi-Image (überall, ohne Root): `pip install pyfatfs==1.1.0`, Programme für `linux/arm64` bauen, dann `python3 pi/build_image.py --arch arm64 --version v0.3.0 --bin <ordner> --out dist`. Gegenprobe: Bootpartition des Ergebnisses öffnen (`pyfatfs`), `honeylite/payload.tar.gz` gegen `payload.tar.gz.sha256` prüfen und den Inhalt listen.

## 8. Commits auf dem Branch

Siehe `git log 60bc36b..HEAD`. Reihenfolge: Plan; Honeypot-Protokolle; Hive-Funktionen (Analyse, Bericht, KI, Benachrichtigungen, AbuseIPDB, TTY); UI (Live-Karte, Analyse, Bericht); Dokumentation; Telnet-Verhalten; Version 0.3.0 mit Ersteinrichtung, Update-Prüfung und Fußzeile; Raspberry-Pi-Image mit Updater und Release-Pipeline; dritte Runde: GreyNoise, STIX, Leserolle, UDP-Dienste, neuer Pi-Bauweg, gebautes Image.
