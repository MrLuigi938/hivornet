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
| P13 | SMB (Negotiate, NTLM-Benutzername) | mittel | hoch | offen |
| P14 | RDP mit NLA/CredSSP | mittel | hoch | offen |
| P15 | GreyNoise per API | niedrig | mittel | offen (Links vorhanden) |
| P16 | UDP-Dienste (SIP, SNMP, DNS) | mittel | hoch | offen |
| P17 | Mehrbenutzer, Leserolle, zweiter Faktor | niedrig | hoch | offen |
| P18 | Fertiges Raspberry-Pi-Image | mittel | hoch | offen |
| P19 | STIX/MISP-Export | niedrig | mittel | offen |
| P20 | Muster rückwirkend für alte Ereignisse zählen | niedrig | niedrig | offen |
| P21 | Ländergrenzen auf der Karte (Einfärbung nach Land) | niedrig | mittel | offen |
| P22 | `proto_other.go` in eine Datei je Protokoll teilen | niedrig | niedrig | verworfen |

Begründungen:

- **P13, P14 offen:** Beide brauchen einen NTLM-Dialog (SPNEGO bzw. CredSSP in ASN.1). Das sind einige hundert Zeilen Binärprotokoll, die sich ohne echten Client auf dem Entwicklungsrechner nicht verlässlich prüfen lassen.
- **P15 offen:** Die Community-API von GreyNoise habe ich nicht aus sicherer Kenntnis parat und nicht nachgeschlagen; statt zu raten, gibt es nur den Link zur GreyNoise-Seite der IP.
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
2. **Ungeprüft gegen echte Gegenstellen:** Cowrie-Mitschnittformat, ntfy, Telegram, AbuseIPDB, KI-Schnittstellen, echter RDP-Client. Alles ist gegen nachgebaute Server getestet.
3. **Docker:** Auf dem Entwicklungsrechner gibt es kein Docker. Die geänderte `docker-compose.yml` und die Images prüft erst die CI (`docker compose config`, Multi-Arch-Build). `staticcheck`, `govulncheck`, Race-Detector und `shellcheck` (neu: `tools/check.sh`) laufen ebenfalls nur dort.
4. **Fehlalarme der Muster.** Die Regeln sind bewusst einfach. `web_rce` und `recon` treffen breit. Wer danach benachrichtigt wird (Schweregrad 3), sollte die Liste beobachten und Regeln schärfen.
5. **Telnet nimmt jeden Login an.** Das macht den Dienst für geübte Scanner als Honeypot erkennbar, liefert aber die Befehle. Cowrie auf Port 23 verhält sich realistischer.
6. **KI-Auswertung kann falsch liegen** und kostet bei Diensten im Internet Geld je Anfrage. Sie ist deshalb aus und nur auf Knopfdruck.
7. **Der Hive baut neue ausgehende Verbindungen auf** (Benachrichtigungen, KI, AbuseIPDB), aber nur zu Adressen, die der Admin eingetragen hat. Ein Angreifer kann diese Adressen nicht beeinflussen.

## 6. Offene Fragen für den Nutzer

1. Soll Port 5900 bei bestehenden Installationen automatisch von `raw` auf `vnc` wechseln? Derzeit nicht; die gespeicherte Konfiguration bleibt unangetastet.
2. Soll Telnet auf 2323 standardmäßig laufen, obwohl es jeden Login annimmt?
3. Version: Die Änderungen stehen im CHANGELOG unter `[Unreleased]`; `HONEYLITE_VERSION` steht weiter auf 0.2.0. Vorschlag: 0.3.0.

## 7. So prüft man den Branch

```bash
sh tools/check.sh                      # gofmt, vet, Tests, Cross-Build (amd64, arm64, armv7)
cd honeypot && go test -run='^$' -fuzz='^FuzzRDP$' -fuzztime=20s .
```

UI von Hand: Hive lokal starten (ARCHITEKTUR.md, Abschnitt 8), dann

1. Dashboard: grüner Standort-Marker auf der Karte.
2. Live-Karte: mit GeoIP-Daten zeichnet jede neue Verbindung eine Linie.
3. Seite eines Angreifers: Angriffsbericht, „Als Text speichern“, Reputation.
4. Cowrie-Sitzung mit Mitschnitt: „Mitschnitt anzeigen“, „Abspielen“.
5. Analyse: Muster, Programme, Nachlade-Adressen.
6. Einstellungen: Zusatzfunktionen speichern, Seite neu laden, Geheimnisfelder bleiben leer mit Hinweis „gespeichert“.

Auf der NAS nach dem Update: `python3 tools/attack_sim.py --host <NAS>` und im Live-Feed nach Telnet, SMTP, VNC und RDP sehen.

## 8. Commits auf dem Branch

Siehe `git log 60bc36b..HEAD`. Reihenfolge: Plan, Honeypot-Protokolle, Hive-Funktionen, UI, Dokumentation.
