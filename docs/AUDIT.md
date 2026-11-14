# HoneyLite – unabhängiges Audit

Stand: 14.11.2026, Version 0.1.0 (Honeypot und Hive). Geprüft wurde der gesamte Code in `honeypot/`, `hive/` (inkl. `web/`), `docker-compose.yml`, beide Dockerfiles, die drei Shell-Skripte, `config/honeypot.yml`, `.env.example` und die README. Am Projekt wurde nichts geändert; nur dieser Bericht ist neu.

## 1. Kurzfazit

Die Grundlage ist solide: kein SQL-Injection- und kein XSS-Weg gefunden, die Container sind gut gehärtet, und 21.000 Zufallseingaben plus 4 Mio. Fuzz-Läufe haben keinen Parser zum Absturz gebracht. Für den Betrieb am offenen Internet reicht es aber noch nicht, vor allem aus vier Gründen:

1. **Der Honeypot lässt sich mit einer einzigen Verbindung per Speicherüberlauf abschießen** (HTTP-Kopfzeilen ohne Größengrenze, Redis-Befehle bis 32 MB). Das Limit von 192 MB ist in Sekunden erreicht, der Container startet neu und verliert alle wartenden Ereignisse.
2. **Die Datenbank hat keine Mengenbegrenzung.** Aufbewahrung gibt es nur nach Tagen. Ein Angreifer mit wenig Bandbreite füllt die NAS-Platte in Tagen.
3. **Große Angriffs-Payloads gehen stillschweigend verloren**, weil der Honeypot bis zu 26 KB pro Ereignis erzeugt und der Hive alles über 16 KB verwirft.
4. **Die Honeypot-Container können ins Heimnetz und ins Internet verbinden.** Das betrifft vor allem Cowrie (Python, Image `latest`, beschreibbares Dateisystem).

Kritische Befunde im Sinn von „Angreifer übernimmt Hive oder NAS“ gibt es nicht. Ein Ausbruch aus dem Go-Honeypot ist nach Codelage sehr unwahrscheinlich (speichersichere Sprache, distroless, kein Root, keine Capabilities, nur lesbares Dateisystem).

Zahlen: 0 kritisch, 5 hoch, 13 mittel, 20 niedrig, 9 Hinweise.

### Was geprüft und ausgeführt wurde

| Prüfung | Ergebnis |
|---|---|
| `go vet ./...` in beiden Modulen (Go 1.26.0) | ohne Meldung |
| Cross-Build `linux/arm64` (Honeypot) und `linux/arm` 32 Bit (Hive) | baut |
| 21.000 mutierte und zufällige Eingaben gegen alle 7 Handler | kein Panic |
| Fuzzing von `readRESP`, 20 s, rund 4 Mio. Läufe | kein Panic |
| Gezielte Tests zu den Befunden 1, 2, 5, 7, 21, 22, 25, 31 | bestätigt, Messwerte stehen in der Tabelle |
| `-race`, Docker-Build, laufender Cowrie-Container | **nicht geprüft** (Race-Detector braucht hier cgo, Docker fehlt) |

Die Tests liefen in einer Kopie außerhalb des Projekts. Die Testdateien liegen unter `C:\Users\Luis\AppData\Local\Temp\claude\d5a3fae6481a58f0\89ca6fdb-a59e-4f5a-bcb4-b85ff04d8c64\scratchpad\audit` (`honeypot/audit_test.go`, `hive/audit_test.go`) und lassen sich als Start für echte Tests übernehmen.

Status in der Tabelle: **T** = per Test bestätigt, **C** = aus dem Code eindeutig belegt, **V** = Vermutung, nicht bestätigt.

## 2. Befunde nach Schwere

Pfade ohne Präfix gelten relativ zum Projektordner. `hp/` steht für `honeypot/`.

### Hoch

| Nr. | Stelle | Beschreibung | Szenario | Empfehlung | Status |
|---|---|---|---|---|---|
| 1 | `hp/proto_http.go:49`, `:70-74` | `http.ReadRequest` begrenzt weder die Anfragezeile noch die Kopfzeilen. Die 30-s-Frist ist die einzige Bremse. Betrifft HTTP, HTTPS und Docker-API, in allen drei Modi. | Ein Client schickt `GET /` plus eine Kopfzeile mit 200 MB. Der Prozess überschreitet `mem_limit: 192m` und wird beendet. Mit `restart: unless-stopped` lässt sich das beliebig wiederholen; alle Tarpit-Verbindungen und bis zu 10.000 wartende Ereignisse sind weg. Test: 64 MB Kopfzeile und 64 MB Pfad werden ohne Fehler angenommen. | Verbindung vor dem Parsen in `io.LimitReader` (z. B. 64 KB für Anfragezeile und Kopf) einpacken, danach für den Body neu begrenzen. Alternativ `http.Server` mit `MaxHeaderBytes` auf einem eigenen Listener. | T |
| 2 | `hp/proto_other.go:86`, `:99-106`, `:151` | Ein RESP-Befehl darf 64 Argumente zu je 512 KB haben, also 32 MB. `strings.Join` verdoppelt das, bevor `clip` auf 4 KB kürzt. | Drei parallele Verbindungen mit je einem Maximalbefehl reichen für den OOM-Kill. Gemessen: 96 MB Allokation für einen einzigen Befehl. Pro IP sind 48 Verbindungen erlaubt. | Gesamtgröße je Befehl begrenzen (z. B. 64 KB), Argumente darüber verwerfen statt puffern (`io.CopyN` nach `io.Discard`), nur die ersten 4 KB behalten. | T |
| 3 | `hive/store.go:281-300`, `hp/manager.go:208`, `:214`, `hive/api.go:109-141` | Es gibt keine Obergrenze für Datenbankgröße oder Ereignisrate. Jede TCP-Verbindung erzeugt mindestens zwei Ereignisse, ein HTTP-Request bis 26 KB. Die Tabellen `attackers` und `hourly` werden nie gekürzt. | Ein Angreifer mit 1 Mbit/s Upload und großen POST-Anfragen erzeugt grob 10 GB pro Tag. Bei 30 Tagen Aufbewahrung ist die NAS-Platte voll, lange bevor die Retention greift. Bei voller Platte verliert der Hive Daten (Befund 7) und andere NAS-Dienste leiden mit. | Größenbasierte Retention (älteste Ereignisse löschen ab X GB oder unter Y GB frei), Rate-Limit pro Quell-IP im Honeypot (z. B. Token-Bucket, danach nur noch zählen), `connect`/`disconnect` ohne Inhalt zu einem Zähler verdichten, `attackers` nach `last_seen` kürzen. | C |
| 4 | `docker-compose.yml:75`, `:96`, `:109` | `honeynet` ist ein normales Bridge-Netz. Honeypot und Cowrie können damit ins Internet, zu allen Geräten im LAN und zu Diensten der NAS selbst verbinden. Die README (Z. 111) erwähnt VLAN nur als Empfehlung. | Wird Cowrie über eine Lücke im Python-Code oder einer Abhängigkeit übernommen, steht der Angreifer mit Netzwerkzugriff im Heimnetz (Router, NAS-Oberfläche, Drucker). Zusätzlich lädt Cowrie bei `wget`/`curl` in der Fake-Shell echte URLs. Ob Cowrie private Zieladressen dabei zuverlässig sperrt, habe ich nicht geprüft (**Vermutung**: nur für IP-Literale, nicht für DNS-Namen). | Ausgehenden Verkehr der Honeypot-Container per Firewall auf „nur Antworten“ beschränken (Regel in der Kette `DOCKER-USER`: Ziel RFC1918 und Host verwerfen, neue ausgehende Verbindungen verwerfen oder nur 80/443 für Cowrie-Downloads). In der README als Pflichtschritt dokumentieren, VLAN/DMZ klar empfehlen. | C, Cowrie-Teil V |
| 5 | `hive/store.go:67-69`, `hp/session.go:155-176`, `hp/proto_other.go:366`, `hp/proto_http.go:74-76` | `printable` macht aus jedem nicht druckbaren Byte 4 Zeichen (`\xNN`), JSON verdoppelt den Backslash. Der Honeypot schickt deshalb bis zu 26 KB `data`. Der Hive setzt `data` über 16 KB kommentarlos auf leer. | Ein binärer Exploit von 4 KB auf dem Raw-Port (z. B. RDP- oder VNC-Scanner) ergibt 20.504 Byte `data`. Gespeichert wird das Ereignis ohne jeden Inhalt. Bei HTTP gehen dann auch Pfad, Methode und User-Agent verloren (gemessen 26.214 Byte). Genau die interessantesten Payloads fehlen. | Ein gemeinsames Budget festlegen: im Honeypot Rohbytes auf z. B. 2 KB kürzen oder als Base64/Hex mit festem Faktor speichern, im Hive einzelne Felder kürzen statt alles zu verwerfen und ein Kennzeichen `truncated` setzen. Vertragstest zwischen beiden Seiten. | T |

### Mittel

| Nr. | Stelle | Beschreibung | Szenario | Empfehlung | Status |
|---|---|---|---|---|---|
| 6 | `hp/hive.go:145-155`, `:68`, `hive/api.go:110-117`, `:134-136` | Schlägt das Senden fehl, sammelt der Emitter bis zu 5.000 Ereignisse und schickt sie als einen Block. Bei großen Ereignissen sind das über 100 MB, der Hive nimmt aber nur 16 MB an und antwortet mit 400. Der Emitter versucht denselben Block endlos weiter. Außerdem: Antwortet der Hive mitten im Block mit 503, wird der ganze Block erneut gesendet (Duplikate). | Während `update.sh` ist der Hive 30 s weg, gleichzeitig laufen große HTTP-Anfragen ein (ab etwa 630 Stück). Danach kommt kein Ereignis mehr im Hive an, bis jemand den Honeypot neu startet. In der UI steht nur „Letzter Fehler“. Zusätzlich fasst die Warteschlange 10.000 Ereignisse (`:119`), bei 26 KB je Ereignis sind das 260 MB bei 192 MB Limit. | Blöcke nach Anzahl **und** Bytes begrenzen (z. B. 200 Ereignisse oder 2 MB), bei 4xx den Block halbieren oder verwerfen statt wiederholen, Ereignis-ID mitsenden und im Hive doppelte verwerfen, Warteschlange nach Bytes begrenzen. | C |
| 7 | `hive/store.go:232-244`, `:227-231`, `:254-258`, `:271-274`, `:260-262` | Fehler von `tx.Prepare` werden ignoriert. Ist ein Statement `nil`, stürzt der Hive beim nächsten `Exec` ab. Bei Fehlern in `Begin`, `INSERT` oder `Commit` wird der ganze Block (bis 500 Ereignisse) ohne Wiederholung verworfen. Fehler bei `hourly` und `attackers` werden gar nicht geprüft. | Platte voll oder Datenbank gesperrt: Der Hive verliert Ereignisse ohne Zähler oder stürzt in einer Schleife ab. Test mit fehlender Tabelle: `nil pointer dereference`. | Prepare-Fehler prüfen, Statements einmalig beim Start vorbereiten, fehlgeschlagene Blöcke begrenzt wiederholen, Zähler „verworfen“ in `/api/system` anzeigen. | T (Panic), C (Verlust) |
| 8 | `hive/main.go:112-134`, `:146-150`, `docker-compose.yml:46-47`, `README.md:116` | Sensor-API, Login und Web-UI hängen an einem Listener auf allen Schnittstellen. Der Honeypot-Container erreicht damit auch Login und UI. `HIVE_BIND` steht standardmäßig auf `0.0.0.0`. Die README-Aussage „Der Hive ist nur über ein internes Docker-Netz erreichbar“ stimmt so nicht. | Steht die NAS als „Exposed Host“ im Router oder hat eine zweite Netzwerkkarte, ist die UI von außen sichtbar. Docker-Portfreigaben umgehen dabei die Firewall der NAS. Ein übernommener Honeypot-Container kann den Login angreifen. | Zwei Listener: Sensor-API nur im Netz `ingest`, UI nur im Netz `admin`. `HIVE_BIND` in `install.sh` auf die erkannte LAN-IP setzen. README korrigieren. | C |
| 9 | `hive/store.go:185`, `:67`, `docker-compose.yml:48` | Die Schreib-Warteschlange fasst 20.000 Ereignisse mit je bis zu 16 KB `data`, also über 320 MB bei 384 MB Limit. | Kommen Ereignisse schneller an, als SQLite auf einer langsamen NAS-Platte schreibt (CPU-Limit 0,5), läuft die Warteschlange voll und der Hive wird per OOM beendet. Realistisch nur bei verteiltem Angriff. | Warteschlange nach Bytes begrenzen oder auf 2.000 verkleinern; der Honeypot puffert ohnehin. | C |
| 10 | `docker-compose.yml:90-91` | Die Volumes `cowrie-log` und `cowrie-lib` wachsen unbegrenzt: tägliche `cowrie.json.*`, TTY-Mitschnitte und heruntergeladene Schadsoftware. Niemand löscht. | Über Monate füllt sich die Platte. Ein Angreifer kann das mit vielen `wget`-Aufrufen großer Dateien beschleunigen. | Aufräum-Job (Dateien älter als N Tage löschen), in Cowrie `download_limit_size` setzen, Speicherverbrauch der Volumes in der UI anzeigen. | C |
| 11 | `hive/auth.go:97-120`, `:128-137` | Die Login-Bremse hat Lücken: (a) Prüfung und Zählen sind getrennt, parallele Anfragen kommen alle durch; (b) jeder Versuch kostet einen bcrypt-Lauf, ohne Begrenzung der Gleichzeitigkeit; (c) ein erfolgreicher Login setzt den Zähler nicht zurück; (d) Einträge werden nie aufgeräumt; (e) geht die echte Client-IP verloren (siehe 16), sperrt ein Gerät alle anderen aus. | Ein Gerät im LAN schickt 500 Logins gleichzeitig: alle werden geprüft, die CPU der NAS ist für Sekunden ausgelastet. Bei einem 16-stelligen Zufallspasswort bleibt das Erraten trotzdem aussichtslos. | Zähler vor dem bcrypt-Lauf erhöhen, bcrypt mit Semaphore auf 2 gleichzeitige Läufe begrenzen, zusätzlich globale Bremse, Aufräumen per Timer. | C |
| 12 | `hive/api.go:381-401`, `hive/auth.go:139-145`, `install.sh:33`, `:68` | Nach einer Passwortänderung bleiben alle bestehenden Sitzungen 7 Tage gültig. Das Startpasswort bleibt im Klartext in `.env` und in der Container-Umgebung (`docker inspect`). | Ein gestohlener Sitzungs-Cookie bleibt trotz Passwortwechsel nutzbar. Wer `.env` lesen kann, kann mit `HIVE_RESET_ADMIN=1` zurücksetzen. | Bei Passwortwechsel alle anderen Sitzungen löschen. `install.sh` sollte nach dem ersten Start das Passwort aus `.env` entfernen oder darauf hinweisen. | C |
| 13 | `hive/cowrie.go:63-67`, `:97-100` | Der gespeicherte Lese-Offset gilt für „die Datei“, ohne zu prüfen, ob es noch dieselbe ist. Gespeichert wird nur am Dateiende, höchstens alle 5 s. | Hive ist über Mitternacht aus, Cowrie rotiert, die neue Datei ist schon größer als der alte Offset: Der Hive steigt mitten in der neuen Datei ein und überspringt alles davor. Umgekehrt führt ein Absturz zu doppelt eingelesenen Ereignissen. | Zum Offset Inode und Dateigröße oder einen Hash der ersten Zeile speichern. Beim Start rotierte Dateien nachlesen. Duplikate über Cowrie-Sitzung plus Zeitstempel erkennen. | C |
| 14 | `hive/sensors.go:68`, `hp/limits.go:19-20`, `:36`, `hive/web/app.js:500` | Die UI erlaubt `max_conns` bis 100.000. Jede Verbindung kostet Goroutine plus Puffer (grob 10–20 KB), dazu einen Dateideskriptor. Der Hilfetext sagt „wenige KB“. | Ein Admin stellt 50.000 ein, ein Botnetz füllt die Plätze, der Honeypot läuft in das 192-MB-Limit. | Obergrenze an das Speicherlimit koppeln (z. B. höchstens 8.000) und `ulimits.nofile` in Compose fest setzen. | C |
| 15 | `docker-compose.yml:84`, `hp/Dockerfile:2`, `:9`, `hive/Dockerfile:2`, `:10`, `update.sh:9-13` | `cowrie/cowrie:latest` und alle Basis-Images sind nur per Tag angegeben. `update.sh` zieht ungeprüft neuen Code und neue Images, ohne vorher zu sichern. | Ein kaputtes oder manipuliertes Cowrie-Image läuft nach dem nächsten Update direkt am Internet. Ein fehlgeschlagenes Update lässt sich nicht zurückrollen. | Images per Digest (`@sha256:…`) festnageln, Renovate oder Dependabot einrichten, `update.sh` um Sicherung und Versionsanzeige ergänzen. | C |
| 16 | `README.md:139`, `hp/manager.go:194-195` | Leitet Docker Ports über den Userland-Proxy weiter, sehen die Container nur die Bridge-Adresse. Dann gelten alle Angreifer als eine IP: das Limit von 48 Verbindungen pro IP gilt für alle zusammen, GeoIP zeigt „LAN“. Die README nennt als Abhilfe `network_mode: host`. Damit ist aber der Name `hive` nicht mehr auflösbar und die Netztrennung entfällt. | Auf betroffenen NAS-Systemen blockiert ein einziger Scanner den ganzen Honeypot. | Beim Start prüfen: Kommt die erste externe Verbindung von einer privaten Adresse, deutlich warnen (Log und UI). README-Abhilfe um `HIVE_URL` und den Verlust der Isolation ergänzen. | V (abhängig vom System, ungetestet) |
| 17 | `hive/store.go:135-142`, `:280` | Die Tabelle `attackers` speichert jede Quell-IP mit Ort und Zeitstempeln für immer, unabhängig von der eingestellten Aufbewahrung. | Die UI verspricht „Rohdaten 30 Tage“, IP-Adressen bleiben aber dauerhaft. Das ist ein Datenschutzthema (IP-Adressen sind personenbezogen) und lässt die Tabelle unbegrenzt wachsen. | Eigene Frist für `attackers`, oder nach Ablauf IP kürzen bzw. hashen. In der UI klar benennen. | C |
| 18 | `hive/main.go:147` und gesamte `main` | Der Hive hat weder `ReadTimeout` noch sauberes Beenden. Bei `docker stop` gehen bis zu 20.000 Ereignisse aus der Warteschlange verloren, Schreibvorgänge werden hart abgebrochen. | Jedes `update.sh` verliert die Ereignisse der letzten Sekunden. Ein langsam gesendeter Body an `/api/login` hält eine Verbindung beliebig lange offen. | Signal abfangen, HTTP-Server mit `Shutdown` beenden, Warteschlange leeren, Datenbank schließen. `ReadTimeout` setzen (SSE braucht nur keinen `WriteTimeout`). | C |

### Niedrig

| Nr. | Stelle | Beschreibung | Szenario | Empfehlung | Status |
|---|---|---|---|---|---|
| 19 | `hive/web/app.js:128-147` | Navigiert man weiter, bevor eine Ansicht fertig geladen ist, zeichnet die ältere Ansicht später über die neuere. Ihre Live-Handler und Timer werden nie abgeräumt. | Schnelles Klicken zwischen Dashboard und Live-Feed: falscher Inhalt, wachsende Zahl an Handlern, Browser wird träge. | Laufende Nummer pro `route()`-Aufruf; Ergebnis verwerfen und Aufräumfunktionen sofort ausführen, wenn die Nummer veraltet ist. | C |
| 20 | `hive/web/app.js:71-74` | Läuft die Sitzung ab, bekommt `EventSource` ein 401 und gibt endgültig auf. Die UI zeigt nur „getrennt“. | Tab bleibt eine Woche offen: keine Live-Daten mehr, kein Hinweis auf Neuanmeldung. | In `onerror` bei geschlossenem Stream `api("me")` prüfen und zum Login wechseln, sonst neu verbinden. | C |
| 21 | `hive/api.go:270` | Die Suche maskiert `%` und `_`, aber nicht den Backslash selbst. | Suche nach `dom\user` findet den vorhandenen Eintrag nicht (Test: 0 Treffer). | `\` zuerst durch `\\` ersetzen. | T |
| 22 | `hp/session.go:143-152`, `hive/store.go:82-93` | `clip` schneidet bei zu langen Texten bis vor das erste ungültige UTF-8-Byte zurück. | Ein langes Passwort mit einem Binärbyte an Stelle 3 wird auf 2 Zeichen gekürzt (Test: `"ab\xffcdefgh"` wird zu `"ab"`). | Nur am Schnittende höchstens 3 Bytes zurückgehen, sonst `strings.ToValidUTF8`. | T |
| 23 | `hive/geo.go:188` | Der Reader zur Prüfung der heruntergeladenen Datei wird nie geschlossen. | Pro Monat bleiben zwei Dateien samt Speicherabbild offen, die gelöschten Vorgänger belegen weiter Plattenplatz bis zum Neustart. | `r.Close()` nach der Prüfung. | C |
| 24 | `hive/geo.go:158` | `AddDate(0, -1, 0)` springt an Monatsenden nicht in den Vormonat (31. März minus 1 Monat ergibt 3. März). | Am 29.–31. eines Monats wirkt der Rückgriff auf die Vormonatsdatei nicht; der Download schlägt fehl, bis DB-IP die neue Datei bereitstellt. | Vom Monatsersten aus rechnen. | C |
| 25 | `hive/auth.go:46-76`, `:141` | Fehler von `SetPassword` und vom Anlegen der Sitzung werden ignoriert. bcrypt lehnt Passwörter über 72 Byte ab. | `HIVE_ADMIN_PASSWORD` mit 80 Zeichen: Log meldet „Admin-Konto angelegt“, es existiert aber keins, Login unmöglich. | Fehler prüfen und mit `log.Fatal` abbrechen; Länge in UI und Skript begrenzen. | T (bcrypt-Fehler), C |
| 26 | `hp/proto_http.go:60-61` | `req.Body.Close()` liest bei Keep-Alive den restlichen Body bis zum Ende. | Ein Client kündigt 10 GB an und sendet 30 s lang; Bandbreite und CPU werden gebunden, Speicher nicht. | Bei mehr als 64 KB Body die Verbindung nach der Antwort schließen. | C |
| 27 | `hp/proto_http.go:47-49`, `:90` | Im Modus `tarpit` wartet HTTP erst bis zu 30 s auf eine vollständige Anfrage. Kommentar und UI sagen „sofort festhalten“. | Scanner, die nur verbinden, werden nicht festgehalten. | Im Tarpit-Modus direkt `httpTarpit` aufrufen oder Text anpassen. | C |
| 28 | `docker-compose.yml:53-99`, `:76` | Nur der Hive hat einen Healthcheck. `depends_on` wartet nicht auf „healthy“. | Hängt der Honeypot oder Cowrie, merkt Docker es nicht. | Healthcheck-Unterbefehl im Honeypot (wie beim Hive), `condition: service_healthy`, einfacher TCP-Check für Cowrie. | C |
| 29 | `.dockerignore`, `docker-compose.yml:18`, `:55` | Die `.dockerignore` liegt im Projektordner, die Build-Kontexte sind aber `./hive` und `./honeypot`. Sie wirkt dort nicht. | Lokal gebaute Binaries oder eine Test-Datenbank in `hive/` landen im Build-Kontext. | Je eine `.dockerignore` in beide Unterordner legen. | C |
| 30 | `install.sh:29-34`, `:42` | `.env` entsteht mit Standardrechten und wird erst nach dem Schreiben der Geheimnisse auf 600 gesetzt. Die Datei wird als Shell-Skript eingelesen; Werte mit Leerzeichen oder `$` verhalten sich dort anders als in Compose. `sed -i` läuft nicht auf BSD/macOS. | Kurzes Zeitfenster, in dem andere lokale Nutzer das Passwort lesen können. Ein Passwort mit `$` bricht das Skript. | `umask 077` am Anfang; nur die benötigten Zeilen per `grep`/`cut` lesen. | C |
| 31 | `hp/proto_http.go:315-318`, `:297`, `:117-133` | `jsonSafe` schneidet Anführungszeichen so ab, dass ein einzelner Backslash übrig bleibt (Test: `a"` wird zu `a\`). `/info` nutzt `%q` statt JSON. Antworten auf `HEAD` und Status 204 enthalten Body und `Content-Length`. | Die Docker-API liefert ungültiges JSON, ein sorgfältiger Scanner erkennt den Honeypot. | Antworten mit `json.Marshal` aus Strukturen bauen. | T (`jsonSafe`), C |
| 32 | `hp/manager.go:121-126`, `hp/config.go:126-128` | Ports unter 1024 werden um 10.000 verschoben, die Prüfung auf doppelte Ports kennt den Versatz nicht. | Port 80 und Port 10080 gleichzeitig konfiguriert: einer scheitert mit „address in use“. | In `Normalize` die tatsächlichen Bind-Ports vergleichen. | C |
| 33 | `hive/api.go:224-235`, `:269-272`, `:250-252` | Top-Listen, Karte und Suche lesen die ganze `events`-Tabelle im Zeitraum, teils mit `json_extract` und `LIKE '%…%'`. Das Dashboard startet 10 solcher Abfragen gleichzeitig bei 4 DB-Verbindungen. | Bei einigen Millionen Ereignissen dauert das Dashboard auf einer NAS Minuten und blockiert andere Abfragen. | Top-Werte beim Schreiben in Zähltabellen pflegen (wie `hourly`), Suche auf Zeitraum begrenzen, Abfrage-Timeout setzen. | C |
| 34 | `hive/store.go:298` | Pro Lauf (alle 6 Stunden) werden höchstens 2.000 Seiten freigegeben, rund 8 MB. | Nach einer großen Löschung schrumpft die Datei nur um etwa 32 MB pro Tag. | Wert an die gelöschte Menge anpassen. | C |
| 35 | `hive/cowrie.go:86`, `:174-180`, `:107-115` | Zeilen werden ohne Längengrenze gelesen. Ab 50.000 offenen Sitzungen wird bei jedem Ereignis die ganze Liste durchlaufen. Zeilen, die in der Sekunde vor der Rotationserkennung in die alte Datei geschrieben werden, gehen verloren. | Eher theoretisch; hohe CPU-Last bei sehr vielen hängenden Sitzungen. | Zeilenlänge begrenzen (1 MB), Aufräumen per Timer, alte Datei nach Rotation noch einmal bis zum Ende lesen. | C |
| 36 | `hp/limits.go:36`, `hp/session.go:73-75`, `:99-101` | Alle Ports teilen sich einen Verbindungs-Pool (4.608 gesamt, 48 pro IP). Tarpit ist standardmäßig zeitlich unbegrenzt. | Rund 100 Quell-IPs mit je 48 offenen Verbindungen belegen alles; neue Verbindungen werden ohne Ereignis abgewiesen. | Kontingent pro Port, Standard für `max_duration_min` z. B. 24 h, abgewiesene Verbindungen zählen. | C |
| 37 | `update.sh:6`, `uninstall.sh:7` | Fehlt Compose ganz, greifen die Skripte ohne Prüfung auf `docker-compose` zurück. Es gibt kein Schema-Versionsfeld in der Datenbank. | Unklare Fehlermeldung; spätere Schemaänderungen lassen sich nicht sauber migrieren. | Prüfung wie in `install.sh`; `PRAGMA user_version` einführen. | C |
| 38 | `hp/session.go:210-211` | Das TLS-Zertifikat gilt 1 Jahr ab Prozessstart und wird nur bei Neustart oder Hostnamen-Wechsel erneuert. | Läuft der Container länger als ein Jahr, ist das Zertifikat abgelaufen. | Beim Übernehmen der Konfiguration Restlaufzeit prüfen. | C |

### Hinweise

| Nr. | Stelle | Beschreibung | Empfehlung |
|---|---|---|---|
| 39 | `hp/proto_http.go:123`, `hp/proto_other.go:113-119` | Feste Server-Kennungen, feste Redis-Werte (`uptime_in_seconds:1739281`), FTP ohne Datenkanal. Der Honeypot ist für geübte Scanner erkennbar. | Werte pro Start variieren; als bekannte Grenze dokumentieren. |
| 40 | `hive/auth.go:141`, `:162` | Sitzungs-Token liegen im Klartext in der Datenbank. | SHA-256 des Tokens speichern. Wichtig, sobald Backups existieren. |
| 41 | `hive/main.go:42-51` | Kein Abgleich des `Host`-Headers. DNS-Rebinding erlaubt fremden Webseiten Login-Versuche über den Browser eines LAN-Nutzers (ohne Cookie). | Erlaubte Hostnamen prüfen. |
| 42 | `hive/api.go:152-155`, `:159-167` | Es gibt genau eine Konfiguration für alle Sensoren; der erste Sensor, der sich meldet, legt sie fest. | Konfiguration pro Sensorname, eigenes Token pro Sensor. |
| 43 | `hive/web/app.js:164-182` | Angreifertexte können Unicode-Steuerzeichen (z. B. Rechts-nach-links) enthalten und die Anzeige optisch verdrehen. Kein XSS. | Steuerzeichen in der Anzeige sichtbar ersetzen. |
| 44 | `hp/hive.go:15` | Der Kommentar verweist auf `docs/events.md`, die Datei gibt es nicht. `config/honeypot.yml:2` sagt „nur beim allerersten Start“; tatsächlich gilt die Datei bei jedem Start, bis der Hive antwortet. | Kommentare und README angleichen. |
| 45 | `hive/cowrie.go:193-224` | Nicht ausgewertet werden u. a. `cowrie.client.kex` (HASSH-Fingerabdruck), `cowrie.session.params`, `cowrie.log.closed` (TTY-Mitschnitt). | Bei Bedarf ergänzen. |
| 46 | `docker-compose.yml:106-109` | Die Docker-Netze haben kein IPv6. Angriffe über IPv6 werden nicht gesehen. | Als Grenze dokumentieren. |
| 47 | Projektordner | Der Ordner ist kein Git-Repository. Es gibt keine Versionsgeschichte, `update.sh:8` läuft ins Leere. | `git init`, erste Version taggen. |

### Antworten auf die drei Kernfragen

- **Ausbruch aus dem Honeypot:** Im Go-Honeypot nach Codelage nicht zu erwarten. Es gibt kein `unsafe`, kein cgo, keine Shell-Aufrufe, keine Dateischreibzugriffe und keinen Panic bei 21.000 Zufallseingaben. Das größere Risiko ist Cowrie plus fehlende Netzsperre (Befund 4).
- **Hive erreichen:** Von außen nur, wenn Port 8088 falsch freigegeben ist (Befund 8). Aus dem Honeypot-Container heraus ist der Hive samt Login erreichbar, das Sensor-Token liegt dort in der Umgebung. Damit ließen sich Ereignisse fälschen, aber kein Code ausführen und keine Konfiguration überschreiben (`PUT /api/settings` braucht die Admin-Sitzung).
- **Datenbank fluten:** Ja, ohne besonderen Aufwand (Befund 3).

## 3. Fehlt noch

### Priorität 1 – vor dem Betrieb am Internet

| Thema | Was fehlt |
|---|---|
| Tests | Es gibt keine einzige Testdatei. Nötig: Unit-Tests für jeden Parser, Go-Fuzz-Ziele (`readRESP`, MySQL-Paket, `serveHTTP`, `readLine`), Test für `Manager.Apply` (Port-Wechsel, Modus-Wechsel), Vertragstest Honeypot zu Hive (hätte Befund 5 und 6 gefunden), Test für Cowrie-Rotation. |
| Mengenbegrenzung | Größenbasierte Retention und Rate-Limit pro IP (Befund 3). |
| Netzsperre | Firewall-Regeln für ausgehenden Verkehr der Honeypot-Container, als Skript und in der README (Befund 4). |
| Feste Image-Versionen | Digest-Pins für Cowrie, Go und distroless (Befund 15). |
| Rechtliches und Datenschutz | Hinweis in der README: IP-Adressen und mitgeschnittene Zugangsdaten sind personenbezogene Daten (DSGVO, berechtigtes Interesse, Löschfristen, Befund 17). Hinweis zu den Nutzungsbedingungen des Internetanbieters, zur Haftung, falls der Anschluss missbraucht wird, und dazu, dass Cowrie echte Schadsoftware speichert. Kein Ersatz für Rechtsberatung. |
| Versionsverwaltung | Git-Repository, `LICENSE` (bisher nennt die README nur fremde Lizenzen, das Projekt selbst hat keine), `SECURITY.md` mit Meldeweg. |

### Priorität 2 – für verlässlichen Dauerbetrieb

| Thema | Was fehlt |
|---|---|
| CI | Pipeline mit `go vet`, `staticcheck`, `govulncheck`, `go test -race`, kurzem Fuzzing, `shellcheck`, `hadolint`, Docker-Build für amd64, arm64 und armv7. |
| Backup und Restore | Die README sagt, `hive.db` kopieren genüge. Bei laufendem Hive im WAL-Modus kann die Kopie unvollständig sein. Nötig: Sicherung per `VACUUM INTO` oder Backup-API, Skript, dokumentierte Wiederherstellung. |
| Überwachung | Healthchecks für alle Container (Befund 28), Endpunkt mit Kennzahlen (z. B. Prometheus-Format), Warnung bei „Sensor meldet sich nicht“, „Platte fast voll“, „Ereignisse verworfen“. |
| Sauberes Beenden | Hive und Honeypot (Befund 18). |
| Releases | `CHANGELOG.md`, Versionsnummer aus Git-Tag statt Konstante (`hp/main.go:16`, `hive/main.go:17`), fertige Images in einer Registry statt Build auf der NAS (auf einem Pi dauert der Build von `modernc.org/sqlite` lange). |
| Abhängigkeiten | Dependabot oder Renovate für Go-Module und Images. |
| Aufräumen | Cowrie-Logs, Downloads und TTY-Mitschnitte (Befund 10). |
| Datenbank-Migrationen | Schema-Version und Migrationsschritte (Befund 37). |

### Priorität 3 – Funktionsumfang

| Thema | Was fehlt |
|---|---|
| Export | JSON- und CSV-Export aus der UI, Blocklisten (IP-Liste für Firewall), STIX/MISP, Weiterleitung per Syslog oder Webhook. |
| TLS für die UI | Eigenes Zertifikat oder Anleitung für einen Reverse-Proxy. `HIVE_COOKIE_SECURE` gibt es schon (`hive/main.go:86`), es steht aber weder in `.env.example` noch in der README. |
| Mehrbenutzer | Nur ein Admin-Konto, keine Leserolle, kein zweiter Faktor, kein Protokoll der Admin-Aktionen. |
| Benachrichtigungen | Mail, Telegram oder ntfy bei erfolgreichem Cowrie-Login, neuem Download usw. |
| Weitere Protokolle | SMB, RDP, VNC (bisher nur Raw), SMTP, Telnet-Tarpit, UDP-Dienste (SIP, SNMP, DNS). |
| Analyse | Abgleich mit AbuseIPDB oder GreyNoise, Hash-Prüfung der Downloads, Fingerabdrücke (JA3/JA4, HASSH). |
| Raspberry-Pi-Image | Build-Skript, erster Start mit Passwortvergabe, Schonung der SD-Karte (SQLite schreibt häufig). |
| Barrierefreiheit und Sprache | UI nur Deutsch; Tabellen ohne Tastaturbedienung für das Aufklappen der Details. |

### Grenzen gegenüber T-Pot

| Punkt | T-Pot | HoneyLite |
|---|---|---|
| Honeypots | Über 20 spezialisierte (Dionaea, Conpot, Heralding, Mailoney, ADBHoney, CitrixHoneypot, ElasticPot …) | 8 einfache Emulationen plus Cowrie |
| Tiefe der Emulation | Teils hohe Interaktion, Malware-Fang über SMB/FTP | Nur Login und erste Befehle, kein Dateisystem, keine Nutzlast-Ausführung |
| Netzwerk-Erkennung | Suricata, p0f, Fatt | Keine; nur was die Handler selbst sehen |
| Auswertung | Elastic Stack, Kibana, frei definierbare Abfragen, Attack Map | Feste Ansichten auf SQLite, keine eigenen Abfragen |
| Werkzeuge | CyberChef, Spiderfoot, Elasticvue | Keine |
| Verteilter Betrieb | Sensoren und zentraler Hive mit TLS, Community-Datenabgabe | Sensor-API vorhanden, aber eine Konfiguration und ein Token für alle, kein TLS |
| UDP | Ja | Nein |
| Ressourcen | 8–16 GB RAM | Unter 512 MB (Ziel erreicht, solange Befunde 1, 2, 6, 9 behoben sind) |
| Zusatz | Kein Tarpit | Tarpit und Hybrid pro Port, Umschalten ohne Neustart |

HoneyLite ist damit ein Sensor für Massenscans und Login-Versuche mit guter Übersicht, kein Werkzeug für Malware-Analyse oder Forschung.

## 4. Was gut umgesetzt ist

- **Kein XSS-Weg:** Die UI nutzt kein `innerHTML`, alle Angreiferdaten laufen über Textknoten (`hive/web/dom.js:6-11`). Links zu Angreifern werden mit `encodeURIComponent` gebaut. Die CSP ist streng: nur eigene Skripte und Styles, `frame-ancestors 'none'`, `base-uri 'none'` (`hive/main.go:45`).
- **Kein SQL-Injection-Weg:** Alle Abfragen sind parametrisiert. Dynamisch zusammengesetzt werden nur Spaltennamen aus festen Listen (`hive/api.go:223-236`, `:263`).
- **Anmeldung:** bcrypt, 256-Bit-Zufallstoken, Cookie mit `HttpOnly` und `SameSite=Strict`, gleiche Laufzeit bei unbekanntem Benutzer (`hive/auth.go:80-84`), CSRF-Schutz per Pflicht-Header für alle schreibenden Aufrufe, Sensor-Token mit zeitkonstantem Vergleich und Ablehnung bei leerem Token (`hive/auth.go:191`).
- **Container-Härtung:** distroless, UID 65532, `cap_drop: ALL`, `no-new-privileges`, nur lesbares Dateisystem, Limits für RAM, CPU und Prozesse, Log-Rotation, internes Netz zwischen Honeypot und Hive, Cowrie ohne Weg zum Hive, Cowrie-Log für den Hive nur lesbar.
- **Port-Versatz statt Root:** Ports unter 1024 ohne `NET_BIND_SERVICE` (`hp/manager.go:118-126`).
- **Parser:** FTP, MySQL, SSH und Raw haben saubere Längen- und Fristgrenzen. Jeder Handler läuft unter `recover` (`hp/manager.go:209-212`). Alle Schleifen sind begrenzt (20 HTTP-Anfragen, 30 FTP-Befehle, 200 Redis-Befehle).
- **Tarpit:** Limits gesamt und pro IP, Zufall im Intervall, Erkennung von Verbindungsabbruch, kein Goroutine-Leck (der Leser endet mit dem Schließen der Verbindung).
- **Listener-Verwaltung:** Moduswechsel ohne Neustart über atomare Zeiger, fehlgeschlagene Ports werden erneut versucht und nur einmal gemeldet (`hp/manager.go:52-116`).
- **Hive-Eingang:** Größenlimit, Typ-Whitelist, IP-Prüfung, vom Sensor gelieferte Geo-Felder werden verworfen (`hive/api.go:129`), Zeitstempel aus der Zukunft korrigiert.
- **Speicherung:** WAL, ein einzelner Schreiber mit Sammeltransaktionen, Stundenwerte vorverdichtet, inkrementelles Vakuum ist wirksam (geprüft: `auto_vacuum=2`).
- **SSE:** Langsame Browser bremsen niemanden (Ereignisse werden ausgelassen), Abmeldung sauber per `defer`.
- **GeoIP:** Download in temporäre Datei, Prüfung vor dem Umbenennen, Größenlimit, Tausch unter Sperre.
- **Skripte:** `set -eu`, sichere Zufallswerte aus `/dev/urandom`, `.env` wird nie überschrieben, Löschen der Daten nur nach Rückfrage.
- **Dokumentation:** Die README ist für Einsteiger gut nutzbar und hat einen eigenen Sicherheitsabschnitt.

## 5. Vorschlag für die Reihenfolge der Korrekturen

1. Befunde 1 und 2 (Speichergrenzen in HTTP und Redis), dazu die Fuzz-Tests übernehmen.
2. Befunde 5 und 6 gemeinsam (Größenbudget pro Ereignis und pro Block, kein endloses Wiederholen).
3. Befund 3 (Größen-Retention, Rate-Limit) und Befund 7 (Fehlerbehandlung im Schreiber).
4. Befunde 4, 8 und 15 (Netzsperre, getrennte Listener, feste Images), dann erster Docker-Test mit Cowrie.
5. Rest nach Tabelle; Priorität-1-Punkte aus „Fehlt noch“ parallel.

## 6. Umsetzung (Version 0.2.0, 14.11.2026)

Alle 47 Befunde wurden bearbeitet. Status **behoben** heißt: geändert und, wo angegeben, mit Test abgesichert. **Dokumentiert** heißt: bewusste Grenze, in README beschrieben.

| Nr. | Status | Umsetzung |
|---|---|---|
| 1 | behoben, Test | `capReader` begrenzt Anfragezeile und Kopf auf 64 KB, Body 64 KB (`TestHTTPHeaderLimit`) |
| 2 | behoben, Test | RESP: höchstens 4 KB je Argument und 64 KB je Befehl behalten, Rest gestreamt verworfen (`TestRedis*`, Fuzzing) |
| 3 | behoben, Test | Größen-Aufbewahrung (`HIVE_MAX_DB_MB`, `HIVE_MIN_FREE_MB`), Drossel 10/s je IP, `attackers` und Zähltabellen nach Frist gekürzt (`TestRetention`, `TestRateLimiter`) |
| 4 | behoben | `tools/firewall.sh` (DOCKER-USER und INPUT), festes Netz `hl-honeynet`, Selbstprüfung des Honeypots mit Warnung in der UI, README-Pflichtschritt |
| 5 | behoben, Test | Budget pro Feld im Honeypot (Ausgabe begrenzt), Hive kürzt feldweise mit `truncated` (`TestEventSizeContract`, `TestSanitizeTruncatesData`) |
| 6 | behoben, Test | Blöcke ≤ 200 Ereignisse/1 MB, Warteschlange nach Bytes, 4xx verwerfen, 5xx mit Backoff, `eid`-Duplikaterkennung (`TestEmitterDropsOn4xxRetriesOn5xx`, `TestWriterDedupe`) |
| 7 | behoben, Test | Statements einmal vorbereitet, alle Fehler geprüft, 3 Versuche, Zähler „nicht gespeichert“ in UI (`TestWriterSurvivesDBError`) |
| 8 | behoben | Zwei Listener (UI 8088, Sensor 8089 nur im Netz `ingest`), UI lehnt Sensor-Netz ab, `HIVE_BIND` = LAN-IP, README korrigiert |
| 9 | behoben | Warteschlange 5.000 Ereignisse und 32 MB |
| 10 | behoben | Dienst `janitor`, Cowrie-Download-Limit 10 MB, Volume-Größen in der UI |
| 11 | behoben, Test | Zählen vor bcrypt, 2 parallele bcrypt-Läufe, globale Grenze, Reset bei Erfolg, Aufräum-Timer (`TestLoginThrottle`) |
| 12 | behoben | Passwortwechsel meldet andere Sitzungen ab; `install.sh` entfernt das Startpasswort aus `.env` |
| 13 | behoben, Test | Stand mit Fingerabdruck der ersten Zeile, rotierte Dateien werden nachgelesen, Cowrie-Ereignis-IDs gegen Duplikate (`TestCowrieCatchUpAfterRotation`) |
| 14 | behoben, Test | `max_conns` höchstens 8.000 (Honeypot und Hive), `ulimits.nofile`, Hilfetext korrigiert |
| 15 | behoben | Digests für Cowrie 3.1.6, Go, distroless, BusyBox; Dependabot; `update.sh` sichert vorher und zeigt Versionen |
| 16 | behoben | Erkennung von Verbindungen aus dem eigenen Docker-Netz, Warnung in der UI, README-Abhilfe ergänzt |
| 17 | behoben, Test | `attackers` nach Aufbewahrungsfrist gelöscht, Datenschutz-Abschnitt in README |
| 18 | behoben | Signalbehandlung, `Shutdown`, Warteschlange und Cowrie-Stand werden geschrieben, Lese-Fristen je Handler |
| 19 | behoben | Laufende Nummer pro Navigation, verspätete Ansichten zeichnen in einen abgehängten Behälter und räumen sofort ab |
| 20 | behoben | Abgelehnter Live-Stream prüft die Sitzung und führt zur Anmeldung bzw. verbindet neu |
| 21 | behoben, Test | Backslash zuerst maskiert (`TestSearchBackslash`) |
| 22 | behoben, Test | `clip` geht höchstens 3 Bytes zurück, sonst Ersetzung (`TestClip`, `TestClipUTF8`) |
| 23 | behoben | Prüf-Reader wird geschlossen |
| 24 | behoben | Vormonat vom Monatsersten aus berechnet |
| 25 | behoben, Test | Fehler führen zum Abbruch mit Meldung, Passwortlänge 10–72 in Server und UI (`TestPasswordLimits`) |
| 26 | behoben, Test | Body wird nicht mehr bis zum Ende gelesen, Verbindung danach geschlossen (`TestHTTPBodyNotDrained`) |
| 27 | behoben, Test | Tarpit-Modus hält sofort fest (`TestHTTPTarpitImmediate`) |
| 28 | behoben | Healthchecks für Honeypot und Cowrie, `depends_on: service_healthy`, Hive-Healthcheck prüft die Datenbank |
| 29 | behoben | `.dockerignore` in `hive/` und `honeypot/` |
| 30 | behoben | `umask 077`, `.env` wird nicht mehr als Skript gelesen (`env_get`/`env_set`), kein `sed -i` |
| 31 | behoben | Docker-API per `json.Marshal`, kein Body bei `HEAD`/204 |
| 32 | behoben, Test | Prüfung auf tatsächlichen Bind-Port (`TestNormalizePortCollision`) |
| 33 | behoben, Test | Zähltabelle `top_hourly` für Top-Listen und Karte, Zeitlimit 20 s je Abfrage, Suche auf Zeitraum begrenzt (`TestTopCounters`) |
| 34 | behoben | `PRAGMA incremental_vacuum` ohne Grenze |
| 35 | behoben | Zeilen über 1 MB übersprungen, Aufräumen per Timer, alte Datei nach Rotation zu Ende gelesen |
| 36 | behoben | Höchstens 2.048 Verbindungen je Port, Tarpit standardmäßig 24 h, abgewiesene Verbindungen gezählt |
| 37 | behoben, Test | Compose-Prüfung in allen Skripten, `PRAGMA user_version` mit Migrationen (`TestMigrationFromV01`) |
| 38 | behoben | Zertifikat wird 30 Tage vor Ablauf erneuert |
| 39 | teilweise, dokumentiert | Redis-Werte variieren pro Start; Erkennbarkeit als Grenze in README |
| 40 | behoben | Nur SHA-256 des Tokens gespeichert |
| 41 | behoben, Test | Host-Prüfung mit `HIVE_ALLOWED_HOSTS` (`TestHostAllowed`) |
| 42 | behoben, dokumentiert | Konfiguration je Sensor in Hive und UI; ein Token für alle Sensoren ist als Grenze dokumentiert |
| 43 | behoben | Steuer- und Richtungszeichen werden in der UI sichtbar ersetzt |
| 44 | behoben | `docs/events.md` angelegt, Kommentar in `config/honeypot.yml` korrigiert |
| 45 | behoben, dokumentiert | HASSH (`cowrie.client.kex`) als Typ `fingerprint`; TTY-Mitschnitte als Grenze dokumentiert |
| 46 | dokumentiert | IPv6 als Grenze in README |
| 47 | behoben | Git-Repository angelegt (`git init`), Version 0.2.0, `CHANGELOG.md` |

### „Fehlt noch“

| Thema | Status |
|---|---|
| Tests | Unit-, Fuzz- und Vertragstests in beiden Modulen |
| Mengenbegrenzung, Netzsperre, feste Images | erledigt (Befunde 3, 4, 15) |
| Recht und Datenschutz | Abschnitt in README |
| Versionsverwaltung, LICENSE, SECURITY.md | erledigt (MIT-Lizenz, änderbar) |
| CI | `.github/workflows/ci.yml` (vet, gofmt, staticcheck, govulncheck, race, Fuzzing, shellcheck, hadolint, Multi-Arch-Build) |
| Backup und Restore | `tools/backup.sh`, `hive backup`, Wiederherstellen über `restore.db` |
| Überwachung | Healthchecks, Warnungen in der UI, `/metrics` |
| Sauberes Beenden, Releases, Abhängigkeiten, Aufräumen, Migrationen | erledigt (`release.yml`, Dependabot, `janitor`, `user_version`) |
| Export, TLS-Anleitung | CSV/JSON-Export, Blockliste, Reverse-Proxy-Anleitung, `HIVE_COOKIE_SECURE` dokumentiert |
| Mehrbenutzer, Benachrichtigungen, weitere Protokolle, Analyse, Pi-Image | offen, als Ausblick in README |

### Noch nicht geprüft

- Docker-Build, laufende Container (inkl. Cowrie mit nur lesbarem Dateisystem) und Netzsperre auf echter Hardware: Auf dem Entwicklungsrechner gibt es kein Docker.
- `staticcheck`, `govulncheck`, Race-Detector und `shellcheck`/`hadolint` laufen erst in der CI.
