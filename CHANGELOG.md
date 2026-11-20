# Changelog

Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionen nach [Semantic Versioning](https://semver.org/lang/de/).

## [Unveröffentlicht]

**Update:** Beim ersten Start zählt der Hive die Top-Listen einmal neu (neue Exploit-Regeln, Fremdprotokolle). Alle neuen Weitergabe- und KI-Funktionen sind zunächst aus.

### Neu
- **Exploit-Erkennung mit Produkt und CVE:** rund 200 Regeln für Router, Kameras, VPN-Gateways, Atlassian, Exchange, Java/Spring, CMS, PHP, Docker-API, Tomcat und mehr. Jede Regel unterscheidet Abtasten (Probe) und Ausnutzung; eine Ausnutzung verdrängt die Probe desselben Produkts. Neue Tabelle **„Exploits nach Produkt“** in der Auswertung, Details an Angriffskarte und Bericht, Suchfelder `regel:` und `produkt:`.
- **Lückendetails (CVE):** CISA-KEV wird täglich lokal geladen, NVD und EPSS werden gedrosselt nachgeschlagen und zwischengespeichert; es gehen nur CVE-Nummern hinaus. Abschaltbar, optional mit NVD-Schlüssel.
- **KI-Regelvorschläge:** Für Exploits ohne Zuordnung schlägt die KI Produkt, CVE und Regel vor; Ausdruck und CVE werden geprüft, angenommene Regeln gelten sofort.
- **Web-Köder:** glaubwürdige Seiten für FortiGate, Ivanti, Cisco ASA, Hikvision, ONVIF, Tomcat, Jira und Keycloak mit „verwundbaren“ Antworten für bekannte Lücken. Anmeldungen und Exploits antworten bewusst langsam. Einstellung „Köder“ beim Geräteprofil (passend zum Profil, alle, aus).
- **Weitergabe an die Community** (jeweils opt-in, mit Probemodus und Tageslimit): Nachlade-Adressen an **URLhaus** melden, **Dateien sammeln** in eine Quarantäne (eigener abgesicherter Download, keine Verbindungen ins LAN, Größen- und Zeitgrenzen), **MalwareBazaar** (Hash nachschlagen, unbekannte Programme hochladen) und stündliche Meldungen an **DShield** (eigene Adresse wird nie gesendet).
- **Weitere KI-Funktionen** (je einzeln schaltbar, gemeinsames Tagesbudget): KI-Wochenbericht, Kurzanalyse schwerer Angriffe (je Angriffsfamilie ein Aufruf), Suche in Alltagssprache (Vorschlag wird geprüft und erst nach Klick angewendet), „Mit KI erklären“ für Befehle und nachgeladene Skripte.
- **Stille Ports:** Der Hive merkt sich, seit wann ein Port läuft, und weist auf Ports ohne jede Verbindung hin (z. B. vom Provider gesperrt).
- **Hostname-Prüfung** nach RFC 952/1123 mit Hinweis beim Tippen und Vorschlag; neue ungültige Namen werden abgelehnt.

- **Dauer-Brute-Force erkennen und verdichten:** Meldet sich eine IP über lange Zeit sehr oft an (Standard: 200 Logins über 30 Minuten, höchstens 3 Clients bzw. HASSH), markiert der Hive sie als Dauer-Brute-Forcer – sichtbar auf der Angriffskarte und beim Angreifer, als Suchfeld `dauer:ja` und als Filter „Dauer-Brute-Force ausblenden“. Ab dann speichert er fehlgeschlagene Logins und die Verbindungen drumherum nur noch gesammelt (höchstens alle fünf Minuten eine Sammelzeile je IP und Dienst). Kennzahlen, Angreiferliste und die Zähler je Kombination bleiben vollständig; angenommene Logins und alles danach, Befehle, Downloads, Köder, eigene Netze und „Nie sperren“ bleiben immer einzeln. Einstellungen → Honeypot → Dauer-Brute-Force.
- **Drossel in der Firewall (abschaltbar, Standard aus):** begrenzt neue Verbindungen zu Cowrie (SSH, Telnet) je Quell-IP (Standard 6 je Minute, Spitze 20, danach 15 Minuten gesperrt). Raspberry Pi: in der Web-UI einschalten, angewendet über nftables. Docker: `BRUTE_LIMIT=1 sudo -E sh tools/firewall.sh` (Werte über `BRUTE_RATE`, `BRUTE_BURST`, `BRUTE_BAN`, `BRUTE_ALLOW`; die UI zeigt den passenden Aufruf). Private Netze, eigene Netze und „Nie sperren“ werden nie gedrosselt; scheitert die Drossel, bleibt die Netzsperre unverändert aktiv.
- **Eigene öffentliche Adresse automatisch:** Der Hive ermittelt die Adresse des Anschlusses stündlich (api.ipify.org, für IPv6 api6.ipify.org) und merkt sich frühere Adressen 30 Tage. Sie und eigene Namen (Domain des Reverse-Proxys, DynDNS) gehen nie an Sprachmodelle, URLhaus, MalwareBazaar, DShield oder in AbuseIPDB-Kommentare; Nachlade-Adressen, die auf den eigenen Anschluss zeigen, werden nie geholt. Bisher kannte der Hive die Adresse nur nach einer Abfrage unter System → „Wie Shodan dich sieht“, und sie veraltete beim nächsten Adresswechsel. Einstellungen → Zugang und Sicherheit → Eigene öffentliche Adresse (abschaltbar).

### Geändert
- **KI-Webantworten:** Produkt wird aus dem Pfad erkannt, feste Produkthinweise je Pfadfamilie, doppelt maskierte Antworten (wörtliches `\n`) werden entmaskiert. 404 und Zufalls- oder Scannerpfade gehen nicht mehr ans Modell.
- **Fremdprotokolle als ein Ereignis:** HTTP-Anfragen, TLS-Handshakes und Binärdaten an Redis, FTP, SMTP, Telnet, MySQL und PostgreSQL zählen nicht mehr als Befehle oder Zugangsdaten je Zeile, sondern als ein Abtast-Ereignis. Behebt überhöhte Redis-Zähler.
- **Geräteprofil** zeigt vor dem Speichern, wie viele Verbindungen die abgeschalteten Dienste zuletzt pro Woche brachten.
- Beim Pi-Update werden geänderte Beobachter-Units (`.path`) neu gestartet, damit sie neue Pfade sofort beobachten.

### Sicherheit
- **Signierte Veröffentlichungen:** Die Prüfsummen jeder Veröffentlichung sind mit Ed25519 signiert (`SHA256SUMS.sig`). Der Raspberry Pi spielt ein Update nur ein, wenn das bereits installierte Programm die Signatur bestätigt; unsignierte oder veränderte Veröffentlichungen werden abgelehnt. Bisher kam die Prüfsumme aus derselben Quelle wie das Paket. Das Update auf diese Version selbst wird noch vom alten Updater ohne Signaturprüfung eingespielt; ab dann gilt die Prüfung.
- KI-Webantworten: Vom Modell gesetzte Cookies werden nur noch als „Name=Wert; Path=/; HttpOnly“ übernommen, ohne Domain-Angabe, ohne `__Host-`/`__Secure-`-Präfix und nie unter dem Namen des Sitzungs-Cookies der Web-UI. Läuft die Hive-UI auf demselben Host, konnte ein solches Cookie sonst die Anmeldung dort überdecken.
- Weitergabe: Nachlade-Adressen, in denen die eigene öffentliche IP oder der Hostname eines Honeypots vorkommt, werden weder an URLhaus gemeldet noch geholt; Dateien mit diesen Angaben gehen nicht an MalwareBazaar.
- DShield: Referer, Origin, Weiterleitungs-Köpfe und Cookies werden nicht mehr mitgesendet. Web-Anfragen gehen nur noch hinaus, wenn die eigene öffentliche Adresse bekannt ist (System → „Wie Shodan dich sieht“).
- Dateien sammeln: Die Platzgrenze der Quarantäne gilt vor jedem Download, nicht nur bei der stündlichen Aufräumrunde. Der abgesicherte Download sperrt zusätzlich IPv4-kompatible und SIIT-IPv6-Adressen sowie 192.88.99.0/24.
- Lückendetails: Nur Admins lösen NVD-Abfragen aus. Werte von NVD und EPSS werden auf gültige Bereiche und Längen begrenzt.
- Raspberry Pi: Die Datenbank des Hive (Passwort-Hash, API-Schlüssel) ist nur noch für den Hive lesbar (`StateDirectoryMode=0700`, `UMask=0077`). Honeypot und Cowrie sehen `/var/lib/hivornet` gar nicht mehr.
- Raspberry Pi: Die Web-UI (Port 8088) ist am Honeypot-Anschluss nur noch aus privaten IPv4-Netzen erreichbar. Steht der Pi als „Exposed Host“ oder in einer DMZ, war die Anmeldeseite vorher aus dem Internet offen.
- Die Ersteinrichtung geht nur noch aus dem Heimnetz (privat, Loopback, Link-local, CGNAT); `HIVE_SETUP_ANY_ADDR=1` hebt das auf. Vorher konnte ein Fremder einem offen erreichbaren Hive zuvorkommen und das Admin-Passwort setzen. Den Standort zeigt `GET /api/setup` nur noch dem Heimnetz.
- Honeypot: Der Tomcat-Köder ließ sich über Zeilenumbrüche im Kontextpfad dazu bringen, eigene Kopfzeilen zu senden, auch Cookies. Steuerzeichen werden abgelehnt, und HTTP-Antworten verwerfen jede Kopfzeile mit Steuerzeichen.
- Honeypot: Sitzungen außerhalb des Tarpits enden nach 20 Minuten. Grenzen für Verbindungen, Tarpit, Ereignisse und Sprachmodell zählen IPv6-Absender je /64. ADB nimmt höchstens 64 KB je Nachricht an.
- Sperrliste und AbuseIPDB werten nur noch Ereignisse vertrauter Sensoren aus. Ein nicht vertrauter Sensor konnte vorher einem echten Angriff erfundene Anmeldungen und Befehle hinzufügen.
- URLhaus meldet im Modus „nur bestätigte“ nur noch Adressen, deren Datei als Schadsoftware erkannt wurde (Programm oder eindeutiges Schadskript). Vorher genügte jede geholte Datei ohne HTML.
- Der KI-Angriffsbericht ersetzt die eigene öffentliche IP, private Adressen und eigene Hostnamen, grenzt die Angreiferdaten ab und verwirft manipulierte Antworten, wie die übrigen KI-Funktionen. Diese ersetzen jetzt ebenfalls eigene Hostnamen.
- API-Schlüssel (AbuseIPDB, abuse.ch, GreyNoise, NVD) werden bei einer Weiterleitung auf einen anderen Host nicht mehr mitgeschickt. Den Fehlertext der KI sehen nur Admins.
- Hive: Werte von Sensoren werden strenger geprüft. Dauern sind begrenzt (ein Überlauf der Summen ließ Schreibvorgänge scheitern), `tty`-Ereignisse kommen nur vom Cowrie-Leser, und Lebenszeichen werden gekürzt, mit höchstens 256 Ports je Sensor.
- Hive: Dateien aus den Cowrie-Ordnern werden ohne Verweis und ohne Blockade an FIFOs geöffnet.
- Antworten des Sprachmodells für Webseiten werden verworfen, wenn ein Skript Cookies oder Browser-Speicher setzt oder Daten per Beacon verschickt.

## [0.7.5-beta] – 2026-11-19

**Update:** Raspberry Pi per Knopf (System → Updates, Kanal „Vorabversionen“), kein neues Image nötig. Docker: `sh update.sh`, danach **`sudo sh tools/firewall.sh`** (neue, ausfallsichere Netzsperre). Beim ersten Start zählt der Hive die Top-Listen einmal neu (Java4Shell). Empfehlung: unter Einstellungen → Auswertung und KI den Zwischenspeicher der Sprachmodell-Antworten einmal leeren.

### Neu
- **Java4Shell (CVE-2026-114938):** Erkennung des veröffentlichten Auslösers für die Lücke im Base64-Dekoder von OpenJDK (volle 64er-Blöcke Base64 mit angehängtem „=“, in Kopfzeilen, Parametern und Body). Muster „Java4Shell“, CVE-Eintrag, MITRE T1190, Phase „Zugriff“ der Angriffskette, meldefähig bei AbuseIPDB. Hivornet selbst ist nicht betroffen (kein Java).
- **„Port hinzufügen“ schlägt den Port vor:** Wählt man in einer neuen Zeile den Dienst, springt der Port auf dessen üblichen Port (HTTP 80, Redis 6379, PostgreSQL 5432, Ollama 11434 …). Das geschieht nur, solange der Port in dieser Zeile nicht von Hand geändert wurde. Ist der Port schon belegt oder reserviert, steht ein Hinweis in der Zeile. SSH und Telnet gehören Cowrie; der Go-Honeypot bekommt dafür 2222 (SSH-Tarpit) und 2323 (Telnet). Die Standardports kommen vom Hive, sodass es nur eine Quelle gibt. Auf dem Raspberry Pi zeigt die Zeile sofort an, dass 22 und 23 für Cowrie reserviert sind, nicht erst beim Speichern.

### Geändert
- **Einstellungen neu geordnet:** Statt einer langen Seite gibt es fünf Unterseiten: **Honeypot** (Ports und Modi, Geräteprofil, Tarpit, Cowrie, Standort für die Karte), **Auswertung und KI** (KI-Auswertung, Antworten vom Sprachmodell, Schlüssel für GreyNoise und abuse.ch), **Weitergabe und Meldungen** (Benachrichtigungen, AbuseIPDB, Blockliste), **Zugang und Sicherheit** (eigenes Passwort, Benutzer, weitere Sensoren, eigene Netze, Reverse-Proxy) und **Daten und Wartung** (Aufbewahrung, Sicherung). Auf dem Handy lässt sich die Leiste seitlich wischen.
- **Jeder Bereich speichert nur sich selbst:** Der Knopf steht unten im Bereich und sagt, was er speichert („Ports speichern“, „Tarpit speichern“ …). Bisher speicherten „Speichern“ und „Zusatzfunktionen speichern“ jeweils viele entfernte Karten auf einmal. Ungespeicherte Änderungen markieren den Bereich, und wer die Seite verlässt, wird gefragt. Die Testnachricht nutzt die gespeicherten Einstellungen; die Blockliste speichert nicht mehr bei jeder Änderung sofort, sondern mit „Blockliste speichern“ („Neues Token“ gilt weiterhin sofort). Die Aufbewahrung der Rohdaten wird getrennt von der Sensor-Konfiguration gespeichert.
- **Geräteprofile stimmig über alle Dienste:** Telnet-Shell (`uname`, `/proc/cpuinfo`, `/proc/mounts`), Redis INFO, Docker `/info` und `/version`, PostgreSQL und Kubernetes melden jetzt dieselbe Architektur und denselben Kernel wie das Profil. Bisher meldete Telnet immer einen MIPS-Router, Redis und Docker dagegen x86_64. Docker-Kennungen (API-Version, Commit, Go-Version) passen zur gemeldeten Docker-Version. Fehlerseiten haben den Stil des gemeldeten Webservers (nginx, lighttpd, Boa) statt immer nginx. Das NAS-Profil ist durchgehend Debian 11 (bisher Synology-Kernel mit Debian). Der Router nutzt nicht mehr vsFTPd 2.3.4, eine bekannte Honeypot-Kennung. Das Sprachmodell erfährt die Architektur; gespeicherte KI-Antworten verfallen dadurch einmal.
- **Neue Geräteprofile:** IP-Kamera (BusyBox, ARM, Boa), Smart-Home-Zentrale (Raspberry Pi 4, Debian 12, MQTT) sowie Entwicklungs- und KI-Server (Ubuntu 24.04 mit Docker, Kubernetes, Ollama, Elasticsearch). Linux-Server, NAS und Router schlagen passendere Dienste vor. Das Profil „Bisher“ ändert sich nur beim Architektur-Widerspruch.
- **Geräteprofil:** Hostname und Profil stehen zusammen. Wahlweise schaltet das Profil die passenden Dienste ein und die übrigen aus; vorher zeigt die Karte, was sich ändert und welche Dienste noch fehlen.

### Sicherheit (drittes Audit)
- **Docker-Netzsperre ausfallsicher:** Neue Regeln werden vollständig aufgebaut und ersetzen die alten in einem Schritt; ein Fehler lässt die bisherige Sperre stehen. Die systemd-Unit startet vor Docker und hebt die Sperre beim Anhalten nicht mehr auf. Zusätzlich wird nach Quell-Netz gesperrt, falls die Bridges anders heißen. **Nach dem Update `sudo sh tools/firewall.sh` ausführen.**
- **Sensor:** Gefälschte UDP-Absender konnten den Speicher füllen; die Drossel-Tabelle ist begrenzt, UDP-Ereignisse haben eine Gesamtgrenze. Kleinere HTTP-Kopfzeilen, MySQL-Pakete ohne Vorab-Speicher, weiches Speicherlimit.
- **Antworten mit Sprachmodell:** Der Schutz vor Prompt-Injection prüft auch kodierte Eingaben (Prozent-Kodierung, `+`, Base64, Hex). Web-Antworten mit fremden Skripten, Formularzielen oder Weiterleitungen werden verworfen und mit eigener CSP ausgeliefert. IP-Adressen in Eingaben werden vor dem Aufruf durch Platzhalter ersetzt. Der Sensor begrenzt Anfragen selbst. **Empfehlung: den Zwischenspeicher der KI-Antworten nach dem Update einmal leeren.**
- **Scanner-Kennzeichen** nur noch über AS-Namen bzw. geprüftes rDNS, nicht über den User-Agent; wer Befehle ausführt oder nachlädt, fällt nie aus Blockliste und AbuseIPDB-Meldung.
- **Hive:** teure Auswertungen (lange Zeiträume) laufen begrenzt parallel und werden zwischengespeichert; Login-Drossel je IPv6-/64 und Benutzername; Passwortprüfungen bei Passwortwechsel und Sicherung mit Versuchszähler; Symlink-Prüfung für Cowrie-Dateien; Erwähnungen wie `@everyone` in Webhook-Meldungen entschärft; Grenzen für Live-Verbindungen und Wiederherstellung.
- **Pi:** Updates auf ältere Versionen werden abgelehnt; die Netzsperre wird in einem Schritt gesetzt und wirkt nach einem Update sofort.
- **Release-Workflow:** Schreibrechte nur je Job, Actions per Commit-SHA festgelegt.
- `install.sh` bindet die UI nur an private Adressen.

## [0.7.0-beta.3] – 2026-11-18

### Neu
- **Antworten der KI sichtbar:** Liefert der Honeypot eine Antwort des Sprachmodells aus, entsteht ein Ereignis „KI-Antwort“ (Eingabe, Antwort, ob aus dem Zwischenspeicher). Angriffe tragen dann die Plakette „beantwortet durch KI“ und zeigen die Antworten aufklappbar; im Angriffe-Tab filtert der Knopf „Beantwortet durch KI“ (Suche `ki:ja`). Auch im Angreifer-Profil, im Angriffsbericht (auch als Text) und in der Angriffskette (violett gepunktet). Der Text des Modells wird nicht als Befehl ausgewertet.
- **Schutz vor Prompt-Injection:** Eingaben, die sich an ein Sprachmodell richten („ignore previous instructions“, „du bist jetzt …“, Rollen-Marker wie `<|im_start|>`, längerer Fließtext statt Befehl), gehen gar nicht erst an das Modell; der Angreifer bekommt die statische Antwort. Die übrigen Eingaben stehen für das Modell zwischen zufälligen Markierungen und gelten ausdrücklich als Daten. Antworten, die sich verraten („As an AI“, „honeypot“, „system prompt“ …), werden verworfen und nicht gespeichert. Die Einstellungen zeigen, wie oft beides geschah. Neues Muster **„KI-Manipulation“** (MITRE ATLAS AML.T0051).
- **Zeitraum frei wählbar:** Neben 24 Std, 7 und 30 Tagen über „Eigener …“ eine beliebige Zahl Tage, Wochen oder Monate (bis drei Jahre), auf allen Seiten mit Zeitraum und im Angriffe-Tab. Reicht der Zeitraum über die Aufbewahrung der Rohdaten hinaus, steht ein Hinweis daneben. Lange Zeiträume werden in Wochen zusammengefasst.
- **Kachel „Nachladeversuche“ statt „Downloads“:** Die alte Kachel zählte nur Downloads über Cowrie. Die gibt es nur, wenn Cowrie ins Internet darf (Docker mit `ALLOW_DOWNLOADS=1`, auf dem Pi nie), deshalb stand sie meist auf 0, obwohl Angreifer etwa über die Docker-API `wget` oder `curl` aufriefen. Jetzt zählt sie jeden Befehl mit Download-Adresse, über alle Dienste; ein Klick zeigt die Angriffe dazu (Suche `nachladen:ja`). Die Stufe „Datei nachgeladen“ bleibt echten Downloads vorbehalten.
- **„Mehr anzeigen“** für die kurzen Listen in Analyse, Erkenntnisse und Zugangsdaten (Werkzeuge, Indikatoren, Fingerabdrücke, Lücken, Kampagnen, Familien, Wiederkehrer, Kombinationen, Benutzernamen, Passwörter, Befehle, Pfade, Clients u. a.).

### Behoben
- **Nachlade-Adresse nur „http://ex“:** Angreifer verschleiern Adressen mit Backslashes (`http://ex\am\ple.org/x.sh`); die Erkennung brach beim ersten Backslash ab. Jetzt wird die ganze Adresse erkannt; vorhandene Zähler werden beim Start einmal neu gezählt.
- **Zeitstreifen eines Angriffs endete vorzeitig:** Bei Angriffen mit mehr als 400 Ereignissen zeigte der Streifen nur den Anfang. Jetzt wird er ausgedünnt und reicht bis zum Ende; Befehle, Downloads und KI-Antworten behalten immer ihren Strich.
- „Ältere laden“ und andere ausgeblendete Knöpfe waren trotzdem sichtbar.
- **Antworten vom Sprachmodell scheiterten oft mit „KI-Antwort nicht lesbar: leere Antwort“.** Ursache war eine Zeitüberschreitung: OpenRouter meldet sofort „OK“ und liefert die Antwort erst später; nach 12 Sekunden brach der Hive ab und hielt das für eine leere Antwort. Jetzt entsteht die Antwort im Hintergrund (bis 90 Sekunden). Der Angreifer wartet höchstens 10 Sekunden und bekommt sonst wie bisher die statische Antwort; die fertige Antwort wird gespeichert und gilt ab dem nächsten gleichen Befehl. Gleiche Anfragen gleichzeitig kosten nur einen Modellaufruf. Fehlermeldungen nennen die Ursache („Modell zu langsam“, „nicht erreichbar“).

### Geändert
- **Datenschutz:** Bei unbekannten Web-Pfaden geht an das Sprachmodell nicht mehr die Host-Angabe des Angreifers (meist die öffentliche IP des Anschlusses) und kein User-Agent, sondern der eigene Hostname. Dadurch greift der Zwischenspeicher auch, wenn verschiedene Scanner denselben Pfad abfragen.

## [0.7.0-beta.2] – 2026-11-17

### Behoben
- CI: Tests der Sprachmodell-Antworten im Honeypot meldeten unter dem Race-Detector einen Wettlauf (nur Testcode, das Programm war nicht betroffen).

### Geändert
- Interne Arbeitsdokumente (Prüfberichte, Protokolle, Vorschläge) liegen nicht mehr im Repository. Hinweise für Mitentwickler zum Windows-Virenscanner stehen jetzt in `docs/ENTWICKLUNG.md`.

## [0.7.0-beta.1] – 2026-11-17

**Update:** Raspberry Pi per Knopf (System → Updates, Kanal „Vorabversionen“), kein neues Image nötig; die neuen Dienste unter Einstellungen → Ports und Modi über „Port hinzufügen“ ergänzen. Docker: `sh update.sh`, danach `sudo sh tools/firewall.sh`.

### Neu
- **Muster „Honeypot-Prüfung“:** Erkennt Testreihen, mit denen Bots nach dem Login prüfen, ob die Shell echt ist (Marker wie `check_<hash>_small_math`, Rechnen mit `$((…))`, Subshell-Test `v=outer; (v=inner; …)`, Quoting-Test, `echo dGVzdA== | base64 -d`). MITRE T1497.001. Die Analyse zeigt, wie viele Angreifer danach weitermachten (Tarnung gehalten) und wie viele abbrachen.
- **Krypto-Wallets und Mining-Pools** werden aus Miner-Befehlen und Docker-`create` herausgezogen (Monero, Bitcoin, Ethereum; Pools aus `stratum+tcp://` und `-o host:port`). Neue Top-Listen `wallet` und `pool`; **Kampagnen auch über gleiche Wallet**.
- **Exploits ohne CVE-Zuordnung:** Die Analyse listet Router-/IoT- und Web-Exploits, für die es noch keine CVE-Regel gibt, mit den häufigsten Pfaden als Vorlage für neue Regeln.
- **Mirai-Liste:** Zugangsdaten aus der bekannten Mirai-Liste sind gekennzeichnet; die Seite Zugangsdaten zeigt ihren Anteil.
- **Sechs neue Dienste**, zunächst ausgeschaltet (Einstellungen → Ports und Modi; Docker-Ports schon freigegeben): **ADB** 5555 (Shell-Befehle und Datei-Ablagen), **MQTT** 1883 (Anmeldung, Themen, Nachrichten), **PostgreSQL** 5432 (Anmeldung, schwache Standardpasswörter werden zum Schein angenommen, danach Abfragen wie `COPY … FROM PROGRAM`), **Elasticsearch** 9200, **Ollama/KI-API** 11434 (Prompts, Modell-Downloads, OpenAI-kompatibel), **Kubernetes** 6443 und Kubelet 10250 (Pods, `exec`, `/run`; mit oder ohne TLS). Alle mit Tarpit- und Hybrid-Modus. `tools/attack_sim.py --new-services` testet sie.
- **Blockliste zum Abonnieren** (Einstellungen): eine Adresse mit Token, die eine Firewall im Heimnetz regelmäßig abruft (OPNsense/pfSense „URL Table“). Zeitraum und Mindeststufe wählbar; nie enthalten sind eigene Netze, private Adressen, Angreifer nur über UDP und auf Wunsch Forschungsscanner. Ergebnis 10 Minuten zwischengespeichert.
- **Nachgeladene Dateien untersuchen** (Angriffsbericht → „Datei untersuchen“): Dateityp, Architektur, UPX-Packung, eingebettete Adressen, IPs, Wallets und erkannte Muster. Die Datei wird nur gelesen, nie ausgeführt oder ausgeliefert.
- **Weitere Sensoren mit eigenem Token** (Einstellungen): Jeder Sensor bekommt ein eigenes, an seinen Namen gebundenes Token (nur einmal angezeigt, nur als Hash gespeichert, einzeln widerrufbar). Für entfernte Sensoren gehört die Sensor-API hinter ein VPN.

- **Antworten vom Sprachmodell für Unbekanntes** (Einstellungen): Kennt die Telnet-Shell einen Befehl nicht oder der Web-Honeypot einen Pfad nicht, erzeugt ein Sprachmodell eine glaubwürdige Antwort; gegen Bots, die die Shell mit Testbefehlen prüfen. Jede OpenAI-kompatible Schnittstelle, lokal oder im Internet (OpenRouter …), eigene Angaben oder die der KI-Auswertung. Jede Antwort wird gespeichert (gleiche Eingabe, gleiche Antwort, nur einmal Kosten); Grenzen je Stunde und je Angreifer; bei Fehlern, Zeitüberschreitung (12 s) oder erreichter Grenze antwortet der Honeypot statisch wie bisher. Der Honeypot fragt den Hive, nie selbst das Internet (Netzsperre bleibt).
- **Neue Seite „Erkenntnisse“:** Angriffsfamilien (Angriffe mit ähnlicher Befehlsfolge, „neu“ in den letzten 24 Stunden, Ausreißer), „Erstmals gesehen“ (Passwörter, Befehle, Pfade, Fingerabdrücke, Wallets … die es vorher nie gab), Wiederkehrer und „Erkunden → Angreifen“ (seltener Fingerabdruck erst beim Abtasten, dann bei einem Angriff einer anderen IP).
- **Spitzen-Warnung** (Benachrichtigungen): Meldung, wenn ein Dienst in der letzten Stunde ein Vielfaches seines üblichen Aufkommens hat.
- **Suchsprache** auf der Seite Angriffe, z. B. `service:ssh stufe>=3 cmd:*wget* -scanner:ja`, mit **gespeicherten Suchen**. Freier Text sucht wie bisher.
- **Wie Shodan dich sieht** (System): fragt Shodan InternetDB nach der öffentlichen Adresse ab und zeigt offene Ports, Software, Lücken und ob Shodan das Gerät als Honeypot führt.

### Sicherheit
- **Blockliste und AbuseIPDB gegen gefälschte Ereignisse geschützt:** Sensoren mit eigenem Token speisen beides erst, wenn du ihnen vertraust (Einstellungen → Weitere Sensoren); öffentliche DNS-Resolver und eine eigene Liste „Nie sperren“ sind immer ausgenommen; höchstens 300 neue Adressen je Stunde (einstellbar), darüber Warnung.
- **Docker:** Das interne Netz zwischen Honeypot und Hive heißt jetzt `hv-ingest` und darf die NAS nicht erreichen; mit `ALLOW_DOWNLOADS=1` darf nur noch Cowrie ins Internet. **Nach dem Update `sudo sh tools/firewall.sh` ausführen.** `update.sh` legt die Netze dafür bei Bedarf neu an.
- **Leserolle** sieht keine Adressen von ntfy oder Webhooks mehr in Fehlermeldungen und kann keine Abfragen bei Dritten oder Probenanalysen mehr auslösen.
- Honeypot-Parser auf 32 Bit abgesichert, Speicher erst bei eintreffenden Daten; Sprachmodell-Antworten mit Tagesbudget, kürzeren Antworten und geprüftem Content-Type; Probenanalyse, „Erstmals gesehen“ und Angriffsfamilien zwischengespeichert und nie parallel; reservierte Ports 8088/8089 (Pi auch 22/23); zusätzliche systemd-Härtung des Honeypots auf dem Pi.
- **Behoben:** Der Honeypot ließ sich für den 32-Bit-Pi (armv7) nicht bauen.

### Geändert (Erkenntnisse)
- **Seite „Erkenntnisse“ neu gestaltet:** Lagebericht „Was ist neu“ mit Filter nach Art (neue Familien, Erstmaliges, Wiederkehrer, Erkunden → Angreifen, Spitzen), Familien als Rangliste zum Aufklappen, Wiederkehrer als Kalenderstreifen und Scanner→Angreifer-Paare.

### Bewusst nicht umgesetzt
- **Alle Ports mitschneiden (Teleskop)** und **passive Betriebssystem-Erkennung**: Beides braucht entweder Umleitungsregeln, die ein root-Dienst laufend nachführen müsste, oder Raw-Sockets, mit denen ein übernommener Honeypot die Ausgangssperre umgehen könnte. Dazu erzeugt ein einziger Komplett-Scan zehntausende Ereignisse (SD-Karte). Sicherheit geht vor.

### Geändert
- **Analyse neu gestaltet:** Muster nach Phasen (Erkundung bis Ziel) mit Schwere, MITRE und Verlauf; Werkzeuge in vier Gruppen; Indikatoren (Nachlade-Adressen, Wallets, Pools); wiedererkannte Werkzeuge über Fingerabdrücke; Kampagnen und Honeypot-Prüfungen laden nach, die Seite erscheint dadurch schneller.
- **Zugangsdaten neu gestaltet:** Kennzahlen zur Vielfalt, Aufbau der Passwörter (Zeichenarten, Länge), Ranglisten mit Kennzeichen, Befehle nach Dienst, HTTP-Pfade nach Zweck (z. B. KI/MCP, VPN, Kamera), Art der User-Agents.
- **Tarpit neu gestaltet:** große Kennzahl mit Vergleichen und Verlauf, **Zeitleiste der zehn hartnäckigsten Angreifer**, Anteil je Port, Verteilung der Haltedauer.
- Beim ersten Start werden die Top-Listen einmal neu gezählt, damit Honeypot-Prüfungen, Wallets und Pools auch für ältere Ereignisse erscheinen.

## [0.6.1-beta.2] – 2026-11-17

### Neu
- **Anmelderegel von Cowrie in den Einstellungen** (Einstellungen → SSH und Telnet): „erst nach mehreren Versuchen“ mit wählbarem Bereich (1–20 je IP) oder „jede Kombination sofort“. Auf dem Raspberry Pi übernimmt ein kleiner Systemdienst (`hivornet-cowrie-config`) die Änderung und startet Cowrie neu; ein neues Image ist dafür nicht nötig. Im Docker-Betrieb steht die Regel in `.env` (`COWRIE_AUTH_CLASS`, `COWRIE_AUTH_PARAMS`), die Einstellungen zeigen sie an.
- **Update per Knopf bringt jetzt auch Systemdateien mit** (Raspberry Pi): systemd-Dienste, Skripte unter `/usr/local/sbin` und Systembenutzer kommen aus dem Programmpaket. Das gilt schon für dieses Update: Auch ältere Pis übernehmen beim Update auf 0.6.1-beta.2 die neuen Dienste, die SSH-Reparatur für Port 22 und die Anmelderegel (2 bis 5 Versuche), ohne neu zu flashen. Einstellungen unter `/etc/hivornet` werden dabei nicht überschrieben.

## [0.6.1-beta.1] – 2026-11-17

### Behoben
- **Cowrie nahm jede SSH- und Telnet-Anmeldung schon beim ersten Versuch an** (mitgelieferte Benutzerliste mit `*:x:*`), woran geübte Bots den Honeypot erkennen. Jetzt gilt `AuthRandom`: Jede IP muss 2 bis 5 verschiedene Kombinationen probieren (zufällig), die erfolgreiche gilt für diese IP weiter. Docker: über Umgebungsvariablen, kommt mit dem Update. Raspberry Pi: in `/etc/hivornet/cowrie.cfg`, also mit dem neuen Image; ältere Images zeigen eine Warnung unter System mit der Anleitung zum Nachtragen.

### Geändert
- **Karten:** Die rote Linie eines Angreifers bleibt stehen, bis er 10 Minuten lang nichts mehr getan hat, und erscheint beim Öffnen von Dashboard und Live-Karte gleich für alle Angreifer der letzten 10 Minuten.
- **Angriffskette aktualisiert sich live** auf der Seite eines Angreifers und einer Sitzung: Bekannte Bubbles behalten Platz, Zoom und Auswahl bleiben, neue kommen mit kurzem Aufleuchten hinzu.

## [0.6.0-beta.1] – 2026-11-17

### Behoben
- **Web-UI springt nicht mehr:** Dashboard, Tarpit und System aktualisieren sich jetzt unauffällig im Hintergrund (neue Fassung unsichtbar aufbauen, dann an derselben Scrollstelle austauschen, kein „Lade …“). Das Dashboard aktualisiert sich nicht, solange die Karte hineingezoomt oder ein Angriff aufgeklappt ist. Auf der Seite Angriffe bleibt beim Herunterscrollen der gelesene Angriff stehen, während oben neue dazukommen.
- **Raspberry Pi: SSH (Port 22) blieb nach einem Stromausfall beim ersten Start dauerhaft zu.** Eine leere Host-Schlüsseldatei ließ Cowrie beim Start abbrechen, Telnet lief weiter. Vor jedem Start entfernt jetzt `hivornet-cowrie-keycheck` leere oder beschädigte Schlüssel; Cowrie erzeugt sie neu. Braucht ein neues Image (Sicherung exportieren, Image aufspielen, Sicherung einspielen).
- **Stufe „Befehle ausgeführt“ nur noch für echte Befehle:** nach einem angenommenen Login oder bei verändernden Befehlen (Redis `CONFIG SET`, `SLAVEOF`, Docker `create`/`exec` …). Protokoll-Abfragen von Forschungsscannern (Redis `PING`/`INFO`, FTP `AUTH TLS`, SMTP `EHLO`) sind Abtasten. Die Angriffskarte trennt „Befehle (ausgeführt)“ und „Protokoll-Befehle“. Alle Regeln an einer Stelle: `hive/einstufung.go`.
- **TLS-Handshakes an Klartext-Ports** (FTP, Redis, SMTP, Telnet, HTTP, MySQL …) sind keine Befehle und keine „Verschleierung“ mehr, sondern ein Ereignis `tls` mit `plain: true` und den Rohdaten (für Fingerabdrücke). Ältere Einträge erkennt der Hive ebenso.
- **Telnet: Befehle an der Login-Abfrage** (`enable`, `system`, `shell`, `sh`, `/bin/busybox …`) zählen nicht mehr als Benutzername und Passwort.
- **Getrennte Top-Listen:** SNMP-Community-Strings, SIP-Adressen und DNS-Abfragen stehen in eigenen Listen statt bei Zugangsdaten bzw. HTTP-Pfaden; IP-Adressen in SIP-Adressen werden ersetzt. Beim ersten Start werden die Top-Listen einmal nach den neuen Regeln neu gezählt.

### Geändert
- **Telnet-Honeypot:** Je Angreifer-IP gilt das dritte verschiedene Werkspasswort aus der bekannten Liste und bleibt danach für diese IP gleich, statt eines einzigen Passworts je Gerät.
- **Tarnung:** HTTP antwortet auf `OPTIONS` mit 405 und auf kaputte Anfragen mit 400 wie nginx; die MySQL-Thread-ID zählt je Verbindung hoch; Redis kennt `CONFIG GET` mit Mustern (auch `*`) und Abschnitte bei `INFO`.

### Neu
- **Warnung, wenn ein Dienst nicht lauscht:** Auf dem Raspberry Pi prüft der Hive jede Minute Cowrie-SSH und -Telnet und nennt bei einem kaputten Host-Schlüssel die Ursache; Ports, die der Honeypot nicht öffnen konnte, erscheinen ebenfalls als Warnung. System → Cowrie zeigt den Stand der Ports. `HIVE_COWRIE_PROBE` setzt die Ziele oder schaltet die Prüfung ab.
- **Automatische Meldung an AbuseIPDB** (standardmäßig aus, mit Probemodus): echte Angriffsversuche mit passender Kategorie und einem Kommentar ohne Passwörter, IP-Adressen und Hostnamen; nie eigene oder private Adressen, nie Angriffe nur über UDP, Forschungsscanner ausnehmbar; je IP höchstens eine Meldung im eingestellten Abstand, Tageslimit, Pause bei erschöpftem Kontingent. Protokoll, Kontingent und Fehler in den Einstellungen.
- **Forschungsscanner gekennzeichnet:** Angriffe von Shodan, Censys, Shadowserver und ähnlichen Diensten tragen ein Kennzeichen (erkannt am Netzbetreiber und User-Agent).
- **Köderdateien:** Der Web-Honeypot liefert `/.env`, `/.git/config`, `/robots.txt`, `/backup/` und `config.php.bak` mit glaubwürdigem Inhalt statt 404. Die Zugangsdaten darin sind erfunden und je Installation verschieden. Probiert sie jemand später bei FTP, MySQL, SMTP, Redis, Telnet oder SSH aus, erscheint das Muster **„Köder benutzt“** (Stufe mindestens „Login angenommen“, Benachrichtigung als schweres Muster).
- **Geräteprofile** (Einstellungen → Geräteprofil): Linux-Server, NAS oder Router/Kamera bestimmen Banner und Versionen aller Dienste; „Profil übernehmen“ schaltet dazu passende Dienste ein und setzt den Hostnamen. Bestehende Installationen behalten ihr Verhalten, bis ein Profil gewählt wird.
- **FTP mit Schein-Verzeichnis:** Anmeldung anonym und mit den Köder-Zugangsdaten, Verzeichnisse und Dateigrößen; `LIST`, `RETR` und `STOR` werden aufgezeichnet, Daten aber nie übertragen (keine Datenverbindung).
- **Docker-API** listet Container und Images.
- **Angriffskette** auf der Seite eines Angreifers und einer Sitzung: ein frei beweglicher Graph aus Bubbles (Ports, Anmeldungen, Exploits, Befehlsgruppen, Nachlade-Hosts, Dateien, Weiterleitungen), angeordnet nach Phasen von Erkundung bis Ziel, mit Pfeilen für die Reihenfolge und die Herkunft von Dateien. Verschieben, zoomen, Bubbles umsetzen; ein Klick zeigt Einzelheiten, MITRE-Techniken und Verbindungen; dazu der Hauptpfad in einer Zeile.
- **Fingerabdrücke:** JA3 und JA4 aus dem TLS-Handshake (HTTPS und Handshakes an Klartext-Ports), Reihenfolge der HTTP-Kopfzeilen, HASSH; am Angriff, im Bericht und in der Analyse.
- **Kampagnen** (Analyse): Angreifer mit gleicher Zugangsdatenliste oder gleicher Nachlade-Adresse werden zusammengefasst; gleiche Fingerabdrücke bei mehreren IPs zeigen dasselbe Werkzeug.
- **Bekannte Lücken und MITRE ATT&CK:** 16 Ausnutzungsversuche bekannter Lücken werden mit CVE-Nummer benannt (Log4Shell, PHPUnit, GPON, Huawei HG532 …); jedes Muster ist MITRE-ATT&CK-Techniken zugeordnet.
- **Angebliche Suchmaschinen-Bots** (Googlebot, Bingbot, Applebot, YandexBot) werden per Rückwärts- und Vorwärtsauflösung geprüft; gefälschte sind gekennzeichnet, echte nicht an AbuseIPDB gemeldet.
- **URLhaus und MalwareBazaar:** Nachlade-Adressen und Datei-Hashes im Bericht auf Knopfdruck nachschlagen (kostenloser Schlüssel von abuse.ch).
- **Ungewöhnliche Zugangsdaten** (nicht in gängigen Standard- und Werkslisten) sind in den Top-Listen markiert.
- **Wochenbericht** montags ab 8 Uhr über ntfy, Telegram oder Webhook (Einstellungen → Benachrichtigungen, mit Vorschau).
- **Eigene Netze:** Verbindungen aus privaten Adressen und aus einstellbaren Netzen gelten als „eigener Test“: gespeichert und auf der Seite Angriffe einsehbar, aber nicht in Kennzahlen, Top-Listen, Angreiferliste, „Gerade aktiv“ und Benachrichtigungen.

## [0.5.2-beta.1] – 2026-11-16

### Neu
- **Verschleierte Befehle werden entschlüsselt.** Base64 (auch verschachtelt und URL-sicher), Hex- und Oktal-Escapes sowie URL-Kodierung in Befehlen, Web-Anfragen und Daten werden automatisch aufgedeckt. Der Klartext erscheint auf der Angriffskarte („Entschlüsselt“) und im Angriffsbericht; Nachlade-Adressen darin landen bei den Nachlade-Adressen, in der Analyse und in der Suche, und die Angriffsmuster prüfen auch den entschlüsselten Inhalt. Neues Muster „Verschleierung“.
- **Gerade festgehaltene Angreifer im Tab Tarpit:** IP, Herkunft, Dienst und Port, Modus, seit wann, und eine mitlaufende Dauer. Der Honeypot meldet die Liste mit jedem Lebenszeichen (alle 10 Sekunden).
- **Live-Anzeige auf jeder Seite:** Oben rechts steht überall „LIVE · N aktiv · N im Tarpit“; beide Angaben sind Links zu den Angriffen bzw. zum Tarpit.
- **Kennzahlen im Dashboard anklickbar:** Verbindungen und Angreifer-IPs führen zu den Angriffen, Login-Versuche und Web-Anfragen zur gefilterten Einzelansicht, „Logins angenommen“ zu den Angriffen mit angenommenem Login, Downloads zu den Angriffen mit nachgeladener Datei.
- **Angriffe über längere Zeiträume:** 30 Tage, 90 Tage und „Alles“ (so weit die Aufbewahrung reicht). Bei sehr vielen Daten wertet der Hive die neuesten 500.000 Ereignisse aus und sagt das an.
- **Live-Karte:** Gerade aktive Angreifer bekommen eine rote Linie zum Honeypot, die stehen bleibt, solange sie etwas tun, und kurz nach ihrer letzten Verbindung verschwindet. Gilt auch für die Karte im Dashboard.

### Geändert
- **KI-Auswertung ausführlicher:** Die KI bekommt zusätzlich den zeitlichen Ablauf aller Ereignisse (gleiche Zeilen zusammengefasst) und die entschlüsselten Inhalte und antwortet gegliedert: Kurzfassung, Ablauf, Technik im Detail (jeder aufschlussreiche Befehl erklärt), Ziel und Schadsoftware, automatisiert oder von Hand, Indikatoren, Empfehlungen. Bei Einbrüchen bis etwa 900 Wörter. Die Antwort wird mit Überschriften und Listen dargestellt.
- Karte: Im Modus „Orte“ reagieren die Länder nicht mehr auf die Maus; die Punkte sind größer (mit Obergrenze) und leichter zu treffen.

## [0.5.1-beta.1] – 2026-11-15

### Neu
- **Erlaubte Hostnamen in der Web-UI.** Unter Einstellungen → Zugriff über Reverse-Proxy trägst du die Domain ein, unter der du die Web-UI über einen Reverse-Proxy aufrufst. Bisher ging das nur mit `HIVE_ALLOWED_HOSTS`, auf dem Raspberry Pi also gar nicht. Die Liste ergänzt `HIVE_ALLOWED_HOSTS` und gilt sofort; IP-Adressen und Heimnetz-Namen bleiben immer erlaubt.
- **Sitzungen** stehen jetzt unter Angriffe (dritter Umschalter neben „Gebündelt“ und „Einzelne Ereignisse“) statt im Benutzermenü.
- **Anmelde-Cookie automatisch nur über HTTPS**, wenn die Anmeldung über HTTPS kommt (direkt oder über einen Proxy mit `X-Forwarded-Proto: https`). `HIVE_COOKIE_SECURE=1` erzwingt es weiterhin immer.

## [0.5.0-beta.1] – 2026-11-15

### Neu
- **Neues Design der Web-UI.** Standardmäßig dunkel, Navigation in einer Kopfleiste, Benutzermenü oben rechts (Darstellung Dunkel/Hell/System, Einstellungen, Sitzungen, Protokolle, Abmelden). Alle Seiten nutzen dieselben Bausteine.
- **Dashboard neu aufgebaut:** sechs Kennzahlen mit Verlaufslinie und Vergleich zum Zeitraum davor (Logins angenommen und Downloads rot, sobald einer vorkommt), große Weltkarte, **Gerade aktiv** mit den Angreifern der letzten 15 Minuten (je IP eine Zeile mit Stufe, Art und Zugangsdaten, aufklappbar), Verlauf nach Dienst und Top-Listen. Die Live-Anzeige oben zeigt, wie viele Angreifer gerade aktiv und wie viele Verbindungen im Tarpit sind.
- **Seite „Angriffe“** (ersetzt den Live-Feed): Ereignisse einer IP werden zu Angriffen gebündelt (weniger als 15 Minuten Pause). Jede Karte zeigt Stufe (Abtasten, Versuche, Login angenommen, Befehle ausgeführt, Datei nachgeladen), vermutete Art (z. B. SSH-Brute-Force, Web-Scanner, IoT-Botnetz, Redis-Übernahme, Port-Scan), Zusammenfassung, Zeitstreifen, Zugangsdaten mit Anzahl, Pfade, Befehle, Nachlade-Adressen und erkannte Muster; aufklappbar mit den Ereignissen, gleichartige zusammengefasst. Filter nach Stufe und Dienst, Suche über alles, Zeitraum 1 Std/24 Std/7 Tage, Live-Aktualisierung. Die Einzelansicht bleibt als Umschalter erhalten und fasst Wiederholungen derselben IP zu einer Zeile mit Zähler zusammen.
- **Weltkarte:** Länder nach Anzahl der Angriffe eingefärbt, Orte als kleine Punkte; Zoom per Mausrad, Verschieben durch Ziehen, Regionen-Knöpfe (Europa, Asien, …) und Umschalter Länder/Orte/Beides. Gilt für Dashboard und Live-Karte.
- **Angreifer-Seite:** Kopf mit Herkunft, Netzbetreiber, höchster Stufe und Kennzahlen; darunter alle Angriffe dieser IP als Karten. Die Einzelereignisse sind eingeklappt.
- Zugangsdaten und Analyse: Ein Klick auf Benutzername, Passwort, Befehl, Pfad oder Angriffsmuster zeigt die Angriffe, in denen er vorkam.
- Live-Karte: Wiederholungen derselben IP zählen in der Laufliste hoch, statt neue Zeilen anzulegen.
- API: `/api/attacks`, `/api/stats/series`; `/api/events` kennt `from` und `to`.

## [0.4.0-beta.6] – 2026-11-15

### Geändert
- Weltkarte: Die Punkte der Angriffsherkunft sind deutlich kleiner (größter Punkt etwa 2 statt 5 Grad Radius), ebenso die Live-Pulse. Nahe Orte lassen sich unterscheiden und das Land darunter bleibt sichtbar.

### Behoben
- KI-Auswertung: „KI-Antwort nicht lesbar“ bei Antworten, die vom einfachsten Format abweichen. Gelesen werden jetzt auch Denkmodelle (`<think>`-Blöcke, `reasoning`-Felder), `content` als Liste, gestreamte Antworten und Ollamas eigenes Format. Die Token-Grenze steigt von 900 auf 4096, damit Denkmodelle nach dem Nachdenken noch antworten. Bleibt die Antwort leer oder unlesbar, nennt die Meldung den Grund: Fehlermeldung des Anbieters, Token-Grenze beim Nachdenken verbraucht, Webseite statt API (falsche Basis-Adresse) oder Inhaltsfilter.

## [0.4.0-beta.5] – 2026-11-15

### Neu
- Raspberry Pi: **Verwaltungsanschluss.** Ein USB-Netzwerkadapter (`eth1` … `eth9`, `enx…`) im Heimnetz macht die Web-UI von dort erreichbar, während der eingebaute Anschluss in einem eigenen Netz steckt (VLAN/DMZ; das FRITZ!Box-Gastnetz erlaubt keine Portfreigaben). `hivornet-firewall` lässt über den Adapter nur Port 8088 herein, sperrt dort alle neuen Verbindungen des Pi (außer DHCP, IPv6-Nachbarsuche und mDNS) und jede Weiterleitung zwischen den Anschlüssen. Die Netzsperre startet jetzt vor dem Netzwerk. Eine NetworkManager-Einstellung gibt der Route des Adapters niedrigeren Rang, damit Internet und Updates über das Gastnetz laufen. Die Web-UI zeigt unter System → Netzwerk den Adapter und den Stand der Sperre und warnt, wenn ein Adapter verbunden, aber nicht geschützt ist (auch auf älteren Images). Braucht ein neues Image.

## [0.4.0-beta.4] – 2026-11-15

### Neu
- **Sicherung über die Web-UI** (Einstellungen → Sicherung, nur Admins): Export aller Daten in eine verschlüsselte Datei (`.hvbak`) mit Einstellungen, Zusatzfunktionen samt API-Schlüsseln, Benutzern, Ereignissen, Angreifern, Statistiken und Berichten. Der Export verlangt das Admin-Passwort und verschlüsselt damit (AES-256-GCM in 1-MiB-Blöcken, Schlüssel per Argon2id; Änderungen, Abschneiden und Umsortieren fallen auf). Der Import verlangt dasselbe Passwort, prüft die Datenbank (Integrität, Schema-Version, Admin-Konto), hebt die bisherige Datenbank unter `backups/vor-wiederherstellung-…` auf und startet den Hive neu. Anmeldesitzungen und der Lesestand des Cowrie-Logs werden nicht übernommen.
- Raspberry Pi: Seite **Protokolle** in der Web-UI (nur Admins, nur lesen). Zeigt die Systemprotokolle der Hivornet-Dienste (Cowrie, Cowrie-Installation, Honeypot, Hive, Netzsperre, Updates) und das Installationsprotokoll des ersten Starts, auf Wunsch alle 5 Sekunden aktualisiert. Ein Bildschirm am Pi ist zur Fehlersuche nicht mehr nötig.
- Raspberry Pi: Die Cowrie-Installation meldet ihren Stand (läuft mit aktuellem Schritt, fertig, gescheitert bei Schritt X). Die Web-UI zeigt ihn unter System und im Hinweis auf dem Dashboard statt der allgemeinen Meldung „Cowrie-Log nicht gefunden“.
- CI: Neuer Test installiert Cowrie mit dem Skript des Pi-Images in Debian 13 und startet es mit der Befehlszeile aus `hivornet-cowrie.service`; SSH, Telnet und `cowrie.json` werden geprüft.

### Behoben
- Raspberry Pi: **Cowrie startete nach der Installation nicht** (`twistd: Unknown command: cowrie`). Cowrie 3.1.6 muss selbst als Paket installiert werden, sonst fehlt `cowrie/_version.py` und das Plugin wird stillschweigend ignoriert. Der Installer installiert es jetzt mit `pip install -e` und prüft am Ende, dass `twistd` das Plugin findet; klappt das nicht, gilt die Installation als gescheitert und wird stündlich wiederholt.
- Raspberry Pi: Beim ersten Start meldete `cloud-final.service` einen Fehler, obwohl die Installation geklappt hatte. vendor-data hatte den Installer schon ausgeführt (er löscht sich danach), und der zweite Anstoß aus user-data fand die Datei nicht mehr. Jetzt prüft der zweite Anstoß nur, ob die Installation fertig ist.
- Image-Bau: pyfatfs 1.1.0 zerstörte beim Überschreiben von `user-data` mit einer kürzeren Datei die Clusterkette der Bootpartition. Vorhandene Dateien werden jetzt vorher gelöscht.
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

Überarbeitung nach 0.2.0; Aufbau in `docs/ARCHITEKTUR.md`. Die Datenbank wird beim ersten Start auf Schema-Version 4 gebracht. Bestehende Installationen bekommen die neuen Dienste automatisch in ihre Port-Konfiguration ergänzt (Port 5900 wird von `raw` zu `vnc`; SMTP, Telnet und RDP kommen auf freie Ports dazu).

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
- **Dokumentation:** `docs/ARCHITEKTUR.md`.

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

Umsetzung einer Sicherheitsprüfung. Datenbanken aus 0.1.0 werden beim ersten Start automatisch migriert. Bestehende Sitzungen werden dabei ungültig: Einmal neu anmelden.

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
