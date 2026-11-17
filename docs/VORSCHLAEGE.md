# Vorschläge für neue Funktionen (Stand 17.11.2026, umgesetzt in Version 0.7.0-beta.1)

Grundlage: README, CHANGELOG, `docs/AUDIT.md`, ein Blick in die laufende Instanz (letzte 24 Stunden, 415 Angriffe) und ein Vergleich mit T-Pot, Cowrie, Dionaea, Conpot, ADBHoney, Beelzebub, Galah, DECEIVE sowie aktueller Forschung.

Schon vorhanden und deshalb hier **nicht** aufgeführt: Tarpit/Hybrid, Angriffsbündelung, Angriffskette, Kampagnen über Zugangsdaten/Nachlade-Adresse, JA3/JA4/HASSH, CVE-Erkennung, MITRE, Entschlüsselung, Köderdateien, Geräteprofile, KI-Bericht, AbuseIPDB/GreyNoise/abuse.ch, STIX, Wochenbericht.

---

## A. Aus deinen eigenen Daten (schnell umsetzbar)

### A1 – Honeypot-Erkennung durch Angreifer sichtbar machen ★★★
In den letzten 24 Stunden haben mindestens zwei IPs nach dem Login eine feste Testreihe geschickt:

```
printf '\n%s|%s\n' 'check_<hash>_small_control' ...
printf ... 'check_<hash>_small_math' "$((535*316+18))"
printf ... 'check_<hash>_small_pid' "$$"
set -- a b; printf ... "$#|$1|$2"
f() { ... }; f value
v=outer; (v=inner; printf 'child=%s\n' "$v"); printf 'parent=%s\n' "$v"
printf '%s\n' 'a b;$()'
echo 'dGVzdA==' | base64 -d
```

Das ist kein Angriff, sondern ein **Echtheitstest der Shell**: Rechnen, `$$`, Positionsparameter, Funktionen, Subshells, Quoting. Eine emulierte Shell scheitert an einigen davon, der Bot merkt sich die IP als Honeypot. Heute läuft das ohne Muster durch.

- Neues Muster **„Honeypot-Prüfung“** (Regeln in `hive/analyze.go`): `check_[0-9a-f]{32}_`, `$((…))` mit Markern, `v=outer`, `printf '%s\n' 'a b;$()'`, `echo <kurz-base64> | base64 -d` direkt nach dem Login.
- Kennzahl **„Tarnung bestanden?“**: Anteil der Sitzungen, die nach so einem Test weitermachen (Befehle, Nachladen) statt sofort abzubrechen. Damit lässt sich jede Tarnungsänderung messen.
- Den Ablauf einmal gegen Cowrie nachspielen und prüfen, welche Antworten falsch sind (`$$`, Funktionen und Subshell sind typische Schwachstellen). Was Cowrie nicht kann, ist ein Kandidat für C1.

### A2 – Krypto-Wallets und Mining-Pools als Indikatoren ★★★
Die Docker-API hat `metal3d/xmrig` mit `-o gulf.moneroocean.stream:10001 -u 45zFhG…` bekommen. „Nachlade-Adressen“ zeigt trotzdem „Noch keine“.

- Monero-, Bitcoin- und Ethereum-Adressen aus Befehlen und Docker-`create` herausziehen; **Kampagnen auch über gleiche Wallet** bilden (das ist der stärkste Zusammenhang zwischen IPs überhaupt).
- Pool-Adressen (`*.moneroocean.stream`, `pool.supportxmr.com`, `:3333`, `:10001`, `stratum+tcp://`) als eigene Liste „Mining-Pools“ führen.
- `--rig-id <IP>` enthält eine IP-Adresse. Ist das die eigene öffentliche Adresse, nutzt der Angreifer sie als Kennung des „Opfers“. Dann gehört sie wie bei SIP ersetzt, bevor sie in Exporte, STIX oder AbuseIPDB-Kommentare gelangt.

### A3 – CVE-Erkennung schließt die Lücke zu „Router-/IoT-Exploit“ nicht ★★
Die Analyse zählt 16 × „Router-/IoT-Exploit“, aber 0 bekannte Lücken. Vorschlag: eine Liste **„Exploit ohne CVE-Zuordnung“** mit Pfad und Rumpf, damit neue Regeln schnell geschrieben werden können. Zusätzlich die Regeln regelmäßig aus Quellen wie CISA KEV erweitern (häufig: Ivanti, Fortinet, Palo Alto, Citrix, TP-Link, Zyxel, Hikvision, ThinkPHP).

### A4 – Analyse-Seite schneller ★★
Die Seite „Analyse“ brauchte auf dem Pi rund zehn Sekunden (`/api/stats/top` zehnmal einzeln plus Kampagnen). Ein gemeinsamer Endpunkt oder vorab berechnete Zähler (z. B. stündlich, wie die Stundenstatistik) würden helfen.

### A5 – Kleinigkeiten
- KI-Bericht nennt 41 Login-Versuche, die Seite 43. Der Ausschnitt für die KI scheint nicht ganz aktuell zu sein.
- 12 angenommene Logins, aber 0 Downloads: Prüfen, ob Cowrie auf dem Pi Nachlade-Versuche aufzeichnet, auch wenn die Netzsperre das Laden verhindert (die URL allein ist schon wertvoll).

---

## B. Was andere Honeypots haben und Hivornet noch fehlt

### B1 – Alle Ports mitschneiden („Teleskop“) ★★★
T-Pot nutzt dafür Honeytrap. Per `nftables`-Regel alle sonst ungenutzten TCP-Ports auf einen Listener umleiten, der nur Verbindung, Zielport und die ersten Bytes speichert. Das ist billig und liefert:
- eine **Port-Heatmap** (welche Ports gerade gescannt werden, z. B. Wellen nach neuen CVEs);
- Protokollerkennung aus den ersten Bytes (TLS, HTTP, SSH, RDP, SMB …) auf beliebigen Ports;
- Hinweise, welchen Dienst man als Nächstes emulieren sollte.

Auf dem Pi einfach, im Docker-Betrieb nur mit Host-Netz bzw. NAT-Regel.

### B2 – Neue Dienste mit gutem Ertrag ★★★
Sortiert nach Nutzen pro Aufwand (alle als kleine Go-Emulation im bestehenden Dienste-Register):

| Dienst | Port | Warum | Vorbild |
|---|---|---|---|
| Android Debug Bridge (ADB) | 5555 | sehr viel Miner- und Botnetz-Verkehr, Befehle im Klartext, einfache Protokollemulation | ADBHoney |
| Ollama / OpenAI-API | 11434 | offene KI-Server sind 2025/26 ein beliebtes Ziel (Modell-Diebstahl, Rechenzeit) | – |
| Elasticsearch | 9200 | Datensuche und alte RCE-Versuche | ElasticPot |
| SMB | 445 | meistgescannter Port überhaupt, EternalBlue, Wurm-Verkehr; zum Aufzeichnen reicht Verhandlung + NTLM-Anmeldung | Dionaea |
| VPN- und Firewall-Anmeldeseiten | 443 | Fortinet, Ivanti, Citrix, Palo Alto sind die Ziele der großen Kampagnen; als zusätzliches Web-Profil | CitrixHoneypot |
| PostgreSQL / MSSQL | 5432 / 1433 | Brute-Force und `COPY … PROGRAM`-Miner | Heralding |
| MQTT | 1883 | IoT, Suche nach offenen Brokern | Conpot |
| Kubernetes-API / kubelet | 6443 / 10250 | Container-Missbrauch wie bei der Docker-API | – |
| CUPS/IPP | 631 (UDP/TCP) | CVE-2024-47176-Scans | – |
| Modbus / S7 | 502 / 102 | Industrie-Scans, eher Forschung | Conpot |

### B3 – Passive Betriebssystem-Erkennung (wie p0f) ★★
Aus TTL, TCP-Fenster und Optionen des SYN das System des Angreifers schätzen. Damit fällt auf, wenn ein „Windows-Browser“-User-Agent in Wahrheit von einem Linux-Server kommt, und Botnetze aus Routern (MIPS/ARM-Linux) lassen sich von gemieteten Servern unterscheiden. Braucht `CAP_NET_RAW` auf dem Hive-Host oder eine nftables-Log-Regel; auf dem Pi machbar.

### B4 – Schadsoftware-Proben auswerten ★★
Ohne Datei auszuführen:
- Typ und Architektur aus dem ELF-Kopf (x86, ARM, MIPS …), Größe, gepackt (UPX);
- Hashes automatisch bei MalwareBazaar nachschlagen (heute nur auf Knopfdruck);
- eingebettete Zeichenketten: C2-Adressen, Wallets, Familienhinweise (`/bin/busybox MIRAI`, `Corona`, `Gafgyt`);
- optional YARA-Regeln aus öffentlichen Sammlungen.

### B5 – Ergebnisse teilen ★★
- **DShield / SANS ISC**: Cowrie kann Logs dorthin schicken, Hivornet könnte das für alle Dienste tun. Dafür bekommt man Vergleichsdaten („wird das gerade überall gesehen?“).
- **Blockliste als Abo-Adresse**: eine Adresse mit Token, die OPNsense, pfSense, MikroTik oder Pi-hole regelmäßig abrufen. So schützt der Honeypot direkt das echte Netz.
- **MISP-Push** statt nur STIX-Datei.

### B6 – Mehrere Sensoren ★★
Im Audit offen: Je Sensor eigener Token, TLS zwischen Sensor und Hive, Sensor als Filter in jeder Ansicht. Damit kann neben dem Pi zu Hause z. B. ein günstiger VPS Daten liefern; der Vergleich Heimanschluss gegen Rechenzentrum ist selbst aufschlussreich.

---

## C. Neue Auswertungen

### C1 – Antworten mit Sprachmodell für Unbekanntes ★★
Beelzebub und Galah lassen ein Sprachmodell Antworten auf Shell-Befehle bzw. beliebige HTTP-Anfragen erzeugen. In Studien hielten Menschen solche Shells deutlich öfter für echt. Für Hivornet passend wäre eine vorsichtige Variante:
- nur für **Befehle bzw. Pfade, die die Emulation nicht kennt**;
- nur mit **lokalem Modell** (die Ollama-Anbindung ist schon da), Antworten zwischenspeichern, damit derselbe Befehl gleich beantwortet wird;
- feste Grenzen für Länge und Antwortzeit, Prompt-Injection ist zu erwarten.

Zusammen mit A1 lässt sich messen, ob mehr Angreifer weitermachen.

### C2 – Ähnliche Sitzungen gruppieren und Ausreißer finden ★★★
Forschung (u. a. Nested-Dirichlet-Modelle 2025, NLP auf Cowrie-Logs) gruppiert Sitzungen nach ihrer Befehlsfolge. Für Hivornet reicht ein einfacher Ansatz ohne ML-Bibliothek:
- jede Sitzung auf normalisierte Befehle reduzieren (Zahlen, IPs, Hashes, Dateinamen ersetzen), daraus Shingles und MinHash;
- **Familien**: Sitzungen mit großer Überlappung zusammenfassen, mit Namen wie „Mirai-Variante“, „Docker-Miner moneroocean“, „Shell-Echtheitstest“;
- **„Neu heute“**: Sitzungen, die zu keiner bekannten Familie passen. Das sind die interessanten Fälle, und sie lassen sich gut benachrichtigen.

### C3 – Erstmals gesehen ★★
Eine Liste „zum ersten Mal“: neue Passwörter, Befehle, Pfade, HASSH/JA4, Nachlade-Adressen, Zielports. Zeigt neue Kampagnen schon in der ersten Stunde.

### C4 – Zusammenhänge über die Zeit ★★
- **Erkunden → Angreifen**: IP A tastet Port X ab, Stunden später greift IP B mit demselben Fingerabdruck oder Werkzeug an. Diese Arbeitsteilung bei Scanner und Angreifer ist häufig.
- **Wiederkehrer**: welche IPs oder Familien regelmäßig wiederkommen und in welchem Rhythmus.
- **Spitzen-Warnung**: Benachrichtigung, wenn ein Dienst oder Port deutlich über dem Mittel liegt.

### C5 – Eigene Abfragen ★
Der größte Unterschied zu T-Pot mit Kibana ist laut Audit, dass es keine freien Abfragen gibt. Eine einfache Suchsprache (`service:ssh stufe>=3 country:CN cmd:*wget*`) mit gespeicherten Suchen deckt das meiste ab.

### C6 – Wie Shodan dich sieht ★
Auf Knopfdruck die eigene öffentliche IP bei Shodan (und dessen „Honeyscore“) oder Censys nachschlagen: Wird der Pi schon als Honeypot markiert? Welche Banner sind öffentlich? Gute Rückmeldung für die Geräteprofile.

---

## Stand der Umsetzung

- **Umgesetzt in 0.7.0-beta.1:** A1 Honeypot-Prüfung mit Kennzahl, A2 Wallets und Pools (ohne Ersetzen der IP in `--rig-id`), A3 Liste „Exploits ohne CVE“, A4 teilweise (Kampagnen laden nach), Mirai-Kennzeichnung; Analyse, Zugangsdaten und Tarpit nach Konzept A (`konzepte/d-auswertung.html`), Tarpit mit Zeitleiste aus Konzept B.
- **Umgesetzt in 0.7.0-beta.1, Teil B:** B2 (ADB, MQTT, PostgreSQL, Elasticsearch, Ollama, Kubernetes; SMB, VPN-Seiten, MSSQL, CUPS, Modbus/S7 nicht), B4 (statische Auswertung, ohne YARA), B5 (Blocklisten-Abo; DShield und MISP nicht), B6 (eigene Tokens je Sensor; TLS über VPN statt im Hive).
- **Bewusst weggelassen:** B1 Teleskop und B3 passive OS-Erkennung, siehe CHANGELOG (Sicherheit, SD-Karte).
- **Umgesetzt in 0.7.0-beta.1, Teil C:** C1 (Telnet-Shell und Web, jede OpenAI-kompatible Schnittstelle inkl. OpenRouter, mit Zwischenspeicher und Grenzen; Cowrie/SSH nicht), C2 (Familien über Jaccard statt MinHash, reicht bei den Mengen), C3, C4 (Wiederkehrer, Erkunden → Angreifen, Spitzen-Warnung), C5 (Suchsprache, gespeicherte Suchen), C6 (Shodan InternetDB, ohne kostenpflichtigen Honeyscore).
- **Offen:** A5.

## Empfohlene Reihenfolge

1. **A1** Honeypot-Prüfung erkennen und messen (klein, sofort Erkenntnis)
2. **A2** Wallets und Pools (klein, starke Kampagnen)
3. **B1** Alle Ports mitschneiden (mittel, viel neuer Überblick)
4. **C2/C3** Familien, „Neu heute“, „Erstmals gesehen“ (mittel, die eigentliche Auswertung)
5. **B2** ADB und Ollama-API als erste neue Dienste
6. **A3/A4** CVE-Lücken, Analyse-Geschwindigkeit
7. danach C1, B3–B6, C4–C6 nach Lust

## Quellen
- [SoK: Honeypots & LLMs (arXiv 2510.25939)](https://arxiv.org/pdf/2510.25939)
- [VelLMes / shelLM (arXiv 2510.06975)](https://arxiv.org/html/2510.06975v1)
- [HoneyGPT (arXiv 2406.01882)](https://arxiv.org/html/2406.01882v2)
- [DECEIVE (Splunk)](https://embargo.splunk.com/en_us/blog/security/deceive-ai-honeypot-concept.html)
- [Beelzebub](https://selfhostyourself.com/services/beelzebub)
- [T-Pot Releases](https://science.ecosyste.ms/projects/44086/releases)
- [Nested Dirichlet models for honeypot data](https://spiral.imperial.ac.uk/entities/publication/ee280f9b-a0ab-4f75-a1e4-12214b251fdf)
- [Botnet-Cluster per NLP (arXiv 2104.10232)](https://arxiv.org/pdf/2104.10232)
