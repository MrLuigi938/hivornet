# Ereignisformat

Sensoren schicken Ereignisse gebündelt an die Sensor-API des Hive. Im Docker-Betrieb ist das Port 8089, nur im internen Netz `ingest` erreichbar.

```
POST /api/ingest
Authorization: Bearer <HIVORNET_TOKEN>
Content-Type: application/json

{"sensor":"nas","events":[ {Ereignis}, ... ]}
```

## Ereignis

| Feld | Typ | Pflicht | Bedeutung |
|---|---|---|---|
| `eid` | Text, ≤ 64 | empfohlen | Zufällige ID. Der Hive verwirft Ereignisse mit bereits gesehener ID (die letzten 200.000), damit wiederholtes Senden keine Duplikate erzeugt. |
| `ts` | RFC 3339 | ja | Zeitpunkt; Werte mehr als 1 h in der Zukunft werden durch „jetzt“ ersetzt |
| `sensor` | Text, ≤ 64 | nein | sonst der Wert aus dem Block |
| `service` | Text, ≤ 32 | ja | Dienste des Honeypots: `http`, `https`, `dockerapi`, `ftp`, `redis`, `mysql`, `ssh-tarpit`, `raw`, `telnet`, `smtp`, `vnc`, `rdp`; von Cowrie: `ssh`, `telnet` |
| `type` | siehe unten | ja | |
| `src_ip` | IPv4/IPv6 | ja | |
| `src_port`, `dst_port` | Zahl | nein | `dst_port` ist der echte Dienst-Port (80, nicht 10080) |
| `session` | Text, ≤ 64 | nein | verbindet die Ereignisse einer Verbindung |
| `username`, `password` | Text, ≤ 256 | bei `login` | |
| `data` | JSON-Objekt, ≤ 16 KB | nein | Inhalt je Typ; größere Objekte kürzt der Hive feldweise und setzt `"truncated": true` |
| `duration_ms` | Zahl | bei `disconnect` | Dauer der Verbindung |
| `tarpit`, `tarpit_ms` | bool, Zahl | bei `disconnect` | festgehalten und wie lange |

Geo-Felder (`country`, `city`, `lat`, `lon`, `asn`, `as_org`) ergänzt der Hive selbst. Was ein Sensor dort mitschickt, wird verworfen.

## Typen

| Typ | Inhalt in `data` |
|---|---|
| `connect` | `mode` |
| `disconnect` | `bytes_out` |
| `login` | `success` (Cowrie), `path` (HTTP), `password_hashed`, `auth_hex`, `database`, `plugin` (MySQL); `accepted` (Telnet und FTP des Honeypots: Login wurde zum Schein angenommen); `bait` (Köder-Zugangsdaten benutzt, bei MySQL am Hash erkannt); `password_hashed`, `challenge`, `response` (VNC, Hex); `cookie`, `protocols` (RDP: nur Benutzername aus dem Cookie); `client_id`, `protocol` (MQTT); `database`, `application`, `success` (PostgreSQL) |
| `command` | `input`, optional `truncated`; bei FTP nach dem Login `cwd` und bei `STOR`/`APPE` `upload: true`; bei ADB `channel` (`shell`, `sync` für Datei-Ablagen, `service`); bei PostgreSQL `extended` (Abfrage im erweiterten Protokoll) |
| `request` | `method`, `path`, `host`, `user_agent`, `version`, `headers`, `body`, `body_truncated`, `header_order` (Namen der Kopfzeilen in gesendeter Reihenfolge, ab 0.5.3); bei Cowrie `forward_to` |
| `download` | `url`, `sha256`, `failed`, bzw. `filename`, `upload` |
| `client_version` | `version`; bei RDP zusätzlich `client_name`, `keyboard_layout` |
| `fingerprint` | `hassh`, `hassh_algorithms` (Cowrie) |
| `payload` | `text` (nicht druckbare Bytes als `\xNN`), `bytes`; bei SMTP `mail: true` (Anfang einer Mail, `bytes` = gelesene Größe) |
| `tls` | `sni`; ab 0.5.3 bei HTTPS auch `client_hello` (für JA3/JA4); TLS-Handshake an einem Klartext-Port (Honeypot ab 0.5.3): `plain: true`, `client_hello` (erster TLS-Record als Hex, höchstens 3.072 Bytes), `bytes` (Länge des Records), `truncated` |
| `tty` | `shasum`, `size`, `duration_s`: Cowrie hat einen Terminal-Mitschnitt geschrieben. Entsteht nur im Hive (Cowrie-Leser), nie über die Sensor-API |
| `ai_reply` | `kind` (`shell`/`web`), `input`, `output`, `status` (nur Web), `cached`: Der Honeypot hat eine Antwort des Sprachmodells ausgeliefert (Einstellungen → Antworten mit Sprachmodell). Der Text des Modells wird nicht als Befehl ausgewertet; Suche `ki:ja` |

## Kompatibilität

Das Format hat keine Versionsnummer; es wird nur ergänzt. Neue Dienste und neue Felder in `data` versteht jeder Hive (Dienst ist freier Text, `data` ein beliebiges Objekt). Einen unbekannten **Typ** verwirft der Hive einzeln, der Rest des Blocks wird angenommen. Ein Sensor mit neueren Diensten läuft also an einem älteren Hive; dieser kann die neuen Dienste aber nicht in den Einstellungen anbieten.

Was der Hive aus Ereignissen ableitet (Angriffsmuster, Werkzeuge, Nachlade-Adressen), steht nicht im Ereignis, sondern in der Zähltabelle `top_hourly` und im Angriffsbericht (siehe [ARCHITEKTUR.md](ARCHITEKTUR.md)).

## Größenbudget

Der Honeypot hält jedes Ereignis unter 12 KB JSON:
- Kopfzeilen und Body je höchstens 1.536 Zeichen, Pfad 1.024, Payload und Befehle 2.048.
- `printable` begrenzt die **Ausgabe**, nicht die Eingabe. JSON-Maskierung kann sie höchstens verdoppeln.

Blöcke umfassen höchstens 200 Ereignisse bzw. 1 MB. Die Vertragstests `TestEventSizeContract` (`honeypot/honeypot_test.go`) und `TestNewProtocolsSizeBudget` (`honeypot/proto_new_test.go`) prüfen das gegen das Hive-Limit.

## Antworten

| Status | Bedeutung | Sensor |
|---|---|---|
| 200 | angenommen | weiter |
| 400, 413 | Block ungültig | verwerfen, nicht wiederholen |
| 401 | Token falsch | verwerfen |
| 429, 5xx, Netzfehler | vorübergehend | später erneut senden (Pause wächst bis 30 s) |

## Weitere Sensor-Endpunkte

- `GET /api/sensor/config` (Header `X-Sensor: <Name>`): wirksame Konfiguration. Das ist die eigene des Sensors oder die für alle. `204`, solange keine existiert.
- `POST /api/sensor/heartbeat`: Zustand alle 10 s: Ports, Zähler, Speicher, Ergebnis der Netzsperren-Prüfung (`egress`), Verdacht auf Userland-Proxy (`proxied_conns`).
