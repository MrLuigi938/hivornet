# Ereignisformat

Sensoren schicken Ereignisse gebündelt an die Sensor-API des Hive. Im Docker-Betrieb ist das Port 8089, nur im internen Netz `ingest` erreichbar.

```
POST /api/ingest
Authorization: Bearer <HONEYLITE_TOKEN>
Content-Type: application/json

{"sensor":"nas","events":[ {Ereignis}, ... ]}
```

## Ereignis

| Feld | Typ | Pflicht | Bedeutung |
|---|---|---|---|
| `eid` | Text, ≤ 64 | empfohlen | Zufällige ID. Der Hive verwirft Ereignisse mit bereits gesehener ID (die letzten 200.000), damit wiederholtes Senden keine Duplikate erzeugt. |
| `ts` | RFC 3339 | ja | Zeitpunkt; Werte mehr als 1 h in der Zukunft werden durch „jetzt“ ersetzt |
| `sensor` | Text, ≤ 64 | nein | sonst der Wert aus dem Block |
| `service` | Text, ≤ 32 | ja | z. B. `http`, `redis`, `ssh` |
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
| `login` | `success` (Cowrie), `path` (HTTP), `password_hashed`, `auth_hex`, `database`, `plugin` (MySQL) |
| `command` | `input`, optional `truncated` |
| `request` | `method`, `path`, `host`, `user_agent`, `version`, `headers`, `body`, `body_truncated`; bei Cowrie `forward_to` |
| `download` | `url`, `sha256`, `failed`, bzw. `filename`, `upload` |
| `client_version` | `version` |
| `fingerprint` | `hassh`, `hassh_algorithms` (Cowrie) |
| `payload` | `text` (nicht druckbare Bytes als `\xNN`), `bytes` |
| `tls` | `sni` |

## Größenbudget

Der Honeypot hält jedes Ereignis unter 12 KB JSON:
- Kopfzeilen und Body je höchstens 1.536 Zeichen, Pfad 1.024, Payload und Befehle 2.048.
- `printable` begrenzt die **Ausgabe**, nicht die Eingabe. JSON-Maskierung kann sie höchstens verdoppeln.

Blöcke umfassen höchstens 200 Ereignisse bzw. 1 MB. Der Vertragstest `TestEventSizeContract` in `honeypot/honeypot_test.go` prüft das gegen das Hive-Limit.

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
