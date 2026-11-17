# Entwicklung

## Bauen und testen

```bash
cd hive && go test ./... && go build -o hive . && cd ../honeypot && go test ./... && go build -o honeypot .
# Hive:     HIVE_DB=./data/hive.db HIVORNET_TOKEN=test HIVE_ADMIN_PASSWORD=testpasswort1 HIVE_LISTEN=127.0.0.1:8088 HIVE_WEB_DIR=./web ./hive
# Honeypot: HONEYPOT_CONFIG=../config/honeypot.yml HIVE_URL=http://127.0.0.1:8088 HIVORNET_TOKEN=test HONEYPOT_LOW_PORT_OFFSET=20000 HONEYPOT_BIND=127.0.0.1 ./honeypot
```

- **Sensor-API ohne eigenen Port:** Ohne `HIVE_SENSOR_LISTEN` ist sie auch über den UI-Port erreichbar, praktisch für lokale Tests.
- **UI ohne Neubau:** Mit `HIVE_WEB_DIR` liefert der Hive die UI direkt aus dem Ordner aus.
- **Go-Version:** 1.26 oder neuer.
- **Alle Prüfungen in einem Aufruf:** `sh tools/check.sh` (gofmt, vet, Tests, Cross-Build für amd64, arm64 und armv7).

Aufbau des Systems und wie man ein Protokoll, ein Angriffsmuster oder eine Ansicht ergänzt: [ARCHITEKTUR.md](ARCHITEKTUR.md). Ereignisformat zwischen Sensor und Hive: [events.md](events.md).

**Tests:** Unit-, Fuzz- und Vertragstests in `honeypot/*_test.go` und `hive/*_test.go`. Fuzzing z. B. mit `go test -run=^$ -fuzz=FuzzReadRESP -fuzztime=60s` im Ordner `honeypot`.

## CI

`.github/workflows/ci.yml` prüft bei jedem Push:
- `go vet`, `gofmt`, `staticcheck`, `govulncheck`;
- `go test -race` und kurzes Fuzzing;
- `shellcheck` und `hadolint`;
- die Netzsperre des Pi mit Ersatzbefehlen für nft und iptables (`pi/test_firewall.sh`);
- die Cowrie-Installation des Pi in einem Debian-13-Container, inklusive Start mit der Befehlszeile aus `hivornet-cowrie.service` (`pi/test_cowrie_install.sh`);
- den Docker-Build für amd64, arm64 und armv7.

## Veröffentlichen

Ein Push auf `main` startet nur die CI. Eine Veröffentlichung entsteht erst durch einen **Tag** `v*` (`.github/workflows/release.yml`):

1. Docker-Images für amd64, arm64 und armv7 in der GitHub Container Registry,
2. Programmpakete `hivornet-<tag>-linux-<arch>.tar.gz` mit `SHA256SUMS` (daraus aktualisiert sich das Pi-Image),
3. Raspberry-Pi-Images `hivornet-pi-<arch>-<tag>.img.xz`,
4. die GitHub-Veröffentlichung mit allen Dateien.

```bash
git tag -a v0.4.0 -m "Hivornet 0.4.0" && git push origin v0.4.0            # fertige Version
git tag -a v0.4.0-beta.1 -m "Hivornet 0.4.0-beta.1" && git push origin v0.4.0-beta.1   # Vorabversion
```

Tags mit Bindestrich werden als **Pre-Release** veröffentlicht und nur Installationen angeboten, die in der UI den Kanal „Vorabversionen“ gewählt haben. Damit Installationen Updates finden, muss das Repository öffentlich sein.

## Virenscanner (Windows)

Regeln und Testdaten enthalten typische Bestandteile von Schadsoftware-Befehlszeilen (Miner, Botnetz-Lader). Der Windows-Virenscanner hält das Testprogramm (`hive.test.exe`) dann für Schadsoftware und sperrt es: `go test` meldet „Zugriff verweigert“ beim Linken. Linux-Builds sind nicht betroffen.

- Keine echten Miner-Befehlszeilen, Wallets oder Malware-Namen am Stück in Tests schreiben; Testtexte zur Laufzeit zusammensetzen (`mk(...)` in `hive/indicators_test.go`).
- Die Regel `miner` in `hive/analyze.go` kommt bewusst ohne den Namen des Monero-Hash-Verfahrens aus.
- Tritt die Sperre auf: verdächtige Testdatei gezielt ausnehmen (umbenennen, `go test -c` erneut), bis die auslösende Zeichenkette gefunden ist. Am Virenscanner selbst nichts ändern.

## Raspberry-Pi-Image selbst bauen

Das Skript ändert nur die Bootpartition eines offiziellen Raspberry Pi OS Lite und braucht weder Linux noch Root, nur Python 3 und openssl:

```bash
pip install "setuptools<80" pyfatfs==1.1.0   # pyfatfs braucht pkg_resources
cd hive && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../dist/arm64/hive . && cd ..
cd honeypot && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../dist/arm64/honeypot . && cd ..
python3 pi/build_image.py --arch arm64 --version v0.4.0 --bin dist/arm64 --out dist
python3 pi/verify_image.py dist/hivornet-pi-arm64-v0.4.0.img.xz v0.4.0 arm64
```

Das Basis-Image (Raspberry Pi OS Lite „trixie“ vom 06.10.2026) wird geladen und an der Prüfsumme erkannt; ein neueres trägt man in `BASE` in `pi/build_image.py` ein. In der CI passiert dasselbe bei jedem Tag, von Hand auch über „Run workflow“.

Auf dem Pi läuft Hivornet ohne Docker als systemd-Dienste (`pi/rootfs`). Cowrie wird beim ersten Start mit Internet installiert (`hivornet-cowrie-install`, Version und Prüfsumme fest im Skript). Ein Update über die UI tauscht nur `hive` und `honeypot` aus (damit auch die Web-UI); Änderungen an Diensten, Skripten oder der Cowrie-Version brauchen ein neues Image. Zur Fehlersuche zeigt die Web-UI unter **Protokolle** die Systemprotokolle der Hivornet-Dienste; die Konsolen-Anmeldung am Pi ist gesperrt.
