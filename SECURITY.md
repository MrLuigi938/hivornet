# Sicherheitsrichtlinie

Hivornet nimmt absichtlich feindlichen Verkehr an. Fehler in den Protokoll-Parsern, der Container-Trennung oder der Web-UI können deshalb direkt ausnutzbar sein. Danke, wenn du sie meldest.

## Unterstützte Versionen

Sicherheitskorrekturen gibt es nur für die jeweils neueste Version (Git-Tag `v*`). Ein Update ist mit `sh update.sh` erledigt.

## Lücke melden

- **Nicht öffentlich als Issue.** Bitte über die Funktion „Report a vulnerability“ (GitHub Security Advisories) des Repositorys melden, oder direkt an die Person, die dir Hivornet gegeben hat.
- Hilfreich sind: betroffene Version, Komponente (`honeypot`, `hive`, UI, Compose/Skripte), Schritte zum Nachstellen, erwartete Auswirkung.
- Rückmeldung innerhalb von 7 Tagen, Korrektur je nach Schwere innerhalb von 30 Tagen. Danach wird die Lücke im `CHANGELOG.md` genannt.

## Im Fokus

- Speicher- oder CPU-Erschöpfung des Honeypots oder Hive durch einzelne Verbindungen
- Absturz eines Parsers (Panic) durch Eingaben aus dem Netz
- Wege aus einem Honeypot-Container zum Hive, zur NAS oder ins Heimnetz
- XSS, CSRF oder Authentifizierungsfehler in der Web-UI
- Fehler, durch die die Netzsperre (`tools/firewall.sh`) unwirksam wird

## Nicht im Fokus

- Dass ein Angreifer den Honeypot als Honeypot erkennt. Das ist eine bekannte Grenze (README, „Grenzen und Ausblick“).
- Lücken in Cowrie selbst: bitte direkt an das [Cowrie-Projekt](https://github.com/cowrie/cowrie/security). Hivornet übernimmt Korrekturen über eine neue Image-Version.
- Betrieb ohne Netzsperre oder mit im Router freigegebener Web-UI.
