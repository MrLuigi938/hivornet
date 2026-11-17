#!/bin/sh
# shellcheck disable=SC2086  # $DC ist absichtlich ungequotet ("docker compose")
# Hivornet aktualisieren. Sichert vorher die Datenbank; Daten und Einstellungen bleiben erhalten.
#   sh update.sh             neuen Code holen (falls Git), neu bauen, neu starten
# Zurückrollen: git checkout <alte Version> && sh update.sh  (Backups unter ./backups)
set -eu
umask 077
cd "$(dirname "$0")"
# shellcheck source=tools/common.sh
. ./tools/common.sh
find_compose

say "Aktuelle Version: $($DC exec -T hive /hive version 2>/dev/null || echo unbekannt)"
if $DC ps --status running hive 2>/dev/null | grep -q hive; then
  say "Sichere die Datenbank ..."
  sh tools/backup.sh || die "Backup fehlgeschlagen, Update abgebrochen."
fi

if [ -d .git ] && command -v git >/dev/null 2>&1; then
  git pull --ff-only
  say "Code-Stand: $(git describe --tags --always 2>/dev/null || git rev-parse --short HEAD)"
fi
$DC pull cowrie janitor 2>/dev/null || true
$DC build --pull
# Geänderte Netzwerk-Einstellungen (z. B. fester Bridge-Name hv-ingest seit 0.7) lassen sich
# nicht im laufenden Betrieb übernehmen: dann einmal alles stoppen (Daten bleiben) und neu starten.
if ! $DC up -d; then
  say "Netze werden neu angelegt ..."
  $DC down
  $DC up -d
fi
$DC ps
say "Netzsperre danach neu setzen (deckt seit 0.7 auch das interne Netz hv-ingest ab): sudo sh tools/firewall.sh"
say "Neue Version: $($DC exec -T hive /hive version 2>/dev/null || echo unbekannt)"
