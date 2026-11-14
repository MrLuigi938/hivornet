#!/bin/sh
# shellcheck disable=SC2086  # $DC ist absichtlich ungequotet ("docker compose")
# HoneyLite-Datenbank sichern (auch im laufenden Betrieb konsistent, per VACUUM INTO).
# Die Sicherung landet unter ./backups/ auf der NAS; im Container bleiben die letzten 7.
#
# Wiederherstellen:
#   docker compose cp backups/hive-JJJJMMTT-HHMMSS.db hive:/data/restore.db
#   docker compose restart hive        # der Hive übernimmt restore.db beim Start
set -eu
umask 077
cd "$(dirname "$0")/.."
# shellcheck source=tools/common.sh
. ./tools/common.sh
find_compose

name=$($DC exec -T hive /hive backup) || die "Backup im Container fehlgeschlagen"
mkdir -p backups
$DC cp "hive:$name" "backups/$(basename "$name")"
say "Gesichert: backups/$(basename "$name")"
# lokal die letzten 14 behalten (portabel, auch mit BusyBox)
# shellcheck disable=SC2012
count=$(ls -1 backups/hive-*.db 2>/dev/null | wc -l)
# shellcheck disable=SC2012
ls -1 backups/hive-*.db 2>/dev/null | sort | awk -v c="$count" 'NR <= c - 14' | while read -r f; do rm -f "$f"; done
