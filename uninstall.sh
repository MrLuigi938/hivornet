#!/bin/sh
# shellcheck disable=SC2086  # $DC ist absichtlich ungequotet ("docker compose")
# HoneyLite stoppen und entfernen.
#   sh uninstall.sh          Container entfernen, Daten behalten
#   sh uninstall.sh --purge  zusätzlich alle Daten löschen (Datenbank, Cowrie-Logs, Downloads)
set -eu
cd "$(dirname "$0")"
# shellcheck source=tools/common.sh
. ./tools/common.sh
find_compose

if [ "${1:-}" = "--purge" ]; then
  printf 'Wirklich ALLE HoneyLite-Daten löschen? Das kann nicht rückgängig gemacht werden. [ja/nein] '
  read -r answer
  [ "$answer" = "ja" ] || { echo "Abgebrochen."; exit 1; }
  $DC --profile cowrie down -v --rmi local
  echo "HoneyLite und alle Daten entfernt. Die Datei .env und der Ordner backups liegen noch hier."
else
  $DC --profile cowrie down
  echo "HoneyLite gestoppt. Daten bleiben erhalten (Neustart: $DC up -d)."
fi
if [ "$(id -u)" = "0" ] && iptables -S HONEYLITE-OUT >/dev/null 2>&1; then
  echo "Hinweis: Die Netzsperre ist noch aktiv. Entfernen mit: sudo sh tools/firewall.sh remove"
fi
