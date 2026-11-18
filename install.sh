#!/bin/sh
# shellcheck disable=SC2086  # $DC ist absichtlich ungequotet ("docker compose")
# Hivornet Installation (NAS, Raspberry Pi, Linux-Server mit Docker).
# Verändert am System nichts außer den Docker-Containern in diesem Ordner
# (und, nur wenn du zustimmst, die Firewall-Regeln der Netzsperre).
set -eu
umask 077
cd "$(dirname "$0")"
# shellcheck source=tools/common.sh
. ./tools/common.sh
find_compose

# --- .env anlegen ---
NEW_PASSWORD=""
if [ ! -f .env ]; then
  [ -f .env.example ] || die ".env.example fehlt."
  cp .env.example .env
  chmod 600 .env
  NEW_PASSWORD=$(rand 16)
  env_set HIVORNET_TOKEN "$(rand 48)"
  env_set HIVE_ADMIN_PASSWORD "$NEW_PASSWORD"
  IP=$(lan_ip) # nur private Adressen (tools/common.sh)
  if [ -n "$IP" ]; then
    env_set HIVE_BIND "$IP" # UI nur auf der LAN-Adresse der NAS
  else
    say "Keine private Heimnetz-Adresse gefunden: Die UI lauscht nur auf 127.0.0.1 (Zugriff z. B. per SSH-Tunnel; HIVE_BIND in .env)."
  fi
  say ".env angelegt (Token und Admin-Passwort erzeugt, UI an ${IP:-127.0.0.1} gebunden)."
else
  say ".env existiert schon, wird nicht verändert."
fi

# --- Ports prüfen ---
busy=""
for name in PORT_SSH PORT_TELNET PORT_FTP PORT_HTTP PORT_HTTPS PORT_HTTP_ALT PORT_DOCKER PORT_SSH_TARPIT PORT_MYSQL PORT_REDIS PORT_RAW HIVE_PORT; do
  p=$(env_get "$name")
  [ -n "$p" ] || continue
  if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$p\$"; then
    docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^hivornet-' || busy="$busy $p"
  fi
done
[ -z "$busy" ] || say "WARNUNG: Diese Ports sind auf der NAS schon belegt:$busy  (in .env ändern)"

# --- Bauen und starten ---
say "Baue und starte Hivornet (beim ersten Mal einige Minuten) ..."
$DC up -d --build

# --- Startpasswort aus .env entfernen, sobald das Konto angelegt ist ---
if [ -n "$NEW_PASSWORD" ]; then
  i=0
  while [ $i -lt 30 ] && ! $DC logs hive 2>/dev/null | grep -q "Admin-Konto"; do sleep 2; i=$((i+1)); done
  if $DC logs hive 2>/dev/null | grep -q "Admin-Konto"; then
    env_set HIVE_ADMIN_PASSWORD ""
    $DC up -d hive >/dev/null 2>&1 || true # Umgebung ohne Passwort neu setzen
  fi
fi

# --- Netzsperre anbieten ---
if [ "$(id -u)" = "0" ] && [ -t 0 ]; then
  printf 'Netzsperre für die Honeypot-Container jetzt setzen (dringend empfohlen)? [J/n] '
  read -r answer
  case "$answer" in
    n|N|nein) say "Übersprungen. Später: sudo sh tools/firewall.sh" ;;
    *) sh tools/firewall.sh apply || say "Netzsperre konnte nicht gesetzt werden, siehe README." ;;
  esac
fi

# --- Zusammenfassung ---
BIND=$(env_get HIVE_BIND); BIND=${BIND:-127.0.0.1}
PORT=$(env_get HIVE_PORT); PORT=${PORT:-8088}
say ""
say "Hivornet läuft."
say "  Web-UI:      http://$BIND:$PORT   (nur im Heimnetz, NICHT im Router freigeben)"
say "  Benutzer:    $(env_get HIVE_ADMIN_USER)"
if [ -n "$NEW_PASSWORD" ]; then
  say "  Passwort:    $NEW_PASSWORD"
  say "               Jetzt notieren: Es steht nicht mehr in .env. Nach dem ersten Login in der UI ändern."
fi
say ""
say "Im Router weiterleiten (extern -> NAS $BIND):"
say "  22 -> $(env_get PORT_SSH)   23 -> $(env_get PORT_TELNET)   21 -> $(env_get PORT_FTP)   80 -> $(env_get PORT_HTTP)   443 -> $(env_get PORT_HTTPS)"
say "  8080 -> $(env_get PORT_HTTP_ALT)   2375 -> $(env_get PORT_DOCKER)   2222 -> $(env_get PORT_SSH_TARPIT)   3306 -> $(env_get PORT_MYSQL)"
say "  6379 -> $(env_get PORT_REDIS)   5900 -> $(env_get PORT_RAW)"
say ""
say "Status:  $DC ps      Logs:  $DC logs -f --tail 50      Backup:  sh tools/backup.sh"
