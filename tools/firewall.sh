#!/bin/sh
# Hivornet Netzsperre
#
# Verhindert, dass die Honeypot-Container (Netz "honeynet", Bridge hv-honeynet)
# NEUE Verbindungen aufbauen: nicht ins Heimnetz, nicht zur NAS selbst und nicht
# ins Internet. Antworten an Angreifer und eingehende Verbindungen bleiben erlaubt.
# Wird ein Honeypot übernommen, kommt der Angreifer damit nicht weiter.
#
#   sudo sh tools/firewall.sh            Regeln setzen (idempotent)
#   sudo sh tools/firewall.sh status     Regeln anzeigen
#   sudo sh tools/firewall.sh remove     Regeln entfernen
#
#   ALLOW_DOWNLOADS=1 sudo sh tools/firewall.sh
#       erlaubt Cowrie zusätzlich HTTP/HTTPS ins Internet (nicht ins LAN), damit
#       Schadsoftware-Proben der Angreifer heruntergeladen werden können.
#
# Die Regeln überleben keinen Neustart der NAS. Siehe README: beim Systemstart
# ausführen (Synology: Aufgabenplaner, sonst tools/hivornet-firewall.service).
set -eu

BR=hv-honeynet
CHAIN=HIVORNET-OUT
CHAIN_IN=HIVORNET-HOST

die() { printf 'FEHLER: %s\n' "$*" >&2; exit 1; }
command -v iptables >/dev/null 2>&1 || die "iptables fehlt"
[ "$(id -u)" = "0" ] || die "bitte mit sudo ausführen"

remove() {
  while iptables -D DOCKER-USER -i "$BR" -j "$CHAIN" 2>/dev/null; do :; done
  while iptables -D INPUT -i "$BR" -j "$CHAIN_IN" 2>/dev/null; do :; done
  for c in "$CHAIN" "$CHAIN_IN"; do
    iptables -F "$c" 2>/dev/null || true
    iptables -X "$c" 2>/dev/null || true
  done
}

apply() {
  iptables -L DOCKER-USER -n >/dev/null 2>&1 || die "Kette DOCKER-USER fehlt. Läuft Docker mit iptables-Unterstützung?"
  remove

  # Weiterleitung (Container -> LAN / Internet)
  iptables -N "$CHAIN"
  iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 224.0.0.0/4; do
    iptables -A "$CHAIN" -d "$net" -j DROP
  done
  if [ "${ALLOW_DOWNLOADS:-0}" = "1" ]; then
    iptables -A "$CHAIN" -p tcp -m multiport --dports 80,443 -j RETURN
  fi
  iptables -A "$CHAIN" -j DROP
  iptables -I DOCKER-USER 1 -i "$BR" -j "$CHAIN"

  # Container -> NAS selbst (Weboberfläche, SSH, SMB der NAS)
  iptables -N "$CHAIN_IN"
  iptables -A "$CHAIN_IN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  iptables -A "$CHAIN_IN" -j DROP
  iptables -I INPUT 1 -i "$BR" -j "$CHAIN_IN"

  echo "Netzsperre aktiv für $BR (Downloads: ${ALLOW_DOWNLOADS:-0})."
  echo "Prüfung: Unter System zeigt die Hivornet-UI nach spätestens 10 Minuten 'Internet: gesperrt'."
}

case "${1:-apply}" in
  apply) apply ;;
  remove) remove; echo "Netzsperre entfernt." ;;
  status)
    iptables -S "$CHAIN" 2>/dev/null || echo "Kette $CHAIN fehlt (Netzsperre nicht aktiv)"
    iptables -S "$CHAIN_IN" 2>/dev/null || true
    ;;
  *) die "unbekannter Befehl: $1 (apply|status|remove)" ;;
esac
