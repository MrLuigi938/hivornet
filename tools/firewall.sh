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
#       erlaubt nur Cowrie (feste Adresse 172.30.252.10) zusätzlich HTTP/HTTPS ins
#       Internet (nicht ins LAN), damit Schadsoftware-Proben der Angreifer heruntergeladen
#       werden können. Der Go-Honeypot bleibt gesperrt.
#
# Auch das interne Netz "ingest" (Bridge hv-ingest, Honeypot -> Hive) darf die NAS selbst
# nicht erreichen: Docker gibt der Bridge die Gateway-Adresse 172.30.250.1 auf dem Host.
# Honeypot und Hive sprechen dort nur untereinander.
#
# Die Regeln überleben keinen Neustart der NAS. Siehe README: beim Systemstart
# ausführen (Synology: Aufgabenplaner, sonst tools/hivornet-firewall.service).
set -eu

BR=hv-honeynet
BR_INGEST=hv-ingest
# Zusätzlich nach Quell-Netz (docker-compose.yml): Alt-Installationen haben Bridges mit
# zufälligem Namen (br-xxxx); die Regeln nach Bridge-Namen greifen dort ins Leere.
NET=172.30.252.0/24
NET_INGEST=172.30.250.0/24
COWRIE_IP=172.30.252.10
CHAIN=HIVORNET-OUT
CHAIN_IN=HIVORNET-HOST

die() { printf 'FEHLER: %s\n' "$*" >&2; exit 1; }
command -v iptables >/dev/null 2>&1 || die "iptables fehlt"
[ "$(id -u)" = "0" ] || die "bitte mit sudo ausführen"

# Neue Regeln entstehen zuerst in Ketten mit dem Zusatz -NEU und werden erst eingehängt, wenn
# sie vollständig sind; danach fallen die alten weg. So gibt es beim erneuten Ausführen keinen
# Augenblick ohne Sperre, und ein Fehler mittendrin lässt die bisherige Sperre unverändert.
NEW=$CHAIN-NEU
NEW_IN=$CHAIN_IN-NEU

# unhook KETTE: alle Sprünge in diese Kette entfernen
unhook() {
  while iptables -D DOCKER-USER -i "$BR" -j "$1" 2>/dev/null; do :; done
  while iptables -D DOCKER-USER -s "$NET" -j "$1" 2>/dev/null; do :; done
  while iptables -D INPUT -i "$BR" -j "$1" 2>/dev/null; do :; done
  while iptables -D INPUT -i "$BR_INGEST" -j "$1" 2>/dev/null; do :; done
  while iptables -D INPUT -s "$NET" -j "$1" 2>/dev/null; do :; done
  while iptables -D INPUT -s "$NET_INGEST" -j "$1" 2>/dev/null; do :; done
}

drop_chain() {
  iptables -F "$1" 2>/dev/null || true
  iptables -X "$1" 2>/dev/null || true
}

exists() { iptables -L "$1" -n >/dev/null 2>&1; }

remove() {
  for c in "$CHAIN" "$CHAIN_IN" "$NEW" "$NEW_IN"; do
    unhook "$c"
    drop_chain "$c"
  done
}

DONE=0
aborted() {
  [ "$DONE" = 1 ] || echo "FEHLER: Netzsperre nicht (neu) gesetzt. Bisherige Regeln, falls vorhanden, gelten unverändert weiter: sudo sh tools/firewall.sh status" >&2
}

apply() {
  trap aborted EXIT
  # Vor dem Start von Docker (Systemstart) gibt es die Kette noch nicht: anlegen. Docker übernimmt
  # eine vorhandene Kette DOCKER-USER samt Regeln und hängt sie selbst in FORWARD ein.
  if ! exists DOCKER-USER; then
    iptables -N DOCKER-USER || die "Kette DOCKER-USER lässt sich nicht anlegen. Läuft Docker mit iptables-Unterstützung?"
    echo "Hinweis: Kette DOCKER-USER angelegt (Docker läuft noch nicht). Die Sperre greift, sobald Docker startet." >&2
  fi
  # Reste eines abgebrochenen Laufs: fertig eingehängte neue Ketten übernehmen, sonst wegräumen
  if exists "$NEW" && ! exists "$CHAIN"; then iptables -E "$NEW" "$CHAIN"; fi
  if exists "$NEW_IN" && ! exists "$CHAIN_IN"; then iptables -E "$NEW_IN" "$CHAIN_IN"; fi
  for c in "$NEW" "$NEW_IN"; do
    unhook "$c"
    drop_chain "$c"
  done

  # Weiterleitung (Container -> LAN / Internet)
  iptables -N "$NEW"
  iptables -A "$NEW" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 224.0.0.0/4; do
    iptables -A "$NEW" -d "$net" -j DROP
  done
  if [ "${ALLOW_DOWNLOADS:-0}" = "1" ]; then
    iptables -A "$NEW" -s "$COWRIE_IP" -p tcp -m multiport --dports 80,443 -j RETURN
  fi
  iptables -A "$NEW" -j DROP

  # Container -> NAS selbst (Weboberfläche, SSH, SMB der NAS)
  iptables -N "$NEW_IN"
  iptables -A "$NEW_IN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  iptables -A "$NEW_IN" -j DROP

  # Einhängen (ab hier gilt die neue Sperre), dann erst die alte entfernen. Das interne Netz
  # Honeypot -> Hive bekommt denselben Schutz: kein Weg zur NAS selbst. Die Regeln hängen am
  # Namen der Bridge und lassen sich setzen, bevor es sie gibt.
  iptables -I DOCKER-USER 1 -s "$NET" -j "$NEW"
  iptables -I DOCKER-USER 1 -i "$BR" -j "$NEW"
  iptables -I INPUT 1 -s "$NET_INGEST" -j "$NEW_IN"
  iptables -I INPUT 1 -s "$NET" -j "$NEW_IN"
  iptables -I INPUT 1 -i "$BR" -j "$NEW_IN"
  iptables -I INPUT 1 -i "$BR_INGEST" -j "$NEW_IN"
  for c in "$CHAIN" "$CHAIN_IN"; do
    unhook "$c"
    drop_chain "$c"
  done
  iptables -E "$NEW" "$CHAIN"
  iptables -E "$NEW_IN" "$CHAIN_IN"
  DONE=1

  # Ältere Installationen ohne die festen Bridge-Namen: Dann greifen nur die Regeln nach Quell-Netz.
  for b in "$BR" "$BR_INGEST"; do
    if command -v ip >/dev/null 2>&1 && ! ip link show "$b" >/dev/null 2>&1; then
      echo "Hinweis: Bridge $b gibt es (noch) nicht; gesperrt wird dann nach Quell-Netz ($NET, $NET_INGEST). Nach 'docker compose up -d' prüfen: Die Hivornet-UI muss unter System 'Internet: gesperrt' zeigen." >&2
    fi
  done
  echo "Netzsperre aktiv für $BR ($NET) und $BR_INGEST ($NET_INGEST) (Downloads nur Cowrie: ${ALLOW_DOWNLOADS:-0})."
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
