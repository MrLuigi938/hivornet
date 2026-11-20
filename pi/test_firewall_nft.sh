#!/bin/sh
# Prüft hivornet-firewall mit echtem nftables in einem eigenen Netz-Namensraum:
# Ein "Heimnetz" hängt über eine veth-Leitung am Anschluss eth1 (Verwaltungsanschluss).
#
#   docker run --rm --privileged -v "$PWD:/src:ro" debian:trixie sh /src/pi/test_firewall_nft.sh
#
# Erwartet: Port 8088 aus dem Heimnetz erreichbar, Honeypot-Port 2222 nicht, und der Pi
# baut über eth1 keine eigene Verbindung ins Heimnetz auf.
set -eu
fail() { echo "FEHLER: $*" >&2; exit 1; }
fw=/src/pi/rootfs/usr/local/sbin/hivornet-firewall

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq nftables iproute2 netcat-openbsd >/dev/null
useradd -r -M hivornet-pot
useradd -r -M hivornet-cowrie

ip netns add home
ip link add eth1 type veth peer name home0
ip link set home0 netns home
ip addr add 10.9.0.1/24 dev eth1
ip link set eth1 up
ip -n home addr add 10.9.0.2/24 dev home0
ip -n home link set home0 up
ip -n home link set lo up

HIVORNET_STATUS_DIR=/tmp/status sh "$fw" apply
nft list table inet hivornet >/dev/null || fail "Tabelle fehlt"
[ "$(head -n 1 /tmp/status/firewall)" = ok ] || fail "Statusdatei: $(cat /tmp/status/firewall)"

# Dienste auf dem "Pi": Web-UI und ein Honeypot-Port
nc -lk -p 8088 >/dev/null 2>&1 &
nc -lk -p 2222 >/dev/null 2>&1 &
# Dienst im "Heimnetz"
ip netns exec home nc -lk -p 9000 >/dev/null 2>&1 &
sleep 1

ip netns exec home nc -z -w 3 10.9.0.1 8088 || fail "Web-UI aus dem Heimnetz nicht erreichbar"
if ip netns exec home nc -z -w 3 10.9.0.1 2222; then fail "Honeypot-Port 2222 aus dem Heimnetz erreichbar"; fi
if nc -z -w 3 10.9.0.2 9000; then fail "Pi kann über eth1 ins Heimnetz verbinden"; fi

# Drossel für Dauer-Brute-Force: "Internet" (öffentliche Testadresse) über einen eigenen Anschluss
ip netns add wan
ip link add wan0 type veth peer name wan1
ip link set wan1 netns wan
ip addr add 198.51.100.1/24 dev wan0
ip link set wan0 up
ip -n wan addr add 198.51.100.2/24 dev wan1
ip -n wan link set wan1 up
ip -n wan link set lo up
nc -lk -p 22 >/dev/null 2>&1 &
sleep 1
printf 'brute 2 5 1\n' >/tmp/brute.conf
HIVORNET_BRUTE_CONF=/tmp/brute.conf HIVORNET_STATUS_DIR=/tmp/status sh "$fw" apply
[ "$(head -n 1 /tmp/status/brute)" = ok ] || fail "Drossel nicht übernommen: $(cat /tmp/status/brute)"
nft list chain inet hivornet brute >/dev/null || fail "Kette brute fehlt"
ok=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if ip netns exec wan nc -z -w 2 198.51.100.1 22; then ok=$((ok + 1)); fi
done
[ "$ok" -ge 4 ] && [ "$ok" -le 6 ] || fail "Drossel: $ok von 10 Verbindungen durchgekommen, erwartet etwa 5 (Spitze)"
nft list set inet hivornet brute_ban4 | grep -q 198.51.100.2 || fail "IP nach Überschreiten nicht gesperrt"
# Heimnetz (privat) nie gedrosselt
for _ in 1 2 3 4 5 6 7 8 9 10; do
  ip netns exec home nc -z -w 3 10.9.0.1 8088 || fail "Heimnetz gedrosselt"
done
printf 'brute off\n' >/tmp/brute.conf
HIVORNET_BRUTE_CONF=/tmp/brute.conf HIVORNET_STATUS_DIR=/tmp/status sh "$fw" apply
ip netns exec wan nc -z -w 3 198.51.100.1 22 || fail "nach 'brute off' weiter gesperrt"

HIVORNET_STATUS_DIR=/tmp/status sh "$fw" remove
nc -z -w 3 10.9.0.2 9000 || fail "nach remove keine Verbindung (Testaufbau defekt?)"
echo "hivornet-firewall (nftables, Verwaltungsanschluss, Drossel): alle Prüfungen bestanden"
