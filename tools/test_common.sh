#!/bin/sh
# Prüft Hilfen aus tools/common.sh mit Ersatzbefehlen. Braucht kein root und kein Docker.
#
#   sh tools/test_common.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { echo "FEHLER: $*" >&2; exit 1; }
mkdir "$t/bin"

# shellcheck source=tools/common.sh
. "$here/common.sh"

# is_private_ip
for a in 10.0.0.5 192.168.178.20 172.16.0.1 172.31.255.254; do
  is_private_ip "$a" || fail "privat nicht erkannt: $a"
done
for a in 203.0.113.7 198.51.100.1 172.15.0.1 172.32.0.1 100.64.0.1 127.0.0.1 169.254.1.1 "" 10.0.0 "10.1.2.3 x" 192.168.1.1.5; do
  if is_private_ip "$a"; then fail "fälschlich privat: '$a'"; fi
done

# lan_ip mit Ersatz für ip und hostname (M9 des dritten Audits)
fake() { # fake ROUTE-SRC "HOSTNAME-I"
  printf '#!/bin/sh\necho "1.1.1.1 via 192.0.2.1 dev eth0 src %s uid 0"\n' "$1" >"$t/bin/ip"
  printf '#!/bin/sh\necho "%s"\n' "$2" >"$t/bin/hostname"
  chmod +x "$t/bin/ip" "$t/bin/hostname"
}
got() { PATH="$t/bin:$PATH" lan_ip; }

fake 192.168.178.20 "192.168.178.20"
[ "$(got)" = 192.168.178.20 ] || fail "LAN-Adresse: $(got)"
fake 203.0.113.7 "203.0.113.7"
[ -z "$(got)" ] || fail "öffentliche Adresse geliefert: $(got)"
fake 203.0.113.7 "203.0.113.7 10.8.0.1 fd00::1"
[ "$(got)" = 10.8.0.1 ] || fail "private Zweitadresse: $(got)"
fake 100.64.3.4 "100.64.3.4"
[ -z "$(got)" ] || fail "CGNAT-Adresse geliefert: $(got)"
echo "common.sh: alle Prüfungen bestanden"
