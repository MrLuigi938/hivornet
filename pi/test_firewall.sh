#!/bin/sh
# Führt pi/rootfs/usr/local/sbin/hivornet-firewall mit Ersatzbefehlen für id, nft und
# iptables aus und prüft die erzeugten Regeln. Braucht kein root und kein echtes nftables.
#
#   sh pi/test_firewall.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
fw="$here/rootfs/usr/local/sbin/hivornet-firewall"
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { echo "FEHLER: $*" >&2; exit 1; }

# setup BACKEND COWRIE: BACKEND nft|iptables, COWRIE 1 = Benutzer hivornet-cowrie existiert
setup() {
  rm -rf "$t/bin" "$t/log"
  mkdir "$t/bin"
  : >"$t/log"
  cat >"$t/bin/id" <<EOF
#!/bin/sh
# id BENUTZER oder id -u BENUTZER
for u; do :; done
case "\$u" in
  hivornet-pot) echo 990 ;;
  hivornet-cowrie) [ "$2" = 1 ] && echo 991 && exit 0; echo "id: unbekannt" >&2; exit 1 ;;
  *) exit 1 ;;
esac
EOF
  # shellcheck disable=SC2016 # $* und $1 gehören in die Ersatzskripte
  if [ "$1" = nft ]; then
    printf '#!/bin/sh\necho "nft $*" >>"%s"\n[ "$1" = -f ] && cat >>"%s"\nexit 0\n' "$t/log" "$t/log" >"$t/bin/nft"
  else
    # -D findet beim ersten Aufruf nichts (wie ohne alte Regeln), sonst Erfolg
    printf '#!/bin/sh\necho "iptables $*" >>"%s"\n[ "$1" = -D ] && exit 1\nexit 0\n' "$t/log" >"$t/bin/iptables"
  fi
  chmod +x "$t/bin/"*
}

run() { PATH="$t/bin:/usr/bin:/bin" sh "$fw" "$@" >"$t/out" 2>&1 || { cat "$t/out"; fail "hivornet-firewall $* (Exit-Code)"; }; }
has() { grep -qF -- "$1" "$t/log" || { cat "$t/log"; fail "erwartet: $1"; }; }
hasnt() { if grep -qF -- "$1" "$t/log"; then cat "$t/log"; fail "unerwartet: $1"; fi; }

for cow in 1 0; do
  setup nft "$cow"
  run apply
  has "meta skuid 990 drop"
  has "tcp dport 8089 accept"
  if [ "$cow" = 1 ]; then has "meta skuid 991 drop"; else hasnt "skuid 991"; fi
  run remove
  run status

  # PATH ohne nft: iptables-Zweig
  setup iptables "$cow"
  run apply
  has "--uid-owner hivornet-pot -j HIVORNET-POT"
  if [ "$cow" = 1 ]; then has "--uid-owner hivornet-cowrie -j HIVORNET-COW"; else hasnt "-N HIVORNET-COW"; fi
  run remove
done
echo "hivornet-firewall: alle Prüfungen bestanden"
