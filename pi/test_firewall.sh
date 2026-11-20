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
  rm -rf "${t:?}/bin" "${t:?}/log"
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
    # NFT_FAIL=1: nft -f scheitert (Syntaxfehler, fehlendes Modul)
    printf '#!/bin/sh\necho "nft $*" >>"%s"\n[ "$1" = -f ] && cat >>"%s" && [ -n "${NFT_FAIL:-}" ] && exit 1\nexit 0\n' "$t/log" "$t/log" >"$t/bin/nft"
  else
    # -D findet beim ersten Aufruf nichts (wie ohne alte Regeln), sonst Erfolg
    for ipt in iptables ip6tables; do
      printf '#!/bin/sh\necho "%s $*" >>"%s"\n[ "$1" = -D ] && exit 1\nexit 0\n' "$ipt" "$t/log" >"$t/bin/$ipt"
    done
  fi
  chmod +x "$t/bin/"*
}

run() { HIVORNET_STATUS_DIR="$t/status" PATH="$t/bin:/usr/bin:/bin" sh "$fw" "$@" >"$t/out" 2>&1 || { cat "$t/out"; fail "hivornet-firewall $* (Exit-Code)"; }; }
has() { grep -qF -- "$1" "$t/log" || { cat "$t/log"; fail "erwartet: $1"; }; }
hasnt() { if grep -qF -- "$1" "$t/log"; then cat "$t/log"; fail "unerwartet: $1"; fi; }

for cow in 1 0; do
  setup nft "$cow"
  run apply
  has "meta skuid 990 drop"
  has "tcp dport 8089 accept"
  if [ "$cow" = 1 ]; then has "meta skuid 991 drop"; else hasnt "skuid 991"; fi
  # Verwaltungsanschluss: Sprünge für USB-Adapter, aber nie für den eingebauten eth0
  has 'iifname "eth1" jump mgmt_in'
  has 'oifname "enx*" jump mgmt_out'
  has 'iifname "eth9" drop'
  has "tcp dport 8088 accept"
  # Audit 4: Web-UI an eth0/WLAN nur aus privaten IPv4-Netzen
  has "tcp dport 8088 ip saddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16 } reject"
  hasnt '"eth0"'
  [ "$(head -n 1 "$t/status/firewall")" = ok ] || fail "Statusdatei nicht ok (nft)"
  # N12 (Audit 3): Ersetzen in einem einzigen nft -f, kein Löschen vorab
  hasnt "nft delete table"
  hasnt "nft add rule"
  [ "$(grep -c '^nft -f' "$t/log")" = 1 ] || { cat "$t/log"; fail "nicht genau ein nft -f"; }
  has "delete table inet hivornet"
  # Fehler in nft -f: Abbruch mit Fehler, Status failed, vorher nichts gelöscht
  : >"$t/log"
  if NFT_FAIL=1 HIVORNET_STATUS_DIR="$t/status" PATH="$t/bin:/usr/bin:/bin" sh "$fw" apply >"$t/out" 2>&1; then fail "Fehler in nft -f nicht bemerkt"; fi
  hasnt "nft delete table"
  [ "$(head -n 1 "$t/status/firewall")" = failed ] || fail "Status nach Fehler nicht failed"
  run remove
  [ ! -e "$t/status/firewall" ] || fail "Statusdatei nach remove noch da"
  run status

  # PATH ohne nft: iptables-Zweig
  setup iptables "$cow"
  run apply
  has "--uid-owner hivornet-pot -j HIVORNET-POT"
  if [ "$cow" = 1 ]; then has "--uid-owner hivornet-cowrie -j HIVORNET-COW"; else hasnt "-N HIVORNET-COW"; fi
  has "iptables -I INPUT 1 -i eth1 -j HIVORNET-MGMT-IN"
  has "ip6tables -I OUTPUT 1 -o enx+ -j HIVORNET-MGMT-OUT"
  has "iptables -A HIVORNET-MGMT-IN -p tcp --dport 8088 -j ACCEPT"
  hasnt "-i eth0"
  [ "$(head -n 1 "$t/status/firewall")" = ok ] || fail "Statusdatei nicht ok (iptables)"
  run remove
done
echo "hivornet-firewall: alle Prüfungen bestanden"
