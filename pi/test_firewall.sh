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
    # NFT_FAIL_BRUTE=1: scheitert nur, wenn die Drossel dabei ist (altes nftables ohne Mengen mit limit)
    printf '#!/bin/sh\necho "nft $*" >>"%s"\nif [ "$1" = -f ]; then\n  in=$(cat)\n  printf "%%s\\n" "$in" >>"%s"\n  [ -n "${NFT_FAIL:-}" ] && exit 1\n  case "$in" in *"chain brute"*) [ -n "${NFT_FAIL_BRUTE:-}" ] && exit 1 ;; esac\nfi\nexit 0\n' "$t/log" "$t/log" >"$t/bin/nft"
  else
    # -D findet beim ersten Aufruf nichts (wie ohne alte Regeln), sonst Erfolg
    for ipt in iptables ip6tables; do
      printf '#!/bin/sh\necho "%s $*" >>"%s"\n[ "$1" = -D ] && exit 1\nexit 0\n' "$ipt" "$t/log" >"$t/bin/$ipt"
    done
  fi
  chmod +x "$t/bin/"*
}

run() { HIVORNET_BRUTE_CONF="$t/brute.conf" HIVORNET_STATUS_DIR="$t/status" PATH="$t/bin:/usr/bin:/bin" sh "$fw" "$@" >"$t/out" 2>&1 || { cat "$t/out"; fail "hivornet-firewall $* (Exit-Code)"; }; }
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
# Drossel für Dauer-Brute-Force (brute.conf von hivornet-cowrie-config)
st() { head -n 1 "$t/status/$1"; }
setup nft 1
rm -f "$t/brute.conf" "$t/status/brute"
run apply
hasnt "chain brute"
[ ! -e "$t/status/brute" ] || fail "Status brute ohne brute.conf"
printf 'brute 6 20 15\nallow 203.0.113.0/24\nallow 2001:db8::/32\n' >"$t/brute.conf"
: >"$t/log"
run apply
has "chain brute {"
has "tcp dport { 22, 23 } ct state new jump brute"
has "update @brute_rate4 { ip saddr limit rate over 6/minute burst 20 packets } add @brute_ban4 { ip saddr timeout 15m } drop"
has "update @brute_rate6 { ip6 saddr limit rate over 6/minute burst 20 packets } add @brute_ban6 { ip6 saddr timeout 15m } drop"
has "192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, 100.64.0.0/10, 203.0.113.0/24 }"
has "fe80::/10, 2001:db8::/32 }"
has "meta skuid 990 drop" # Sperre unverändert dabei
# Ausnahmen vor Sperre und Rate
[ "$(grep -n 'saddr @brute_allow4 return' "$t/log" | cut -d: -f1)" -lt "$(grep -n 'saddr @brute_ban4 drop' "$t/log" | cut -d: -f1)" ] || fail "Ausnahmen nicht zuerst"
[ "$(grep -c '^nft -f' "$t/log")" = 1 ] || fail "mit Drossel nicht genau ein nft -f"
{ [ "$(st brute)" = ok ] && [ "$(st firewall)" = ok ]; } || fail "Status mit Drossel nicht ok"
grep -q "Drossel aktiv: höchstens 6" "$t/status/brute" || fail "Statustext der Drossel"
# ohne Sperre
printf 'brute 10 30 0\n' >"$t/brute.conf"
: >"$t/log"
run apply
has "update @brute_rate4 { ip saddr limit rate over 10/minute burst 30 packets } drop"
hasnt "add @brute_ban4"
# nftables kennt die Drossel nicht: Sperre trotzdem, Status brute failed
printf 'brute 6 20 15\n' >"$t/brute.conf"
: >"$t/log"
NFT_FAIL_BRUTE=1 run apply
[ "$(grep -c '^nft -f' "$t/log")" = 2 ] || fail "nach abgelehnter Drossel nicht ohne sie wiederholt"
[ "$(st firewall)" = ok ] || fail "Sperre nach abgelehnter Drossel nicht ok"
[ "$(st brute)" = failed ] || fail "Status brute nach Ablehnung nicht failed"
# aus
printf 'brute off\n' >"$t/brute.conf"
: >"$t/log"
run apply
hasnt "chain brute"
{ [ "$(st brute)" = ok ] && grep -q "Drossel aus" "$t/status/brute"; } || fail "Status 'Drossel aus'"
# ungültige oder von Hand verdorbene Datei: keine Drossel, nichts davon in nft
for bad in "brute 6 20 15
allow 1.2.3.4/32 } ; flush ruleset ; table x {" "brute 6 20 15
allow 203.0.113.0" "brute 999 20 15" "brute 6 20 15
reboot" "brute 6;20;15"; do
  printf '%s\n' "$bad" >"$t/brute.conf"
  : >"$t/log"
  run apply
  hasnt "chain brute"
  hasnt "flush ruleset"
  has "meta skuid 990 drop"
  [ "$(st brute)" = failed ] || fail "ungültige brute.conf nicht gemeldet: $bad"
done
# iptables (ohne nft): Hinweis, Sperre trotzdem
printf 'brute 6 20 15\n' >"$t/brute.conf"
setup iptables 1
run apply
has "--uid-owner hivornet-pot -j HIVORNET-POT"
[ "$(st brute)" = failed ] || fail "iptables: Drossel nicht als nicht möglich gemeldet"
echo "hivornet-firewall: alle Prüfungen bestanden"
