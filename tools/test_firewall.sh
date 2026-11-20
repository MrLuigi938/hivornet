#!/bin/sh
# Prüft tools/firewall.sh mit einem Ersatz für iptables, der Ketten und Regeln in Dateien führt.
# Braucht kein root und kein Docker.
#
#   sh tools/test_firewall.sh
#
# Geprüft wird vor allem: Beim erneuten Setzen gibt es keinen Augenblick ohne Sperre, und ein
# Fehler mittendrin lässt die bisherige Sperre unverändert.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
fw="$here/firewall.sh"
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { echo "FEHLER: $*" >&2; exit 1; }

mkdir "$t/bin" "$t/chains"
printf '#!/bin/sh\necho 0\n' >"$t/bin/id"
printf '#!/bin/sh\nexit 0\n' >"$t/bin/ip"
# Ersatz-iptables: je Kette eine Datei, je Regel eine Zeile. FW_FAIL=Text lässt den Aufruf
# scheitern, dessen Argumente den Text enthalten. Nach jeder Änderung prüft "guard", ob die
# Sperre steht, und schreibt Lücken nach $FW_STATE/gaps (nur wenn $FW_STATE/watch existiert).
cat >"$t/bin/iptables" <<'MOCK'
#!/bin/sh
d="$FW_STATE/chains"
all="$*"
if [ -n "${FW_FAIL:-}" ]; then
  case "$all" in *"$FW_FAIL"*) echo "iptables: nachgestellter Fehler" >&2; exit 1 ;; esac
fi
guard() {
  [ -e "$FW_STATE/watch" ] || return 0
  ok=0
  if [ -e "$d/DOCKER-USER" ]; then
    while read -r line; do
      case "$line" in
        "-i hv-honeynet -j "*)
          c=${line##* -j }
          [ -e "$d/$c" ] && [ "$(tail -n 1 "$d/$c")" = "-j DROP" ] && ok=1 ;;
      esac
    done <"$d/DOCKER-USER"
  fi
  [ "$ok" = 1 ] || echo "Lücke nach: $all" >>"$FW_STATE/gaps"
}
op=$1; shift
case "$op" in
  -L|-S) [ -e "$d/$1" ] || exit 1; cat "$d/$1" ;;
  -N) [ -e "$d/$1" ] && exit 1; : >"$d/$1" ;;
  -F) [ -e "$d/$1" ] || exit 1; : >"$d/$1" ;;
  -X)
    [ -e "$d/$1" ] || exit 1
    if grep -qe "-j $1\$" "$d"/*; then echo "iptables: Kette noch eingehängt" >&2; exit 1; fi
    rm "$d/$1" ;;
  -E)
    [ -e "$d/$1" ] || exit 1; [ -e "$d/$2" ] && exit 1
    mv "$d/$1" "$d/$2"
    for f in "$d"/*; do sed "s/-j $1\$/-j $2/" "$f" >"$f.tmp"; mv "$f.tmp" "$f"; done ;;
  -A) c=$1; shift; [ -e "$d/$c" ] || exit 1; echo "$*" >>"$d/$c" ;;
  -I) c=$1; shift; shift; [ -e "$d/$c" ] || exit 1; { echo "$*"; cat "$d/$c"; } >"$d/$c.tmp"; mv "$d/$c.tmp" "$d/$c" ;;
  -D)
    c=$1; shift; [ -e "$d/$c" ] || exit 1
    grep -qxFe "$*" "$d/$c" || exit 1
    grep -vxFe "$*" "$d/$c" >"$d/$c.tmp" || true
    mv "$d/$c.tmp" "$d/$c" ;;
  *) exit 2 ;;
esac
guard
exit 0
MOCK
chmod +x "$t/bin/"*

run() { FW_STATE="$t" PATH="$t/bin:/usr/bin:/bin" sh "$fw" "$@" >"$t/out" 2>&1; }
must() { run "$@" || { cat "$t/out"; fail "firewall.sh $* (Exit-Code)"; }; }
has() { grep -qxFe "$2" "$t/chains/$1" || { cat "$t/chains/$1" 2>/dev/null; fail "in $1 erwartet: $2"; }; }
active() {
  has DOCKER-USER "-i hv-honeynet -j HIVORNET-OUT"
  has INPUT "-i hv-honeynet -j HIVORNET-HOST"
  has INPUT "-i hv-ingest -j HIVORNET-HOST"
  # M6 (Audit 3): zusätzlich nach Quell-Netz, für Bridges mit anderem Namen
  has DOCKER-USER "-s 172.30.252.0/24 -j HIVORNET-OUT"
  has INPUT "-s 172.30.252.0/24 -j HIVORNET-HOST"
  has INPUT "-s 172.30.250.0/24 -j HIVORNET-HOST"
  [ "$(tail -n 1 "$t/chains/HIVORNET-OUT")" = "-j DROP" ] || fail "HIVORNET-OUT endet nicht mit DROP"
  [ "$(tail -n 1 "$t/chains/HIVORNET-HOST")" = "-j DROP" ] || fail "HIVORNET-HOST endet nicht mit DROP"
  has HIVORNET-OUT "-d 192.168.0.0/16 -j DROP"
  if [ -e "$t/chains/HIVORNET-OUT-NEU" ] || [ -e "$t/chains/HIVORNET-HOST-NEU" ]; then fail "Ketten -NEU übrig"; fi
  [ "$(grep -c -- '-j HIVORNET-OUT$' "$t/chains/DOCKER-USER")" = 2 ] || fail "DOCKER-USER: nicht genau zwei Sprünge der Sperre"
  [ "$(grep -c . "$t/chains/INPUT")" = 4 ] || fail "INPUT: nicht genau vier Sprünge"
}
nogap() { if [ -e "$t/gaps" ]; then cat "$t/gaps"; fail "$1"; fi; }

# 1. Vor dem Start von Docker: DOCKER-USER fehlt noch und wird angelegt
: >"$t/chains/INPUT"
must apply
active

# 2. Erneutes Setzen (Aufgabenplaner alle 15 Minuten): zu keinem Zeitpunkt ohne Sperre
: >"$t/watch"
must apply
active
ALLOW_DOWNLOADS=1 must apply
active
has HIVORNET-OUT "-s 172.30.252.10 -p tcp -m multiport --dports 80,443 -j RETURN"
nogap "Sperre war beim erneuten Setzen zeitweise offen"

# 3. Fehler an jeder Stelle des Neuaufbaus: Abbruch mit Fehler, bisherige Sperre bleibt
for f in "-N HIVORNET-OUT-NEU" "--ctstate" "-A HIVORNET-OUT-NEU -j DROP" "-N HIVORNET-HOST-NEU" \
  "-I DOCKER-USER 1 -s" "-I DOCKER-USER 1 -i" "-I INPUT 1 -s 172.30.250.0/24" "-I INPUT 1 -i hv-ingest" \
  "-E HIVORNET-OUT-NEU" "-E HIVORNET-HOST-NEU"; do
  if FW_FAIL="$f" run apply; then fail "Fehler bei '$f' nicht bemerkt"; fi
  nogap "Fehler bei '$f' öffnet die Sperre"
  must apply # der nächste Lauf räumt auf, wieder ohne Lücke
  active
  nogap "Aufräumen nach Fehler bei '$f' öffnet die Sperre"
done

# 4. Alt-Installation ohne feste Bridge-Namen (M6): Hinweis auf die Sperre nach Quell-Netz
printf '#!/bin/sh\nexit 1\n' >"$t/bin/ip"
must apply
active
grep -q "nach Quell-Netz" "$t/out" || { cat "$t/out"; fail "kein Hinweis auf fehlende Bridge"; }
printf '#!/bin/sh\nexit 0\n' >"$t/bin/ip"
nogap "Sperre war bei fehlender Bridge zeitweise offen"

# 5. Drossel für Dauer-Brute-Force (Standard aus)
HOOK="-d 172.30.252.10 -p tcp -m multiport --dports 2222,2223 -m conntrack --ctstate NEW -j HIVORNET-BRUTE"
brute_on() {
  has DOCKER-USER "$HOOK"
  [ "$(grep -c -- '-j HIVORNET-BRUTE' "$t/chains/DOCKER-USER")" = 1 ] || fail "DOCKER-USER: nicht genau ein Sprung der Drossel"
  [ ! -e "$t/chains/HIVORNET-BRUTE-NEU" ] || fail "Kette HIVORNET-BRUTE-NEU übrig"
  # private Netze vor jeder Begrenzung
  for n in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8; do has HIVORNET-BRUTE "-s $n -j RETURN"; done
  [ "$(head -n 1 "$t/chains/HIVORNET-BRUTE")" = "-s 10.0.0.0/8 -j RETURN" ] || fail "Ausnahmen nicht am Anfang"
  [ "$(tail -n 1 "$t/chains/HIVORNET-BRUTE" | cut -c1-2)" = "-m" ] || [ "$(tail -n 1 "$t/chains/HIVORNET-BRUTE")" = "-j DROP" ] || fail "Drossel endet nicht mit Verwerfen"
}
[ ! -e "$t/chains/HIVORNET-BRUTE" ] || fail "Drossel ohne BRUTE_LIMIT=1"
grep -q "Dauer-Brute-Force: aus" "$t/out" || { cat "$t/out"; fail "kein Hinweis 'Drossel aus'"; }
BRUTE_LIMIT=1 BRUTE_ALLOW="203.0.113.0/24 198.51.100.7 2001:db8::/32" must apply
active
brute_on
has HIVORNET-BRUTE "-s 203.0.113.0/24 -j RETURN"
has HIVORNET-BRUTE "-s 198.51.100.7 -j RETURN"
has HIVORNET-BRUTE "-m recent --name hvbrute --rcheck --seconds 900 -j DROP"
has HIVORNET-BRUTE "-m hashlimit --hashlimit-upto 6/min --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name hvb6-20 --hashlimit-htable-expire 600000 -j RETURN"
has HIVORNET-BRUTE "-m recent --name hvbrute --set -j DROP"
grep -q "IPv6" "$t/out" || fail "kein Hinweis auf übersprungenes IPv6-Netz"
if grep -q "2001:db8" "$t/chains/HIVORNET-BRUTE"; then fail "IPv6-Netz in iptables"; fi
# andere Werte, ohne Sperre: getauscht, nicht doppelt
BRUTE_LIMIT=1 BRUTE_RATE=10 BRUTE_BURST=30 BRUTE_BAN=0 must apply
active
brute_on
has HIVORNET-BRUTE "-m hashlimit --hashlimit-upto 10/min --hashlimit-burst 30 --hashlimit-mode srcip --hashlimit-name hvb10-30 --hashlimit-htable-expire 600000 -j RETURN"
[ "$(tail -n 1 "$t/chains/HIVORNET-BRUTE")" = "-j DROP" ] || fail "ohne Sperre: letzte Regel nicht DROP"
if grep -q "recent" "$t/chains/HIVORNET-BRUTE"; then fail "Sperre trotz BRUTE_BAN=0"; fi
nogap "Sperre war beim Setzen der Drossel zeitweise offen"
# Fehler in der Drossel (z. B. Modul hashlimit fehlt) oder falsche Werte: Sperre bleibt, alte Drossel auch
cp "$t/chains/HIVORNET-BRUTE" "$t/brute.vorher"
for f in "--hashlimit-upto" "-N HIVORNET-BRUTE-NEU" "-I DOCKER-USER 1 -d" "-E HIVORNET-BRUTE-NEU"; do
  if BRUTE_LIMIT=1 BRUTE_RATE=12 FW_FAIL="$f" run apply; then fail "Fehler bei '$f' in der Drossel nicht bemerkt"; fi
  grep -q "Netzsperre ist aktiv" "$t/out" || { cat "$t/out"; fail "keine Meldung nach Fehler bei '$f'"; }
  active
  nogap "Fehler bei '$f' in der Drossel öffnet die Sperre"
  BRUTE_LIMIT=1 BRUTE_RATE=10 BRUTE_BURST=30 BRUTE_BAN=0 must apply # räumt auf
  brute_on
  cmp -s "$t/chains/HIVORNET-BRUTE" "$t/brute.vorher" || fail "Drossel nach Fehler bei '$f' verändert"
done
for bad in "BRUTE_RATE=1" "BRUTE_RATE=abc" "BRUTE_BURST=0" "BRUTE_BAN=99999" "BRUTE_RATE=6;reboot" "BRUTE_ALLOW=10.0.0.0/8;x"; do
  if env BRUTE_LIMIT=1 "$bad" FW_STATE="$t" PATH="$t/bin:/usr/bin:/bin" sh "$fw" apply >"$t/out" 2>&1; then fail "ungültiger Wert $bad angenommen"; fi
  active
  cmp -s "$t/chains/HIVORNET-BRUTE" "$t/brute.vorher" || fail "Drossel nach ungültigem $bad verändert"
done
# ausschalten
must apply
active
[ ! -e "$t/chains/HIVORNET-BRUTE" ] || fail "Drossel nach BRUTE_LIMIT=0 noch da"
if grep -q "HIVORNET-BRUTE" "$t/chains/DOCKER-USER"; then fail "Sprung der Drossel nach BRUTE_LIMIT=0 noch da"; fi
BRUTE_LIMIT=1 must apply
brute_on

# 6. Entfernen
rm "$t/watch"
must remove
if [ -e "$t/chains/HIVORNET-OUT" ] || [ -e "$t/chains/HIVORNET-HOST" ] || [ -e "$t/chains/HIVORNET-BRUTE" ]; then fail "Ketten nach remove noch da"; fi
if [ -s "$t/chains/DOCKER-USER" ] || [ -s "$t/chains/INPUT" ]; then fail "Sprünge nach remove noch da"; fi
echo "firewall.sh: alle Prüfungen bestanden"
