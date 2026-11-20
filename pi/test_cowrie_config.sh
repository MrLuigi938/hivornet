#!/bin/sh
# Prüft hivornet-cowrie-config (Anmelderegel aus der Web-UI) ohne root und ohne systemd:
# gültige Anfragen werden in cowrie.cfg eingetragen, ungültige abgelehnt.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/bin" "$t/status"
printf '#!/bin/sh\necho "systemctl $*" >>"%s/calls"\n' "$t" >"$t/bin/systemctl"
chmod 755 "$t/bin/systemctl"
cp "$here/rootfs/etc/hivornet/cowrie.cfg" "$t/cowrie.cfg"

run() { # run ANFRAGE
  printf '%s\n' "$1" >"$t/req"
  PATH="$t/bin:$PATH" HIVORNET_COWRIE_REQUEST="$t/req" HIVORNET_COWRIE_CFG="$t/cowrie.cfg" HIVORNET_STATUS_DIR="$t/status" \
    sh "$here/rootfs/usr/local/sbin/hivornet-cowrie-config" >/dev/null 2>&1
}
fail() { echo "FEHLER: $*" >&2; exit 1; }

run "random 3 6" || fail "gültige Anfrage abgelehnt"
grep -qx 'auth_class = AuthRandom' "$t/cowrie.cfg" || fail "AuthRandom fehlt"
grep -qx 'auth_class_parameters = 3, 6, 10' "$t/cowrie.cfg" || fail "Parameter fehlen"
[ "$(grep -c '^auth_class' "$t/cowrie.cfg")" -eq 2 ] || fail "alte Regel nicht ersetzt"
[ "$(head -n 1 "$t/status/cowrie-config")" = ok ] || fail "Status nicht ok"
grep -q "try-restart hivornet-cowrie.service" "$t/calls" || fail "Cowrie nicht neu gestartet"
[ ! -e "$t/req" ] || fail "Anfrage nicht entfernt"

run "userdb" || fail "userdb abgelehnt"
grep -qx 'auth_class = UserDB' "$t/cowrie.cfg" || fail "UserDB fehlt"
if grep -q '^auth_class_parameters' "$t/cowrie.cfg"; then fail "Parameter bei UserDB übrig"; fi

cp "$t/cowrie.cfg" "$t/vorher"
for bad in "random 0 5" "random 6 3" "random 3 99" "rm -rf /" "random 3 6; reboot" ""; do
  if run "$bad"; then fail "ungültige Anfrage angenommen: $bad"; fi
  cmp -s "$t/cowrie.cfg" "$t/vorher" || fail "cowrie.cfg trotz ungültiger Anfrage geändert: $bad"
done
[ "$(head -n 1 "$t/status/cowrie-config")" = failed ] || fail "Status nicht failed"

# Ordner als Anfrage (N17, Audit 3): wird entfernt, die nächste Anfrage geht wieder
mkdir -p "$t/req/sub" && : >"$t/req/sub/x"
PATH="$t/bin:$PATH" HIVORNET_COWRIE_REQUEST="$t/req" HIVORNET_COWRIE_CFG="$t/cowrie.cfg" HIVORNET_STATUS_DIR="$t/status" \
  sh "$here/rootfs/usr/local/sbin/hivornet-cowrie-config" >/dev/null 2>&1 || fail "Ordner: Fehler statt still verwerfen"
[ ! -e "$t/req" ] || fail "Ordner als Anfrage nicht entfernt"
cmp -s "$t/cowrie.cfg" "$t/vorher" || fail "Ordner hat cowrie.cfg verändert"
run "random 2 4" || fail "Anfrage nach dem Ordner abgelehnt"
cp "$t/cowrie.cfg" "$t/vorher"

# Symlink als Anfrage wird nicht gelesen (nur wo echte Symlinks gehen, also nicht unter Git Bash)
ln -s "$t/vorher" "$t/req" 2>/dev/null || true
if [ -L "$t/req" ]; then
PATH="$t/bin:$PATH" HIVORNET_COWRIE_REQUEST="$t/req" HIVORNET_COWRIE_CFG="$t/cowrie.cfg" HIVORNET_STATUS_DIR="$t/status" \
  sh "$here/rootfs/usr/local/sbin/hivornet-cowrie-config" >/dev/null 2>&1 || fail "Symlink: Fehler statt still verwerfen"
cmp -s "$t/cowrie.cfg" "$t/vorher" || fail "Symlink hat cowrie.cfg verändert"
fi
# Drossel für Dauer-Brute-Force: brute-request -> brute.conf, dann hivornet-firewall apply
printf '#!/bin/sh\necho "firewall $*" >>"%s/calls"\n' "$t" >"$t/bin/fw"
chmod 755 "$t/bin/fw"
brun() { # brun ANFRAGE (mit Zeilenumbrüchen)
  printf '%s' "$1" >"$t/breq"
  PATH="$t/bin:$PATH" HIVORNET_COWRIE_REQUEST="$t/keine" HIVORNET_COWRIE_CFG="$t/cowrie.cfg" HIVORNET_STATUS_DIR="$t/status" \
    HIVORNET_BRUTE_REQUEST="$t/breq" HIVORNET_BRUTE_CONF="$t/brute.conf" HIVORNET_FIREWALL="$t/bin/fw" \
    sh "$here/rootfs/usr/local/sbin/hivornet-cowrie-config" >/dev/null 2>&1
}
fwcalls() { grep -c "^firewall apply" "$t/calls" || true; }
brun "brute 6 20 15
allow 203.0.113.0/24
allow 2001:db8::/32
" || fail "gültige Drossel abgelehnt"
[ "$(cat "$t/brute.conf")" = "brute 6 20 15
allow 203.0.113.0/24
allow 2001:db8::/32" ] || { cat "$t/brute.conf"; fail "brute.conf falsch"; }
[ "$(fwcalls)" = 1 ] || fail "hivornet-firewall nicht aufgerufen"
[ ! -e "$t/breq" ] || fail "brute-request nicht entfernt"
cmp -s "$t/cowrie.cfg" "$t/vorher" || fail "Drossel hat cowrie.cfg verändert"
brun "brute off
" || fail "Drossel aus abgelehnt"
[ "$(cat "$t/brute.conf")" = "brute off" ] || fail "brute.conf nach 'aus' falsch"
[ "$(fwcalls)" = 2 ] || fail "hivornet-firewall nach 'aus' nicht aufgerufen"
cp "$t/brute.conf" "$t/brute.vorher"
for bad in "brute 1 20 15" "brute 6 2 15" "brute 6 20 99999" "brute 6 20" "brute 6 20 15; reboot" \
  "brute 6 20 15
allow 1.2.3.4/32; flush ruleset" "brute 6 20 15
allow \$(reboot)/32" "brute 6 20 15
allow 203.0.113.0" "brute 6 20 15
rm -rf /" "allow 203.0.113.0/24" ""; do
  brun "$bad" || fail "ungültige Drossel: Fehler statt Status"
  cmp -s "$t/brute.conf" "$t/brute.vorher" || fail "brute.conf trotz ungültiger Anfrage geändert: $bad"
  [ "$(fwcalls)" = 2 ] || fail "hivornet-firewall trotz ungültiger Anfrage aufgerufen: $bad"
  [ "$(head -n 1 "$t/status/brute")" = failed ] || fail "Status brute nicht failed: $bad"
  [ ! -e "$t/breq" ] || fail "ungültige Anfrage nicht entfernt: $bad"
done
echo "hivornet-cowrie-config: ok"
