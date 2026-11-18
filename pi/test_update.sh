#!/bin/sh
# Prüft die Eingangsprüfungen von hivornet-update ohne root, ohne Netz und ohne systemd:
# Anfrage-Datei (N17), Versionsformat und Schutz vor älteren Versionen (M7, Audit 3).
# Downloads scheitern absichtlich (Ersatz für curl und wget); geprüft wird, bis wohin das
# Skript kommt.
#
#   sh pi/test_update.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
up="$here/rootfs/usr/local/sbin/hivornet-update"
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { echo "FEHLER: $*" >&2; exit 1; }

mkdir -p "$t/bin" "$t/root/var/lib/hivornet" "$t/root/opt/hivornet"
for c in curl wget; do
  printf '#!/bin/sh\necho "%s $*" >>"%s/calls"\nexit 22\n' "$c" "$t" >"$t/bin/$c"
done
printf '#!/bin/sh\necho aarch64\n' >"$t/bin/uname"
chmod +x "$t/bin/"*
REQ="$t/root/var/lib/hivornet/update-request"
ST="$t/root/var/lib/hivornet-update/status"

run() { # run [ANFRAGE]; Rückgabe: Exit-Code des Updaters
  rm -f "$t/calls"
  [ $# -eq 0 ] || printf '%s\n' "$1" >"$REQ"
  rc=0
  PATH="$t/bin:$PATH" HIVORNET_TEST_ROOT="$t/root" sh "$up" >"$t/out" 2>&1 || rc=$?
  return $rc
}
downloaded() { [ -s "$t/calls" ]; }

printf 'v0.7.0-beta.3\n' >"$t/root/opt/hivornet/VERSION"

# Ungültige Angaben: kein Download
for bad in "0.8.0" "v0.8" "v0.8.0;reboot" "v0.8.0 x" "../v0.8.0"; do
  if run "$bad"; then fail "ungültige Version angenommen: $bad"; fi
  if downloaded; then fail "Download trotz ungültiger Version: $bad"; fi
  grep -q "ungültige Versionsangabe" "$ST" || fail "Status ohne Grund: $bad"
done

# Ältere Versionen: abgelehnt, kein Download (M7)
for old in v0.7.0-beta.2 v0.7.0-alpha.9 v0.6.9 v0.6.1-beta.2 v0.1.0; do
  if run "$old"; then fail "ältere Version angenommen: $old"; fi
  if downloaded; then fail "Download einer älteren Version: $old"; fi
  grep -q "älter als die installierte" "$ST" || { cat "$ST"; fail "Status nennt den Grund nicht: $old"; }
done
[ ! -e "$REQ" ] || fail "Anfrage nach Ablehnung nicht entfernt"

# Gleiche und neuere Versionen: Prüfung bestanden, Download wird versucht
for new in v0.7.0-beta.3 v0.7.0-beta.10 v0.7.0-rc.1 v0.7.0 v0.7.1 v0.8.0-beta.1 v1.0.0; do
  if run "$new"; then fail "Download sollte im Test scheitern: $new"; fi
  downloaded || { cat "$t/out"; fail "kein Download für $new"; }
  grep -q "Download von hivornet-$new-linux-arm64.tar.gz nicht möglich" "$ST" || { cat "$ST"; fail "Status für $new"; }
done

# Ohne VERSION-Datei (sehr alte Images): keine Sperre, Download wird versucht
rm "$t/root/opt/hivornet/VERSION"
run v0.6.0 || true
downloaded || fail "ohne VERSION-Datei blockiert"
printf 'v0.7.0-beta.3\n' >"$t/root/opt/hivornet/VERSION"

# Ordner als Anfrage (N17): wird entfernt, die nächste Anfrage geht wieder
mkdir -p "$REQ/sub" && : >"$REQ/sub/x"
run || fail "Ordner als Anfrage: Fehler statt still verwerfen"
[ ! -e "$REQ" ] || fail "Ordner als Anfrage nicht entfernt"
run v0.6.0 || true
grep -q "älter als die installierte" "$ST" || fail "Anfrage nach dem Ordner nicht bearbeitet"
echo "hivornet-update: alle Prüfungen bestanden"
