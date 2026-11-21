#!/bin/sh
# Prüft hivornet-memstat mit nachgebautem /proc und /sys/fs/cgroup und einem systemctl-Ersatz.
#   sh pi/test_memstat.sh
set -eu
fail() { echo "FEHLER: $*" >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT

cg="$t/cg" proc="$t/proc"
mkdir -p "$cg/system.slice/hivornet-hive.service" "$cg/system.slice/hivornet-cowrie.service" "$t/bin" "$proc/101" "$proc/202" "$proc/203"
printf 'cpuset cpu io pids\n' >"$cg/cgroup.controllers" # ohne memory wie auf dem Pi
printf '101\n' >"$cg/system.slice/hivornet-hive.service/cgroup.procs"
printf '202\n203\nkaputt\n' >"$cg/system.slice/hivornet-cowrie.service/cgroup.procs"
printf 'Name:\thive\nVmRSS:\t   94208 kB\n' >"$proc/101/status"
printf 'Name:\ttwistd\nVmRSS:\t   70000 kB\n' >"$proc/202/status"
printf 'Name:\tsh\nVmRSS:\t    1000 kB\n' >"$proc/203/status"
cat >"$t/bin/systemctl" <<'EOS'
#!/bin/sh
for a; do last=$a; done
case "$last" in
  hivornet-hive.service) echo 402653184 ;;
  *) echo infinity ;;
esac
EOS
chmod +x "$t/bin/systemctl"

PATH="$t/bin:$PATH" HIVORNET_STATUS_DIR="$t/status" HIVORNET_CGROUP_ROOT="$cg" HIVORNET_PROC_ROOT="$proc" \
  sh "$here/rootfs/usr/local/sbin/hivornet-memstat"
f="$t/status/memory"
[ -f "$f" ] || fail "Statusdatei fehlt"
[ "$(sed -n 1p "$f")" = ok ] || fail "Zustand: $(sed -n 1p "$f")"
grep -qx 'memcg 0' "$f" || fail "memcg nicht 0: $(cat "$f")"
grep -qx 'hivornet-hive 96468992 402653184' "$f" || fail "Hive: $(cat "$f")"
grep -qx 'hivornet-cowrie 72704000 0' "$f" || fail "Cowrie (zwei Prozesse, ohne Grenze): $(cat "$f")"
if grep -q '^hivornet-honeypot' "$f"; then fail "Dienst ohne cgroup aufgeführt"; fi

printf 'cpuset cpu io memory pids\n' >"$cg/cgroup.controllers"
PATH="$t/bin:$PATH" HIVORNET_STATUS_DIR="$t/status" HIVORNET_CGROUP_ROOT="$cg" HIVORNET_PROC_ROOT="$proc" \
  sh "$here/rootfs/usr/local/sbin/hivornet-memstat"
grep -qx 'memcg 1' "$f" || fail "memcg nicht 1"
echo "hivornet-memstat: alle Prüfungen bestanden"
