#!/bin/sh
# Baut das HoneyLite-Image für den Raspberry Pi.
#
# Nimmt ein offizielles "Raspberry Pi OS Lite" und legt HoneyLite hinein: die beiden
# Programme, systemd-Dienste, Netzsperre und Updater (Ordner pi/rootfs). Es wird
# nichts im Image ausgeführt und kein Paket nachinstalliert; deshalb braucht der
# Bau keine ARM-Emulation.
#
# Braucht Linux mit Root-Rechten (losetup, mount), xz, curl, openssl. Gedacht für
# die CI (.github/workflows/release.yml), läuft aber auch auf jedem Linux-Rechner:
#
#   sudo sh pi/build-image.sh arm64 v0.3.0 dist/arm64      # Pi 3, 4, 5, Zero 2 (64 Bit)
#   sudo sh pi/build-image.sh armv7 v0.3.0 dist/armv7      # ältere 32-Bit-Systeme
#
#   Argument 3 ist der Ordner mit den fertigen Programmen "hive" und "honeypot".
#   BASE_URL=...   anderes Basis-Image (xz-gepackt)
#   PI_PASSWORD=.. Passwort für den Konsolen-Benutzer "honeylite" (Fehlersuche mit
#                  Tastatur und Bildschirm). Ohne Angabe ist die Anmeldung gesperrt.
#
# Ergebnis: honeylite-pi-<arch>-<version>.img.xz im aktuellen Ordner.
set -eu

ARCH=${1:?Architektur fehlt (arm64 oder armv7)}
VERSION=${2:?Version fehlt (z. B. v0.3.0)}
BIN=${3:?Ordner mit hive und honeypot fehlt}
HERE=$(cd "$(dirname "$0")" && pwd)

die() { printf 'FEHLER: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = "0" ] || die "bitte mit sudo ausführen"
for t in losetup mount xz curl openssl; do
  command -v "$t" >/dev/null 2>&1 || die "$t fehlt"
done
[ -f "$BIN/hive" ] && [ -f "$BIN/honeypot" ] || die "$BIN enthält nicht hive und honeypot"

case "$ARCH" in
  arm64) DEFAULT_URL=https://downloads.raspberrypi.com/raspios_lite_arm64_latest ;;
  armv7) DEFAULT_URL=https://downloads.raspberrypi.com/raspios_lite_armhf_latest ;;
  *) die "unbekannte Architektur $ARCH" ;;
esac
BASE_URL=${BASE_URL:-$DEFAULT_URL}

WORK=$(mktemp -d)
MNT="$WORK/mnt"
LOOP=""
cleanup() {
  mountpoint -q "$MNT/boot/firmware" 2>/dev/null && umount "$MNT/boot/firmware"
  mountpoint -q "$MNT" 2>/dev/null && umount "$MNT"
  [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "Lade Basis-Image: $BASE_URL"
curl -fL --retry 3 -o "$WORK/base.img.xz" "$BASE_URL"
xz -dc "$WORK/base.img.xz" >"$WORK/pi.img"
rm -f "$WORK/base.img.xz"

LOOP=$(losetup -fP --show "$WORK/pi.img")
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"
[ -d "$MNT/etc/systemd/system" ] || die "Partition 2 sieht nicht nach Raspberry Pi OS aus"
# Die Boot-Partition liegt je nach Version unter /boot/firmware oder /boot.
BOOT="$MNT/boot/firmware"
[ -d "$BOOT" ] || BOOT="$MNT/boot"
mount "${LOOP}p1" "$BOOT"

echo "Kopiere HoneyLite ..."
cp -a "$HERE/rootfs/." "$MNT/"
chown -R 0:0 "$MNT/etc/honeylite" "$MNT/usr/local/sbin/honeylite-firstboot" "$MNT/usr/local/sbin/honeylite-firewall" \
  "$MNT/usr/local/sbin/honeylite-update" "$MNT/usr/lib/sysusers.d/honeylite.conf"
chmod 755 "$MNT/usr/local/sbin/honeylite-firstboot" "$MNT/usr/local/sbin/honeylite-firewall" "$MNT/usr/local/sbin/honeylite-update"
for u in honeylite-hive honeylite-honeypot honeylite-firstboot honeylite-firewall honeylite-update; do
  for f in "$MNT/etc/systemd/system/$u".*; do
    chown 0:0 "$f"
    chmod 644 "$f"
  done
done
mkdir -p "$MNT/opt/honeylite"
install -m 755 -o 0 -g 0 "$BIN/hive" "$BIN/honeypot" "$MNT/opt/honeylite/"
printf '%s\n' "$VERSION" >"$MNT/opt/honeylite/VERSION"

# Dienste einschalten (entspricht "systemctl enable", ohne das Image zu starten)
WANTS="$MNT/etc/systemd/system/multi-user.target.wants"
mkdir -p "$WANTS"
for u in honeylite-firstboot.service honeylite-firewall.service honeylite-hive.service honeylite-honeypot.service honeylite-update.path; do
  ln -sf "/etc/systemd/system/$u" "$WANTS/$u"
done

# Rechnername: Die Web-UI ist danach unter http://honeylite.local:8088 erreichbar (mDNS).
echo honeylite >"$MNT/etc/hostname"
if grep -q '^127\.0\.1\.1' "$MNT/etc/hosts"; then
  sed -i 's/^127\.0\.1\.1.*/127.0.1.1\thoneylite/' "$MNT/etc/hosts"
else
  printf '127.0.1.1\thoneylite\n' >>"$MNT/etc/hosts"
fi

# Konsolen-Benutzer. Raspberry Pi OS verlangt beim ersten Start einen Benutzer;
# ohne PI_PASSWORD bekommt er ein Zufallspasswort, das niemand kennt. SSH bleibt aus
# (Port 22 gehört dem Honeypot). Bedient wird das Gerät nur über die Web-UI.
pw=${PI_PASSWORD:-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')}
printf 'honeylite:%s\n' "$(openssl passwd -6 "$pw")" >"$BOOT/userconf.txt"
rm -f "$BOOT/ssh" "$BOOT/ssh.txt"

sync
umount "$BOOT"
umount "$MNT"
losetup -d "$LOOP"
LOOP=""

OUT="honeylite-pi-$ARCH-$VERSION.img"
mv "$WORK/pi.img" "$OUT"
xz -T0 -6 -f "$OUT"
echo "Fertig: $OUT.xz"
