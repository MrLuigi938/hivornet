#!/usr/bin/env python3
"""Prüft ein fertiges HoneyLite-Pi-Image: Bootpartition, Paket, Prüfsummen, Rechte, Architektur.

  python3 pi/verify_image.py honeylite-pi-arm64-v0.3.0.img.xz v0.3.0 arm64

Entpackt nur den vorderen Teil des Images (MBR und Bootpartition). Braucht pyfatfs.
Exit-Code 0, wenn alles stimmt.
"""
import hashlib, io, lzma, os, struct, sys, tarfile, tempfile

img_xz, version, arch = sys.argv[1], sys.argv[2], sys.argv[3]
ELF_MACHINE = {"arm64": 0xB7, "armv7": 0x28}[arch]
ok = True


def check(cond, msg):
    global ok
    print(("OK    " if cond else "FEHLER") + "  " + msg)
    ok = ok and cond


# sha256 der Datei gegen .sha256
h = hashlib.sha256()
with open(img_xz, "rb") as f:
    for b in iter(lambda: f.read(8 << 20), b""):
        h.update(b)
want = open(img_xz + ".sha256").read().split()[0]
check(h.hexdigest() == want, f"Prüfsumme der .img.xz ({want[:16]}…)")

# Nur die ersten 600 MB entpacken (MBR + Bootpartition)
head = bytearray()
with lzma.open(img_xz) as f:
    while len(head) < 600 << 20:
        b = f.read(16 << 20)
        if not b:
            break
        head += b
mbr = bytes(head[:512])
check(mbr[510:512] == b"\x55\xaa", "MBR vorhanden")
parts = []
for i in range(4):
    e = mbr[446 + 16 * i: 462 + 16 * i]
    lba, n = struct.unpack("<II", e[8:16])
    parts.append((e[4], lba * 512, n * 512))
typ, off, size = parts[0]
check(typ in (0x0b, 0x0c), f"Partition 1 FAT32 (Typ 0x{typ:02x}, {size >> 20} MB)")
check(parts[1][0] == 0x83, "Partition 2 Linux")

tmp = tempfile.mkdtemp()
boot = os.path.join(tmp, "boot.img")
with open(boot, "wb") as o:
    o.write(head[off:off + size])
from pyfatfs.PyFatFS import PyFatFS
fs = PyFatFS(boot, read_only=True)
names = set(fs.listdir("/"))
for n in ("cmdline.txt", "config.txt", "kernel8.img", "user-data", "vendor-data", "userconf.txt", "HONEYLITE.txt", "honeylite"):
    check(n in names, f"/{n} vorhanden")
cmd = fs.readtext("/cmdline.txt")
check("root=PARTUUID=" in cmd and "resize" in cmd and "systemd.run" not in cmd, "cmdline.txt unverändert (resize, keine Zusätze)")
ud = fs.readtext("/user-data")
check(ud.startswith("#cloud-config") and "hostname: honeylite" in ud and "/boot/firmware/honeylite/install.sh" in ud, "user-data: cloud-config, Hostname, runcmd")
check(fs.readtext("/vendor-data").startswith("#!/bin/sh"), "vendor-data ist ein Skript")
uc = fs.readtext("/userconf.txt").strip()
check(uc.startswith("honeylite:$6$") and len(uc) > 100, "userconf.txt: Benutzer honeylite mit SHA-512-Hash")
hn = set(fs.listdir("/honeylite"))
check(hn == {"payload.tar.gz", "payload.tar.gz.sha256", "install.sh"}, f"/honeylite: {sorted(hn)}")
inst = fs.readbytes("/honeylite/install.sh")
check(b"\r\n" not in inst and inst.startswith(b"#!/bin/sh"), "install.sh mit Unix-Zeilenenden")
pl = fs.readbytes("/honeylite/payload.tar.gz")
sha_line = fs.readtext("/honeylite/payload.tar.gz.sha256").split()
check(hashlib.sha256(pl).hexdigest() == sha_line[0] and sha_line[1] == "payload.tar.gz", "Paket-Prüfsumme stimmt")
fs.close()

with tarfile.open(fileobj=io.BytesIO(pl), mode="r:gz") as t:
    members = {m.name: m for m in t.getmembers()}
    expect = {
        "opt/honeylite/hive": 0o755, "opt/honeylite/honeypot": 0o755, "opt/honeylite/VERSION": 0o644,
        "etc/honeylite/honeypot.yml": 0o644, "usr/lib/sysusers.d/honeylite.conf": 0o644,
        "usr/local/sbin/honeylite-firstboot": 0o755, "usr/local/sbin/honeylite-firewall": 0o755, "usr/local/sbin/honeylite-update": 0o755,
        "etc/systemd/system/honeylite-hive.service": 0o644, "etc/systemd/system/honeylite-honeypot.service": 0o644,
        "etc/systemd/system/honeylite-firstboot.service": 0o644, "etc/systemd/system/honeylite-firewall.service": 0o644,
        "etc/systemd/system/honeylite-update.service": 0o644, "etc/systemd/system/honeylite-update.path": 0o644,
    }
    for n, mode in expect.items():
        m = members.get(n)
        check(m is not None and m.mode == mode and m.uid == 0 and m.gid == 0, f"{n} ({oct(mode)}, root)")
    for n in ("opt/honeylite/hive", "opt/honeylite/honeypot"):
        b = t.extractfile(n).read(64)
        machine = struct.unpack("<H", b[18:20])[0]
        check(b[:4] == b"\x7fELF" and machine == 0xB7, f"{n}: Linux-Programm für AArch64 (arm64)")
    check(t.extractfile("opt/honeylite/VERSION").read().decode().strip() == version, f"VERSION = {version}")
    for n, m in members.items():
        if m.isfile() and n.startswith(("usr/local/sbin/", "etc/")):
            check(b"\r\n" not in t.extractfile(n).read(), f"{n}: Unix-Zeilenenden")
    unexpected = [n for n in members if not n.startswith(("opt/honeylite", "etc/honeylite", "etc/systemd/system/honeylite-", "usr/lib/sysusers.d/honeylite", "usr/local/sbin/honeylite-"))]
    check(not unexpected, f"keine fremden Dateien im Paket {unexpected}")

os.remove(boot)
print("\nErgebnis:", "alles in Ordnung" if ok else "FEHLER gefunden")
sys.exit(0 if ok else 1)
