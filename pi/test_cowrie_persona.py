# Prüft die Persona in Cowrie (siehe hivornet-cowrie-install): Jede Angreifer-IP sieht ein festes
# Gerät. Gleiche IP, gleiche Woche = gleicher Name, Kernel, Laufzeit und Prozessliste; andere IPs
# sehen andere Geräte; alle Stellen, die Name oder Kernel zeigen, stimmen untereinander überein.
#
# Läuft wie test_cowrie_proc_self.py im Cowrie-Verzeichnis (siehe test_cowrie_install.sh).
from __future__ import annotations

import json
import os
import re
import tempfile
import time
import unittest
from types import SimpleNamespace

os.environ.setdefault("COWRIE_HONEYPOT_DATA_PATH", "data")
os.environ.setdefault("COWRIE_HONEYPOT_DOWNLOAD_PATH", tempfile.gettempdir())
os.environ.setdefault("COWRIE_SHELL_FILESYSTEM", "src/cowrie/data/fs.pickle")

from cowrie.insults import insults  # noqa: E402
from cowrie.shell import protocol  # noqa: E402
from cowrie.shell.protocol import HV_WEEK, hivornet_persona  # noqa: E402
from cowrie.test.eventcapture import CaptureSink, make_exec_transport  # noqa: E402
from cowrie.test.fake_server import FakeAvatar, FakeServer  # noqa: E402


def processes() -> list:
    from cowrie.core.resources import open_data_binary

    with open_data_binary("cmdoutput.json") as f:
        return json.load(f)["command"]["ps"]


def run(cmd: str, ip: str) -> str:
    out = bytearray()
    transport = make_exec_transport(CaptureSink())
    transport.write = out.extend
    transport.session.conn.transport.transport.getPeer = lambda: SimpleNamespace(host=ip, port=2222)
    server = FakeServer()
    server.process = processes()
    lsp = insults.LoggingServerProtocol(protocol.HoneyPotExecProtocol, FakeAvatar(server), cmd.encode())
    lsp.makeConnection(transport)
    return out.decode(errors="replace").replace("\r\n", "\n")


class PersonaTests(unittest.TestCase):
    def test_gleiche_ip_gleiches_geraet(self) -> None:
        cmd = "uname -a; hostname; cat /etc/hostname; ps auxw"
        a, b = run(cmd, "203.0.113.5"), run(cmd, "203.0.113.5")
        # PIDs der eigenen Prozesse (sshd/bash/ps) sind zufällig, der Rest muss gleich sein
        strip = lambda t: "\n".join(l for l in t.split("\n") if not re.search(r"(sshd:|-bash|ps auxw)", l))  # noqa: E731
        self.assertEqual(strip(a), strip(b))

    def test_andere_ips_andere_geraete(self) -> None:
        names = {run("hostname", f"198.51.100.{i}").strip() for i in range(1, 41)}
        kernels = {run("uname -r", f"198.51.100.{i}").strip() for i in range(1, 41)}
        self.assertGreaterEqual(len(names), 12)
        self.assertGreaterEqual(len(kernels), 4)

    def test_name_und_kernel_stimmen_ueberall_ueberein(self) -> None:
        ip = "203.0.113.77"
        host = run("hostname", ip).strip()
        self.assertEqual(run("uname -n", ip).strip(), host)
        self.assertEqual(run("cat /etc/hostname", ip).strip(), host)
        rel = run("uname -r", ip).strip()
        build = run("uname -v", ip).strip()
        ver = run("cat /proc/version", ip)
        self.assertIn(f"Linux version {rel} ", ver)
        self.assertTrue(ver.strip().endswith(build), ver)
        self.assertEqual(run("uname -a", ip).strip(), f"Linux {host} {rel} {build} x86_64 GNU/Linux")

    def test_laufzeit_ist_fest_und_waechst(self) -> None:
        ip = "203.0.113.9"
        p = hivornet_persona(ip)
        days = (time.time() - p["boot"]) / 86400
        self.assertTrue(2 <= days <= 130, days)
        up = float(run("cat /proc/uptime", ip).split()[0])
        self.assertAlmostEqual(up, time.time() - p["boot"], delta=30)

    def test_woche_bestimmt_ablauf(self) -> None:
        ip = "203.0.113.10"
        t = 40 * HV_WEEK + 12345
        self.assertEqual(hivornet_persona(ip, t), hivornet_persona(ip, t + HV_WEEK - 20000))
        later = [hivornet_persona(ip, t + k * HV_WEEK)["hostname"] for k in range(1, 6)]
        self.assertGreater(len(set(later + [hivornet_persona(ip, t)["hostname"]])), 2)

    def test_prozessliste(self) -> None:
        ip = "203.0.113.11"
        p = hivornet_persona(ip)
        text = run("ps auxw", ip)
        self.assertNotIn("VBox", text)
        self.assertNotIn("iprt", text)
        start = time.strftime("%b%d", time.gmtime(p["boot"]))
        self.assertIn(start, text)
        for _user, cmd, *_ in p["daemons"]:
            self.assertIn(cmd[:30], text)
        # VSZ in KiB wie bei ps, nicht in Byte
        for line in text.split("\n")[1:]:
            fields = line.split()
            if len(fields) > 6 and fields[4].isdigit():
                self.assertLess(int(fields[4]), 20_000_000, line)


if __name__ == "__main__":
    unittest.main()
