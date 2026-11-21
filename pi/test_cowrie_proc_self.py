# Prüft, dass Cowrie (mit den Änderungen aus hivornet-cowrie-install) die Prüfreihe der Bots
# so beantwortet wie eine echte Shell. Die Reihe, mit der Bots nach dem Login testen, ob sie in
# einem Honeypot sind (Marker "check_<hex>_…", Rechnen mit $((…)), $$, Subshell, Quoting,
# set --, Funktion, exit 37, Lesen von /proc/self/stat und /proc/self/status), läuft als
# SSH-Exec-Befehl durch Cowrie und, wo es eine gibt, durch /bin/sh. Ausgabe und Exit-Code müssen
# gleich sein; nur Prozessnummern dürfen abweichen (sie müssen aber untereinander stimmen).
#
# Läuft im Cowrie-Verzeichnis mit der Python-Umgebung von Cowrie, siehe test_cowrie_install.sh:
#   cd /opt/hivornet/cowrie && PYTHONPATH=src /opt/hivornet/cowrie-env/bin/python -m unittest -v /pfad/zu/test_cowrie_proc_self.py
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
import uuid

os.environ.setdefault("COWRIE_HONEYPOT_DATA_PATH", "data")
os.environ.setdefault("COWRIE_HONEYPOT_DOWNLOAD_PATH", tempfile.gettempdir())
os.environ.setdefault("COWRIE_SHELL_FILESYSTEM", "src/cowrie/data/fs.pickle")

from cowrie.insults import insults  # noqa: E402
from cowrie.shell import protocol  # noqa: E402
from cowrie.test.eventcapture import CaptureSink, make_exec_transport  # noqa: E402
from cowrie.test.fake_server import FakeAvatar, FakeServer  # noqa: E402

SQ = "'\"'\"'"  # ein einfaches Anführungszeichen innerhalb von sh -c '…'


def wrap(cmd: str) -> str:
    """Wie die Bots: dieselbe Zeile noch einmal als sh -c '…'."""
    return "sh -c '" + cmd.replace("'", SQ) + "'"


def run_cowrie(cmd: str) -> tuple[str, int]:
    out = bytearray()
    done: dict[str, int] = {}

    def ended(reason: object = None) -> None:
        value = getattr(reason, "value", None)
        done["code"] = getattr(value, "exitCode", 0) if value is not None else 0

    transport = make_exec_transport(CaptureSink(), processEnded=ended)
    transport.write = out.extend
    lsp = insults.LoggingServerProtocol(protocol.HoneyPotExecProtocol, FakeAvatar(FakeServer()), cmd.encode())
    lsp.makeConnection(transport)
    return out.decode(errors="replace").replace("\r\n", "\n"), done.get("code", 0)


def run_real(sh: str, cmd: str) -> tuple[str, int]:
    p = subprocess.run([sh, "-c", cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=20)
    return p.stdout.decode(errors="replace").replace("\r\n", "\n"), p.returncode


STAT_LINE = re.compile(r"^(check_\w+)\|(\d+)\|(\d+)\|42\|\t(\d+)\|(NA|\t?\d+)\|1$")
PID_LINE = re.compile(r"^(check_\w+_small_pid)\|(\d+)$")


def normalize(out: str) -> str:
    """Prozessnummern durch <PID> ersetzen; vorher prüfen, dass zusammengehörige gleich sind."""
    lines = []
    for line in out.split("\n"):
        if m := STAT_LINE.match(line):
            if not (m.group(2) == m.group(3) == m.group(4)):
                raise AssertionError(f"$$, /proc/self/stat und Pid stimmen nicht überein: {line!r}")
            ns = m.group(5).strip()
            if ns != "NA" and ns != m.group(2):
                raise AssertionError(f"NSpid weicht von Pid ab: {line!r}")
            line = f"{m.group(1)}|<PID>|<PID>|42|\t<PID>|<NS>|1"
        elif m := PID_LINE.match(line):
            line = f"{m.group(1)}|<PID>"
        lines.append(line)
    return "\n".join(lines)


def series() -> list[str]:
    """Die Prüfreihe, nachgebaut aus beobachteten Sitzungen (Marker zufällig)."""
    cmds: list[str] = []
    for _ in range(2):
        i = uuid.uuid4().hex
        base = [
            f"printf '\\n%s|%s\\n' 'check_{i}_small_control' 'check_{i}'",
            f"printf '\\n%s|%s\\n' 'check_{i}_small_math' \"$((573*264+18))\"",
            f"printf '\\n%s|%s\\n' 'check_{i}_small_pid' \"$$\"",
            f"set -- 'check_{i}_arg1' 'check_{i}_arg2'; printf '\\n%s|%s\\n' 'check_{i}_small_positional' \"$#|$1|$2\"",
            f"f_check_{i}() {{ printf '\\n%s|%s\\n' 'check_{i}_small_function' \"$1|$#\"; }}; f_check_{i} 'check_{i}_function_value'",
            f"printf '\\n%s\\n' 'check_{i}_small_done'",
        ]
        for c in base:
            cmds += [wrap(c), c]
    cmds.append(f"echo; echo 'check_{uuid.uuid4().hex}_transport_done'")
    p = f"check_{uuid.uuid4().hex}"
    stat = (
        "if IFS=' ' read -r _filter_pid _filter_rest < /proc/self/stat; then _filter_status_pid=NA; _filter_ns=NA; _filter_status_ok=0; "
        "if [ -r /proc/self/status ]; then _filter_status_ok=1; while IFS=: read -r _filter_key _filter_values; do "
        'case "$_filter_key" in Pid) _filter_status_pid=$_filter_values;; NSpid) _filter_ns=$_filter_values;; esac; done < /proc/self/status; fi; '
        f"printf '%s|%s|%s|%s|%s|%s|%s\\n' '{p}' \"$$\" \"$_filter_pid\" \"$((6*7))\" \"$_filter_status_pid\" \"$_filter_ns\" \"$_filter_status_ok\"; "
        f"else printf '%s\\n' '{p}:NA'; fi"
    )
    cmds += [stat, wrap(stat)]
    cmds += [
        f"value=$((19+23)); if [ \"$value\" -eq 42 ]; then printf '%s\\n' '{p}' \"$value\" 'branch-ok'; else exit 9; fi",
        f"printf '%s\\n' '{p}' | while IFS= read -r line; do printf 'pipe=%s\\n' \"$line\"; done",
        "v=outer; (v=inner; printf 'child=%s\\n' \"$v\"); printf 'parent=%s\\n' \"$v\"",
        "printf '%s\\n' 'a b;$()'",
        f"set -- '{p}' 'second value'; printf '%s|%s|%s\\n' \"$#\" \"$1\" \"$2\"",
        f"f_{p}() {{ printf 'arg=%s|count=%s\\n' \"$1\" \"$#\"; }}; f_{p} '{p}'; printf '%s\\n' '{p}'",
        f"printf '%s\\n' '{p}' >&2; exit 37",
        f"echo; echo 'check_{uuid.uuid4().hex}_transport_done'",
    ]
    return cmds


class ProcSelfTests(unittest.TestCase):
    def test_proc_self_stat_und_status(self) -> None:
        out, _ = run_cowrie("read -r a b < /proc/self/stat; echo \"$a|$$\"")
        pid, shell_pid = out.strip().split("|")
        self.assertEqual(pid, shell_pid)
        out, _ = run_cowrie("while IFS=: read -r k v; do case \"$k\" in Pid|NSpid) echo \"$k=$v\";; esac; done < /proc/self/status")
        self.assertRegex(out, r"Pid=\t\d+\nNSpid=\t\d+\n")

    def test_proc_self_stat_felder(self) -> None:
        out, _ = run_cowrie("cat /proc/self/stat")
        fields = out.strip().split(" ")
        self.assertGreaterEqual(len(fields), 50)
        self.assertEqual(fields[1], "(bash)")

    def test_pruefreihe_wie_echte_shell(self) -> None:
        sh = shutil.which("sh")
        if sh is None:
            self.skipTest("keine /bin/sh zum Vergleichen")
        for cmd in series():
            with self.subTest(cmd=cmd[:100]):
                want_out, want_code = run_real(sh, cmd)
                got_out, got_code = run_cowrie(cmd)
                self.assertEqual(normalize(got_out), normalize(want_out))
                self.assertEqual(got_code, want_code)


if __name__ == "__main__":
    unittest.main()
