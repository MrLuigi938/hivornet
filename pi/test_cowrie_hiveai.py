# Prüft das Modell für Unbekanntes in Cowrie (hivornet_ai.py): Verlauf, Zustandsregister, Mindestdauer,
# Grenzen und der Rückfall auf "command not found". Der Hive ist nachgebaut (HiveAI.post), die Uhr
# ist ein task.Clock; es gibt kein Netz. Läuft wie test_cowrie_persona.py im Cowrie-Verzeichnis.
from __future__ import annotations

import os
import tempfile
import unittest
from types import SimpleNamespace

from twisted.internet import defer, task

os.environ.setdefault("COWRIE_HONEYPOT_DATA_PATH", "data")
os.environ.setdefault("COWRIE_HONEYPOT_DOWNLOAD_PATH", tempfile.gettempdir())
os.environ.setdefault("COWRIE_SHELL_FILESYSTEM", "src/cowrie/data/fs.pickle")

from cowrie.insults import insults  # noqa: E402
from cowrie.shell import hivornet_ai, protocol  # noqa: E402
from cowrie.test.eventcapture import CaptureSink, make_exec_transport  # noqa: E402
from cowrie.test.fake_server import FakeAvatar, FakeServer  # noqa: E402


class Session:
    """Eine Exec-Sitzung mit nachgebautem Hive."""

    def __init__(self, token: bool = True, answers: list | None = None, max_calls: int | None = None) -> None:
        self.sent: list[dict] = []
        self.answers = answers if answers is not None else []
        self.clock = task.Clock()
        self.token = token
        self.max_calls = max_calls
        self.out = bytearray()
        self.code: int | None = None

    def run(self, cmd: str) -> str:
        self.out = bytearray()
        transport = make_exec_transport(CaptureSink(), processEnded=self._ended)
        transport.write = self.out.extend
        transport.session.conn.transport.transport.getPeer = lambda: SimpleNamespace(host="203.0.113.5", port=2222)
        lsp = insults.LoggingServerProtocol(protocol.HoneyPotExecProtocol, FakeAvatar(FakeServer()), cmd.encode())
        orig_init = hivornet_ai.HiveAI.__init__
        sess = self

        def init(ai, proto):  # type: ignore[no-untyped-def]
            orig_init(ai, proto)
            if sess.max_calls is not None:
                ai.max_calls = sess.max_calls
            ai.token = lambda: "t" * 64 if sess.token else ""
            ai.post = lambda body, _tok: sess._post(body)
            sess.ai = ai

        hivornet_ai.HiveAI.__init__ = init  # type: ignore[method-assign]
        hivornet_ai.clock = self.clock
        try:
            lsp.makeConnection(transport)
            for _ in range(8):  # über die Mindestdauer jedes Befehls hinaus
                self.clock.advance(3)
        finally:
            hivornet_ai.HiveAI.__init__ = orig_init  # type: ignore[method-assign]
        return bytes(self.out).decode(errors="replace").replace("\r\n", "\n")

    def _ended(self, reason: object = None) -> None:
        value = getattr(reason, "value", None)
        self.code = getattr(value, "exitCode", 0) if value is not None else 0

    def _post(self, body: dict) -> defer.Deferred:
        self.sent.append(body)
        ans = self.answers.pop(0) if self.answers else None
        return defer.succeed(ans)


class HiveAITests(unittest.TestCase):
    def test_ohne_token_wie_bisher(self) -> None:
        s = Session(token=False)
        out = s.run("hvctl status")
        self.assertEqual(out, "bash: line 1: hvctl: command not found\n")
        self.assertEqual(s.sent, [])
        self.assertEqual(s.code, 127)

    def test_antwort_des_modells(self) -> None:
        s = Session(answers=[{"out": "hvctl 2.4.1 ready\n"}])
        out = s.run("hvctl status")
        self.assertEqual(out, "hvctl 2.4.1 ready\n")
        self.assertEqual(s.code, 0)
        req = s.sent[0]
        self.assertEqual((req["kind"], req["input"], req["service"]), ("shell", "hvctl status", "ssh"))
        self.assertEqual(req["ip"], "203.0.113.5")
        self.assertTrue(req["host"] and req["kernel"].startswith("6.1.0-"))
        self.assertEqual(req["reg"]["user"], "root")

    def test_fehler_und_zeitueberschreitung_geben_command_not_found(self) -> None:
        for ans in (None, "kein dict", {"nein": 1}):
            s = Session(answers=[ans])
            out = s.run("hvctl status")
            self.assertEqual(out, "bash: line 1: hvctl: command not found\n", ans)
            self.assertEqual(s.code, 127)

    def test_mindestdauer(self) -> None:
        s = Session(answers=[{"out": "ok\n"}])
        # ohne Uhr-Vorlauf darf nach 0 Sekunden noch nichts da sein
        s.clock.advance = lambda _t: None  # type: ignore[method-assign]
        out = s.run("hvctl status")
        self.assertEqual(out, "")
        self.assertIsNone(s.code)
        for _ in range(3):  # die Mindestdauer liegt zwischen 0,9 und 2,8 s
            task.Clock.advance(s.clock, 1)
        self.assertEqual(bytes(s.out).decode().replace("\r\n", "\n"), "ok\n")
        self.assertEqual(s.code, 0)

    def test_steuerzeichen_werden_entfernt(self) -> None:
        s = Session(answers=[{"out": "a\x1b[31mb\x07c\n"}])
        self.assertEqual(s.run("hvctl x"), "a[31mbc\n")

    def test_verlauf_und_register(self) -> None:
        first = Session(answers=[{"out": "Setting up nginx ...\n", "delta": {"pkgs_add": ["nginx"], "services": ["nginx:active"], "impact": 3}}])
        # Verlauf und Register gelten für die Sitzung: zwei Befehle in einer Exec-Zeile
        out = first.run("id; hvapt install nginx; hvapt list")
        self.assertIn("Setting up nginx", out)
        self.assertEqual(len(first.sent), 2)
        second = first.sent[1]
        self.assertEqual([h["cmd"] for h in second["history"]], ["id", "hvapt install nginx"])
        self.assertEqual(second["history"][1]["out"], "Setting up nginx ...\n")
        self.assertEqual(second["history"][1]["impact"], 3)
        self.assertEqual(second["reg"]["pkgs"], ["nginx"])
        self.assertEqual(second["reg"]["services"], ["nginx:active"])

    def test_register_aendern_und_begrenzen(self) -> None:
        ai = hivornet_ai.HiveAI.__new__(hivornet_ai.HiveAI)
        ai.reg = {"files": [], "gone": [], "pkgs": [], "services": [], "users": [], "vars": []}
        entry = {"impact": 0}
        ai.apply_delta({"files_add": ["/tmp/a", "/tmp/b"], "services": ["nginx:active"], "impact": 2}, entry)
        ai.apply_delta({"files_del": ["/tmp/a"], "services": ["nginx:stopped"], "impact": 99}, entry)
        self.assertEqual(ai.reg["files"], ["/tmp/b"])
        self.assertEqual(ai.reg["gone"], ["/tmp/a"])
        self.assertEqual(ai.reg["services"], ["nginx:stopped"])
        self.assertEqual(entry["impact"], 4)
        ai.apply_delta({"pkgs_add": [f"p{i}" for i in range(40)]}, entry)
        self.assertEqual(len(ai.reg["pkgs"]), hivornet_ai.REG_ITEMS)
        self.assertEqual(ai.reg["pkgs"][-1], "p39")
        ai.apply_delta("kein dict", entry)  # darf nicht werfen

    def test_grenze_je_sitzung(self) -> None:
        s = Session(answers=[{"out": "1\n"}, {"out": "2\n"}, {"out": "3\n"}], max_calls=2)
        out = s.run("hv1; hv2; hv3")
        self.assertEqual(len(s.sent), 2)
        self.assertEqual(out, "1\n2\nbash: line 1: hv3: command not found\n")

    def test_pfade_und_bekannte_befehle_gehen_nicht_zum_hive(self) -> None:
        s = Session(answers=[{"out": "x\n"}])
        out = s.run("./nope; /usr/bin/nope; echo hallo; uname -n >/dev/null")
        self.assertEqual(s.sent, [])
        self.assertIn("hallo", out)


if __name__ == "__main__":
    unittest.main()
