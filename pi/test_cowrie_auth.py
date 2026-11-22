# Prüft die Cowrie-Anpassung "Fremdprotokoll" (siehe hivornet-cowrie-install): HTTP-Anfrage- und
# Kopfzeilen, die ein Web-Scanner an Telnet schickt, nimmt AuthRandom nie als Login an; echte
# Zugangsdaten kommen weiterhin nach einigen Versuchen durch.
#
# Läuft wie test_cowrie_proc_self.py im Cowrie-Verzeichnis (siehe test_cowrie_install.sh).
from __future__ import annotations

import os
import tempfile
import unittest

os.environ.setdefault("COWRIE_HONEYPOT_STATE_PATH", tempfile.mkdtemp())
os.environ.setdefault("COWRIE_HONEYPOT_AUTH_CLASS_PARAMETERS", "2, 5, 10")

from cowrie.core.auth import AuthRandom  # noqa: E402


class FremdprotokollTests(unittest.TestCase):
    def test_http_zeilen_nie_angenommen(self) -> None:
        auth = AuthRandom()
        zeilen = [
            (b"GET / HTTP/1.1", b"Host: 203.0.113.1:23"),
            (b"User-Agent: Mozilla/5.0 (X11; Linux x86_64)", b"Accept: */*"),
            (b"Accept-Encoding: gzip", b"Connection: close"),
            (b"POST /cgi-bin/x HTTP/1.0", b"Content-Length: 0"),
        ]
        for i in range(20):
            user, pw = zeilen[i % len(zeilen)]
            self.assertFalse(auth.checklogin(user, pw + str(i).encode(), "203.0.113.5"), user)

    def test_echte_zugangsdaten_weiter_moeglich(self) -> None:
        auth = AuthRandom()
        ok = [auth.checklogin(f"root{i}".encode(), b"admin", "203.0.113.6") for i in range(12)]
        self.assertTrue(any(ok))
        # Benutzer mit Doppelpunkt mitten im Namen bleiben normale Versuche
        self.assertIsInstance(auth.checklogin(b"a:b", b"x", "203.0.113.7"), bool)


if __name__ == "__main__":
    unittest.main()
