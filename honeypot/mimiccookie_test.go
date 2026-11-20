package main

import "testing"

// Cookies aus Modell-Antworten: nie der Sitzungs-Cookie der Hive-UI (Cookies trennen nicht nach
// Port), keine Domain-Angabe, kein __Host-/__Secure-Präfix.
func TestMimicHeadersCookie(t *testing.T) {
	out := mimicHeaders(map[string]string{"Set-Cookie": "JSESSIONID=AB12; Domain=example.org; Path=/x", "X-Powered-By": "PHP/8.1"})
	if out["Set-Cookie"] != "JSESSIONID=AB12; Path=/; HttpOnly" || out["X-Powered-By"] != "PHP/8.1" {
		t.Fatalf("Kopfzeilen: %v", out)
	}
	for _, in := range []string{"hv_session=x; Path=/api", "Hv_Session=x", "__Host-a=1", "__secure-a=1", "a=1,2", "kein"} {
		if got := mimicHeaders(map[string]string{"set-cookie": in}); got["Set-Cookie"] != "" {
			t.Errorf("%q durchgelassen: %q", in, got["Set-Cookie"])
		}
	}
}
