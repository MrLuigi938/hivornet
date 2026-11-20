package main

import (
	"strings"
	"testing"
)

func TestEveryPatternHasMitre(t *testing.T) {
	for _, p := range patterns {
		ids := patternMitre[p.ID]
		if len(ids) == 0 {
			t.Errorf("Muster %s ohne MITRE-Zuordnung", p.ID)
		}
		for _, id := range ids {
			if mitreNames[id] == "" {
				t.Errorf("Technik %s ohne Namen", id)
			}
		}
	}
}

// Java4Shell (CVE-2026-114938): volle 64er-Blöcke Base64 mit angehängtem "=". Gültiges Base64 und
// gewöhnliche Anfragen dürfen die Regel nicht auslösen.
func TestJava4Shell(t *testing.T) {
	a64 := strings.Repeat("A", 64)
	mixed := strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5YWJjZGVmZ2hpamts", 2) // 128 Zeichen
	hit := func(s string) bool {
		for _, m := range eventCVEs(s, "web") {
			if m.CVE == "CVE-2026-114938" {
				return contains(matchPatterns(s, "web"), "java4shell")
			}
		}
		return false
	}
	for _, s := range []string{
		"/\n\nAuthorization: Basic " + a64 + "=",
		"/\n\nAuthorization: Basic " + a64 + a64 + "=\nUser-Agent: x",
		"/\n\nAuthorization: Bearer " + mixed + "==",
		"/login?token=" + a64 + "%3D&x=1",
		"/api\n{\"saml\":\"" + mixed + "=\"}\n",
		"/\n\nCookie: JSESSIONID=" + a64 + "=; a=b",
	} {
		if !hit(s) {
			t.Errorf("nicht erkannt: %q", s)
		}
	}
	hex64 := strings.Repeat("0123456789abcdef", 4)
	for _, s := range []string{
		"/\n\nAuthorization: Basic YWRtaW46YWRtaW4=",                              // admin:admin
		"/\n\nAuthorization: Basic " + strings.Repeat("A", 62) + "==",             // gültig: 64 Zeichen mit Füllung
		"/\n\nAuthorization: Basic " + strings.Repeat("A", 63) + "=",              // gültig
		"/\n\nAuthorization: Bearer " + a64,                                       // gültig, ohne Füllung
		"/\n\nAuthorization: Basic " + strings.Repeat("A", 131) + "=",             // gültig: 132 Zeichen
		"/dl?sha256=" + hex64 + "&x=1",                                            // Prüfsumme als Wert
		"/\n\nCookie: session=" + hex64 + "; theme=dark",                          // Sitzungskennung
		"/\n" + strings.Repeat("A", 64) + "\n" + strings.Repeat("A", 62) + "==\n", // PEM-artig umbrochen
		"/a?" + hex64 + "=wert",                                                   // langer Parametername mit Wert
	} {
		if hit(s) || contains(matchPatterns(s, "web"), "java4shell") {
			t.Errorf("fälschlich erkannt: %q", s)
		}
	}
}
