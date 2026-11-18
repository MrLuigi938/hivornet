package main

import (
	"strings"
	"testing"
	"time"
)

var cveExamples = map[string]string{
	"CVE-2017-9841":   "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
	"CVE-2018-20062":  `/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array`,
	"CVE-2021-44228":  "/?x=${jndi:ldap://x.example/a}",
	"CVE-2026-114938": "/rest/api/2/serverInfo\n\nAuthorization: Basic " + strings.Repeat("A", 128) + "=",
	"CVE-2018-10561":  "/GponForm/diag_Form?images/",
	"CVE-2017-17215":  "/ctrlt/DeviceUpgrade_1",
	"CVE-2014-8361":   "/picsdesc.xml",
	"CVE-2017-5638":   "/\n\nContent-Type: %{(#_='multipart/form-data')}",
	"CVE-2022-22947":  "/actuator/gateway/routes/hacktest",
	"CVE-2021-41773":  "/cgi-bin/.%2e/.%2e/.%2e/bin/sh",
	"CVE-2022-1388":   "/mgmt/tm/util/bash",
	"CVE-2023-1389":   "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id)",
	"CVE-2020-25506":  "/cgi-bin/system_mgr.cgi?cmd=cgi_get_log_item",
	"CVE-2014-6271":   "/\n\nUser-Agent: () { :; }; /bin/bash -c id",
	"CVE-2015-2051":   "/HNAP1/\n\nSOAPAction: http://purenetworks.com/HNAP1/GetDeviceSettings/`id`",
	"CVE-2021-26084":  "/pages/createpage-entervariables.action?SpaceKey=x",
	"CVE-2019-9082":   `/index.php?s=index/\think\app/invokefunction`,
}

func TestCVERules(t *testing.T) {
	for _, r := range cveRules {
		ex, ok := cveExamples[r.CVE]
		if !ok {
			t.Errorf("%s ohne Beispiel", r.CVE)
			continue
		}
		found := false
		for _, m := range eventCVEs(ex, "web") {
			found = found || m.CVE == r.CVE
		}
		if !found {
			t.Errorf("%s passt nicht auf %q", r.CVE, ex)
		}
	}
	for _, harmless := range []string{"/index.html", "/wp-login.php", "/.env", "/robots.txt"} {
		if m := eventCVEs(harmless, "web"); len(m) != 0 {
			t.Errorf("%q löst %v aus", harmless, m)
		}
	}
	// am Angriff und im Bericht
	e := evAt(time.Time{}, "request", "http", "", 80, map[string]any{"path": cveExamples["CVE-2017-17215"], "method": "POST"})
	a := attackOf(e)
	if len(a.CVEs) != 1 || a.CVEs[0].Key != "CVE-2017-17215" || len(a.Mitre) == 0 {
		t.Fatalf("Angriff: %v %v", a.CVEs, a.Mitre)
	}
	if r := BuildReport("x", []*Event{e}, false); len(r.CVEs) != 1 || r.Severity != "hoch" {
		t.Fatalf("Bericht: %v %s", r.CVEs, r.Severity)
	}
}

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
