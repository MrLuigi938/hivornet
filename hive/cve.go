package main

// Bekannte Lücken (CVE) und MITRE-ATT&CK-Techniken.
//
// cveRules erkennt in Web-Anfragen (Pfad, Body, Kopfzeilen) und Rohdaten Ausnutzungs-
// versuche bestimmter, gut dokumentierter Lücken. Aufgenommen sind nur Lücken, deren
// Anfrage eindeutig ist; ein Treffer heißt "jemand hat es versucht", nicht "das Gerät
// wäre verwundbar". Die Ergebnisse stehen am Angriff, im Bericht und in der Zähltabelle
// (Feld "cve").
//
// patternMitre ordnet die Angriffsmuster aus analyze.go Techniken aus MITRE ATT&CK
// (Enterprise) zu: https://attack.mitre.org/techniques/<ID>/

import "regexp"

type cveRule struct {
	CVE  string
	Name string
	re   *regexp.Regexp
}

func cve(id, name, expr string) cveRule {
	return cveRule{id, name, regexp.MustCompile(`(?i)` + expr)}
}

var cveRules = []cveRule{
	cve("CVE-2017-9841", "PHPUnit eval-stdin.php", `phpunit/.*eval-stdin\.php`),
	cve("CVE-2018-20062", "ThinkPHP invokefunction", `think\\+app/invokefunction|s=/index/\\+think`),
	cve("CVE-2021-44228", "Log4Shell (Apache Log4j)", `\$\{jndi:`),
	cve("CVE-2026-114938", "Java4Shell (OpenJDK Base64)", java4shellExpr),
	cve("CVE-2018-10561", "GPON-Router: Umgehung der Anmeldung", `/GponForm/diag_Form\?images/`),
	cve("CVE-2017-17215", "Huawei HG532: Befehlsausführung", `/ctrlt/DeviceUpgrade`),
	cve("CVE-2014-8361", "Realtek SDK miniigd (UPnP)", `/picsdesc\.xml|NewInternalClient`),
	cve("CVE-2017-5638", "Apache Struts: Content-Type-Injektion", `Content-Type:[^\n]*%\{\(#`),
	cve("CVE-2022-22947", "Spring Cloud Gateway", `/actuator/gateway/routes`),
	cve("CVE-2021-41773", "Apache 2.4.49: Pfad-Traversal", `/cgi-bin/(\.%2e|%2e%2e|\.\.%2f|\.%%32%65)`),
	cve("CVE-2022-1388", "F5 BIG-IP iControl REST", `/mgmt/tm/util/bash`),
	cve("CVE-2023-1389", "TP-Link Archer: Befehlsausführung", `/cgi-bin/luci/;stok=/locale\?form=country`),
	cve("CVE-2020-25506", "D-Link DNS-320: Befehlsausführung", `/cgi-bin/system_mgr\.cgi`),
	cve("CVE-2014-6271", "Shellshock (Bash)", `\(\)\s*\{\s*:?\s*;\s*\}\s*;`),
	cve("CVE-2015-2051", "D-Link HNAP: Befehlsausführung", `/HNAP1/?[^\n]*GetDeviceSettings|SOAPAction:[^\n]*GetDeviceSettings`),
	cve("CVE-2021-26084", "Confluence OGNL-Injektion", `/pages/(createpage-entervariables|doenterpagevariables)\.action`),
	cve("CVE-2019-9082", "ThinkPHP 5.0.x Befehlsausführung", `index\.php\?s=/?index/\\+think\\+(app|container)`),
}

// eventCVEs: erkannte Lücken eines Ereignisses (Web-Anfragen und Rohdaten); über den
// Zwischenspeicher (analysiscache.go).
func eventCVEs(text, on string) []cveRule {
	if text == "" || on != "web" && on != "raw" {
		return nil
	}
	return analyzeText(text, on).cves
}

func matchCVEs(text, on string) []cveRule {
	if text == "" || on != "web" && on != "raw" {
		return nil
	}
	var out []cveRule
	for _, r := range cveRules {
		if r.re.MatchString(text) {
			out = append(out, r)
		}
	}
	return out
}

var cveByID = func() map[string]cveRule {
	m := map[string]cveRule{}
	for _, r := range cveRules {
		m[r.CVE] = r
	}
	return m
}()

var patternMitre = map[string][]string{
	"download_exec":    {"T1105", "T1059.004"},
	"miner":            {"T1496"},
	"iot_botnet":       {"T1105", "T1059.004"},
	"persist_ssh":      {"T1098.004"},
	"persist_cron":     {"T1053.003"},
	"docker_escape":    {"T1610", "T1611"},
	"redis_takeover":   {"T1190", "T1053.003"},
	"account":          {"T1136.001", "T1098"},
	"cover_tracks":     {"T1070.003", "T1070.002"},
	"kill_rivals":      {"T1489"},
	"obfuscation":      {"T1027", "T1140"},
	"recon":            {"T1082", "T1033"},
	"honeypot_check":   {"T1497.001"},
	"prompt_injection": {"AML.T0051"},
	"data_theft":       {"T1552.001", "T1005"},
	"log4shell":        {"T1190"},
	"java4shell":       {"T1190"},
	"web_rce":          {"T1190"},
	"secret_hunt":      {"T1595.003"},
	"iot_exploit":      {"T1190"},
	"traversal":        {"T1190", "T1083"},
	"sqli":             {"T1190"},
	"cms_login":        {"T1110"},
	"api_probe":        {"T1595"},
	"bait_used":        {"T1078"},
	"tls_on_plain":     {"T1595"},
	"smb_probe":        {"T1595"},
	"http_on_raw":      {"T1595"},
}

// mitreNames: Namen der Techniken (für Anzeige und Bericht).
var mitreNames = map[string]string{
	"T1105": "Ingress Tool Transfer", "T1059.004": "Unix Shell", "T1496": "Resource Hijacking",
	"T1098.004": "SSH Authorized Keys", "T1053.003": "Cron", "T1610": "Deploy Container", "T1611": "Escape to Host",
	"T1190": "Exploit Public-Facing Application", "T1136.001": "Create Local Account", "T1098": "Account Manipulation",
	"T1070.003": "Clear Command History", "T1070.002": "Clear Linux or Mac System Logs", "T1489": "Service Stop",
	"T1027": "Obfuscated Files or Information", "T1140": "Deobfuscate/Decode Files or Information",
	"T1082": "System Information Discovery", "T1033": "System Owner/User Discovery", "T1552.001": "Credentials In Files",
	"T1005": "Data from Local System", "T1595.003": "Wordlist Scanning", "T1083": "File and Directory Discovery",
	"T1497.001": "System Checks", "AML.T0051": "LLM Prompt Injection (MITRE ATLAS)", "T1110": "Brute Force", "T1595": "Active Scanning", "T1078": "Valid Accounts",
}
