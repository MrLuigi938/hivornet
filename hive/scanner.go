package main

// Forschungsscanner: Dienste wie Shodan, Censys oder Shadowserver tasten das ganze
// Internet ab, um es zu vermessen. Sie sind kein Angriff im eigentlichen Sinn; Angriffe
// tragen dann ein Kennzeichen, und die Meldung an AbuseIPDB lässt sie standardmäßig aus.
//
// Erkannt wird am Netzbetreiber (AS-Name aus GeoIP) und am User-Agent. Die Liste ist
// bewusst kurz und enthält nur Betreiber, die sich selbst als Forschungs- oder
// Vermessungsdienst ausweisen.

import (
	"regexp"
	"strings"
)

type scannerRule struct {
	Name string
	re   *regexp.Regexp
}

var researchScanners = []scannerRule{
	{"Shodan", regexp.MustCompile(`(?i)shodan`)},
	{"Censys", regexp.MustCompile(`(?i)censys`)},
	{"Shadowserver", regexp.MustCompile(`(?i)shadowserver`)},
	{"BinaryEdge", regexp.MustCompile(`(?i)binaryedge`)},
	{"Rapid7 Sonar", regexp.MustCompile(`(?i)rapid7|project sonar`)},
	{"Stretchoid", regexp.MustCompile(`(?i)stretchoid`)},
	{"Internet Measurement", regexp.MustCompile(`(?i)internet-?measurement|internetmeasurement`)},
	{"Driftnet", regexp.MustCompile(`(?i)driftnet`)},
	{"ONYPHE", regexp.MustCompile(`(?i)onyphe`)},
	{"LeakIX", regexp.MustCompile(`(?i)leakix|l9explore|l9tcpid`)},
	{"Criminal IP", regexp.MustCompile(`(?i)criminal ?ip|ai spera`)},
	{"Palo Alto Cortex Xpanse", regexp.MustCompile(`(?i)xpanse|expanse,? inc`)},
	{"Alpha Strike Labs", regexp.MustCompile(`(?i)alpha ?strike`)},
	{"Recyber", regexp.MustCompile(`(?i)recyber`)},
	{"Academy for Internet Research", regexp.MustCompile(`(?i)internet research`)},
	{"BitSight", regexp.MustCompile(`(?i)bitsight`)},
	{"Netcraft", regexp.MustCompile(`(?i)netcraft`)},
	{"ipip.net", regexp.MustCompile(`(?i)ipip\.net`)},
	{"ModatScanner", regexp.MustCompile(`(?i)modat`)},
}

// researchScanner liefert den Namen des Dienstes, wenn AS-Name oder ein User-Agent passt.
func researchScanner(asOrg string, userAgents ...string) string {
	text := asOrg + "\n" + strings.Join(userAgents, "\n")
	for _, r := range researchScanners {
		if r.re.MatchString(text) {
			return r.Name
		}
	}
	return ""
}
