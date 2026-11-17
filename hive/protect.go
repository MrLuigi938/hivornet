package main

// Schutz für alles, was aus Angreiferdaten nach außen wirkt (Blockliste zum Abonnieren,
// automatische Meldung an AbuseIPDB). Ereignisse kommen von Sensoren; ein übernommener
// Honeypot oder ein entfernter Sensor könnte beliebige src_ip-Werte schicken und so
// fremde Adressen sperren oder melden lassen. Deshalb:
//   - Sensoren mit eigenem Token speisen beides nur, wenn der Admin ihnen vertraut;
//   - wichtige Infrastruktur (öffentliche DNS-Resolver) und eine eigene Liste "Nie sperren"
//     sind immer ausgenommen;
//   - die Blockliste nimmt je Stunde nur begrenzt viele neue Adressen auf (feed.go).

import (
	"net"
	"strings"
)

// builtinProtected: öffentliche DNS-Resolver. Fällt einer davon aus, steht das ganze Netz.
var builtinProtected = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{
		"1.1.1.0/24", "1.0.0.0/24", "8.8.8.0/24", "8.8.4.0/24", "9.9.9.0/24", "149.112.112.0/24",
		"208.67.222.0/24", "208.67.220.0/24", "94.140.14.0/24", "94.140.15.0/24", "76.76.2.0/24", "76.76.10.0/24",
		"2606:4700:4700::/48", "2001:4860:4860::/48", "2620:fe::/48", "2620:119:35::/48", "2620:119:53::/48", "2a10:50c0::/32",
	} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// parseNets liest Adressen und Netze (eine je Eintrag); ungültige werden gemeldet.
func parseNets(list []string) ([]*net.IPNet, []string) {
	var out []*net.IPNet
	var bad []string
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				if ip.To4() != nil {
					s += "/32"
				} else {
					s += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		} else {
			bad = append(bad, s)
		}
	}
	return out, bad
}

// neverBlock: Adresse ist geschützt (eingebaut oder Liste "Nie sperren" der Blockliste).
func (h *Hive) neverBlock(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return true
	}
	for _, n := range builtinProtected {
		if n.Contains(p) {
			return true
		}
	}
	nets, _ := parseNets(h.feedConfig().NeverBlock)
	for _, n := range nets {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

// untrustedSensors: Namen der Sensoren mit eigenem Token, denen der Admin (noch) nicht vertraut.
func (h *Hive) untrustedSensors() map[string]bool {
	out := map[string]bool{}
	if h.auth == nil {
		return out
	}
	a := h.auth
	a.tokens.mu.Lock()
	defer a.tokens.mu.Unlock()
	a.loadSensorTokens()
	for name, t := range a.tokens.m {
		if !t.Trusted {
			out[name] = true
		}
	}
	return out
}

// trustedAttack: mindestens ein meldender Sensor ist vertrauenswürdig.
func trustedAttack(a *Attack, untrusted map[string]bool) bool {
	if len(a.Sensors) == 0 || len(untrusted) == 0 {
		return true
	}
	for _, s := range a.Sensors {
		if !untrusted[s] {
			return true
		}
	}
	return false
}
