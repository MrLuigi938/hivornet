package main

// Eigene Netze: Verbindungen aus dem Heimnetz (Tests des Betreibers) oder aus einer
// eingetragenen Liste sind "eigene Tests". Sie werden gespeichert und bleiben auf der
// Seite Angriffe (Filter "Eigene Tests") und beim Angreifer einsehbar, zählen aber
// standardmäßig nicht in Kennzahlen, Top-Listen, Angreiferliste, "Gerade aktiv" und
// Benachrichtigungen. Einstellungen → Eigene Netze (Extras.Own).
//
// Privat heißt: RFC 1918, Loopback, Link-Local, IPv6-ULA und Carrier-Grade-NAT (100.64/10).
// Ausnahme gilt erst ab dem Speichern; ältere Zähler bleiben, wie sie sind.

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
)

type OwnNets struct {
	Private bool     `json:"private"`  // private Adressen als eigene Tests werten (Standard)
	Nets    []string `json:"nets"`     // weitere Netze oder Adressen (CIDR oder IP)
	InStats bool     `json:"in_stats"` // eigene Tests trotzdem mitzählen und melden
}

type ownMatcher struct {
	private bool
	inStats bool
	nets    []*net.IPNet
}

var ownCur atomic.Pointer[ownMatcher]

var cgnat = func() *net.IPNet { _, n, _ := net.ParseCIDR("100.64.0.0/10"); return n }()

func parseNet(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("%q ist keine IP-Adresse und kein Netz", s)
		}
		bits := 128
		if ip.To4() != nil {
			ip, bits = ip.To4(), 32
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("%q ist kein gültiges Netz (z. B. 203.0.113.0/24)", s)
	}
	return n, nil
}

func (o *OwnNets) validate() error {
	if len(o.Nets) > 50 {
		return fmt.Errorf("Eigene Netze: höchstens 50 Einträge")
	}
	var clean []string
	for _, s := range o.Nets {
		if strings.TrimSpace(s) == "" {
			continue
		}
		if _, err := parseNet(s); err != nil {
			return fmt.Errorf("Eigene Netze: %v", err)
		}
		clean = append(clean, strings.TrimSpace(s))
	}
	o.Nets = clean
	return nil
}

// setOwnNets übernimmt die Einstellung (beim Laden und Speichern der Extras).
func setOwnNets(o OwnNets) {
	m := &ownMatcher{private: o.Private, inStats: o.InStats}
	for _, s := range o.Nets {
		if n, err := parseNet(s); err == nil {
			m.nets = append(m.nets, n)
		}
	}
	ownCur.Store(m)
}

// isOwnIP: Adresse gehört zu einem eigenen Netz.
func isOwnIP(s string) bool {
	m := ownCur.Load()
	if m == nil {
		m = &ownMatcher{private: true}
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if m.private && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || cgnat.Contains(ip)) {
		return true
	}
	for _, n := range m.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ownHidden: Ereignisse dieser Adresse bleiben aus Kennzahlen und Benachrichtigungen heraus.
func ownHidden(ip string) bool {
	m := ownCur.Load()
	if m != nil && m.inStats {
		return false
	}
	return isOwnIP(ip)
}
