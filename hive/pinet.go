package main

import (
	"net"
	"os"
	"path"
	"sort"
	"strings"
)

// Verwaltungsanschluss auf dem Raspberry Pi: Ein USB-Netzwerkadapter steckt im Heimnetz,
// der eingebaute Anschluss im Gastnetz. hivornet-firewall lässt dort nur die Web-UI herein
// und meldet das in einer Statusdatei (HIVE_FIREWALL_STATUS). Die Namen sind dieselben wie
// in hivornet-firewall und in der NetworkManager-Einstellung.
var mgmtPatterns = []string{"eth[1-9]", "enx*"}

type mgmtIface struct {
	Name  string   `json:"name"`
	Up    bool     `json:"up"`
	Addrs []string `json:"addrs"`
}

type netStatus struct {
	Supported bool        `json:"supported"` // Image kennt den Verwaltungsanschluss
	Firewall  *statusFile `json:"firewall"`
	Mgmt      []mgmtIface `json:"mgmt"`
}

func isMgmtName(name string) bool {
	for _, p := range mgmtPatterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

// mgmtIfaces listet die Verwaltungsanschlüsse; listIfaces ist für Tests austauschbar.
var listIfaces = net.Interfaces

func mgmtIfaces() []mgmtIface {
	ifs, err := listIfaces()
	if err != nil {
		return nil
	}
	var out []mgmtIface
	for _, i := range ifs {
		if !isMgmtName(i.Name) {
			continue
		}
		m := mgmtIface{Name: i.Name, Up: i.Flags&net.FlagUp != 0 && i.Flags&net.FlagRunning != 0, Addrs: []string{}}
		if addrs, err := i.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
					m.Addrs = append(m.Addrs, ipn.IP.String())
				}
			}
		}
		out = append(out, m)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

// piNetStatus ist nil außerhalb des Pi-Images (Docker).
func piNetStatus() *netStatus {
	if os.Getenv("HIVE_DIRECT_PORTS") != "1" {
		return nil
	}
	p := os.Getenv("HIVE_FIREWALL_STATUS")
	return &netStatus{Supported: p != "", Firewall: readStatusFile(p), Mgmt: mgmtIfaces()}
}

// mgmtWarning liefert einen Text, wenn ein Verwaltungsanschluss verbunden, aber nicht geschützt ist.
func (n *netStatus) mgmtWarning() string {
	if n == nil {
		return ""
	}
	var up []string
	for _, m := range n.Mgmt {
		if m.Up {
			up = append(up, m.Name)
		}
	}
	if len(up) == 0 {
		return ""
	}
	names := strings.Join(up, ", ")
	switch {
	case !n.Supported:
		return "Netzwerkadapter " + names + " ist verbunden, aber dieses Image schützt keinen Verwaltungsanschluss. Bitte das aktuelle Image aufspielen oder den Adapter abziehen."
	case n.Firewall == nil || n.Firewall.State != "ok":
		text := "keine Rückmeldung"
		if n.Firewall != nil {
			text = n.Firewall.Text
		}
		return "Verwaltungsanschluss " + names + " ist verbunden, aber die Netzsperre wirkt nicht (" + text + "). Adapter abziehen und die Seite Protokolle prüfen."
	}
	return ""
}
