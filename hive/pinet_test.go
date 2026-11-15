package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMgmtNames(t *testing.T) {
	for name, want := range map[string]bool{
		"eth0": false, "eth1": true, "eth9": true, "eth10": false, "enx00e04c680001": true,
		"wlan0": false, "lo": false, "end0": false, "docker0": false,
	} {
		if got := isMgmtName(name); got != want {
			t.Errorf("isMgmtName(%q) = %v, erwartet %v", name, got, want)
		}
	}
}

func TestPiNetStatus(t *testing.T) {
	old := listIfaces
	t.Cleanup(func() { listIfaces = old })
	up := net.FlagUp | net.FlagRunning
	listIfaces = func() ([]net.Interface, error) {
		return []net.Interface{{Name: "lo", Flags: up}, {Name: "eth0", Flags: up}, {Name: "eth1", Flags: up}}, nil
	}

	t.Setenv("HIVE_DIRECT_PORTS", "")
	if piNetStatus() != nil {
		t.Fatal("ohne HIVE_DIRECT_PORTS (Docker) darf es keinen Netzwerkstatus geben")
	}

	t.Setenv("HIVE_DIRECT_PORTS", "1")
	t.Setenv("HIVE_FIREWALL_STATUS", "")
	n := piNetStatus()
	if n == nil || len(n.Mgmt) != 1 || n.Mgmt[0].Name != "eth1" || !n.Mgmt[0].Up {
		t.Fatalf("Verwaltungsanschluss nicht erkannt: %+v", n)
	}
	if w := n.mgmtWarning(); !strings.Contains(w, "aktuelle Image") {
		t.Errorf("altes Image ohne Schutz: Warnung fehlt (%q)", w)
	}

	p := filepath.Join(t.TempDir(), "firewall")
	t.Setenv("HIVE_FIREWALL_STATUS", p)
	if w := piNetStatus().mgmtWarning(); !strings.Contains(w, "keine Rückmeldung") {
		t.Errorf("ohne Statusdatei: %q", w)
	}
	os.WriteFile(p, []byte("failed\n1700000000\nweder nft noch iptables vorhanden\n"), 0o644)
	if w := piNetStatus().mgmtWarning(); !strings.Contains(w, "weder nft") {
		t.Errorf("gescheiterte Sperre: %q", w)
	}
	os.WriteFile(p, []byte("ok\n1700000000\nnftables\n"), 0o644)
	if w := piNetStatus().mgmtWarning(); w != "" {
		t.Errorf("Sperre wirkt, trotzdem Warnung: %q", w)
	}

	// Adapter nicht verbunden: keine Warnung, auch ohne Schutz
	listIfaces = func() ([]net.Interface, error) {
		return []net.Interface{{Name: "eth0", Flags: up}, {Name: "eth1", Flags: net.FlagUp}}, nil
	}
	t.Setenv("HIVE_FIREWALL_STATUS", "")
	if w := piNetStatus().mgmtWarning(); w != "" {
		t.Errorf("Adapter ohne Verbindung: %q", w)
	}
}
