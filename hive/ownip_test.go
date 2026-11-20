package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// ipifyStub: liefert nacheinander die angegebenen Adressen; "" = Fehler.
func ipifyStub(t *testing.T, addrs *[]string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(*addrs) == 0 || (*addrs)[0] == "" {
			if len(*addrs) > 0 {
				*addrs = (*addrs)[1:]
			}
			http.Error(w, "nein", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintf(w, `{"ip":%q}`, (*addrs)[0])
		*addrs = (*addrs)[1:]
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestOwnIPRefresh(t *testing.T) {
	h := testHive(t)
	v4 := []string{"203.0.113.10", "203.0.113.20", ""}
	v6 := []string{"2001:db8::1", "", ""}
	s4, s6 := ipifyStub(t, &v4), ipifyStub(t, &v6)
	o4, o6 := ownIPv4URL, ownIPv6URL
	ownIPv4URL, ownIPv6URL = s4.URL, s6.URL
	t.Cleanup(func() { ownIPv4URL, ownIPv6URL = o4, o6 })
	ctx := context.Background()

	s, err := h.refreshOwnIP(ctx)
	if err != nil || strings.Join(s.Current, ",") != "203.0.113.10,2001:db8::1" || s.Changed == 0 {
		t.Fatalf("erste Abfrage: %+v %v", s, err)
	}
	if h.ownPublicIP() != "203.0.113.10" {
		t.Errorf("ownPublicIP = %q", h.ownPublicIP())
	}
	// Adresswechsel: neue zuerst, frühere bleiben bekannt
	s, err = h.refreshOwnIP(ctx)
	if err != nil || strings.Join(s.Current, ",") != "203.0.113.20" {
		t.Fatalf("Wechsel: %+v %v", s, err)
	}
	known := h.knownOwnIPs()
	if known[0] != "203.0.113.20" || !contains(known, "203.0.113.10") || !contains(known, "2001:db8::1") {
		t.Errorf("knownOwnIPs = %v", known)
	}
	if len(h.ownPublicIPs()) != 3 {
		t.Errorf("ownPublicIPs = %v", h.ownPublicIPs())
	}
	// beide Endpunkte scheitern: Fehler, bekannte Adressen bleiben
	if _, err = h.refreshOwnIP(ctx); err == nil {
		t.Fatal("Fehler erwartet")
	}
	s = h.ownIPState()
	if s.Error == "" || s.Current[0] != "203.0.113.20" || h.ownPublicIP() != "203.0.113.20" {
		t.Errorf("nach Fehler: %+v", s)
	}
	// Marken für die Weitergabe enthalten auch frühere Adressen
	if m := h.ownMarkers(); !contains(m, "203.0.113.10") {
		t.Errorf("ownMarkers = %v", m)
	}
}

func TestOwnIPRejectsPrivate(t *testing.T) {
	for _, a := range []string{"192.168.178.1", "10.0.0.1", "100.64.1.1", "127.0.0.1", "fd00::1", "fe80::1", "::"} {
		if usablePublic(netip.MustParseAddr(a)) {
			t.Errorf("%s gilt als öffentlich", a)
		}
	}
	h := testHive(t)
	v4, v6 := []string{"192.168.178.20"}, []string{"fd00::5"}
	s4, s6 := ipifyStub(t, &v4), ipifyStub(t, &v6)
	o4, o6 := ownIPv4URL, ownIPv6URL
	ownIPv4URL, ownIPv6URL = s4.URL, s6.URL
	t.Cleanup(func() { ownIPv4URL, ownIPv6URL = o4, o6 })
	if _, err := h.refreshOwnIP(context.Background()); err == nil || h.ownPublicIP() != "" {
		t.Errorf("private Antwort übernommen: %q %v", h.ownPublicIP(), err)
	}
	// IPv4-Endpunkt liefert IPv6 bzw. umgekehrt: verworfen
	v4, v6 = []string{"2001:db8::9"}, []string{"203.0.113.9"}
	if _, err := h.refreshOwnIP(context.Background()); err == nil {
		t.Error("vertauschte Familien übernommen")
	}
}

func TestOwnIPPrune(t *testing.T) {
	now := time.Now()
	s := ownIPState{Current: []string{"203.0.113.1"}, Seen: map[string]int64{
		"203.0.113.1": now.Add(-40 * 24 * time.Hour).UnixMilli(), // aktuell: bleibt
		"203.0.113.2": now.Add(-40 * 24 * time.Hour).UnixMilli(), // zu alt
		"203.0.113.3": now.Add(-time.Hour).UnixMilli(),
	}}
	for i := 0; i < 40; i++ {
		s.Seen[fmt.Sprintf("198.51.100.%d", i)] = now.Add(-time.Duration(i) * time.Minute).UnixMilli()
	}
	s.prune(now)
	if _, ok := s.Seen["203.0.113.2"]; ok || len(s.Seen) > ownIPMaxSeen+1 { // + die aktuelle
		t.Errorf("prune: %d Einträge", len(s.Seen))
	}
	if _, ok := s.Seen["203.0.113.1"]; !ok {
		t.Error("aktuelle Adresse vergessen")
	}
}

func TestOwnIPNames(t *testing.T) {
	c := OwnIPConfig{Names: []string{" Hivornet.Example.ORG. ", "https://dyn.example.net", "", "dyn.example.net"}}
	if err := c.validate(); err != nil || strings.Join(c.Names, ",") != "hivornet.example.org,dyn.example.net" {
		t.Fatalf("validate: %v %v", c.Names, err)
	}
	for _, bad := range []string{"localhost", "a b.example.org", "x.y/z", "äh.example.org"} {
		c := OwnIPConfig{Names: []string{bad}}
		if c.validate() == nil {
			t.Errorf("%q angenommen", bad)
		}
	}
	h := testHive(t)
	x := h.Extras()
	x.OwnIP.Names = []string{"hivornet.example.org"}
	h.extras.x = x
	if !contains(h.ownMarkers(), "hivornet.example.org") {
		t.Errorf("eigener Name fehlt in ownMarkers: %v", h.ownMarkers())
	}
	if got := h.aiScrub("Login auf https://HIVORNET.example.org/admin"); strings.Contains(strings.ToLower(got), "hivornet.example.org") {
		t.Errorf("aiScrub: %q", got)
	}
}

func TestOwnIPAPIAdminOnly(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/ownip", nil)
	if viewerAllowed(r) {
		t.Error("Leserolle darf die eigene Adresse sehen")
	}
}
