package main

import (
	"net"
	"testing"
)

// Fehlalarm auf dem Raspberry Pi: Zugriffe aus dem Heimnetz dürfen nicht als
// "Userland-Proxy" zählen; nur die Gateway-Adresse des Docker-Netzes.
func TestProxyDetectionOnlyGateway(t *testing.T) {
	m := testManager()
	if len(m.proxyGateways) != 0 {
		t.Fatal("ohne HONEYPOT_PROXY_CHECK=1 darf die Erkennung nicht aktiv sein")
	}
	if m.fromOwnNet(net.ParseIP("192.168.178.20")) {
		t.Fatal("LAN-Zugriff ohne Docker als Proxy gewertet")
	}
	m.proxyGateways = []net.IP{net.ParseIP("172.30.252.1")}
	if !m.fromOwnNet(net.ParseIP("172.30.252.1")) {
		t.Fatal("Docker-Gateway nicht erkannt")
	}
	if m.fromOwnNet(net.ParseIP("172.30.252.7")) || m.fromOwnNet(net.ParseIP("192.168.178.20")) {
		t.Fatal("andere Adressen dürfen nicht als Proxy gelten")
	}
}

func TestDockerGatewaysNotSelf(t *testing.T) {
	addrs, _ := net.InterfaceAddrs()
	for _, gw := range dockerGateways() {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(gw) {
				t.Fatalf("eigene Adresse %s als Gateway erkannt", gw)
			}
		}
	}
}
