package main

// Weitere Indikatoren aus Befehlen:
//   - Krypto-Wallets und Mining-Pools (Miner-Befehle, Docker-"create" mit Miner-Image).
//     Die Wallet ist das stärkste Merkmal einer Kampagne: Wer an dieselbe Adresse schürft,
//     gehört zusammen (campaigns.go). Pools werden nur gezählt, nicht verkettet, weil sich
//     viele fremde Miner denselben öffentlichen Pool teilen.
//   - Honeypot-Prüfungen: Testreihen, mit denen Bots nach dem Login prüfen, ob die Shell
//     echt ist (Muster "honeypot_check" in analyze.go). hpCheckStats zählt, wie viele
//     Angreifer danach weitermachten – ein Maß dafür, ob die Tarnung hält.

import (
	"regexp"
	"slices"
	"sort"
	"strings"
)

var (
	// Monero: Standard- (4…) und Unteradressen (8…) mit 95 Zeichen, integrierte mit 106.
	moneroRe = regexp.MustCompile(`\b(?:[48][1-9A-HJ-NP-Za-km-z]{94}|4[1-9A-HJ-NP-Za-km-z]{105})\b`)
	ethRe    = regexp.MustCompile(`\b0x[0-9a-fA-F]{40}\b`)
	bech32Re = regexp.MustCompile(`\bbc1[02-9ac-hj-np-z]{25,87}\b`)
	// Alte Bitcoin-Adressen sehen aus wie beliebige Zeichenketten; nur nach -u/--user/wallet.
	btcUserRe = regexp.MustCompile(`(?:\s-u\s*|--user[= ]\s*|wallet[= ]\s*)([13][1-9A-HJ-NP-Za-km-z]{25,34})\b`)
	// Pool: stratum-Adresse immer, "-o host:port" bzw. "--url host:port" nur in Miner-Befehlen
	// (bei curl/wget heißt -o "Ausgabedatei").
	stratumRe = regexp.MustCompile(`(?i)stratum\d?\+(?:tcp|ssl|tls)://([a-z0-9.-]+(?::\d{2,5})?)`)
	poolOptRe = regexp.MustCompile(`(?i)(?:[\s=]-o\s*|--url[= ]\s*|[\s=]-url[= ]\s*)(?:[a-z0-9+]+://)?([a-z0-9-]+(?:\.[a-z0-9-]+)+:\d{2,5})\b`)
)

// cryptoIndicators liefert Wallets und Pool-Adressen aus einem Befehl.
func cryptoIndicators(text string) (wallets, pools []string) {
	if text == "" {
		return nil, nil
	}
	add := func(list *[]string, v string) {
		if v != "" && !slices.Contains(*list, v) && len(*list) < 6 {
			*list = append(*list, v)
		}
	}
	for _, w := range moneroRe.FindAllString(text, 4) {
		add(&wallets, w)
	}
	for _, w := range ethRe.FindAllString(text, 4) {
		add(&wallets, strings.ToLower(w))
	}
	for _, w := range bech32Re.FindAllString(text, 4) {
		add(&wallets, w)
	}
	for _, m := range btcUserRe.FindAllStringSubmatch(text, 4) {
		add(&wallets, m[1])
	}
	for _, m := range stratumRe.FindAllStringSubmatch(text, 4) {
		add(&pools, strings.ToLower(m[1]))
	}
	if patternByID["miner"].re.MatchString(text) || len(wallets) > 0 {
		for _, m := range poolOptRe.FindAllStringSubmatch(" "+text, 4) {
			add(&pools, strings.ToLower(m[1]))
		}
	}
	return wallets, pools
}

// walletKind benennt die Art einer Wallet für die Anzeige.
func walletKind(w string) string {
	switch {
	case strings.HasPrefix(w, "0x"):
		return "Ethereum"
	case strings.HasPrefix(w, "bc1"), strings.HasPrefix(w, "1"), strings.HasPrefix(w, "3"):
		return "Bitcoin"
	default:
		return "Monero"
	}
}

// shortWallet kürzt eine Wallet für Begründungen und Listen (Anfang…Ende).
func shortWallet(w string) string {
	if len(w) <= 16 {
		return w
	}
	return w[:8] + "…" + w[len(w)-4:]
}

// ---- Honeypot-Prüfungen ----

type HPCheckItem struct {
	IP        string `json:"ip"`
	Country   string `json:"country,omitempty"`
	Last      int64  `json:"last"`
	Checks    int    `json:"checks"`         // Prüfbefehle
	Continued bool   `json:"continued"`      // danach weitere Befehle
	Next      string `json:"next,omitempty"` // erster Befehl nach der Prüfung
}

type HPCheckStats struct {
	Attacks   int           `json:"attacks"`
	IPs       int           `json:"ips"`
	Continued int           `json:"continued"`
	Recent    []HPCheckItem `json:"recent"`
}

func isHPCheck(cmd string) bool { return patternByID["honeypot_check"].re.MatchString(cmd) }

// trivialCmd: Befehle, die nichts über das Weitermachen aussagen.
func trivialCmd(cmd string) bool {
	switch strings.ToLower(strings.TrimSpace(cmd)) {
	case "", "exit", "logout", "quit", "exit 0":
		return true
	}
	return false
}

// hpCheckStats wertet die Angriffe eines Zeitraums aus: Wer hat die Shell geprüft, und wer
// hat danach noch etwas anderes ausgeführt (dann hielt die Tarnung)?
func hpCheckStats(list []*Attack) HPCheckStats {
	st := HPCheckStats{Recent: []HPCheckItem{}}
	ips := map[string]bool{}
	for _, a := range list {
		if a.Own {
			continue
		}
		first, checks := -1, 0
		for i, c := range a.Commands {
			if isHPCheck(c) {
				checks++
				if first < 0 {
					first = i
				}
			}
		}
		if first < 0 {
			continue
		}
		it := HPCheckItem{IP: a.IP, Country: a.Country, Last: a.Last, Checks: checks}
		for _, c := range a.Commands[first+1:] {
			if !isHPCheck(c) && !trivialCmd(c) {
				it.Continued, it.Next = true, clip(c, 200)
				break
			}
		}
		st.Attacks++
		ips[a.IP] = true
		if it.Continued {
			st.Continued++
		}
		st.Recent = append(st.Recent, it)
	}
	st.IPs = len(ips)
	sort.Slice(st.Recent, func(i, j int) bool { return st.Recent[i].Last > st.Recent[j].Last })
	if len(st.Recent) > 20 {
		st.Recent = st.Recent[:20]
	}
	return st
}
