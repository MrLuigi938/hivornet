package main

// Angebliche Suchmaschinen-Bots prüfen. Viele Scanner geben sich als Googlebot aus,
// weil Webseiten Suchmaschinen gern durchlassen. Google und Microsoft empfehlen selbst
// die Prüfung per DNS: Rückwärtsauflösung der IP (PTR) muss auf eine ihrer Domains
// enden, und die Vorwärtsauflösung dieses Namens muss wieder die IP ergeben.
//
// Der Hive löst dazu über den Resolver des Systems auf (einzige zusätzliche ausgehende
// Verbindung: DNS). Geprüft wird im Hintergrund, höchstens 2 Adressen je Sekunde; das
// Ergebnis bleibt 30 Tage im Zwischenspeicher (Tabelle lookups, source "rdns") und im
// Speicher. Bis zum Ergebnis heißt es "wird geprüft".
//
// Ein echter Bot zählt wie ein Forschungsscanner (keine AbuseIPDB-Meldung); ein
// gefälschter trägt das Kennzeichen "gibt sich als … aus".

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

type botRule struct {
	Name     string
	UA       string   // Teil des User-Agents (klein)
	Suffixes []string // erlaubte Domains der Rückwärtsauflösung
}

var botRules = []botRule{
	// Bewusst ohne .googleusercontent.com: Unter dieser Domain hängen auch die Rechner der
	// Google-Cloud-Kunden. Ein Angreifer mit gemieteter VM und Googlebot-Kennung würde sonst
	// als echter Googlebot gelten und von der AbuseIPDB-Meldung ausgenommen.
	{"Googlebot", "googlebot", []string{".googlebot.com", ".google.com"}},
	{"Bingbot", "bingbot", []string{".search.msn.com"}},
	{"Applebot", "applebot", []string{".applebot.apple.com"}},
	{"YandexBot", "yandexbot", []string{".yandex.ru", ".yandex.net", ".yandex.com"}},
}

// claimedBot: Name des Bots, als der sich ein User-Agent ausgibt ("" = keiner).
func claimedBot(uas []string) *botRule {
	for _, ua := range uas {
		l := strings.ToLower(ua)
		for i := range botRules {
			if strings.Contains(l, botRules[i].UA) {
				return &botRules[i]
			}
		}
	}
	return nil
}

type botResult struct {
	Verdict string // ok | fake
	PTR     string
	At      time.Time
}

type botVerifierT struct {
	mu      sync.Mutex
	cache   map[string]botResult // ip|bot -> Ergebnis
	pending map[string]bool
	queue   chan [2]string // ip, bot
	st      *Store
	lookPTR func(ctx context.Context, ip string) ([]string, error)
	lookIP  func(ctx context.Context, host string) ([]string, error)
}

var botVerifier = &botVerifierT{cache: map[string]botResult{}, pending: map[string]bool{}, queue: make(chan [2]string, 256),
	lookPTR: net.DefaultResolver.LookupAddr, lookIP: net.DefaultResolver.LookupHost}

const botCacheAge = 30 * 24 * time.Hour

// status liefert "ok", "fake" oder "" (noch unbekannt; die Prüfung wird angestoßen).
func (v *botVerifierT) status(ip string, b *botRule) (string, string) {
	key := ip + "|" + b.Name
	v.mu.Lock()
	r, ok := v.cache[key]
	if ok && time.Since(r.At) < botCacheAge {
		v.mu.Unlock()
		return r.Verdict, r.PTR
	}
	st := v.st
	v.mu.Unlock()
	if st != nil {
		if data, at, ok := st.lookupGet("ip:"+ip, "rdns", botCacheAge); ok {
			verdict, ptr, _ := strings.Cut(data, " ")
			if f := strings.SplitN(verdict, "|", 2); len(f) == 2 && f[1] == b.Name {
				v.mu.Lock()
				v.cache[key] = botResult{f[0], ptr, at}
				v.mu.Unlock()
				return f[0], ptr
			}
		}
	}
	v.mu.Lock()
	if !v.pending[key] && len(v.pending) < 1000 {
		select {
		case v.queue <- [2]string{ip, b.Name}:
			v.pending[key] = true
		default:
		}
	}
	v.mu.Unlock()
	return "", ""
}

// check führt eine Prüfung aus (Rückwärts-, dann Vorwärtsauflösung).
func (v *botVerifierT) check(ctx context.Context, ip, name string) botResult {
	var rule *botRule
	for i := range botRules {
		if botRules[i].Name == name {
			rule = &botRules[i]
		}
	}
	res := botResult{Verdict: "fake", At: time.Now()}
	if rule == nil {
		return res
	}
	names, err := v.lookPTR(ctx, ip)
	if err != nil && ctx.Err() != nil {
		res.Verdict = "" // Zeitüberschreitung: später erneut
		return res
	}
	for _, n := range names {
		host := strings.TrimSuffix(strings.ToLower(n), ".")
		res.PTR = host
		okSuffix := false
		for _, s := range rule.Suffixes {
			okSuffix = okSuffix || strings.HasSuffix(host, s)
		}
		if !okSuffix {
			continue
		}
		addrs, err := v.lookIP(ctx, host)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if net.ParseIP(a).Equal(net.ParseIP(ip)) {
				res.Verdict = "ok"
				return res
			}
		}
	}
	return res
}

func (v *botVerifierT) run(stop <-chan struct{}) {
	tick := time.NewTicker(500 * time.Millisecond) // höchstens 2 Prüfungen je Sekunde
	defer tick.Stop()
	for {
		var job [2]string
		select {
		case <-stop:
			return
		case job = <-v.queue:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		r := v.check(ctx, job[0], job[1])
		cancel()
		key := job[0] + "|" + job[1]
		v.mu.Lock()
		delete(v.pending, key)
		if r.Verdict != "" {
			v.cache[key] = r
			if len(v.cache) > 20000 {
				for k := range v.cache {
					delete(v.cache, k)
					if len(v.cache) < 15000 {
						break
					}
				}
			}
		}
		st := v.st
		v.mu.Unlock()
		if r.Verdict != "" && st != nil {
			st.lookupPut("ip:"+job[0], "rdns", r.Verdict+"|"+job[1]+" "+r.PTR)
		}
		select {
		case <-stop:
			return
		case <-tick.C:
		}
	}
}

// botLabel: Text für den Angriff und ob der Bot echt ist.
func botLabel(ip string, uas []string) (label string, real bool) {
	b := claimedBot(uas)
	if b == nil {
		return "", false
	}
	switch v, ptr := botVerifier.status(ip, b); v {
	case "ok":
		return b.Name + " (echt, " + ptr + ")", true
	case "fake":
		return "gibt sich als " + b.Name + " aus (gefälscht)", false
	}
	return b.Name + "? (wird geprüft)", false
}
