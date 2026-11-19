package main

// Angriffskette: Was hat ein Angreifer (eine IP oder eine Sitzung) nacheinander getan,
// was hing wovon ab und wohin ging es? Die Ereignisse werden zu Knoten zusammengefasst
// und sechs Phasen zugeordnet (angelehnt an die Taktiken von MITRE ATT&CK):
//
//	Erkundung → Zugang → Ausführung → Persistenz & Tarnung → Nachladen → Ziel
//
// Knoten: angesprochene Dienste, Anmeldeversuche, angenommene Logins, Exploits (mit CVE),
// Befehle gruppiert nach Muster, Nachlade-Hosts, Dateien, Weiterleitungsziele.
// Kanten: die Reihenfolge innerhalb einer Sitzung (was folgte worauf) und die Herkunft
// von Adressen (Befehl → Host, aus dem er nachlädt → Datei).
//
// GET /api/chain?ip=… oder ?session=… (höchstens 5.000 Ereignisse, die neuesten).

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

var chainPhases = []string{"Erkundung", "Zugang", "Ausführung", "Persistenz & Tarnung", "Nachladen", "Ziel"}

const (
	phRecon = iota
	phAccess
	phExec
	phPersist
	phIngress
	phImpact
)

// patternPhase: Phase eines Musters (analyze.go).
var patternPhase = map[string]int{
	"download_exec": phIngress, "miner": phImpact, "iot_botnet": phImpact, "persist_ssh": phPersist, "persist_cron": phPersist,
	"docker_escape": phImpact, "redis_takeover": phAccess, "account": phPersist, "cover_tracks": phPersist, "kill_rivals": phPersist,
	"obfuscation": phPersist, "recon": phExec, "honeypot_check": phExec, "prompt_injection": phExec, "data_theft": phImpact, "log4shell": phAccess, "java4shell": phAccess, "web_rce": phAccess,
	"secret_hunt": phRecon, "iot_exploit": phAccess, "traversal": phAccess, "sqli": phAccess, "cms_login": phRecon,
	"api_probe": phRecon, "known_exploit": phAccess, "product_probe": phRecon, "bait_used": phAccess, "tls_on_plain": phRecon, "smb_probe": phRecon, "http_on_raw": phRecon,
}

type ChainNode struct {
	ID       string   `json:"id"`
	Phase    int      `json:"phase"`
	Kind     string   `json:"kind"` // service, login, login_ok, exploit, pattern, commands, host, file, forward, prompt, web, ai
	Label    string   `json:"label"`
	Sub      string   `json:"sub,omitempty"`
	N        int      `json:"n"`
	Sev      int      `json:"sev"` // 0–4 wie die Stufen
	First    int64    `json:"first"`
	Last     int64    `json:"last"`
	Examples []string `json:"examples,omitempty"`
	Mitre    []string `json:"mitre,omitempty"`
}

type ChainEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	N     int    `json:"n"`
	Label string `json:"label,omitempty"` // z. B. "lädt von"
}

type Chain struct {
	Phases    []string     `json:"phases"`
	Nodes     []*ChainNode `json:"nodes"`
	Edges     []*ChainEdge `json:"edges"`
	Sessions  int          `json:"sessions"`
	Events    int          `json:"events"`
	Truncated bool         `json:"truncated"`
}

const (
	chainMaxNodes    = 60
	chainMaxEdges    = 160
	chainMaxExamples = 8
)

type chainBuilder struct {
	c     *Chain
	nodes map[string]*ChainNode
	edges map[[2]string]*ChainEdge
}

func (b *chainBuilder) node(id string, phase int, kind, label string, sev int, e *Event, example string) *ChainNode {
	n := b.nodes[id]
	ms := e.TS.UnixMilli()
	if n == nil && len(b.nodes) >= chainMaxNodes { // zu viele: Sammelknoten je Phase
		id, kind, label, example = fmt.Sprintf("more:%d", phase), "more", "weitere", label
		n = b.nodes[id]
	}
	if n == nil {
		n = &ChainNode{ID: id, Phase: phase, Kind: kind, Label: clip(label, 80), Sev: sev, First: ms}
		b.nodes[id] = n
		b.c.Nodes = append(b.c.Nodes, n)
	}
	n.N++
	n.Last = max(n.Last, ms)
	n.Sev = max(n.Sev, sev)
	if example = clip(strings.TrimSpace(example), 200); example != "" && len(n.Examples) < chainMaxExamples && !contains(n.Examples, example) {
		n.Examples = append(n.Examples, example)
	}
	return n
}

func (b *chainBuilder) edge(from, to *ChainNode, label string) {
	if from == nil || to == nil || from == to {
		return
	}
	k := [2]string{from.ID, to.ID}
	if e := b.edges[k]; e != nil {
		e.N++
		return
	}
	if len(b.edges) >= chainMaxEdges {
		return
	}
	e := &ChainEdge{From: from.ID, To: to.ID, N: 1, Label: label}
	b.edges[k] = e
	b.c.Edges = append(b.c.Edges, e)
}

func setMitre(n *ChainNode, id string) {
	if n.Kind != "more" {
		n.Mitre = patternMitre[id]
	}
}

func setSub(n *ChainNode, s string) {
	if n.Kind != "more" {
		n.Sub = s
	}
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	return ""
}

// BuildChain baut die Kette aus Ereignissen (aufsteigend nach Zeit).
func BuildChain(evs []*Event, truncated bool) *Chain {
	b := &chainBuilder{c: &Chain{Phases: chainPhases, Nodes: []*ChainNode{}, Edges: []*ChainEdge{}, Events: len(evs), Truncated: truncated},
		nodes: map[string]*ChainNode{}, edges: map[[2]string]*ChainEdge{}}
	last := map[string]*ChainNode{} // letzter bedeutsamer Knoten je Sitzung
	okSess := map[string]bool{}
	sessions := map[string]bool{}
	step := func(e *Event, n *ChainNode) {
		if n == nil {
			return
		}
		key := e.Session
		if key == "" {
			key = e.Service
		}
		b.edge(last[key], n, "")
		last[key] = n
	}
	for _, e := range evs {
		if e.Session != "" {
			sessions[e.Session] = true
		}
		svc := svcShort(e.Service)
		kind := eventKind(e, okSess[e.Session])
		text, on, revealed := analysisText(e)
		ids := eventPatterns(e, text, on, revealed)
		cves := eventCVEs(text, on)
		switch e.Type {
		case "connect":
			n := b.node(fmt.Sprintf("svc:%s:%d", e.Service, e.DstPort), phRecon, "service", fmt.Sprintf("Port %d", e.DstPort), 0, e, "")
			if n.Kind == "service" {
				n.Sub = strings.ToUpper(svc)
			}
			step(e, n)
			continue
		case "client_version":
			if n := b.nodes[fmt.Sprintf("svc:%s:%d", e.Service, e.DstPort)]; n != nil {
				if v := clip("Client "+dataString(e.Data, "version"), 200); len(n.Examples) < chainMaxExamples && !contains(n.Examples, v) {
					n.Examples = append(n.Examples, v)
				}
			}
			continue
		case "disconnect", "fingerprint", "tty":
			continue
		case "ai_reply":
			// Antwort des Sprachmodells: hängt am Schritt davor, ohne die Reihenfolge der
			// Angreifer-Schritte zu unterbrechen
			r := aiReplyFrom(e)
			n := b.node("ai:"+e.Service, phExec, "ai", "Antworten der KI", 1, e, r.Input+" → "+strings.Join(strings.Fields(r.Output), " "))
			setSub(n, strings.ToUpper(svc))
			key := e.Session
			if key == "" {
				key = e.Service
			}
			b.edge(last[key], n, "KI antwortet")
			continue
		}
		var n *ChainNode
		switch {
		case kind == kindTLSPlain:
			n = b.node("tlsplain:"+e.Service, phRecon, "pattern", "TLS am Klartext-Port", 0, e, svc)
		case kind == kindPrompt:
			lines, _ := promptLines(e)
			n = b.node("prompt:"+e.Service, phAccess, "prompt", "Befehle an der Login-Abfrage", 1, e, strings.Join(lines, " ⏎ "))
		case e.Type == "login":
			cred := e.Username + " / " + e.Password
			if dataBool(e.Data, "password_hashed") {
				cred = e.Username + " / (gehasht)"
			}
			if dataBool(e.Data, "success") || dataBool(e.Data, "accepted") {
				okSess[e.Session] = true
				n = b.node("loginok:"+e.Service+":"+cred, phAccess, "login_ok", "Login angenommen", 2, e, cred)
				setSub(n, clip(cred, 60))
			} else {
				n = b.node("login:"+e.Service, phAccess, "login", "Anmeldeversuche "+strings.ToUpper(svc), 1, e, cred)
			}
		case e.Type == "request" && dataString(e.Data, "forward_to") != "":
			fw := dataString(e.Data, "forward_to")
			n = b.node("fwd:"+fw, phImpact, "forward", "Weiterleitung", 3, e, fw)
			setSub(n, clip(fw, 60))
		case e.Type == "request":
			if len(cves) > 0 {
				n = b.node("cve:"+cves[0].CVE, phAccess, "exploit", cves[0].CVE, 3, e, requestKey(e))
				setSub(n, clip(cves[0].Label(), 60))
				break
			}
			if r, ok := firstExploit(eventRules(text, on)); ok { // Fehlkonfiguration ohne CVE (offene Docker-API …)
				n = b.node("rule:"+r.ID, phAccess, "exploit", r.Product, 3, e, requestKey(e))
				setSub(n, clip(r.Name, 60))
				break
			}
			best := ""
			for _, id := range ids {
				if p := patternByID[id]; p != nil && (best == "" || p.Sev > patternByID[best].Sev) {
					best = id
				}
			}
			if best != "" {
				p := patternByID[best]
				n = b.node("pat:"+best, patternPhase[best], "exploit", p.Name, p.Sev, e, requestKey(e))
				setMitre(n, best)
			} else {
				n = b.node("web:"+e.Service, phRecon, "web", "Anfragen "+strings.ToUpper(svc), 0, e, requestKey(e))
			}
		case e.Type == "command" || e.Type == "payload":
			best := ""
			for _, id := range ids {
				if p := patternByID[id]; p != nil && id != "obfuscation" && (best == "" || patternPhase[id] > patternPhase[best]) {
					best = id
				}
			}
			switch {
			case best != "":
				p := patternByID[best]
				sev := p.Sev
				if kind == kindExec {
					sev = max(sev, 3)
				}
				n = b.node("pat:"+best, patternPhase[best], "pattern", p.Name, sev, e, text)
				setMitre(n, best)
			case kind == kindExec:
				n = b.node("cmd:"+e.Service, phExec, "commands", "Befehle "+strings.ToUpper(svc), 3, e, text)
			default:
				n = b.node("proto:"+e.Service, phRecon, "commands", "Protokoll-Befehle "+strings.ToUpper(svc), 0, e, text)
			}
			if contains(ids, "obfuscation") && n != nil {
				ob := b.node("pat:obfuscation", phPersist, "pattern", "Verschleierung", 2, e, strings.Join(revealed, " ⏎ "))
				b.edge(n, ob, "verschleiert")
				setMitre(ob, "obfuscation")
			}
		case e.Type == "download":
			u := dataString(e.Data, "url")
			label := nonEmptyFirst(dataString(e.Data, "filename"), u)
			id := "file:" + nonEmptyFirst(dataString(e.Data, "sha256"), label)
			failed := strings.Contains(string(e.Data), `"failed":true`)
			title := "Datei geladen"
			if dataBool(e.Data, "upload") {
				title = "Datei hochgeladen"
			} else if failed {
				title = "Download gescheitert"
			}
			n = b.node(id, phIngress, "file", title, 4, e, label)
			if h := dataString(e.Data, "sha256"); h != "" {
				setSub(n, h[:min(16, len(h))]+"…")
			}
			if host := hostOf(u); host != "" {
				hn := b.node("host:"+host, phIngress, "host", host, 4, e, u)
				b.edge(hn, n, "liefert")
			}
		}
		if n == nil {
			continue
		}
		// gefundene Muster außer dem Knoten selbst als eigene Knoten (z. B. Persistenz im selben Befehl)
		for _, id := range ids {
			if p := patternByID[id]; p != nil && "pat:"+id != n.ID && id != "obfuscation" && p.On == "cmd" && kind == kindExec {
				pn := b.node("pat:"+id, patternPhase[id], "pattern", p.Name, max(p.Sev, 3), e, text)
				setMitre(pn, id)
				b.edge(n, pn, "")
			}
		}
		for _, c := range cves[min(1, len(cves)):] {
			cn := b.node("cve:"+c.CVE, phAccess, "exploit", c.CVE, 3, e, requestKey(e))
			setSub(cn, clip(c.Label(), 60))
		}
		step(e, n)
		// Nachlade-Adressen: Befehl bzw. Anfrage → Host
		if e.Type == "command" || e.Type == "payload" || len(revealed) > 0 {
			src := text
			if e.Type == "request" {
				src = ""
			}
			for _, u := range allURLs(src, revealed, 4) {
				if host := hostOf(u); host != "" {
					hn := b.node("host:"+host, phIngress, "host", host, 3, e, u)
					b.edge(n, hn, "lädt von")
				}
			}
		}
	}
	b.c.Sessions = len(sessions)
	sort.SliceStable(b.c.Nodes, func(i, j int) bool {
		if b.c.Nodes[i].Phase != b.c.Nodes[j].Phase {
			return b.c.Nodes[i].Phase < b.c.Nodes[j].Phase
		}
		return b.c.Nodes[i].First < b.c.Nodes[j].First
	})
	return b.c
}

// chain: GET /api/chain?ip=… oder ?session=…
func (h *Hive) chain(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := qctx(r)
	defer cancel()
	var where string
	var args []any
	switch {
	case r.URL.Query().Get("session") != "":
		where, args = "session = ?", []any{r.URL.Query().Get("session")}
	case r.URL.Query().Get("ip") != "":
		where, args = "src_ip = ?", []any{r.URL.Query().Get("ip")}
	default:
		httpErr(w, 400, "ip oder session fehlt")
		return
	}
	evs, err := h.loadEvents(ctx, where, args, "DESC", 5001)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	truncated := len(evs) > 5000
	if truncated {
		evs = evs[:5000]
	}
	sort.Slice(evs, func(i, j int) bool {
		return evs[i].TS.Before(evs[j].TS) || evs[i].TS.Equal(evs[j].TS) && evs[i].ID < evs[j].ID
	})
	writeJSON(w, BuildChain(evs, truncated))
}
