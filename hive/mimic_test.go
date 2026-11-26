package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMimicEndpoint(t *testing.T) {
	h := testHive(t)
	calls := 0
	old := mimicAsk
	t.Cleanup(func() { mimicAsk = old })
	mimicAsk = func(_ context.Context, c AIConfig, msgs []map[string]string) (string, error) {
		calls++
		if c.Model != "eigenes-modell" || c.BaseURL != "https://openrouter.ai/api/v1" {
			t.Errorf("Konfiguration: %+v", c)
		}
		if strings.Contains(msgs[0]["content"], "web server") {
			return "```json\n{\"status\":200,\"content_type\":\"text/html\",\"body\":\"<h1>Router Login</h1>\"}\n```", nil
		}
		return "```\nprintf: usage\n```", nil
	}
	set := func(m MimicConfig) {
		x := h.Extras()
		x.AI = AIConfig{BaseURL: "https://openrouter.ai/api/v1", Model: "allgemein", APIKey: "k"}
		x.Mimic = m
		if err := x.Validate(); err != nil {
			t.Fatal(err)
		}
		h.extras.x = x
	}
	ask := func(body string) (int, mimicResp, string) {
		w := httptest.NewRecorder()
		h.mimic(w, httptest.NewRequest("POST", "/api/sensor/mimic", strings.NewReader(body)))
		var r mimicResp
		json.Unmarshal(w.Body.Bytes(), &r)
		return w.Code, r, w.Header().Get("X-Mimic")
	}
	shell := `{"kind":"shell","input":"printf","ip":"203.0.113.9","host":"cam1","shell":"BusyBox"}`

	set(defaultMimic())
	if code, _, off := ask(shell); code != 204 || off != "off" {
		t.Fatalf("ausgeschaltet: %d %q", code, off)
	}
	m := defaultMimic()
	m.Enabled, m.Model, m.MaxPerIPHour = true, "eigenes-modell", 2
	set(m)
	code, r, _ := ask(shell)
	if code != 200 || r.Out != "printf: usage\n" || r.Cached {
		t.Fatalf("Shell: %d %+v", code, r)
	}
	if _, r, _ = ask(shell); !r.Cached || calls != 1 {
		t.Errorf("Zwischenspeicher: %+v, %d Aufrufe", r, calls)
	}
	code, r, _ = ask(`{"kind":"web","input":"GET /cgi-bin/login.cgi HTTP/1.1","ip":"203.0.113.9","host":"cam1"}`)
	if code != 200 || r.Status != 200 || r.Out != "<h1>Router Login</h1>" {
		t.Fatalf("Web: %d %+v", code, r)
	}
	// Grenze je IP: 2 Anfragen ans Modell sind verbraucht; Zwischenspeicher geht weiter
	if code, _, _ := ask(`{"kind":"shell","input":"neu","ip":"203.0.113.9"}`); code != 204 {
		t.Errorf("Grenze je IP: %d", code)
	}
	if _, r, _ := ask(shell); !r.Cached {
		t.Error("Zwischenspeicher trotz Grenze erwartet")
	}
	if calls != 2 {
		t.Errorf("Aufrufe: %d", calls)
	}
	// nur Web eingeschaltet: Shell wird abgelehnt
	m.Shell = false
	set(m)
	if code, _, _ := ask(`{"kind":"shell","input":"x","ip":"203.0.113.10"}`); code != 204 {
		t.Errorf("Shell aus: %d", code)
	}
}

func TestMimicValidate(t *testing.T) {
	m := defaultMimic()
	m.Enabled = true
	if m.validate(AIConfig{}) == nil {
		t.Error("ohne Adresse und Modell angenommen")
	}
	if m.validate(AIConfig{BaseURL: "http://ollama:11434/v1", Model: "llama3.1:8b"}) != nil {
		t.Error("Angaben der KI-Auswertung müssen genügen")
	}
	if got := cleanShellOut("```bash\nls\n```"); got != "ls\n" {
		t.Errorf("Code-Zaun: %q", got)
	}
	if _, ok := parseWebOut("kein json"); ok {
		t.Error("ungültige Web-Antwort angenommen")
	}
}

// Langsames Modell: Der Angreifer bekommt nach mimicTimeout die statische Antwort (204), die
// Antwort entsteht im Hintergrund fertig und kommt beim nächsten gleichen Befehl aus dem Speicher.
// Gleichzeitige gleiche Anfragen kosten nur einen Aufruf.
func TestMimicSlowModelBackground(t *testing.T) {
	h := testHive(t)
	oldAsk, oldWait := mimicAsk, mimicTimeout
	t.Cleanup(func() { mimicAsk, mimicTimeout = oldAsk, oldWait })
	mimicTimeout = 50 * time.Millisecond
	var calls atomic.Int32
	release := make(chan struct{})
	mimicAsk = func(ctx context.Context, c AIConfig, msgs []map[string]string) (string, error) {
		calls.Add(1)
		<-release
		return "slow output", nil
	}
	x := h.Extras()
	x.AI = AIConfig{BaseURL: "http://127.0.0.1:1/v1", Model: "m"}
	x.Mimic = defaultMimic()
	x.Mimic.Enabled = true
	h.extras.x = x
	ask := func() int {
		w := httptest.NewRecorder()
		h.mimic(w, httptest.NewRequest("POST", "/api/sensor/mimic", strings.NewReader(`{"kind":"shell","input":"slowcmd","ip":"203.0.113.9"}`)))
		return w.Code
	}
	if c1, c2 := ask(), ask(); c1 != 204 || c2 != 204 {
		t.Fatalf("erst statisch erwartet: %d %d", c1, c2)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := h.mimicCached(mimicKey(mimicReq{Kind: "shell", Input: "slowcmd", IP: "203.0.113.9"})); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Antwort nicht im Speicher angekommen")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code := ask(); code != 200 {
		t.Errorf("zweites Mal aus dem Speicher erwartet: %d", code)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("Modellaufrufe: %d (gleiche Eingabe sollte nur einmal gehen)", n)
	}
	// Bis der Hintergrundauftrag abgemeldet ist (unter der Sperre), bevor Cleanup mimicAsk zurücksetzt
	for {
		h.mimicSt.mu.Lock()
		n := len(h.mimicSt.jobs)
		h.mimicSt.mu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestMimicErrTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	<-ctx.Done()
	if err := mimicErr(ctx, ctx.Err(), time.Now().Add(-11*time.Second)); !strings.Contains(err.Error(), "zu langsam") {
		t.Errorf("Zeitüberschreitung nicht benannt: %v", err)
	}
}

// Shell-Ausgaben mit wörtlichem \n verraten den Honeypot: entmaskieren, echte Backslashes lassen.
func TestUnescapeShell(t *testing.T) {
	cases := []struct{ out, in, want string }{
		{`sh: user: not found\n`, "user", "sh: user: not found\n"},
		{`a\nb\tc`, "ls", "a\nb\tc"},
		{`"total 0\ndrwx root"`, "ls -l", "total 0\ndrwx root"},
		{"zeile1\nzeile2\\n", "cat x", "zeile1\nzeile2"},
		{`a\nb`, `echo 'a\nb'`, `a\nb`},          // echo ohne -e gibt den Backslash aus
		{"x\\ty\n", `printf 'x\\ty'`, "x\\ty\n"}, // Backslash im Befehl: Ausgabe bleibt
		{`C:\temp`, "pwd", `C:\temp`},            // kein Escape-Muster
		{"Zeile mit \\n im Text\nund\nweitere\n", "cat s.sh", "Zeile mit \\n im Text\nund\nweitere\n"},
	}
	for _, c := range cases {
		if got := unescapeShell(c.out, c.in); got != c.want {
			t.Errorf("unescapeShell(%q, %q) = %q, erwartet %q", c.out, c.in, got, c.want)
		}
	}
	if got := cleanShellOut(unescapeShell(`sh: wget: not found\n`, "wget x")); got != "sh: wget: not found\n" {
		t.Errorf("Ausgabe an den Angreifer: %q", got)
	}
}

// Alte Shell-Einträge im Speicher und in der Fallakte werden beim Lesen bereinigt.
func TestMimicCachedShellUnescape(t *testing.T) {
	h := testHive(t)
	h.mimicStore("k1", mimicReq{Kind: "shell", Input: "user"}, mimicResp{Out: `sh: user: not found\n`})
	r, ok := h.mimicCached("k1")
	if !ok || r.Out != "sh: user: not found\n" {
		t.Fatalf("Speicher: %v %q", ok, r.Out)
	}
	d, _ := json.Marshal(map[string]any{"kind": "shell", "input": "user", "output": `sh: user: not found\n`})
	if x := aiReplyFrom(&Event{TS: time.Now(), Data: d}); strings.TrimSpace(x.Output) != "sh: user: not found" {
		t.Errorf("Fallakte: %q", x.Output)
	}
	if !strings.Contains(fmt.Sprintf(mimicShellPrompt, "h", "Linux", "k", "n", "n"), `never as the two characters \n`) {
		t.Error("Prompt warnt nicht vor maskierten Zeilenumbrüchen")
	}
}
