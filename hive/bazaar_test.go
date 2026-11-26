package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// bazaarTestServer: Nachschlagen meldet hash_not_found (oder ok, sobald known gesetzt ist),
// Hochladen antwortet mit reply. Zählt die Uploads und merkt sich Dateinamen und Parts.
type bazaarTestServer struct {
	mu       sync.Mutex
	reply    string
	known    bool
	uploads  int
	fileName string
	jsonCT   string
	jsonFile string
}

func newBazaarTestServer(t *testing.T, reply string) *bazaarTestServer {
	t.Helper()
	bs := &bazaarTestServer{reply: reply}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bs.mu.Lock()
		defer bs.mu.Unlock()
		if ct, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct == "multipart/form-data" {
			mr := multipart.NewReader(r.Body, params["boundary"])
			for p, err := mr.NextPart(); err == nil; p, err = mr.NextPart() {
				switch p.FormName() {
				case "file":
					bs.fileName = p.FileName()
				case "json_data":
					bs.jsonCT, bs.jsonFile = p.Header.Get("Content-Type"), p.FileName()
				}
				io.Copy(io.Discard, p)
			}
			bs.uploads++
			io.WriteString(w, bs.reply)
			return
		}
		if bs.known {
			io.WriteString(w, `{"query_status":"ok","data":[{"signature":"Mirai"}]}`)
			return
		}
		io.WriteString(w, `{"query_status":"hash_not_found"}`)
	}))
	t.Cleanup(srv.Close)
	old := bazaarBase
	bazaarBase = srv.URL
	t.Cleanup(func() { bazaarBase = old })
	return bs
}

// bazaarTestSample legt ein synthetisches ELF in die Quarantäne (keine echte Schadsoftware).
func bazaarTestSample(t *testing.T, h *Hive) (string, SampleInfo) {
	t.Helper()
	b := buildTestELF(t, testELFSpec{class64: false, bigEndian: true, machine: 8})
	sum := sha256.Sum256(b)
	sha := hex.EncodeToString(sum[:])
	dir := h.quarantineDir()
	os.MkdirAll(dir, 0o700)
	if err := os.WriteFile(filepath.Join(dir, sha), b, 0o600); err != nil {
		t.Fatal(err)
	}
	si, err := h.loadSample(sha)
	if err != nil || !bazaarEligible(si) {
		t.Fatalf("Auswertung: %+v %v", si, err)
	}
	return sha, si
}

func bazaarTestHive(t *testing.T) (*Hive, Extras) {
	h := shareHive(t)
	x := h.Extras()
	x.AbuseChKey = "GEHEIMERSCHLUESSEL123"
	x.Bazaar = BazaarConfig{Lookup: true, Upload: true}
	return h, x
}

func TestBazaarUploadReplies(t *testing.T) {
	cases := []struct {
		name, reply, status, errPart, detailPart string
		requeued                                 bool
	}{
		{"leer", "", "error", "ohne Inhalt", "neuer Versuch", true},
		{"html", "<html><body>Wartung GEHEIMERSCHLUESSEL123</body></html>", "error", "Webseite statt JSON", "Antwort: <html>", true},
		{"text", "Internal hiccup, try later", "error", "nicht im erwarteten Format", "Antwort: Internal hiccup", true},
		{"inserted", `{"query_status":"inserted"}`, "ok", "", "hochgeladen als sora.mips", false},
		{"bom", "\xef\xbb\xbf{\"query_status\":\"inserted\"}", "ok", "", "hochgeladen", false},
		{"array", `[{"query_status":"inserted"}]`, "ok", "", "hochgeladen", false},
		{"wort", `file_already_known`, "known", "", "schon bekannt", false},
		{"known", `{"query_status":"file_already_known"}`, "known", "", "schon bekannt", false},
		{"unbekannt", `{"query_status":"something_new"}`, "error", "unbekannten Status: something_new", "neuer Versuch", true},
		{"gesperrt", `{"query_status":"user_blacklisted"}`, "error", "gesperrt", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			allowDoc(t)
			bs := newBazaarTestServer(t, c.reply)
			h, x := bazaarTestHive(t)
			sha, si := bazaarTestSample(t, h)
			h.bazaarHandle(context.Background(), x, sha, si, "http://198.51.100.20/bins/sora.mips")
			if bs.uploads != 1 {
				t.Fatalf("Uploads: %d", bs.uploads)
			}
			if bs.fileName != "sora.mips" || bs.jsonCT != "application/json" || bs.jsonFile != "" {
				t.Fatalf("Formular: file=%q json_data ct=%q filename=%q", bs.fileName, bs.jsonCT, bs.jsonFile)
			}
			lg := h.share.channel("bazaar").Log
			if len(lg) != 1 || lg[0].Status != c.status || !strings.Contains(lg[0].Error, c.errPart) || !strings.Contains(lg[0].Detail, c.detailPart) {
				t.Fatalf("Protokoll: %+v", lg)
			}
			if strings.Contains(lg[0].Detail+lg[0].Error, "GEHEIMERSCHLUESSEL123") {
				t.Fatal("Schlüssel im Protokoll")
			}
			_, _, done := h.st.lookupGet("hash:"+sha, "bazaar_upload", 0)
			if done == (c.status == "error") {
				t.Fatalf("erledigt=%v bei Status %s", done, c.status)
			}
			_, _, waiting := h.st.lookupGet("hash:"+sha, "bazaar_wait", 0)
			if waiting != c.requeued {
				t.Fatalf("vorgemerkt=%v, erwartet %v", waiting, c.requeued)
			}
		})
	}
}

// Nach einem Fehler wird später erneut versucht; hat der erste Upload in Wahrheit geklappt,
// meldet das Nachschlagen die Datei als bekannt, und sie wird nicht noch einmal gesendet.
func TestBazaarRetryNoDoubleUpload(t *testing.T) {
	allowDoc(t)
	bs := newBazaarTestServer(t, "")
	h, x := bazaarTestHive(t)
	sha, si := bazaarTestSample(t, h)
	h.bazaarHandle(context.Background(), x, sha, si, "http://198.51.100.20/s2")
	v, _, ok := h.st.lookupGet("hash:"+sha, "bazaar_wait", 0)
	var w bazaarWait
	json.Unmarshal([]byte(v), &w)
	if !ok || w.Tries != 1 || w.Next <= time.Now().UnixMilli() {
		t.Fatalf("nicht vorgemerkt: %s", v)
	}
	// noch nicht fällig: nichts passiert
	h.bazaarDue(context.Background(), x)
	if bs.uploads != 1 {
		t.Fatalf("zu früh versucht: %d", bs.uploads)
	}
	w.Next = time.Now().Add(-time.Minute).UnixMilli()
	b, _ := json.Marshal(w)
	h.st.lookupPut("hash:"+sha, "bazaar_wait", string(b))
	bs.mu.Lock()
	bs.known = true
	bs.mu.Unlock()
	h.bazaarDue(context.Background(), x)
	if bs.uploads != 1 {
		t.Fatalf("doppelt hochgeladen: %d", bs.uploads)
	}
	if st, _, _ := h.st.lookupGet("hash:"+sha, "bazaar_upload", 0); st != "known" {
		t.Fatalf("Stand: %q", st)
	}
	if _, _, still := h.st.lookupGet("hash:"+sha, "bazaar_wait", 0); still {
		t.Fatal("noch vorgemerkt")
	}
}

// Die Wiederholung ist begrenzt.
func TestBazaarRetryLimit(t *testing.T) {
	allowDoc(t)
	newBazaarTestServer(t, "<html>down</html>")
	h, x := bazaarTestHive(t)
	sha, si := bazaarTestSample(t, h)
	h.bazaarRun(context.Background(), x, sha, si, "http://198.51.100.20/a", bazaarMaxTries-1)
	if _, _, waiting := h.st.lookupGet("hash:"+sha, "bazaar_wait", 0); waiting {
		t.Fatal("über die Grenze hinaus vorgemerkt")
	}
	if lg := h.share.channel("bazaar").Log; len(lg) != 1 || !strings.Contains(lg[0].Detail, "kein weiterer Versuch") {
		t.Fatalf("Protokoll: %+v", lg)
	}
}

// Ist der Kanal pausiert, wird die Datei vorgemerkt statt verworfen.
func TestBazaarPausedRequeues(t *testing.T) {
	allowDoc(t)
	bs := newBazaarTestServer(t, `{"query_status":"inserted"}`)
	h, x := bazaarTestHive(t)
	sha, si := bazaarTestSample(t, h)
	h.share.setErr("bazaar", "Störung", time.Hour)
	h.bazaarHandle(context.Background(), x, sha, si, "http://198.51.100.20/a")
	if bs.uploads != 0 {
		t.Fatal("trotz Pause gesendet")
	}
	if _, _, waiting := h.st.lookupGet("hash:"+sha, "bazaar_wait", 0); !waiting {
		t.Fatal("verworfen statt vorgemerkt")
	}
}

func TestBazaarFileName(t *testing.T) {
	elf := SampleInfo{Type: "ELF 32-Bit"}
	sh := SampleInfo{Type: "Skript"}
	sha := strings.Repeat("ab", 32)
	for _, c := range []struct {
		url  string
		si   SampleInfo
		want string
	}{
		{"http://198.51.100.20/bins/sora.mips", elf, "sora.mips"},
		{"http://198.51.100.20/s2", sh, "s2.sh"},
		{"http://198.51.100.20/", elf, sha + ".elf"},
		{"http://198.51.100.20/a%20b;rm -rf", sh, "abrm-rf.sh"},
		{"", SampleInfo{}, sha},
	} {
		if got := bazaarFileName(sha, c.url, c.si); got != c.want {
			t.Errorf("%s: %q, erwartet %q", c.url, got, c.want)
		}
	}
}

func TestBazaarStatusText(t *testing.T) {
	for _, qs := range []string{"inserted", "file_already_known", "file_expected", "http_post_expected", "no_api_key",
		"user_blacklisted", "hash_not_found", "illegal_hash", "no_hash_provided", "illegal_file", "unknown_file_type", "no_file"} {
		if msg, _ := bazaarStatusText(qs); strings.Contains(msg, "unbekannten Status") {
			t.Errorf("%s nicht übersetzt", qs)
		}
	}
	if _, retry := bazaarStatusText("user_blacklisted"); retry {
		t.Error("Sperre soll nicht wiederholt werden")
	}
	if msg, retry := bazaarStatusText("brand_new"); !retry || !strings.Contains(msg, "brand_new") {
		t.Error("unbekannter Status")
	}
}
