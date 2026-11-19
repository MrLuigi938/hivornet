package main

// Statische Auswertung nachgeladener Dateien (Cowrie legt sie unter <lib>/downloads/<sha256> ab).
// Die Datei wird nur gelesen, nie ausgeführt und nie über die Web-UI ausgeliefert.
//
//   GET /api/sample?hash=<sha256>
//
// Ermittelt: Größe, Dateityp (ELF, Skript, Archiv, Windows-Programm), bei ELF Architektur,
// Bitbreite und Byte-Reihenfolge, ob UPX-gepackt, eingebettete Adressen, IPs, Wallets und
// Mining-Pools sowie die Angriffsmuster aus analyze.go, angewendet auf die Zeichenketten
// der Datei (Miner, IoT-Botnetz, Nachladen, Persistenz …).

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const sampleMaxBytes = 16 << 20

type SampleInfo struct {
	SHA256      string   `json:"sha256"`
	Size        int64    `json:"size"`
	Truncated   bool     `json:"truncated,omitempty"` // nur der Anfang wurde gelesen
	Type        string   `json:"type"`
	Arch        string   `json:"arch,omitempty"`
	Bits        int      `json:"bits,omitempty"`
	Endian      string   `json:"endian,omitempty"`
	Static      bool     `json:"static,omitempty"` // ELF ohne Interpreter (statisch gelinkt)
	Packed      string   `json:"packed,omitempty"`
	Interpreter string   `json:"interpreter,omitempty"` // Skript: erste Zeile
	Strings     int      `json:"strings"`
	URLs        []string `json:"urls,omitempty"`
	IPs         []string `json:"ips,omitempty"`
	Wallets     []string `json:"wallets,omitempty"`
	Pools       []string `json:"pools,omitempty"`
	Patterns    []Count  `json:"patterns,omitempty"` // Key = Muster-ID, Label = Name
	Mismatch    bool     `json:"hash_mismatch,omitempty"`
}

var elfMachines = map[uint16]string{
	2: "SPARC", 3: "x86", 4: "m68k", 8: "MIPS", 20: "PowerPC", 21: "PowerPC 64", 22: "s390", 40: "ARM",
	42: "SuperH", 62: "x86-64", 183: "AArch64 (ARM64)", 243: "RISC-V",
}

var sampleIPRe = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)

// printableRuns liefert druckbare ASCII-Folgen ab minLen Zeichen (wie "strings").
func printableRuns(b []byte, minLen, max int) []string {
	var out []string
	start := -1
	for i := 0; i <= len(b); i++ {
		if i < len(b) && b[i] >= 0x20 && b[i] < 0x7f || i < len(b) && b[i] == '\t' {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= minLen {
			out = append(out, string(b[start:i]))
			if len(out) >= max {
				return out
			}
		}
		start = -1
	}
	return out
}

func analyzeSample(b []byte) SampleInfo {
	var si SampleInfo
	switch {
	case len(b) >= 20 && bytes.HasPrefix(b, []byte("\x7fELF")):
		si.Type = "ELF-Programm (Linux)"
		var bo binary.ByteOrder = binary.LittleEndian
		si.Endian = "Little-Endian"
		if b[5] == 2 {
			bo, si.Endian = binary.BigEndian, "Big-Endian"
		}
		si.Bits = map[byte]int{1: 32, 2: 64}[b[4]]
		m := bo.Uint16(b[18:20])
		si.Arch = elfMachines[m]
		if si.Arch == "" {
			si.Arch = "unbekannt (" + hex.EncodeToString(b[18:20]) + ")"
		}
		si.Static = !bytes.Contains(b[:min(len(b), 4096)], []byte("/lib")) // kein Interpreter-Pfad im Kopfbereich
	case bytes.HasPrefix(b, []byte("#!")):
		si.Type = "Skript"
		line, _, _ := bytes.Cut(b[:min(len(b), 200)], []byte("\n"))
		si.Interpreter = clip(strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return '?'
			}
			return r
		}, strings.ToValidUTF8(string(line), "?")), 120)
	case bytes.HasPrefix(b, []byte("\x1f\x8b")):
		si.Type = "gzip-Archiv"
	case bytes.HasPrefix(b, []byte("PK\x03\x04")):
		si.Type = "ZIP-Archiv"
	case bytes.HasPrefix(b, []byte("MZ")):
		si.Type = "Windows-Programm (PE)"
	case len(b) > 0 && bytes.IndexByte(b[:min(len(b), 4096)], 0) < 0:
		si.Type = "Text"
	default:
		si.Type = "unbekannt"
	}
	if bytes.Contains(b, []byte("UPX!")) {
		si.Packed = "UPX"
	}
	runs := printableRuns(b, 6, 50000)
	si.Strings = len(runs)
	// Für Adressen, IPs und Wallets genügt der Anfang: höchstens 2 MB Text (Speicher auf dem Pi).
	var tb strings.Builder
	for _, r := range runs {
		if tb.Len()+len(r) > 2<<20 {
			break
		}
		tb.WriteString(r)
		tb.WriteByte('\n')
	}
	text := tb.String()
	si.URLs = allURLs(text, nil, 20)
	ips := map[string]bool{}
	for _, ip := range sampleIPRe.FindAllString(text, 200) {
		if p := net.ParseIP(ip); p != nil && !p.IsPrivate() && !p.IsLoopback() && !p.IsUnspecified() && p.To4()[0] != 0 && !ips[ip] && len(ips) < 20 {
			ips[ip] = true
			si.IPs = append(si.IPs, ip)
		}
	}
	si.Wallets, si.Pools = cryptoIndicators(text)
	tags := map[string]int{}
	for _, r := range runs { // zeilenweise: Muster sollen nicht über Zeichenketten hinweg passen
		for _, id := range matchPatterns(r, "cmd") {
			tags[id]++
		}
	}
	for _, id := range matchPatterns(text, "web") {
		if id == "log4shell" || id == "web_rce" {
			tags[id]++
		}
	}
	delete(tags, "recon") // breite Regel, in Programmen fast immer
	si.Patterns = topCounts(tags, 12)
	for i := range si.Patterns {
		si.Patterns[i].Label = patternByID[si.Patterns[i].Key].Name
	}
	sort.Strings(si.IPs)
	return si
}

var errNoSample = errors.New("Datei nicht (mehr) vorhanden")

// sampleSem: höchstens eine Untersuchung gleichzeitig (bis zu 16 MB je Datei).
var sampleSem = make(chan struct{}, 1)

func (h *Hive) loadSample(hash string) (SampleInfo, error) {
	if !sha256Re.MatchString(hash) {
		return SampleInfo{}, errNoSample
	}
	// Downloads von Cowrie oder vom Hive selbst geholte Dateien (Quarantäne, samplecollect.go)
	var path string
	if h.cowrieLibDir != "" {
		path = filepath.Join(h.cowrieLibDir, "downloads", hash)
	}
	if q := h.quarantineDir(); q != "" {
		if _, err := os.Lstat(filepath.Join(q, hash)); err == nil || path == "" {
			path = filepath.Join(q, hash)
		}
	}
	if path == "" {
		return SampleInfo{}, errNoSample
	}
	// Ergebnis je Hash speichern: Die Datei ändert sich nie.
	if v, _, ok := h.st.lookupGet("sample:"+hash, "sample", 0); ok {
		var si SampleInfo
		if json.Unmarshal([]byte(v), &si) == nil {
			return si, nil
		}
	}
	select {
	case sampleSem <- struct{}{}:
		defer func() { <-sampleSem }()
	case <-time.After(20 * time.Second):
		return SampleInfo{}, errors.New("gerade wird schon eine Datei untersucht, bitte gleich noch einmal")
	}
	// Nur reguläre Dateien, keine Verweise oder FIFOs: Wer Cowrie übernimmt,
	// könnte sonst einen Symlink auf andere Dateien des Hive legen.
	lst, err := os.Lstat(path)
	if err != nil {
		if os.IsPermission(err) {
			return SampleInfo{}, errors.New("Datei nicht lesbar (Rechte)")
		}
		return SampleInfo{}, errNoSample
	}
	if !lst.Mode().IsRegular() {
		return SampleInfo{}, errors.New("keine reguläre Datei")
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsPermission(err) {
			return SampleInfo{}, errors.New("Datei nicht lesbar (Rechte)")
		}
		return SampleInfo{}, errNoSample
	}
	defer f.Close()
	st, _ := f.Stat()
	if st == nil || !os.SameFile(st, lst) { // zwischen Prüfung und Öffnen ausgetauscht
		return SampleInfo{}, errors.New("keine reguläre Datei")
	}
	b, err := io.ReadAll(io.LimitReader(f, sampleMaxBytes))
	if err != nil {
		return SampleInfo{}, err
	}
	si := analyzeSample(b)
	si.SHA256, si.Size = hash, int64(len(b))
	if st != nil {
		si.Size = st.Size()
	}
	if si.Size > sampleMaxBytes {
		si.Truncated = true
	} else if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != hash {
		si.Mismatch = true
	}
	if js, err := json.Marshal(si); err == nil {
		h.st.lookupPut("sample:"+hash, "sample", string(js))
	}
	return si, nil
}

// sample: GET /api/sample?hash=<sha256>
func (h *Hive) sample(w http.ResponseWriter, r *http.Request) {
	si, err := h.loadSample(strings.ToLower(r.URL.Query().Get("hash")))
	if err != nil {
		httpErr(w, 404, err.Error())
		return
	}
	writeJSON(w, si)
}
