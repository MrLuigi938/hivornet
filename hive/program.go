package main

// Programme lesbar machen: rein statische Auswertung einer nachgeladenen Binärdatei für die
// Fallakte (Tab „Funde“, Reiter „Inhalt“). Nichts wird ausgeführt oder emuliert.
//
//   GET /api/funde/program?sha=<sha256>
//
// Liefert:
//   - ELF-Übersicht (debug/elf, bei beschädigten Headern ein eigener Notbehelf): Architektur,
//     Byte-Reihenfolge, Bits, Einsprungpunkt, statisch/dynamisch, gestrippt, Segmente,
//     Sections, Bibliotheken und importierte Symbole, Packer (UPX).
//   - Lesbare Zeichenketten (ASCII ab 4 Zeichen und UTF-16LE), dedupliziert, begrenzt und in
//     Gruppen eingeordnet: Merkmale bekannter Botnetze (Mirai, Gafgyt, Mozi), Adressen,
//     Befehle, Pfade, HTTP, Rest.
//   - Mirai-Tabelle: Mirai verschleiert seine Konfiguration mit einem Ein-Byte-XOR (klassisch
//     0x22 = 0xDEADBEEF zusammengefaltet). Gesucht wird schlüsselunabhängig nach bekannten
//     Merkmalen (Differenzen der Bytes bleiben beim XOR gleich); nur wenn ein Schlüssel klar
//     über der Schwelle liegt, werden die entschlüsselten Zeichenketten gezeigt.
//   - Hex-Ansicht der ersten 4 KB.
//
// Das Ergebnis wird je Hash gespeichert (Datei ändert sich nie); gerechnet wird höchstens
// eine Datei gleichzeitig (sampleSem), gelesen höchstens sampleMaxBytes.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// programVersion: bei Änderungen der Auswertung erhöhen (gespeicherte Ergebnisse veralten).
const programVersion = 1

const (
	progMaxRuns     = 20000   // Zeichenketten insgesamt beim Durchsuchen
	progMaxLen      = 200     // Zeichen je Zeichenkette in der Ausgabe
	progGroupMax    = 400     // Einträge je Gruppe (außer Rest)
	progRestMax     = 1500    // Einträge im Rest
	progHexBytes    = 4096    // Hex-Ansicht
	progXORScanMax  = 8 << 20 // so viele Bytes werden nach der Mirai-Tabelle durchsucht
	progXORMax      = 300     // entschlüsselte Zeichenketten
	progXORMinMarks = 3       // verschiedene Merkmale, ab denen ein Schlüssel gilt
	progXORMinStrs  = 4       // entschlüsselte Zeichenketten, ab denen ein Schlüssel gilt
	progSymbolsMax  = 300
)

type ProgramInfo struct {
	Version   int           `json:"version"`
	SHA256    string        `json:"sha256"`
	Size      int64         `json:"size"`
	Truncated bool          `json:"truncated,omitempty"`
	ELF       *ELFOverview  `json:"elf,omitempty"`
	Strings   int           `json:"strings"` // gefundene Zeichenketten (vor der Begrenzung)
	Groups    []StringGroup `json:"groups"`
	XOR       *XORTable     `json:"xor,omitempty"`
	Hex       []string      `json:"hex"`
}

type ELFOverview struct {
	Class       int          `json:"bits"`
	Endian      string       `json:"endian"`
	Arch        string       `json:"arch"`
	Machine     int          `json:"machine"`
	Kind        string       `json:"kind"` // ausführbar, Bibliothek/PIE, Objekt …
	OSABI       string       `json:"osabi,omitempty"`
	Entry       string       `json:"entry"`
	Static      bool         `json:"static"`
	Interpreter string       `json:"interpreter,omitempty"`
	Stripped    bool         `json:"stripped"`
	Packer      string       `json:"packer,omitempty"`
	Libraries   []string     `json:"libraries,omitempty"`
	Imports     []string     `json:"imports,omitempty"`
	Symbols     []string     `json:"symbols,omitempty"` // Funktionsnamen, falls nicht gestrippt
	Segments    []ELFSegment `json:"segments,omitempty"`
	Sections    []ELFSection `json:"sections,omitempty"`
	Notes       []string     `json:"notes,omitempty"` // Auffälligkeiten (beschädigte Header …)
}

type ELFSegment struct {
	Type     string `json:"type"`
	Flags    string `json:"flags"`
	Offset   uint64 `json:"offset"`
	VAddr    string `json:"vaddr"`
	FileSize uint64 `json:"filesz"`
	MemSize  uint64 `json:"memsz"`
}

type ELFSection struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Flags string `json:"flags"`
	Addr  string `json:"addr"`
	Size  uint64 `json:"size"`
}

type StringGroup struct {
	Key   string    `json:"key"`
	Label string    `json:"label"`
	Items []StrItem `json:"items"`
	More  int       `json:"more,omitempty"` // weggelassene Einträge
}

type StrItem struct {
	Text string `json:"t"`
	Off  int64  `json:"o"`
	Enc  string `json:"e,omitempty"`   // "u16" für UTF-16LE, "xor" für entschlüsselt
	Tag  string `json:"tag,omitempty"` // Einordnung, z. B. „Mirai: Telnet-Anmeldung“
}

type XORTable struct {
	Key     int        `json:"key"`
	KeyHex  string     `json:"key_hex"`
	Marks   []string   `json:"marks"` // gefundene Merkmale
	Strings []StrItem  `json:"strings"`
	Classic bool       `json:"classic,omitempty"` // 0x22 wie im veröffentlichten Mirai-Quelltext
	spans   [][2]int64 // Lage der verschlüsselten Einträge (deren Rohform ist kein lesbarer Text)
}

// ---- ELF-Übersicht ----

var elfKinds = map[elf.Type]string{elf.ET_EXEC: "ausführbares Programm", elf.ET_DYN: "positionsunabhängig (PIE) oder Bibliothek",
	elf.ET_REL: "Objektdatei (nicht gelinkt)", elf.ET_CORE: "Speicherabbild (core)"}

func elfOverview(b []byte) (ov *ELFOverview) {
	if len(b) < 20 || !bytes.HasPrefix(b, []byte("\x7fELF")) {
		return nil
	}
	ov = elfHeaderFallback(b)
	if bytes.Contains(b, []byte("UPX!")) {
		ov.Packer = "UPX"
	}
	// debug/elf ist für vertrauenswürdige Dateien gebaut; Schadprogramme manipulieren Header
	// gezielt. Ein Fehler oder eine Panik ergibt nur einen Hinweis, nie einen Absturz.
	defer func() {
		if r := recover(); r != nil {
			ov.Notes = append(ov.Notes, "Header nur teilweise lesbar (beschädigt oder manipuliert)")
		}
	}()
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		ov.Notes = append(ov.Notes, "Header beschädigt oder manipuliert: "+clip(err.Error(), 120)+" (Angaben aus dem Kopf gelesen)")
		return ov
	}
	defer f.Close()
	if n, ok := elfMachines[uint16(f.Machine)]; ok {
		ov.Arch = n
	}
	if k, ok := elfKinds[f.Type]; ok {
		ov.Kind = k
	}
	if f.OSABI != elf.ELFOSABI_NONE && f.OSABI != elf.ELFOSABI_LINUX {
		ov.OSABI = strings.TrimPrefix(f.OSABI.String(), "ELFOSABI_")
	}
	hasDyn := false
	for _, p := range f.Progs {
		if len(ov.Segments) >= 64 {
			break
		}
		ov.Segments = append(ov.Segments, ELFSegment{Type: strings.TrimPrefix(p.Type.String(), "PT_"), Flags: progFlags(p.Flags),
			Offset: p.Off, VAddr: fmt.Sprintf("0x%x", p.Vaddr), FileSize: p.Filesz, MemSize: p.Memsz})
		switch p.Type {
		case elf.PT_INTERP:
			if p.Off < uint64(len(b)) {
				end := min(uint64(len(b)), p.Off+min(p.Filesz, 256))
				ov.Interpreter = cleanPrintable(string(bytes.TrimRight(b[p.Off:end], "\x00")))
			}
		case elf.PT_DYNAMIC:
			hasDyn = true
		}
		if p.Flags&elf.PF_W != 0 && p.Flags&elf.PF_X != 0 && p.Type == elf.PT_LOAD {
			ov.Notes = appendOnce(ov.Notes, "Segment zugleich beschreib- und ausführbar (typisch für Packer)")
		}
	}
	if len(f.Progs) == 0 {
		ov.Notes = append(ov.Notes, "keine Programm-Header")
	}
	hasSymtab := false
	for _, s := range f.Sections {
		if s.Type == elf.SHT_SYMTAB {
			hasSymtab = true
		}
		if s.Type == elf.SHT_NULL || len(ov.Sections) >= 80 {
			continue
		}
		ov.Sections = append(ov.Sections, ELFSection{Name: cleanPrintable(clip(s.Name, 40)), Type: strings.TrimPrefix(s.Type.String(), "SHT_"),
			Flags: sectFlags(s.Flags), Addr: fmt.Sprintf("0x%x", s.Addr), Size: s.Size})
	}
	if len(f.Sections) <= 1 {
		ov.Notes = append(ov.Notes, "keine Section-Tabelle (entfernt oder abgeschnitten – häufig bei gepackten Programmen)")
	}
	ov.Stripped = !hasSymtab
	if libs, err := f.ImportedLibraries(); err == nil {
		for _, l := range libs {
			ov.Libraries = append(ov.Libraries, cleanPrintable(clip(l, 80)))
		}
	}
	if syms, err := f.ImportedSymbols(); err == nil {
		seen := map[string]bool{}
		for _, s := range syms {
			if n := cleanPrintable(clip(s.Name, 80)); n != "" && !seen[n] && len(ov.Imports) < progSymbolsMax {
				seen[n] = true
				ov.Imports = append(ov.Imports, n)
			}
		}
		sort.Strings(ov.Imports)
	}
	if hasSymtab {
		if syms, err := f.Symbols(); err == nil {
			seen := map[string]bool{}
			for _, s := range syms {
				if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Name == "" {
					continue
				}
				if n := cleanPrintable(clip(s.Name, 80)); !seen[n] && len(ov.Symbols) < progSymbolsMax {
					seen[n] = true
					ov.Symbols = append(ov.Symbols, n)
				}
			}
			sort.Strings(ov.Symbols)
		}
	}
	ov.Static = ov.Interpreter == "" && len(ov.Libraries) == 0 && !hasDyn
	return ov
}

// elfHeaderFallback liest das Nötigste selbst aus dem Kopf (falls debug/elf aufgibt).
func elfHeaderFallback(b []byte) *ELFOverview {
	ov := &ELFOverview{Class: 32, Endian: "Little-Endian", Kind: "unbekannt"}
	var bo binary.ByteOrder = binary.LittleEndian
	if b[5] == 2 {
		bo, ov.Endian = binary.BigEndian, "Big-Endian"
	}
	if b[4] == 2 {
		ov.Class = 64
	}
	m := bo.Uint16(b[18:20])
	ov.Machine = int(m)
	ov.Arch = elfMachines[m]
	if ov.Arch == "" {
		ov.Arch = fmt.Sprintf("unbekannt (0x%x)", m)
	}
	if k, ok := elfKinds[elf.Type(bo.Uint16(b[16:18]))]; ok {
		ov.Kind = k
	}
	switch {
	case ov.Class == 32 && len(b) >= 28:
		ov.Entry = fmt.Sprintf("0x%x", bo.Uint32(b[24:28]))
	case ov.Class == 64 && len(b) >= 32:
		ov.Entry = fmt.Sprintf("0x%x", bo.Uint64(b[24:32]))
	default:
		ov.Entry = "?"
		ov.Notes = append(ov.Notes, "Kopf abgeschnitten")
	}
	ov.Static = !bytes.Contains(b[:min(len(b), 4096)], []byte("/lib"))
	ov.Stripped = true
	return ov
}

func progFlags(f elf.ProgFlag) string {
	s := []byte("---")
	if f&elf.PF_R != 0 {
		s[0] = 'R'
	}
	if f&elf.PF_W != 0 {
		s[1] = 'W'
	}
	if f&elf.PF_X != 0 {
		s[2] = 'X'
	}
	return string(s)
}

func sectFlags(f elf.SectionFlag) string {
	s := ""
	if f&elf.SHF_ALLOC != 0 {
		s += "A"
	}
	if f&elf.SHF_WRITE != 0 {
		s += "W"
	}
	if f&elf.SHF_EXECINSTR != 0 {
		s += "X"
	}
	return s
}

func appendOnce(l []string, s string) []string {
	for _, x := range l {
		if x == s {
			return l
		}
	}
	return append(l, s)
}

// cleanPrintable ersetzt alles außer druckbarem ASCII durch "?".
func cleanPrintable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r >= 0x7f {
			return '?'
		}
		return r
	}, s)
}

// ---- Zeichenketten ----

type strRun struct {
	off int64
	s   string
	enc string
}

func isPrint(c byte) bool { return c >= 0x20 && c < 0x7f || c == '\t' }

// stringRuns: ASCII ab minLen Zeichen und UTF-16LE (ASCII-Zeichen mit Nullbyte) ab minLen.
func stringRuns(b []byte, minLen, max int) []strRun {
	var out []strRun
	start := -1
	for i := 0; i <= len(b) && len(out) < max; i++ {
		if i < len(b) && isPrint(b[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= minLen {
			out = append(out, strRun{int64(start), string(b[start:i]), ""})
		}
		start = -1
	}
	// UTF-16LE: Zeichen, Null, Zeichen, Null …
	for par := 0; par < 2 && len(out) < max; par++ {
		start = -1
		for i := par; i <= len(b) && len(out) < max; i += 2 {
			ok := i+1 < len(b) && isPrint(b[i]) && b[i+1] == 0
			if ok {
				if start < 0 {
					start = i
				}
				continue
			}
			if start >= 0 && (i-start)/2 >= minLen {
				var sb strings.Builder
				for j := start; j < i; j += 2 {
					sb.WriteByte(b[j])
				}
				out = append(out, strRun{int64(start), sb.String(), "u16"})
			}
			start = -1
		}
	}
	return out
}

// Merkmale bekannter IoT-Botnetze. exact: nur die ganze Zeichenkette zählt (kurze Wörter).
type botMark struct {
	s, tag string
	exact  bool
}

var botMarks = []botMark{
	// Mirai: Telnet-Anmeldung, Busybox-Prüfung, Watchdog, Killer, Angriffe
	{"ogin", "Mirai: Telnet-Anmeldung", true}, {"enter", "Mirai: Telnet-Anmeldung", true}, {"assword", "Mirai: Telnet-Anmeldung", true},
	{"ncorrect", "Mirai: Telnet-Anmeldung", true}, {"enable", "Mirai: Telnet-Befehl", true}, {"system", "Mirai: Telnet-Befehl", true},
	{"shell", "Mirai: Telnet-Befehl", true}, {"sh", "Mirai: Telnet-Befehl", true},
	{"/bin/busybox ", "Busybox-Prüfung (Mirai-Familie)", false}, {"ECCHI", "Mirai: Kennwort der Busybox-Prüfung", false},
	{"MIRAI", "Mirai", false}, {"listening tun0", "Mirai: Tarntext", false}, {"/dev/watchdog", "Watchdog abschalten (Gerät startet nicht neu)", false},
	{"/dev/misc/watchdog", "Watchdog abschalten (Gerät startet nicht neu)", false}, {"TSource Engine Query", "Angriff: Valve-Source-Flut (VSE)", false},
	{"/proc/net/tcp", "Killer: sucht fremde Verbindungen", false}, {"/proc/self/exe", "liest das eigene Programm", false},
	{".anime", "Mirai-Killer: beendet Konkurrenz", false}, {"REPORT %s:%s", "Mirai: meldet gefundene Zugangsdaten", false},
	{"udpplain", "Angriffsmethode", true}, {"greip", "Angriffsmethode", true}, {"greeth", "Angriffsmethode", true}, {"vse", "Angriffsmethode", true},
	{"stomp", "Angriffsmethode", true}, {"syn", "Angriffsmethode", true}, {"ack", "Angriffsmethode", true}, {"udpflood", "Angriffsmethode", false},
	{"httpflood", "Angriffsmethode", false}, {"HTTPFLOOD", "Angriffsmethode", false}, {"tcpflood", "Angriffsmethode", false},
	// Passwortliste des Mirai-Scanners
	{"xc3511", "Scanner-Passwortliste", false}, {"vizxv", "Scanner-Passwortliste", false}, {"xmhdipc", "Scanner-Passwortliste", false},
	{"juantech", "Scanner-Passwortliste", false}, {"7ujMko0", "Scanner-Passwortliste", false}, {"Zte521", "Scanner-Passwortliste", false},
	{"hi3518", "Scanner-Passwortliste", false}, {"jvbzd", "Scanner-Passwortliste", false}, {"klv123", "Scanner-Passwortliste", false},
	{"ikwb", "Scanner-Passwortliste", true}, {"dreambox", "Scanner-Passwortliste", true}, {"realtek", "Scanner-Passwortliste", true},
	{"smcadmin", "Scanner-Passwortliste", false}, {"zlxx.", "Scanner-Passwortliste", false}, {"GM8182", "Scanner-Passwortliste", false},
	{"anko", "Scanner-Passwortliste", true}, {"Win1doW$", "Scanner-Passwortliste", false},
	// Gafgyt/Bashlite
	{"KILLATTK", "Gafgyt: Angriff beenden", false}, {"LOLNOGTFO", "Gafgyt: Befehl zum Beenden", false}, {"GETLOCALIP", "Gafgyt: Steuerbefehl", false},
	{"!* ", "Gafgyt: Steuerbefehl", false}, {"BOTKILL", "Gafgyt: Steuerbefehl", false}, {"SCANNER ON", "Gafgyt: Scanner", false},
	{"Flooding", "Gafgyt: Angriffsmeldung", false}, {"BASHLITE", "Gafgyt/Bashlite", false}, {"gafgyt", "Gafgyt", false},
	// Mozi (Peer-to-Peer über DHT)
	{"dht.transmissionbt.com", "Mozi: DHT-Startknoten", false}, {"router.bittorrent.com", "Mozi: DHT-Startknoten", false},
	{"router.utorrent.com", "Mozi: DHT-Startknoten", false}, {"bttracker.debian.org", "Mozi: DHT-Startknoten", false},
	{"/usr/networks", "Mozi: Persistenz", false}, {"Mozi.", "Mozi", false}, {"[ss]", "Mozi: Konfiguration", false}, {"[cpu]", "Mozi: Konfiguration", false},
	// allgemein
	{"/etc/rc.d/", "Persistenz (Startskripte)", false}, {"/etc/init.d/", "Persistenz (Startskripte)", false}, {"crontab", "Persistenz (cron)", false},
	{"iptables", "Firewall ändern", false}, {"/etc/resolv.conf", "liest DNS-Einstellungen", false}, {"stratum+tcp", "Krypto-Miner", false},
}

var (
	progDomainRe = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|ru|cn|xyz|top|io|info|biz|cc|tk|me|su|pw|online|site|club|ml|ga|cf|gq|in|de|uk|nl|us|eu|br|vn|ir|ua|kr|jp|tw|hk|sg|co|app|dev|ly|to|ws|onion|bit|live|fun|icu|shop|store|space|tech|win|host|lol|cyou|sbs|work)\b`)
	progCmdRe    = regexp.MustCompile(`(?i)(?:^|[\s;|&])(?:wget|curl|tftp|ftpget|busybox|chmod|chattr|rm\s+-r?f|killall|pkill|kill\s+-9|iptables|crontab|nohup|/bin/sh|sh\s+-c|echo\s|cat\s|cd\s+/|mount\s|ulimit|netstat|history\s+-c|uname|nc\s|telnetd|dropbear|passwd|useradd|systemctl|service\s|ps\s|\./|>\s*/)`)
	progPathRe   = regexp.MustCompile(`(?:^|[\s"'=:])/(?:proc|tmp|dev|etc|var|bin|sbin|usr|lib|home|root|mnt|sys|run|data|opt|system|boot)(?:/|\b)`)
	progHTTPRe   = regexp.MustCompile(`(?i)^(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|CONNECT) \S|HTTP/[12]|user-agent|mozilla/|^host:|content-type|content-length|^accept|connection: |cookie|referer|keep-alive`)
)

var progGroupLabels = [][2]string{
	{"merkmale", "Merkmale bekannter Botnetze"}, {"adressen", "Adressen, IPs und Domains"}, {"befehle", "Shell-Befehle"},
	{"pfade", "Dateipfade"}, {"http", "HTTP und User-Agents"}, {"rest", "Übrige Zeichenketten"},
}

// classifyString ordnet eine Zeichenkette einer Gruppe zu (erste passende gewinnt).
func classifyString(s string) (group, tag string) {
	ls := strings.ToLower(s)
	for _, m := range botMarks {
		if m.exact && s == m.s || !m.exact && strings.Contains(s, m.s) {
			return "merkmale", m.tag
		}
	}
	if strings.Contains(ls, "://") || sampleIPRe.MatchString(s) {
		return "adressen", ""
	}
	if progHTTPRe.MatchString(s) {
		return "http", ""
	}
	if progCmdRe.MatchString(s) {
		return "befehle", ""
	}
	if progPathRe.MatchString(s) {
		return "pfade", ""
	}
	if progDomainRe.MatchString(s) && !strings.Contains(ls, ".so") {
		return "adressen", "Domain"
	}
	return "rest", ""
}

func shortStr(s string) string {
	if len(s) > progMaxLen {
		return s[:progMaxLen] + "…"
	}
	return s
}

// ---- Mirai-Tabelle (Ein-Byte-XOR) ----

// xorMarks: Klartexte, die in Mirai-Tabellen vorkommen. Gesucht wird über die Differenzen
// benachbarter Bytes, die beim XOR mit einem festen Byte gleich bleiben.
var xorMarks = []string{"/proc/", "watchdog", "busybox", "shell", "enable", "system", "POST /", "GET /", "/dev/", "assword",
	"ncorrect", "ogin", "TSource Engine", "/etc/resolv.conf", "/proc/net/tcp", "listening tun0", "Mozilla/", "User-Agent",
	"Connection:", "/bin/sh", ".anime", "REPORT", "/maps", "/exe", "/status", "Content-Type", "keep-alive", "ECCHI"}

func findXORTable(b []byte) *XORTable {
	if len(b) > progXORScanMax {
		b = b[:progXORScanMax]
	}
	marks := map[byte]map[string]bool{}
	for _, m := range xorMarks {
		mb := []byte(m)
		n := len(mb)
		d1 := mb[1] ^ mb[0]
		for p := 0; p+n <= len(b); p++ {
			if b[p+1]^b[p] != d1 {
				continue
			}
			k := b[p] ^ mb[0]
			if k == 0 {
				continue // Klartext
			}
			ok := true
			for i := 2; i < n; i++ {
				if b[p+i]^k != mb[i] {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
			if marks[k] == nil {
				marks[k] = map[string]bool{}
			}
			marks[k][m] = true
		}
	}
	best, bestN := byte(0), 0
	for k, ms := range marks {
		if len(ms) > bestN || len(ms) == bestN && k == 0x22 {
			best, bestN = k, len(ms)
		}
	}
	if bestN < progXORMinMarks {
		return nil
	}
	strs, spans := xorStrings(b, best)
	if len(strs) < progXORMinStrs {
		return nil
	}
	t := &XORTable{Key: int(best), KeyHex: fmt.Sprintf("0x%02x", best), Strings: strs, Classic: best == 0x22, spans: spans}
	for m := range marks[best] {
		t.Marks = append(t.Marks, m)
	}
	sort.Strings(t.Marks)
	return t
}

// xorStrings entschlüsselt mit key und behält nur Zeichenketten, die wie ein Eintrag der
// Tabelle aussehen: druckbar, mit verschlüsseltem Nullbyte am Ende (Rohbyte == key),
// überwiegend Buchstaben, Ziffern und übliche Satzzeichen.
func xorStrings(b []byte, key byte) ([]StrItem, [][2]int64) {
	var out []StrItem
	var spans [][2]int64
	seen := map[string]bool{}
	start := -1
	// Ein Rohbyte 0 ist meist ein Füllbyte zwischen zwei Einträgen. Nur wenn der Schlüssel
	// selbst ein Buchstabe oder eine Ziffer ist, kann es im Eintrag vorkommen (dieses Zeichen).
	zeroInside := key >= 'a' && key <= 'z' || key >= 'A' && key <= 'Z' || key >= '0' && key <= '9'
	for i := 0; i < len(b) && len(out) < progXORMax; i++ {
		if isPrint(b[i]^key) && (b[i] != 0 || zeroInside) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && b[i] == key {
			// Nullbytes davor sind Füllbytes des Compilers (bei druckbarem Schlüssel sähen
			// sie wie das Schlüsselzeichen aus).
			for start < i && b[start] == 0 {
				start++
			}
			if i-start >= 3 {
				s := xorDecode(b[start:i], key)
				if xorPlausible(s) {
					spans = append(spans, [2]int64{int64(start), int64(i)})
					if !seen[s] {
						seen[s] = true
						out = append(out, StrItem{Text: shortStr(s), Off: int64(start), Enc: "xor"})
					}
				}
			}
		}
		start = -1
	}
	return out, spans
}

func xorDecode(b []byte, key byte) string {
	o := make([]byte, len(b))
	for i, c := range b {
		o[i] = c ^ key
	}
	return string(o)
}

func xorPlausible(s string) bool {
	good, letters := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			letters++
			good++
		case c >= '0' && c <= '9' || strings.IndexByte(" /.:-_%=,?&+()[]\r\n\t", c) >= 0:
			good++
		}
	}
	return letters >= 2 && good*100 >= len(s)*85
}

// ---- Hex ----

func hexLines(b []byte, n int) []string {
	if len(b) > n {
		b = b[:n]
	}
	var out []string
	for o := 0; o < len(b); o += 16 {
		row := b[o:min(o+16, len(b))]
		var hx, as strings.Builder
		for i := 0; i < 16; i++ {
			if i < len(row) {
				fmt.Fprintf(&hx, "%02x ", row[i])
				if row[i] >= 0x20 && row[i] < 0x7f {
					as.WriteByte(row[i])
				} else {
					as.WriteByte('.')
				}
			} else {
				hx.WriteString("   ")
			}
			if i == 7 {
				hx.WriteByte(' ')
			}
		}
		out = append(out, fmt.Sprintf("%08x  %s |%s|", o, hx.String(), as.String()))
	}
	return out
}

// ---- Gesamtauswertung ----

func analyzeProgram(b []byte) ProgramInfo {
	pi := ProgramInfo{Version: programVersion}
	pi.ELF = elfOverview(b)
	runs := stringRuns(b, 4, progMaxRuns)
	pi.Strings = len(runs)
	if pi.ELF == nil && bytes.Contains(b, []byte("UPX!")) {
		pi.Groups = append(pi.Groups, StringGroup{Key: "merkmale", Label: "Merkmale bekannter Botnetze",
			Items: []StrItem{{Text: "UPX!", Off: int64(bytes.Index(b, []byte("UPX!"))), Tag: "Packer: UPX"}}})
	}
	sort.SliceStable(runs, func(i, j int) bool { return runs[i].off < runs[j].off })
	groups := map[string]*StringGroup{}
	for _, gl := range progGroupLabels {
		groups[gl[0]] = &StringGroup{Key: gl[0], Label: gl[1], Items: []StrItem{}}
	}
	if len(pi.Groups) > 0 {
		groups["merkmale"].Items = pi.Groups[0].Items
		pi.Groups = nil
	}
	add := func(r strRun, enc string) {
		g, tag := classifyString(r.s)
		gr := groups[g]
		limit := progGroupMax
		if g == "rest" {
			limit = progRestMax
		}
		if len(gr.Items) >= limit {
			gr.More++
			return
		}
		if enc == "xor" {
			tag = strings.TrimSpace("entschlüsselt " + tag)
		}
		gr.Items = append(gr.Items, StrItem{Text: shortStr(r.s), Off: r.off, Enc: enc, Tag: tag})
	}
	pi.XOR = findXORTable(b)
	inXOR := func(off int64) bool { return false }
	if pi.XOR != nil {
		sp := pi.XOR.spans
		inXOR = func(off int64) bool {
			i := sort.Search(len(sp), func(i int) bool { return sp[i][1] > off })
			return i < len(sp) && sp[i][0] <= off
		}
	}
	seen := map[string]bool{}
	for _, r := range runs {
		s := strings.TrimSpace(r.s)
		if len(s) < 4 || seen[s] || inXOR(r.off) {
			continue
		}
		seen[s] = true
		r.s = s
		add(r, r.enc)
	}
	if pi.XOR != nil {
		for _, x := range pi.XOR.Strings {
			if g, _ := classifyString(x.Text); g != "rest" && !seen[x.Text] {
				seen[x.Text] = true
				add(strRun{x.Off, x.Text, "xor"}, "xor")
			}
		}
	}
	for _, gl := range progGroupLabels {
		if g := groups[gl[0]]; len(g.Items) > 0 || g.More > 0 {
			pi.Groups = append(pi.Groups, *g)
		}
	}
	pi.Hex = hexLines(b, progHexBytes)
	return pi
}

// loadProgram: gespeicherte oder neu berechnete Auswertung (höchstens eine gleichzeitig).
func (h *Hive) loadProgram(hash string) (ProgramInfo, error) {
	if !sha256Re.MatchString(hash) || h.samplePath(hash) == "" {
		return ProgramInfo{}, errNoSample
	}
	if v, _, ok := h.st.lookupGet("prog:"+hash, "program", 0); ok {
		var pi ProgramInfo
		if json.Unmarshal([]byte(v), &pi) == nil && pi.Version == programVersion {
			return pi, nil
		}
	}
	select {
	case sampleSem <- struct{}{}:
		defer func() { <-sampleSem }()
	case <-time.After(20 * time.Second):
		return ProgramInfo{}, errors.New("gerade wird schon eine Datei untersucht, bitte gleich noch einmal")
	}
	b, size, err := h.readSample(hash, sampleMaxBytes)
	if err != nil {
		return ProgramInfo{}, err
	}
	if size <= sampleMaxBytes {
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != hash {
			return ProgramInfo{}, errors.New("Datei verändert (Hash passt nicht)")
		}
	}
	pi := analyzeProgram(b)
	pi.SHA256, pi.Size, pi.Truncated = hash, size, size > sampleMaxBytes
	if js, err := json.Marshal(pi); err == nil {
		h.st.lookupPut("prog:"+hash, "program", string(js))
	}
	return pi, nil
}

// fundeProgram: GET /api/funde/program?sha=
func (h *Hive) fundeProgram(w http.ResponseWriter, r *http.Request) {
	sha := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sha")))
	if !sha256HexRe.MatchString(sha) {
		httpErr(w, 400, "SHA-256 erwartet")
		return
	}
	pi, err := h.loadProgram(sha)
	if err != nil {
		httpErr(w, 404, err.Error())
		return
	}
	writeJSON(w, pi)
}

// programExplainText: Metadaten und Zeichenketten eines Programms für die KI-Erklärung
// (nie die Datei selbst), höchstens max Zeichen.
func programExplainText(pi ProgramInfo, max int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Nachgeladenes Programm (SHA-256 %s, %d Byte)", pi.SHA256, pi.Size)
	if e := pi.ELF; e != nil {
		fmt.Fprintf(&b, "\nELF %d Bit, %s, %s, %s, Einsprung %s", e.Class, e.Endian, e.Arch, e.Kind, e.Entry)
		if e.Static {
			b.WriteString(", statisch gelinkt")
		}
		if e.Stripped {
			b.WriteString(", gestrippt")
		}
		if e.Packer != "" {
			b.WriteString(", gepackt mit " + e.Packer)
		}
		if e.Interpreter != "" {
			b.WriteString("\nInterpreter: " + e.Interpreter)
		}
		if len(e.Libraries) > 0 {
			b.WriteString("\nBibliotheken: " + strings.Join(e.Libraries, ", "))
		}
		if len(e.Imports) > 0 {
			b.WriteString("\nImportierte Funktionen: " + strings.Join(e.Imports[:min(len(e.Imports), 120)], ", "))
		}
		if len(e.Symbols) > 0 {
			b.WriteString("\nFunktionsnamen: " + strings.Join(e.Symbols[:min(len(e.Symbols), 150)], ", "))
		}
		if len(e.Notes) > 0 {
			b.WriteString("\nAuffällig: " + strings.Join(e.Notes, "; "))
		}
	}
	if x := pi.XOR; x != nil {
		fmt.Fprintf(&b, "\n\nMit Ein-Byte-XOR (Schlüssel %s) verschleierte Zeichenketten, entschlüsselt:\n", x.KeyHex)
		for _, s := range x.Strings {
			b.WriteString(s.Text + "\n")
		}
	}
	for _, g := range pi.Groups {
		fmt.Fprintf(&b, "\n%s:\n", g.Label)
		for _, s := range g.Items {
			if b.Len() > max {
				break
			}
			if s.Tag != "" {
				b.WriteString(s.Text + "   [" + s.Tag + "]\n")
			} else {
				b.WriteString(s.Text + "\n")
			}
		}
	}
	return clip(b.String(), max)
}

// explainProgram: Erklärtext für eine Datei, die kein Text ist.
func (h *Hive) explainProgram(ctx context.Context, hash string) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	pi, err := h.loadProgram(hash)
	if err != nil {
		return "", err
	}
	if pi.ELF == nil && pi.Strings == 0 {
		return "", errors.New("In der Datei sind keine lesbaren Zeichenketten; erklären lässt sich nichts.")
	}
	return programExplainText(pi, explainMaxText), nil
}
