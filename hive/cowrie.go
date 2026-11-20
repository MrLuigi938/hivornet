package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

const cowrieMaxLine = 1 << 20 // längere Zeilen werden übersprungen

// CowrieTail liest cowrie.json fortlaufend mit, auch über Log-Rotation und
// Neustarts hinweg, und wandelt die Ereignisse in das Hivornet-Format um.
// Die Position wird zusammen mit einem Fingerabdruck der ersten Zeile gespeichert,
// damit sie nach einer Rotation nicht auf die falsche Datei angewendet wird.
type CowrieTail struct {
	path   string
	sensor string
	st     *Store
	submit func(*Event)

	stop chan struct{}

	mu        sync.Mutex
	lastEvent time.Time
	found     bool
	sessions  map[string]cowrieSess
}

type cowrieSess struct {
	service string
	dport   int
	seen    time.Time
}

type tailState struct {
	Head string `json:"head"` // SHA-256 der ersten Zeile
	Off  int64  `json:"off"`
}

func NewCowrieTail(path, sensor string, st *Store, submit func(*Event)) *CowrieTail {
	return &CowrieTail{path: path, sensor: sensor, st: st, submit: submit, sessions: map[string]cowrieSess{}, stop: make(chan struct{})}
}

// Stop beendet Run (Datei wird geschlossen, Stand gespeichert).
func (c *CowrieTail) Stop() { close(c.stop) }

// sleep wartet d und liefert false, wenn Stop aufgerufen wurde.
func (c *CowrieTail) sleep(d time.Duration) bool {
	select {
	case <-c.stop:
		return false
	case <-time.After(d):
		return true
	}
}

func (c *CowrieTail) Status() (bool, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.found, c.lastEvent
}

// openRegular öffnet nur reguläre Dateien, keine Verweise, FIFOs oder Geräte (N5 des dritten
// Audits, wie sample.go). Die Ordner von Cowrie kann beschreiben, wer Cowrie übernimmt; ein
// Symlink auf eine Datei des Hive (Datenbank, Einstellungen) würde sonst gelesen und angezeigt.
// Nach dem Öffnen wird geprüft, dass es dieselbe Datei ist (kein Austausch dazwischen).
func openRegular(path string) (*os.File, error) {
	lst, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !lst.Mode().IsRegular() {
		return nil, errors.New("keine reguläre Datei: " + filepath.Base(path))
	}
	f, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !os.SameFile(lst, fi) {
		f.Close()
		return nil, errors.New("Datei während des Öffnens ausgetauscht: " + filepath.Base(path))
	}
	return f, nil
}

func fileHead(path string) string {
	f, err := openRegular(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	line, err := bufio.NewReaderSize(f, 4096).ReadSlice('\n')
	if err != nil { // erste Zeile noch unvollständig
		return ""
	}
	h := sha256.Sum256(line)
	return hex.EncodeToString(h[:])
}

func (c *CowrieTail) loadState() tailState {
	var s tailState
	if v, ok := c.st.GetKV("cowrie_state"); ok {
		json.Unmarshal([]byte(v), &s)
		return s
	}
	// Stand aus Version 0.1 (nur Offset) übernehmen, damit nichts doppelt eingelesen wird
	if v, ok := c.st.GetKV("cowrie_offset"); ok {
		if off, err := strconv.ParseInt(v, 10, 64); err == nil {
			s = tailState{Head: fileHead(c.path), Off: off}
		}
		c.st.DelKV("cowrie_offset")
	}
	return s
}

func (c *CowrieTail) saveState(s tailState) {
	b, _ := json.Marshal(s)
	c.st.SetKV("cowrie_state", string(b))
}

// lineReader liefert vollständige Zeilen und überspringt überlange.
type lineReader struct {
	f   *os.File
	br  *bufio.Reader
	off int64 // Position nach der letzten vollständigen Zeile
}

func newLineReader(f *os.File, off int64) *lineReader {
	f.Seek(off, io.SeekStart)
	return &lineReader{f: f, br: bufio.NewReaderSize(f, 64<<10), off: off}
}

// next liefert die nächste vollständige Zeile; ok=false am Dateiende (unvollständige
// letzte Zeile wird beim nächsten Versuch erneut gelesen).
func (l *lineReader) next() (line []byte, ok bool) {
	var buf []byte
	skipping := false
	consumed := int64(0)
	for {
		frag, err := l.br.ReadSlice('\n')
		consumed += int64(len(frag))
		if !skipping && len(buf)+len(frag) <= cowrieMaxLine {
			buf = append(buf, frag...)
		} else {
			skipping, buf = true, nil
		}
		switch {
		case err == nil:
			l.off += consumed
			if skipping {
				log.Printf("Cowrie: überlange Zeile übersprungen")
				return nil, true
			}
			return buf, true
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default: // EOF: zurück an den Zeilenanfang
			l.f.Seek(l.off, io.SeekStart)
			l.br.Reset(l.f)
			return nil, false
		}
	}
}

// drain liest eine Datei ab off bis zum Ende.
func (c *CowrieTail) drain(path string, off int64) {
	f, err := openRegular(path)
	if err != nil {
		return
	}
	defer f.Close()
	lr := newLineReader(f, off)
	for {
		line, ok := lr.next()
		if !ok {
			return
		}
		if line != nil {
			c.handle(line)
		}
	}
}

// catchUp sucht die rotierte Datei, zu der der gespeicherte Stand gehört, und liest sie zu Ende.
func (c *CowrieTail) catchUp(s tailState) {
	if s.Head == "" {
		return
	}
	files, _ := filepath.Glob(c.path + ".*")
	sort.Strings(files)
	for i, p := range files {
		if fileHead(p) == s.Head {
			log.Printf("Cowrie: lese rotierte Datei %s ab Position %d nach", filepath.Base(p), s.Off)
			c.drain(p, s.Off)
			for _, later := range files[i+1:] { // dazwischen rotierte Dateien vollständig
				c.drain(later, 0)
			}
			return
		}
	}
}

func (c *CowrieTail) Run() {
	go func() { // offene Sitzungen ohne "closed" aufräumen
		for c.sleep(5 * time.Minute) {
			c.mu.Lock()
			for k, v := range c.sessions {
				if time.Since(v.seen) > 2*time.Hour {
					delete(c.sessions, k)
				}
			}
			c.mu.Unlock()
		}
	}()

	var f *os.File
	var fi os.FileInfo
	var lr *lineReader
	var head string
	lastSave := time.Now()
	first := true

	open := func() bool {
		nf, err := openRegular(c.path)
		if err != nil {
			return false
		}
		nfi, err := nf.Stat()
		if err != nil {
			nf.Close()
			return false
		}
		h := fileHead(c.path)
		off := int64(0)
		if first {
			s := c.loadState()
			switch {
			case s.Head != "" && s.Head == h && s.Off <= nfi.Size():
				off = s.Off // gleiche Datei wie beim letzten Lauf
			case s.Head != "" && s.Head != h:
				c.catchUp(s) // inzwischen rotiert: alte Datei zu Ende lesen
			}
		}
		f, fi, head, lr = nf, nfi, h, newLineReader(nf, off)
		c.mu.Lock()
		c.found = true
		c.mu.Unlock()
		first = false
		return true
	}

	defer func() {
		if f != nil {
			c.saveState(tailState{Head: head, Off: lr.off})
			f.Close()
		}
	}()
	for {
		select {
		case <-c.stop:
			return
		default:
		}
		if f == nil {
			if !open() {
				if !c.sleep(5 * time.Second) {
					return
				}
				continue
			}
		}
		line, ok := lr.next()
		if ok {
			if line != nil {
				c.handle(line)
			}
			if head == "" && lr.off > 0 { // erste Zeile jetzt vollständig
				head = fileHead(c.path)
			}
			if time.Since(lastSave) > 2*time.Second {
				c.saveState(tailState{Head: head, Off: lr.off})
				lastSave = time.Now()
			}
			continue
		}
		if time.Since(lastSave) > 2*time.Second {
			c.saveState(tailState{Head: head, Off: lr.off})
			lastSave = time.Now()
		}
		if !c.sleep(time.Second) {
			return
		}
		nfi, err := os.Stat(c.path)
		if err != nil {
			continue
		}
		if !os.SameFile(fi, nfi) || nfi.Size() < lr.off {
			// Rotation: was seit dem letzten Lesen noch in die alte Datei kam, mitnehmen
			for {
				line, ok := lr.next()
				if !ok {
					break
				}
				if line != nil {
					c.handle(line)
				}
			}
			f.Close()
			f = nil
			if open() {
				c.saveState(tailState{Head: head, Off: 0})
				log.Printf("Cowrie-Log rotiert, lese neue Datei")
			}
		}
	}
}

func str(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func num(m map[string]any, k string) float64 {
	switch v := m[k].(type) {
	case float64:
		return v
	case string:
		f, _ := strconv.ParseFloat(v, 64)
		return f
	}
	return 0
}

// Cowrie lauscht im Container auf 2222/2223; nach außen sind es SSH 22 und Telnet 23.
func cowriePort(p int) int {
	switch p {
	case 2222:
		return 22
	case 2223:
		return 23
	}
	return p
}

func (c *CowrieTail) handle(line []byte) {
	var m map[string]any
	if json.Unmarshal(line, &m) != nil {
		return
	}
	// Prüfverbindungen des Hive (probe.go) kommen von Loopback: keine Angriffe
	if ip := net.ParseIP(str(m, "src_ip")); ip != nil && ip.IsLoopback() {
		return
	}
	id := str(m, "eventid")
	sess := str(m, "session")
	ts, err := time.Parse(time.RFC3339Nano, str(m, "timestamp"))
	if err != nil {
		ts = time.Now()
	}
	sum := sha256.Sum256(line)
	e := &Event{EID: "c-" + hex.EncodeToString(sum[:12]), TS: ts, Sensor: c.sensor, SrcIP: str(m, "src_ip"),
		SrcPort: int(num(m, "src_port")), Session: sess}
	data := map[string]any{}

	c.mu.Lock()
	info := c.sessions[sess]
	if id == "cowrie.session.connect" {
		info = cowrieSess{service: str(m, "protocol"), dport: cowriePort(int(num(m, "dst_port"))), seen: ts}
		if info.service == "" {
			info.service = "ssh"
		}
		c.sessions[sess] = info
	}
	if id == "cowrie.session.closed" {
		delete(c.sessions, sess)
	}
	c.lastEvent = time.Now()
	c.mu.Unlock()

	e.Service = info.service
	if e.Service == "" {
		e.Service = "ssh"
	}
	e.DstPort = info.dport
	if e.DstPort == 0 {
		e.DstPort = 22
	}

	switch id {
	case "cowrie.session.connect":
		e.Type = "connect"
	case "cowrie.login.success", "cowrie.login.failed":
		e.Type = "login"
		e.Username, e.Password = str(m, "username"), str(m, "password")
		data["success"] = id == "cowrie.login.success"
	case "cowrie.command.input":
		e.Type = "command"
		data["input"] = clip(str(m, "input"), 4096)
	case "cowrie.session.file_download", "cowrie.session.file_download.failed":
		e.Type = "download"
		data["url"] = clip(str(m, "url"), 2048)
		data["sha256"] = str(m, "shasum")
		data["failed"] = id != "cowrie.session.file_download"
	case "cowrie.session.file_upload":
		e.Type = "download"
		data["filename"] = clip(str(m, "filename"), 512)
		data["sha256"] = str(m, "shasum")
		data["upload"] = true
	case "cowrie.client.version":
		e.Type = "client_version"
		data["version"] = clip(str(m, "version"), 256)
	case "cowrie.client.kex":
		e.Type = "fingerprint"
		data["hassh"] = str(m, "hassh")
		data["hassh_algorithms"] = clip(str(m, "hasshAlgorithms"), 2048)
	case "cowrie.direct-tcpip.request":
		e.Type = "request"
		data["forward_to"] = str(m, "dst_ip") + ":" + strconv.Itoa(int(num(m, "dst_port")))
	case "cowrie.log.closed": // TTY-Mitschnitt fertig; die Datei liest tty.go auf Abruf
		if !sha256Re.MatchString(str(m, "shasum")) {
			return
		}
		e.Type = "tty"
		data["shasum"] = str(m, "shasum")
		data["size"] = int64(num(m, "size"))
		data["duration_s"] = num(m, "duration")
	case "cowrie.session.closed":
		e.Type = "disconnect"
		e.DurationMs = int64(num(m, "duration") * 1000)
	default:
		return
	}
	if len(data) > 0 {
		e.Data, _ = json.Marshal(data)
	}
	if e.Sanitize() == nil {
		c.submit(e)
	}
}
