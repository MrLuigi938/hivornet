package main

import (
	"bufio"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Sicherung und Wiederherstellung über die Web-UI (System → Sicherung).
//
// Export: Der angemeldete Admin bestätigt mit seinem Passwort. Der Hive erstellt eine
// konsistente Kopie der Datenbank (VACUUM INTO): Einstellungen, Zusatzfunktionen mit
// allen API-Schlüsseln, Benutzer, Ereignisse, Angreifer, Statistiken, Abfrage-Ergebnisse.
// Nicht enthalten sind Anmeldesitzungen und der Lesestand des Cowrie-Logs (gehört zur
// alten Installation). Die Kopie wird mit gzip gepackt und verschlüsselt:
//
//	Kopf:   "HVBACKUP" | Version (1 Byte) | Salz (16) | Argon2id Zeit, Speicher (KiB), Threads (je 4)
//	        | Nonce-Präfix (4) | Länge der Metadaten (4) | Metadaten (JSON, unverschlüsselt)
//	Blöcke: Länge (4) | AES-256-GCM(Klartext ≤ 1 MiB); Nonce = Präfix | Blocknummer (8),
//	        Zusatzdaten = der ganze Kopf + Merker "letzter Block" (1 Byte)
//
// Der Schlüssel entsteht mit Argon2id aus dem Passwort. Ohne Passwort ist die Datei
// nicht lesbar; jede Änderung, jedes Abschneiden und jedes Umsortieren fällt auf.
//
// Import: Datei und das Passwort, mit dem sie erstellt wurde. Der Hive entschlüsselt in
// eine temporäre Datei, prüft sie als SQLite-Datenbank (Integrität, Schema-Version, ein
// Admin vorhanden), legt sie als restore.db ab und startet neu. Beim Start sichert
// applyRestore die bisherige Datenbank nach backups/ und übernimmt restore.db.

const (
	backupMagic     = "HVBACKUP"
	backupVersion   = 1
	backupChunk     = 1 << 20
	backupMaxUpload = 4 << 30 // 4 GB
	backupMaxMeta   = 4096
)

// Argon2id-Parameter für neue Sicherungen (auf einem Pi 3 etwa eine Sekunde).
var backupKDF = struct{ time, memory, threads uint32 }{3, 64 * 1024, 2}

type backupMeta struct {
	Format   string    `json:"format"`
	Created  time.Time `json:"created"`
	Version  string    `json:"hive_version"`
	Schema   int       `json:"schema"`
	Events   int64     `json:"events"`
	Hostname string    `json:"host,omitempty"`
}

// backupMu: immer nur eine Sicherung oder Wiederherstellung gleichzeitig.
var backupMu sync.Mutex

func backupKey(pass string, salt []byte, t, m, p uint32) []byte {
	return argon2.IDKey([]byte(pass), salt, t, m, uint8(p), 32)
}

// ---- Verschlüsselung in Blöcken ----

type chunkWriter struct {
	w      io.Writer
	aead   cipher.AEAD
	prefix []byte
	head   []byte // Kopf als Zusatzdaten
	n      uint64
	buf    []byte
}

func (c *chunkWriter) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		k := min(backupChunk-len(c.buf), len(p))
		c.buf = append(c.buf, p[:k]...)
		p = p[k:]
		if len(c.buf) == backupChunk {
			if err := c.flush(false); err != nil {
				return 0, err
			}
		}
	}
	return total, nil
}

func (c *chunkWriter) nonce() []byte {
	nonce := make([]byte, 12)
	copy(nonce, c.prefix)
	binary.BigEndian.PutUint64(nonce[4:], c.n)
	return nonce
}

func (c *chunkWriter) flush(last bool) error {
	ad := append(append([]byte{}, c.head...), 0)
	if last {
		ad[len(ad)-1] = 1
	}
	ct := c.aead.Seal(nil, c.nonce(), c.buf, ad)
	c.n++
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(ct)))
	if _, err := c.w.Write(l[:]); err != nil {
		return err
	}
	_, err := c.w.Write(ct)
	c.buf = c.buf[:0]
	return err
}

// Close schreibt den letzten (eventuell leeren) Block mit Merker.
func (c *chunkWriter) Close() error { return c.flush(true) }

type chunkReader struct {
	r      io.Reader
	aead   cipher.AEAD
	prefix []byte
	head   []byte
	n      uint64
	buf    []byte
	done   bool
}

var errBackupAuth = errors.New("Passwort falsch oder Datei beschädigt")

func (c *chunkReader) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		if c.done {
			return 0, io.EOF
		}
		var l [4]byte
		if _, err := io.ReadFull(c.r, l[:]); err != nil {
			return 0, errors.New("Datei unvollständig")
		}
		size := binary.BigEndian.Uint32(l[:])
		if size > backupChunk+uint32(c.aead.Overhead()) {
			return 0, errBackupAuth
		}
		ct := make([]byte, size)
		if _, err := io.ReadFull(c.r, ct); err != nil {
			return 0, errors.New("Datei unvollständig")
		}
		nonce := make([]byte, 12)
		copy(nonce, c.prefix)
		binary.BigEndian.PutUint64(nonce[4:], c.n)
		ad := append(append([]byte{}, c.head...), 0)
		pt, err := c.aead.Open(nil, nonce, ct, ad)
		if err != nil { // vielleicht der letzte Block
			ad[len(ad)-1] = 1
			if pt, err = c.aead.Open(nil, nonce, ct, ad); err != nil {
				return 0, errBackupAuth
			}
			c.done = true
		}
		c.n++
		c.buf = pt
	}
	k := copy(p, c.buf)
	c.buf = c.buf[k:]
	return k, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// writeBackup verschlüsselt den Inhalt von src (eine SQLite-Datei) nach w.
func writeBackup(w io.Writer, src io.Reader, pass string, meta backupMeta) error {
	salt := make([]byte, 16)
	prefix := make([]byte, 4)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := rand.Read(prefix); err != nil {
		return err
	}
	mj, _ := json.Marshal(meta)
	head := []byte(backupMagic)
	head = append(head, backupVersion)
	head = append(head, salt...)
	head = binary.BigEndian.AppendUint32(head, backupKDF.time)
	head = binary.BigEndian.AppendUint32(head, backupKDF.memory)
	head = binary.BigEndian.AppendUint32(head, backupKDF.threads)
	head = append(head, prefix...)
	head = binary.BigEndian.AppendUint32(head, uint32(len(mj)))
	head = append(head, mj...)
	if _, err := w.Write(head); err != nil {
		return err
	}
	aead, err := newAEAD(backupKey(pass, salt, backupKDF.time, backupKDF.memory, backupKDF.threads))
	if err != nil {
		return err
	}
	cw := &chunkWriter{w: w, aead: aead, prefix: prefix, head: head}
	gz, _ := gzip.NewWriterLevel(cw, gzip.BestSpeed)
	if _, err := io.Copy(gz, src); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return cw.Close()
}

// readBackup liest den Kopf und liefert Metadaten und einen Leser für den Klartext.
func readBackup(r io.Reader, pass string) (backupMeta, io.Reader, error) {
	var meta backupMeta
	fixed := make([]byte, len(backupMagic)+1+16+12+4+4)
	if _, err := io.ReadFull(r, fixed); err != nil || string(fixed[:len(backupMagic)]) != backupMagic {
		return meta, nil, errors.New("keine Hivornet-Sicherung")
	}
	p := fixed[len(backupMagic):]
	if p[0] != backupVersion {
		return meta, nil, fmt.Errorf("Sicherungsformat %d wird nicht unterstützt", p[0])
	}
	salt := p[1:17]
	t := binary.BigEndian.Uint32(p[17:21])
	m := binary.BigEndian.Uint32(p[21:25])
	th := binary.BigEndian.Uint32(p[25:29])
	prefix := p[29:33]
	ml := binary.BigEndian.Uint32(p[33:37])
	// Grenzen, damit eine manipulierte Datei den Hive nicht lahmlegt
	if t < 1 || t > 10 || m < 8*1024 || m > 256*1024 || th < 1 || th > 8 || ml > backupMaxMeta {
		return meta, nil, errors.New("ungültige Sicherung")
	}
	mj := make([]byte, ml)
	if _, err := io.ReadFull(r, mj); err != nil {
		return meta, nil, errors.New("Datei unvollständig")
	}
	if json.Unmarshal(mj, &meta) != nil {
		return meta, nil, errors.New("ungültige Sicherung")
	}
	aead, err := newAEAD(backupKey(pass, salt, t, m, th))
	if err != nil {
		return meta, nil, err
	}
	head := append(append([]byte{}, fixed...), mj...)
	cr := &chunkReader{r: r, aead: aead, prefix: prefix, head: head}
	// Ersten Block sofort prüfen, damit ein falsches Passwort früh auffällt
	br := bufio.NewReaderSize(cr, 64<<10)
	if _, err := br.Peek(1); err != nil && !errors.Is(err, io.EOF) {
		return meta, nil, err
	}
	gz, err := gzip.NewReader(br)
	if err != nil {
		return meta, nil, errBackupAuth
	}
	return meta, gz, nil
}

// ---- HTTP ----

func (h *Hive) backupDir() string { return filepath.Join(filepath.Dir(h.dbPath), "backups") }

// backupExport: POST /api/backup/export {"password": "..."} liefert die verschlüsselte Datei.
func (h *Hive) backupExport(w http.ResponseWriter, r *http.Request) {
	var req struct{ Password string }
	if readJSON(w, r, &req) != nil {
		httpErr(w, 400, "ungültige Anfrage")
		return
	}
	ip := clientIP(r)
	if !h.auth.attempt(ip) { // N4 des dritten Audits: gleiche Drossel wie beim Login
		httpErr(w, 429, "zu viele Fehlversuche, bitte 15 Minuten warten")
		return
	}
	if len(req.Password) > maxPasswordLen || !h.auth.Check(h.auth.User(r), req.Password) {
		time.Sleep(time.Second)
		httpErr(w, 403, "Passwort ist falsch")
		return
	}
	h.auth.success(ip)
	if !backupMu.TryLock() {
		httpErr(w, 409, "Es läuft schon eine Sicherung oder Wiederherstellung")
		return
	}
	defer backupMu.Unlock()
	dir := h.backupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		httpErr(w, 500, "Ordner für Sicherungen: "+err.Error())
		return
	}
	snap := filepath.Join(dir, fmt.Sprintf("export-%d.tmp", time.Now().UnixNano()))
	defer os.Remove(snap)
	if _, err := h.st.db.ExecContext(r.Context(), `VACUUM INTO ?`, snap); err != nil {
		httpErr(w, 500, "Kopie der Datenbank: "+err.Error())
		return
	}
	meta, err := prepareSnapshot(snap)
	if err != nil {
		httpErr(w, 500, "Kopie der Datenbank: "+err.Error())
		return
	}
	meta.Created = time.Now().UTC()
	meta.Version = version
	meta.Hostname, _ = os.Hostname()
	f, err := os.Open(snap)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer f.Close()
	name := "hivornet-sicherung-" + hiveNow().Format("2006-01-02-1504") + ".hvbak"
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	if err := writeBackup(w, f, req.Password, meta); err != nil {
		log.Printf("Sicherung abgebrochen: %v", err) // Kopf ist schon gesendet; der Browser sieht den Abbruch
		return
	}
	log.Printf("Sicherung exportiert (%d Ereignisse)", meta.Events)
}

// prepareSnapshot entfernt aus der Kopie, was nicht zur neuen Installation gehört,
// und liest die Metadaten.
func prepareSnapshot(path string) (backupMeta, error) {
	meta := backupMeta{Format: "sqlite"}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return meta, err
	}
	defer db.Close()
	for _, q := range []string{
		`DELETE FROM auth_sessions`,
		`DELETE FROM kv WHERE k IN ('cowrie_state', 'cowrie_offset')`,
		`VACUUM`,
	} {
		if _, err := db.Exec(q); err != nil {
			return meta, err
		}
	}
	db.QueryRow(`PRAGMA user_version`).Scan(&meta.Schema)
	db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&meta.Events)
	return meta, nil
}

// backupImport: POST /api/backup/import, multipart mit den Feldern "password" und "file"
// (in dieser Reihenfolge). Antwortet nach erfolgreicher Prüfung und startet den Hive neu.
func (h *Hive) backupImport(w http.ResponseWriter, r *http.Request) {
	if !backupMu.TryLock() {
		httpErr(w, 409, "Es läuft schon eine Sicherung oder Wiederherstellung")
		return
	}
	defer backupMu.Unlock()
	r.Body = http.MaxBytesReader(w, r.Body, backupMaxUpload)
	mr, err := r.MultipartReader()
	if err != nil {
		httpErr(w, 400, "ungültige Anfrage")
		return
	}
	part, err := mr.NextPart()
	if err != nil || part.FormName() != "password" {
		httpErr(w, 400, "Passwort fehlt")
		return
	}
	pb, _ := io.ReadAll(io.LimitReader(part, maxPasswordLen+1))
	pass := string(pb)
	if pass == "" || len(pass) > maxPasswordLen {
		httpErr(w, 400, "Passwort fehlt")
		return
	}
	part, err = mr.NextPart()
	if err != nil || part.FormName() != "file" {
		httpErr(w, 400, "Datei fehlt")
		return
	}
	meta, plain, err := readBackup(part, pass)
	if err != nil {
		if errors.Is(err, errBackupAuth) {
			time.Sleep(time.Second)
			httpErr(w, 403, err.Error())
			return
		}
		httpErr(w, 400, err.Error())
		return
	}
	dir := filepath.Dir(h.dbPath)
	tmp := filepath.Join(dir, "restore.db.tmp")
	defer os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	// Größengrenze nach dem Entpacken (N8 des dritten Audits): Eine kleine, stark komprimierte
	// Datei könnte sonst den Datenträger füllen. Größer als die erlaubte Datenbank plus Reserve
	// kann eine echte Sicherung nicht sein.
	limit := restoreLimit(h.maxDBBytes)
	var n int64
	n, err = io.Copy(f, io.LimitReader(plain, limit+1))
	if err == nil && n > limit {
		err = fmt.Errorf("entpackt größer als %d MB (HIVE_MAX_DB_MB)", limit>>20)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		if errors.Is(err, errBackupAuth) {
			httpErr(w, 403, err.Error())
			return
		}
		httpErr(w, 400, "Sicherung nicht lesbar: "+err.Error())
		return
	}
	if err := checkRestoreDB(tmp); err != nil {
		httpErr(w, 400, "Sicherung ungültig: "+err.Error())
		return
	}
	if err := os.Rename(tmp, filepath.Join(dir, "restore.db")); err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	log.Printf("Sicherung vom %s (%d Ereignisse) angenommen, starte neu", meta.Created.Format(time.RFC3339), meta.Events)
	writeJSON(w, map[string]any{"ok": true, "meta": meta})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	if h.restart != nil {
		go func() {
			time.Sleep(500 * time.Millisecond)
			select {
			case h.restart <- struct{}{}:
			default:
			}
		}()
	}
}

// restoreLimit: größte entpackte Sicherung (erlaubte Datenbankgröße plus 25 %, mindestens
// restoreMin).
func restoreLimit(maxDB int64) int64 {
	if maxDB <= 0 {
		maxDB = 2048 << 20
	}
	return max(maxDB+maxDB/4, restoreMin)
}

var restoreMin int64 = 256 << 20 // Variable nur für Tests

// checkRestoreDB prüft eine entschlüsselte Sicherung, bevor sie die Datenbank ersetzt.
func checkRestoreDB(path string) error {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	var res string
	if err := db.QueryRow(`PRAGMA quick_check`).Scan(&res); err != nil || res != "ok" {
		return errors.New("Datenbank beschädigt")
	}
	var v int
	db.QueryRow(`PRAGMA user_version`).Scan(&v)
	if v < 1 || v > len(migrations) {
		return fmt.Errorf("Schema-Version %d passt nicht zu diesem Hive (bis %d); erst Hivornet aktualisieren", v, len(migrations))
	}
	var n int
	q := `SELECT COUNT(*) FROM users`
	if v >= 4 {
		q += ` WHERE role = 'admin'`
	}
	if err := db.QueryRow(q).Scan(&n); err != nil || n == 0 {
		return errors.New("kein Admin-Konto enthalten")
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n); err != nil {
		return errors.New("Tabelle events fehlt")
	}
	return nil
}
