package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// TTY-Mitschnitte von Cowrie. Cowrie schreibt je Shell-Sitzung eine Datei nach
// var/lib/cowrie/tty/<sha256> und meldet sie mit "cowrie.log.closed". Der Hive
// speichert dazu ein Ereignis vom Typ "tty" und liest die Datei erst, wenn die
// UI den Mitschnitt anfordert (Volume cowrie-lib, nur lesbar).
//
// Dateiformat (cowrie/core/ttylog.py, struct "<iLiiLL"): Folge von Sätzen mit
// 24 Byte Kopf, alles little-endian: op, tty, Länge, Richtung, Sekunden, Mikrosekunden;
// danach "Länge" Datenbytes. op 3 = Daten; Richtung 1 = Eingabe, 2 = Ausgabe.
//
// Angenommen aus dem Cowrie-Quelltext (3.1.x); gegen einen laufenden Container
// noch nicht geprüft.

const (
	ttyMaxFile   = 2 << 20   // so viel einer Datei wird höchstens gelesen
	ttyMaxOut    = 256 << 10 // so viel Text geht höchstens an die UI
	ttyMaxFrames = 4000
)

type ttyFrame struct {
	T   int64  `json:"t"` // Millisekunden seit Beginn
	Dir string `json:"d"` // "in" oder "out"
	S   string `json:"s"`
}

type ttyLog struct {
	Frames    []ttyFrame `json:"frames"`
	DurationM int64      `json:"duration_ms"`
	Truncated bool       `json:"truncated"`
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[@-_]`)

// ttyClean macht Terminal-Ausgabe zu schlichtem Text: Steuerfolgen entfernen,
// Zeilenenden vereinheitlichen, übrige Steuerzeichen verwerfen.
func ttyClean(b []byte) string {
	s := ansiRe.ReplaceAllString(string(b), "")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		// auch ein einzelnes \r (Eingabetaste des Angreifers; den Umbruch liefert die Ausgabe)
		case r < 32 || r == 127 || r == utf8.RuneError:
			return -1
		}
		return r
	}, s)
	return s
}

// parseTTYLog liest einen Mitschnitt. Fehlerhafte oder abgeschnittene Dateien
// liefern, was bis dahin lesbar war.
func parseTTYLog(r io.Reader) ttyLog {
	var out ttyLog
	lr := io.LimitReader(r, ttyMaxFile)
	hdr := make([]byte, 24)
	var start int64 = -1
	total := 0
	for {
		if _, err := io.ReadFull(lr, hdr); err != nil {
			break
		}
		op := int32(binary.LittleEndian.Uint32(hdr[0:]))
		n := int(binary.LittleEndian.Uint32(hdr[8:]))
		dir := binary.LittleEndian.Uint32(hdr[12:])
		ms := int64(binary.LittleEndian.Uint32(hdr[16:]))*1000 + int64(binary.LittleEndian.Uint32(hdr[20:]))/1000
		if n < 0 || n > ttyMaxFile {
			out.Truncated = true
			break
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(lr, data); err != nil {
			out.Truncated = true
			break
		}
		if start < 0 {
			start = ms
		}
		out.DurationM = ms - start
		if op != 3 || n == 0 || (dir != 1 && dir != 2) {
			continue
		}
		s := ttyClean(data)
		if s == "" {
			continue
		}
		if total+len(s) > ttyMaxOut || len(out.Frames) >= ttyMaxFrames {
			out.Truncated = true
			break
		}
		total += len(s)
		d := "out"
		if dir == 1 {
			d = "in"
		}
		// aufeinanderfolgende Stücke gleicher Richtung zusammenfassen (weniger Knoten in der UI)
		if k := len(out.Frames) - 1; k >= 0 && out.Frames[k].Dir == d && ms-start-out.Frames[k].T < 200 {
			out.Frames[k].S += s
			continue
		}
		out.Frames = append(out.Frames, ttyFrame{T: ms - start, Dir: d, S: s})
	}
	return out
}

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// sessionTTY liefert den Mitschnitt einer Cowrie-Sitzung als JSON.
func (h *Hive) sessionTTY(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := qctx(r)
	defer cancel()
	var data string
	err := h.st.db.QueryRowContext(ctx, `SELECT data FROM events WHERE session = ? AND type = 'tty' ORDER BY id DESC LIMIT 1`,
		r.PathValue("id")).Scan(&data)
	if err != nil {
		httpErr(w, 404, "Für diese Sitzung gibt es keinen Mitschnitt.")
		return
	}
	sum := dataString(json.RawMessage(data), "shasum")
	if h.cowrieLibDir == "" || !sha256Re.MatchString(sum) { // nur ein Hash als Dateiname, nie ein Pfad
		httpErr(w, 404, "Mitschnitt nicht verfügbar.")
		return
	}
	f, err := os.Open(filepath.Join(h.cowrieLibDir, "tty", sum))
	if err != nil {
		httpErr(w, 410, "Der Mitschnitt wurde bereits aufgeräumt (COWRIE_KEEP_DAYS).")
		return
	}
	defer f.Close()
	writeJSON(w, parseTTYLog(f))
}
