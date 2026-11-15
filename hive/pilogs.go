package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Protokolle und Installationsstand auf dem Raspberry Pi (ohne Docker).
//
// Auf dem Pi ist die Anmeldung an der Konsole gesperrt und SSH aus (Port 22 gehört
// Cowrie). Damit niemand einen Bildschirm anschließen muss, zeigt die Web-UI
//   - den Stand der Cowrie-Installation (Datei von hivornet-cowrie-install) und
//   - die Systemprotokolle der Hivornet-Dienste (journalctl, nur lesen).
// Nur für Admins. Abrufbar sind ausschließlich die Quellen aus logSources; aus der
// Anfrage gelangt nichts in die Befehlszeile außer der Zeilenzahl (als Zahl geprüft).
// Der Hive-Dienst braucht dafür die Gruppe systemd-journal (hivornet-hive.service).

type logSource struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	unit  string // systemd-Dienst für journalctl
	file  string // oder eine Datei
}

func logSources() []logSource {
	src := []logSource{
		{ID: "cowrie-install", Label: "Cowrie-Installation", unit: "hivornet-cowrie-install.service"},
		{ID: "cowrie", Label: "Cowrie (SSH/Telnet)", unit: "hivornet-cowrie.service"},
		{ID: "honeypot", Label: "Honeypot", unit: "hivornet-honeypot.service"},
		{ID: "hive", Label: "Hive (Web-UI)", unit: "hivornet-hive.service"},
		{ID: "firewall", Label: "Netzsperre", unit: "hivornet-firewall.service"},
		{ID: "update", Label: "Updates", unit: "hivornet-update.service"},
		{ID: "firstboot", Label: "Erster Start", unit: "hivornet-firstboot.service"},
	}
	if p := os.Getenv("HIVE_INSTALL_LOG"); p != "" {
		src = append(src, logSource{ID: "install", Label: "Installation (erster Start)", file: p})
	}
	return src
}

func logsEnabled() bool { return os.Getenv("HIVE_JOURNAL") == "1" }

// journalctlPath und journalArgsPrefix sind in Tests überschreibbar.
var (
	journalctlPath    = "journalctl"
	journalArgsPrefix []string
)

func (h *Hive) logsList(w http.ResponseWriter, r *http.Request) {
	if !logsEnabled() {
		writeJSON(w, map[string]any{"enabled": false, "sources": []logSource{}})
		return
	}
	writeJSON(w, map[string]any{"enabled": true, "sources": logSources()})
}

func (h *Hive) logsGet(w http.ResponseWriter, r *http.Request) {
	if !logsEnabled() {
		httpErr(w, 404, "Protokolle gibt es nur auf dem Raspberry Pi")
		return
	}
	var src *logSource
	for _, s := range logSources() {
		if s.ID == r.PathValue("id") {
			src = &s
			break
		}
	}
	if src == nil {
		httpErr(w, 404, "unbekannte Quelle")
		return
	}
	n, err := strconv.Atoi(r.URL.Query().Get("lines"))
	if err != nil || n <= 0 {
		n = 200
	}
	n = min(n, 2000)
	var text string
	if src.file != "" {
		text, err = tailFile(src.file, n)
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		text, err = journal(ctx, src.unit, n)
	}
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"id": src.ID, "text": text})
}

// limitBuf nimmt höchstens max Bytes auf und verwirft den Rest.
type limitBuf struct {
	bytes.Buffer
	max int
}

func (b *limitBuf) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func journal(ctx context.Context, unit string, n int) (string, error) {
	out := &limitBuf{max: 1 << 20}
	errb := &limitBuf{max: 4096}
	args := append(append([]string{}, journalArgsPrefix...), "--no-pager", "--quiet", "--output=short-iso", "--lines="+strconv.Itoa(n), "--unit="+unit)
	cmd := exec.CommandContext(ctx, journalctlPath, args...)
	cmd.Stdout, cmd.Stderr = out, errb
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && out.Len() > 0 {
			return out.String(), nil
		}
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", errors.New("Systemprotokoll nicht lesbar: " + clip(msg, 300))
	}
	if strings.TrimSpace(out.String()) == "" {
		return "(keine Einträge)", nil
	}
	return out.String(), nil
}

// tailFile liefert die letzten n Zeilen einer Datei (liest höchstens das letzte MB).
func tailFile(p string, n int) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "(Datei noch nicht vorhanden)", nil
		}
		return "", errors.New("Datei nicht lesbar")
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > 1<<20 {
		f.Seek(st.Size()-1<<20, io.SeekStart)
	}
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	return strings.Join(lines, "\n"), nil
}

// cowrieInstall ist der Stand von hivornet-cowrie-install (Datei: Zustand, Unix-Zeit, Text).
type cowrieInstall struct {
	State string    `json:"state"` // running, ok, failed
	Since time.Time `json:"since"`
	Text  string    `json:"text"`
}

func cowrieInstallStatus() *cowrieInstall {
	p := os.Getenv("HIVE_COWRIE_INSTALL_STATUS")
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil || len(b) > 4096 {
		return nil
	}
	f := strings.SplitN(strings.TrimRight(string(b), "\n"), "\n", 3)
	if len(f) < 3 {
		return nil
	}
	st := strings.TrimSpace(f[0])
	if st != "running" && st != "ok" && st != "failed" {
		return nil
	}
	sec, _ := strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64)
	return &cowrieInstall{State: st, Since: time.Unix(sec, 0), Text: clip(f[2], 300)}
}
