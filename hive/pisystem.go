package main

// Systemdateien des Raspberry-Pi-Images aktualisieren, ohne neu zu flashen.
//
// Das Programmpaket einer Veröffentlichung enthält neben hive und honeypot den Ordner
// system/ mit den systemd-Diensten, den Skripten unter /usr/local/sbin und den
// Systembenutzern (Kopie aus pi/rootfs). Der Updater (hivornet-update, root) ruft
// "hive install-system <ordner>" auf und übernimmt sie so.
//
// Ältere Updater kennen system/ nicht, starten aber das neue Programm einmal als root
// mit "hive version" zur Probe. Dabei installiert es die Systemdateien selbst
// (selfInstallSystem), damit auch diese Geräte ohne neues Image auf den neuen Stand
// kommen. Das Paket ist zu diesem Zeitpunkt schon über die SHA-256-Prüfsumme der
// Veröffentlichung geprüft; es gilt also dasselbe Vertrauen wie für das Programm selbst.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// Nur diese Dateien werden übernommen; Einstellungen unter /etc/hivornet nie überschrieben.
func systemFileAllowed(rel string) (mode os.FileMode, ok bool) {
	dir, name := path.Split(rel)
	switch {
	case dir == "etc/systemd/system/" && strings.HasPrefix(name, "hivornet-") &&
		(strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".path") || strings.HasSuffix(name, ".timer")):
		return 0o644, true
	case dir == "usr/local/sbin/" && strings.HasPrefix(name, "hivornet-") && !strings.Contains(name, "."):
		return 0o755, true
	case rel == "usr/lib/sysusers.d/hivornet.conf":
		return 0o644, true
	case dir == "etc/NetworkManager/conf.d/" && strings.HasPrefix(name, "hivornet-") && strings.HasSuffix(name, ".conf"):
		return 0o644, true
	// Schutz gegen Hänger (0.9.6): Protokoll auf der Karte, Watchdog, wenig Auslagern
	case rel == "etc/systemd/journald.conf.d/hivornet.conf", rel == "etc/systemd/system.conf.d/hivornet-watchdog.conf",
		rel == "etc/sysctl.d/90-hivornet.conf":
		return 0o644, true
	}
	return 0, false
}

// cmdlinePaths: Kernel-Befehlszeile des Raspberry Pi (Bookworm/Trixie bzw. ältere Images).
var cmdlinePaths = []string{"/boot/firmware/cmdline.txt", "/boot/cmdline.txt"}

// memCgroupArgs schalten die Speicherverwaltung der cgroups ein; erst damit greifen die
// Speichergrenzen der Dienste (MemoryMax). Raspberry Pi OS lässt sie ab Werk aus.
const memCgroupArgs = "cgroup_enable=memory cgroup_memory=1"

// ensureMemCgroup ergänzt memCgroupArgs in der ersten vorhandenen cmdline.txt (eine Zeile,
// vorher Kopie als .hivornet-alt). true = geändert, wirkt nach dem nächsten Neustart.
func ensureMemCgroup(paths []string) (bool, string, error) {
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		line := strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
		if line == "" {
			return false, p, fmt.Errorf("%s ist leer", p)
		}
		if strings.Contains(line, "cgroup_enable=memory") {
			return false, p, nil
		}
		if err := os.WriteFile(p+".hivornet-alt", b, 0o644); err != nil {
			return false, p, err
		}
		tmp := p + ".neu"
		if err := os.WriteFile(tmp, []byte(line+" "+memCgroupArgs+"\n"), 0o644); err != nil {
			return false, p, err
		}
		return true, p, os.Rename(tmp, p)
	}
	return false, "", nil // keine cmdline.txt: kein Raspberry Pi
}

// installSystem kopiert erlaubte Dateien aus src nach root (atomar über Umbenennen, damit
// ein gerade laufendes Skript wie der Updater selbst nicht mittendrin verändert wird).
// Liefert die geänderten Dateien (relativ).
func installSystem(src, root string) ([]string, error) {
	var changed []string
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(src, p)
		rel = filepath.ToSlash(rel)
		mode, ok := systemFileAllowed(rel)
		if !ok || d.Type()&os.ModeSymlink != 0 || !d.Type().IsRegular() {
			return nil // anderes überspringen
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		dst := filepath.Join(root, filepath.FromSlash(rel))
		if old, err := os.ReadFile(dst); err == nil && string(old) == string(data) {
			return nil // unverändert
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		tmp := dst + ".neu"
		if err := os.WriteFile(tmp, data, mode); err != nil {
			return err
		}
		os.Chmod(tmp, mode)
		if err := os.Rename(tmp, dst); err != nil {
			os.Remove(tmp)
			return err
		}
		changed = append(changed, rel)
		return nil
	})
	return changed, err
}

// ensureCowrieAuth trägt in cowrie.cfg die Anmelderegel ein, falls keine festgelegt ist
// (ältere Images: Cowrie nahm sonst jede Kombination sofort an). true = geändert.
func ensureCowrieAuth(cfg string) (bool, error) {
	b, err := os.ReadFile(cfg)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if !cowrieAcceptsAll(cfg) {
		return false, nil
	}
	return true, writeCowrieAuth(cfg, string(b), "AuthRandom", "2, 5, 10")
}

// writeCowrieAuth setzt auth_class (und Parameter) im Abschnitt [honeypot].
func writeCowrieAuth(cfg, content, class, params string) error {
	var out []string
	inserted := false
	for _, line := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "auth_class") { // alte Regel samt Parametern entfernen
			continue
		}
		out = append(out, line)
		if t == "[honeypot]" && !inserted {
			out = append(out, "auth_class = "+class)
			if params != "" {
				out = append(out, "auth_class_parameters = "+params)
			}
			inserted = true
		}
	}
	if !inserted {
		out = append(out, "", "[honeypot]", "auth_class = "+class)
		if params != "" {
			out = append(out, "auth_class_parameters = "+params)
		}
	}
	tmp := cfg + ".neu"
	if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, cfg)
}

// applySystem: nach dem Kopieren Systembenutzer anlegen, systemd neu laden, neue
// Beobachter (.path) einschalten und die Cowrie-Anmelderegel sicherstellen.
func applySystem(changed []string, run func(string, ...string) error, w io.Writer) {
	sysusers := false
	for _, c := range changed {
		if strings.HasPrefix(c, "usr/lib/sysusers.d/") {
			sysusers = true
		}
	}
	if sysusers {
		run("systemd-sysusers", "/usr/lib/sysusers.d/hivornet.conf")
	}
	run("systemctl", "daemon-reload")
	applyFailsafe(changed, run, w)
	for _, c := range changed {
		if strings.HasPrefix(c, "etc/systemd/system/") && strings.HasSuffix(c, ".path") {
			if err := run("systemctl", "enable", "--now", path.Base(c)); err != nil {
				fmt.Fprintf(w, "Einschalten von %s: %v\n", path.Base(c), err)
			}
			// lief er schon, beobachtet er neue Pfade (z. B. brute-request) erst nach einem Neustart
			run("systemctl", "restart", path.Base(c))
		}
	}
	// Neue Zeitgeber, die schon laufende Geräte brauchen (Sperrliste der Drossel, Arbeitsspeicher
	// der Dienste für die Web-UI)
	for _, c := range changed {
		if t := path.Base(c); c == "etc/systemd/system/"+t && (t == "hivornet-brute-bans.timer" || t == "hivornet-memstat.timer") {
			if err := run("systemctl", "enable", "--now", t); err != nil {
				fmt.Fprintf(w, "Einschalten von %s: %v\n", t, err)
			}
		}
	}
	// Geänderte Netzsperre sofort anwenden, nicht erst nach dem nächsten Neustart (M8 des
	// dritten Audits). Direkt "apply" statt "systemctl restart": restart ruft vorher ExecStop
	// (remove) auf, der Honeypot liefe kurz ohne Sperre; apply ersetzt die Regeln in einem
	// Schritt (nft -f).
	for _, c := range changed {
		if c == "usr/local/sbin/hivornet-firewall" || c == "etc/systemd/system/hivornet-firewall.service" {
			if err := run("/usr/local/sbin/hivornet-firewall", "apply"); err != nil {
				fmt.Fprintf(w, "Netzsperre neu setzen: %v\n", err)
			} else {
				fmt.Fprintln(w, "Netzsperre neu gesetzt")
			}
			break
		}
	}
	// Geänderte Cowrie-Dienstdatei (z. B. neue Ordner unter StateDirectory=) wirkt erst nach
	// einem Neustart; try-restart lässt einen ausgeschalteten Dienst aus.
	cowrieRestart := false
	for _, c := range changed {
		if c == "etc/systemd/system/hivornet-cowrie.service" {
			cowrieRestart = true
		}
	}
	if ch, err := ensureCowrieAuth(cowrieCfgPath); err != nil {
		fmt.Fprintf(w, "Cowrie-Anmelderegel: %v\n", err)
	} else if ch {
		cowrieRestart = true
		fmt.Fprintln(w, "Cowrie: Anmeldung erst nach 2 bis 5 Versuchen je IP eingestellt")
	}
	if cowrieRestart {
		if err := run("systemctl", "try-restart", "hivornet-cowrie.service"); err != nil {
			fmt.Fprintf(w, "Cowrie neu starten: %v\n", err)
		}
	}
	// Geändertes Installationsskript (Anpassungen an Cowrie, Token für die KI-Antworten): Auf
	// einem Gerät mit fertigem Cowrie startet hivornet-cowrie-install.service nie wieder
	// (ConditionPathExists=!…/.hivornet-ok). Das Skript trägt im installierten Zustand nur
	// fehlende Anpassungen und das Token nach, ohne Internet, und startet Cowrie selbst neu.
	for _, c := range changed {
		if c == "usr/local/sbin/hivornet-cowrie-install" {
			if _, err := os.Stat(cowrieInstalledMark); err != nil {
				break // noch nicht installiert: das erledigt der Installationsdienst
			}
			if err := run("/usr/local/sbin/hivornet-cowrie-install"); err != nil {
				fmt.Fprintf(w, "Cowrie-Anpassungen nachtragen: %v\n", err)
			} else {
				fmt.Fprintln(w, "Cowrie-Anpassungen nachgetragen")
			}
			break
		}
	}
}

// applyFailsafe wendet die Schutzeinstellungen gegen Hänger an (0.9.6): Protokoll auf der
// Karte, Watchdog, wenig Auslagern und die Speicherverwaltung der cgroups.
func applyFailsafe(changed []string, run func(string, ...string) error, w io.Writer) {
	for _, c := range changed {
		switch c {
		case "etc/systemd/journald.conf.d/hivornet.conf":
			os.MkdirAll("/var/log/journal", 0o755)
			run("systemd-tmpfiles", "--create", "--prefix", "/var/log/journal")
			if err := run("systemctl", "restart", "systemd-journald"); err != nil {
				fmt.Fprintf(w, "Protokoll auf der Karte: %v\n", err)
			} else {
				run("journalctl", "--flush")
				fmt.Fprintln(w, "Systemprotokoll bleibt jetzt auf der Karte erhalten (höchstens 64 MB, 14 Tage)")
			}
		case "etc/systemd/system.conf.d/hivornet-watchdog.conf":
			if err := run("systemctl", "daemon-reexec"); err != nil {
				fmt.Fprintf(w, "Watchdog: %v\n", err)
			} else {
				fmt.Fprintln(w, "Hardware-Watchdog aktiv: bei einem Hänger startet der Pi selbst neu")
			}
		case "etc/sysctl.d/90-hivornet.conf":
			if err := run("sysctl", "--load", "/etc/sysctl.d/90-hivornet.conf"); err != nil {
				fmt.Fprintf(w, "Kernel-Einstellungen: %v\n", err)
			}
		}
	}
	if ch, p, err := ensureMemCgroup(cmdlinePaths); err != nil {
		fmt.Fprintf(w, "Speichergrenzen: %v\n", err)
	} else if ch {
		fmt.Fprintf(w, "Speichergrenzen in %s eingeschaltet; wirksam nach dem nächsten Neustart\n", p)
		os.MkdirAll("/var/lib/hivornet-status", 0o755)
		os.WriteFile("/var/lib/hivornet-status/reboot-needed", []byte("Speichergrenzen der Dienste\n"), 0o644)
	}
}

// cowrieInstalledMark: Merker der fertigen Cowrie-Installation (hivornet-cowrie-install); in Tests überschreibbar.
var cowrieInstalledMark = "/opt/hivornet/cowrie-env/.hivornet-ok"

func runCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, clip(strings.TrimSpace(string(out)), 300))
	}
	return nil
}

// cmdInstallSystem: "hive install-system <ordner>" (vom Updater als root aufgerufen).
func cmdInstallSystem(dir string) error {
	changed, err := installSystem(dir, "/")
	if err != nil {
		return err
	}
	for _, c := range changed {
		fmt.Println("aktualisiert: /" + c)
	}
	applySystem(changed, runCmd, os.Stdout)
	return nil
}

// selfInstallSystem: Aufruf als root durch einen älteren Updater ("hive version" zur Probe).
// Nur auf dem Pi (/etc/hivornet vorhanden) und nur, wenn neben dem Programm system/ liegt.
func selfInstallSystem() {
	if os.Getenv("HIVORNET_NO_SELFINSTALL") != "" || os.Geteuid() != 0 {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Join(filepath.Dir(exe), "system")
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return
	}
	if _, err := os.Stat("/etc/hivornet"); err != nil {
		return
	}
	var log strings.Builder
	changed, err := installSystem(dir, "/")
	if err != nil {
		fmt.Fprintf(&log, "Fehler: %v\n", err)
	} else {
		applySystem(changed, runCmd, &log)
		fmt.Fprintf(&log, "%d Systemdateien aktualisiert\n", len(changed))
	}
	// für die Fehlersuche: Stand neben dem Update-Status ablegen
	os.MkdirAll("/var/lib/hivornet-update", 0o755)
	os.WriteFile("/var/lib/hivornet-update/system", []byte(log.String()), 0o644)
}
