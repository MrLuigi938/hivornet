package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Jedes Profil ist vollständig und widerspruchsfrei: Telnet (uname, /proc/cpuinfo), Redis INFO
// und Docker /version und /info melden dieselbe Architektur und denselben Kernel.
func TestProfilesConsistent(t *testing.T) {
	for name, p := range profiles {
		v := reflect.ValueOf(p)
		for i := 0; i < v.NumField(); i++ {
			if f := v.Field(i); f.IsZero() && v.Type().Field(i).Name != "HTTPServer" {
				t.Errorf("%q: Feld %s leer", name, v.Type().Field(i).Name)
			}
		}
		if _, ok := dockerBuilds[p.DockerVer]; !ok {
			t.Errorf("%q: Docker %s fehlt in dockerBuilds", name, p.DockerVer)
		}
		cpuMark := map[string]string{"x86_64": "vendor_id\t:", "aarch64": "CPU architecture: 8", "armv7l": "CPU architecture: 7", "mips": "cpu model\t\t: MIPS"}[p.Arch]
		if cpuMark == "" || !strings.Contains(p.CPUInfo, cpuMark) {
			t.Errorf("%q: CPUInfo passt nicht zu %s", name, p.Arch)
		}
		if strings.Contains(p.FTPBanner, "2.3.4") {
			t.Errorf("%q: vsFTPd 2.3.4 ist eine bekannte Honeypot-Kennung", name)
		}

		ua := telnetReply(p, "h", "uname -a")
		want := "Linux h " + p.Kernel + " " + p.KernelBuild + " " + p.Arch
		if !strings.HasPrefix(ua, want) || !strings.HasSuffix(ua, " GNU/Linux\r\n") {
			t.Errorf("%q: uname -a = %q, erwartet Anfang %q", name, ua, want)
		}
		if got := telnetReply(p, "h", "uname -m;busybox uname -r"); got != p.Arch+"\r\n"+p.Kernel+"\r\n" {
			t.Errorf("%q: uname -m/-r = %q", name, got)
		}
		if got := telnetReply(p, "h", "cat /proc/cpuinfo"); got != strings.ReplaceAll(p.CPUInfo, "\n", "\r\n") {
			t.Errorf("%q: cpuinfo über Telnet weicht ab", name)
		}

		info := redisInfo(p, "server")
		if !strings.Contains(info, "os:Linux "+p.Kernel+" "+p.Arch+"\r\n") {
			t.Errorf("%q: Redis os-Zeile passt nicht: %q", name, info)
		}
		if bits := map[bool]string{true: "arch_bits:64", false: "arch_bits:32"}[p.Arch == "x86_64" || p.Arch == "aarch64"]; !strings.Contains(info, bits) {
			t.Errorf("%q: Redis %s fehlt", name, bits)
		}
		if !strings.Contains(pgVersion(p), p.gnuTriple()) {
			t.Errorf("%q: PostgreSQL-Version ohne %s", name, p.gnuTriple())
		}

		m := testManager()
		key := name
		m.profile.Store(&key)
		var di struct {
			Architecture, KernelVersion, OperatingSystem string
			NCPU                                         int
		}
		json.Unmarshal([]byte(dockerGet(t, m, "/info")), &di)
		if di.Architecture != p.Arch || di.KernelVersion != p.Kernel || di.OperatingSystem != p.OSName || di.NCPU != p.nCPU() {
			t.Errorf("%q: Docker /info %+v", name, di)
		}
		var dv struct{ Arch, KernelVersion, ApiVersion string }
		json.Unmarshal([]byte(dockerGet(t, m, "/version")), &dv)
		if dv.Arch != p.goArch() || dv.KernelVersion != p.Kernel || dv.ApiVersion != p.docker().API {
			t.Errorf("%q: Docker /version %+v", name, dv)
		}
	}
}

func dockerGet(t *testing.T, m *Manager, path string) string {
	t.Helper()
	c, done := run(t, m, "dockerapi", "emulate")
	go func() { c.Write([]byte("GET " + path + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")) }()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	c.Close()
	waitDone(t, done, 5*time.Second)
	return string(body)
}

// Fehlerseiten passen zum Webserver des Profils.
func TestErrorPageStyle(t *testing.T) {
	if p := errorPage(404, "lighttpd/1.4.59", "/x"); !strings.Contains(p, "<?xml") || strings.Contains(p, "<center>") {
		t.Errorf("lighttpd: %q", p)
	}
	if p := errorPage(404, "Boa/0.94.14rc21", "/<x>"); !strings.Contains(p, "The requested URL /&lt;x&gt; was not found") {
		t.Errorf("Boa: %q", p)
	}
	if p := errorPage(405, "nginx/1.18.0 (Ubuntu)", "/"); !strings.Contains(p, "405 Not Allowed") || !strings.Contains(p, "<center>nginx/1.18.0 (Ubuntu)</center>") {
		t.Errorf("nginx: %q", p)
	}
}

// Jeder Profilschlüssel ist auch dem Hive (Validierung) und der Web-UI (Auswahl) bekannt.
func TestProfileListsInSync(t *testing.T) {
	for _, f := range []string{"../hive/sensors.go", "../hive/web/settings.js"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Skipf("%s nicht lesbar (Build ohne Hive-Quellen): %v", f, err)
		}
		for name := range profiles {
			if name != "" && !strings.Contains(string(b), `"`+name+`"`) {
				t.Errorf("Profil %q fehlt in %s", name, f)
			}
		}
	}
}
