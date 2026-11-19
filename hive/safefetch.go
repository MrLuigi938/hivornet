package main

// Abgesicherter Download von Dateien, die Angreifer nachladen wollten (samplecollect.go).
//
// Der Hive holt die Datei selbst; Honeypot und Cowrie bleiben ohne Internet. Schutz:
//   - Nur http und https (ftp und tftp nicht: kein eigener Client dafür, also gar nicht).
//   - Jede Verbindung, auch nach einer Weiterleitung, wird erst NACH der Namensauflösung
//     geprüft: Ziel darf keine private, lokale, Link-Local-, Multicast-, CGNAT- oder sonst
//     besondere Adresse sein, nicht das eigene Netz und nicht die eigene öffentliche IP.
//     Verbunden wird genau mit der geprüften Adresse (kein zweites Auflösen, kein DNS-Rebinding);
//     Dialer.Control prüft die tatsächliche Gegenstelle noch einmal.
//   - Kein Proxy aus der Umgebung (der würde die Prüfung umgehen), keine Kompression,
//     keine wiederverwendeten Verbindungen, höchstens 3 Weiterleitungen, Zeitgrenzen.
//   - Größe begrenzt (Content-Length und gelesene Bytes); HTML-Seiten werden verworfen.
//   - Gespeichert wird nur in den Quarantäne-Ordner (0700), Datei 0600, Name = SHA-256.
//     Nie entpackt, nie ausgeführt, nie über die Web-UI ausgeliefert.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// specialNets: Bereiche, die nie Ziel eines Downloads oder einer Meldung sind (IANA
// Special-Purpose Registry, dazu 6to4 und NAT64, die private IPv4-Adressen einbetten können).
var specialNets = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2002::/16",
		"fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// docNets: Dokumentationsadressen. Im Betrieb nie ein echtes Ziel; die Tests nutzen sie
// als "öffentliche" Adressen (shareAllowDocNets).
var docNets = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}

var shareAllowDocNets = false // nur Tests

// specialIP: Grund, warum die Adresse kein zulässiges Ziel ist ("" = zulässig). own ist die
// eigene öffentliche IP (exposure.go), falls bekannt.
func specialIP(ip netip.Addr, own string) string {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" {
		return "ungültige Adresse"
	}
	for _, n := range specialNets {
		if n.Contains(ip) {
			return "private oder besondere Adresse"
		}
	}
	if !ip.IsGlobalUnicast() {
		return "private oder besondere Adresse"
	}
	if !shareAllowDocNets {
		for _, n := range docNets {
			if n.Contains(ip) {
				return "Dokumentationsadresse"
			}
		}
	}
	if isOwnIP(ip.String()) {
		return "eigenes Netz"
	}
	if o, err := netip.ParseAddr(own); err == nil && o.Unmap() == ip {
		return "eigene öffentliche Adresse"
	}
	return ""
}

type safeFetcher struct {
	ownIP     string
	deny      func(netip.Addr) string
	lookup    func(ctx context.Context, host string) ([]netip.Addr, error)
	userAgent string
	maxBytes  int64
	timeout   time.Duration
}

func newSafeFetcher(ownIP, ua string, maxBytes int64) *safeFetcher {
	return &safeFetcher{
		ownIP: ownIP,
		deny:  func(ip netip.Addr) string { return specialIP(ip, ownIP) },
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		userAgent: ua, maxBytes: maxBytes, timeout: 60 * time.Second,
	}
}

var errFetchDenied = errors.New("Ziel nicht erlaubt")

func (f *safeFetcher) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		ips, err = f.lookup(lctx, host)
		cancel()
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("Name nicht auflösbar")
		}
	}
	// Liefert der Name auch nur eine unzulässige Adresse, gilt er als Ganzes nicht.
	for _, ip := range ips {
		if why := f.deny(ip); why != "" {
			return nil, fmt.Errorf("%w: %s", errFetchDenied, why)
		}
	}
	d := net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return errFetchDenied
		}
		if why := f.deny(ap.Addr()); why != "" {
			return fmt.Errorf("%w: %s", errFetchDenied, why)
		}
		return nil
	}}
	var last error
	for _, ip := range ips[:min(len(ips), 4)] {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

func (f *safeFetcher) client() *http.Client {
	tr := &http.Transport{
		Proxy:                  nil, // nie einen Proxy aus der Umgebung
		DialContext:            f.dial,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  20 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		ForceAttemptHTTP2:      false,
	}
	return &http.Client{Transport: tr, Timeout: f.timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("zu viele Weiterleitungen")
		}
		if why := fetchURLProblem(req.URL, f.ownIP); why != "" {
			return fmt.Errorf("%w: Weiterleitung (%s)", errFetchDenied, why)
		}
		req.Header.Del("Referer")
		return nil
	}}
}

// fetchURLProblem: Darf diese Adresse geholt werden? Prüft Schema und Namen; die Adresse
// selbst prüft dial nach der Auflösung.
func fetchURLProblem(u *url.URL, own string) string {
	if u.Scheme != "http" && u.Scheme != "https" {
		return "nur http und https"
	}
	if u.User != nil {
		return "Adresse mit Zugangsdaten"
	}
	return hostProblem(u, own)
}

type fetched struct {
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type,omitempty"`
	FinalHost   string `json:"final_host,omitempty"`
	New         bool   `json:"-"`
}

// fetchTo lädt raw in den Ordner dir. Die Datei heißt danach wie ihr SHA-256.
func (f *safeFetcher) fetchTo(ctx context.Context, raw, dir string) (fetched, error) {
	var out fetched
	u, err := url.Parse(raw)
	if err != nil {
		return out, errors.New("Adresse unlesbar")
	}
	if why := fetchURLProblem(u, f.ownIP); why != "" {
		return out, fmt.Errorf("%w: %s", errFetchDenied, why)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return out, errors.New("Adresse unlesbar")
	}
	req.Header.Set("User-Agent", f.userAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := f.client().Do(req)
	if err != nil {
		if errors.Is(err, errFetchDenied) {
			var ue *url.Error
			if errors.As(err, &ue) {
				return out, ue.Err
			}
			return out, err
		}
		if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
			return out, errors.New("Zeitüberschreitung")
		}
		return out, errors.New("nicht erreichbar")
	}
	defer resp.Body.Close()
	out.FinalHost = resp.Request.URL.Hostname()
	if resp.StatusCode != 200 {
		return out, fmt.Errorf("Server antwortet %d", resp.StatusCode)
	}
	if resp.ContentLength > f.maxBytes {
		return out, fmt.Errorf("zu groß (%d Bytes)", resp.ContentLength)
	}
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	out.ContentType = clip(ct, 80)
	if ct == "text/html" || ct == "application/xhtml+xml" {
		return out, errors.New("HTML-Seite statt Datei")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return out, errors.New("Quarantäne-Ordner nicht anlegbar")
	}
	os.Chmod(dir, 0o700)
	tmp, err := os.CreateTemp(dir, ".part-*")
	if err != nil {
		return out, errors.New("Quarantäne-Ordner nicht beschreibbar")
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // nach dem Umbenennen ohne Wirkung
	tmp.Chmod(0o600)
	hs := sha256.New()
	var head bytes.Buffer
	n, err := io.Copy(io.MultiWriter(tmp, hs, &limitedBuf{&head, 512}), io.LimitReader(resp.Body, f.maxBytes+1))
	cerr := tmp.Close()
	switch {
	case err != nil:
		return out, errors.New("Übertragung abgebrochen")
	case cerr != nil:
		return out, errors.New("Speichern fehlgeschlagen")
	case n > f.maxBytes:
		return out, fmt.Errorf("zu groß (mehr als %d Bytes)", f.maxBytes)
	case n == 0:
		return out, errors.New("leere Antwort")
	case looksHTML(head.Bytes()):
		return out, errors.New("HTML-Seite statt Datei")
	}
	out.SHA256, out.Size = hex.EncodeToString(hs.Sum(nil)), n
	final := filepath.Join(dir, out.SHA256)
	if _, err := os.Lstat(final); err == nil {
		return out, nil // schon vorhanden
	}
	if err := os.Rename(tmpName, final); err != nil {
		return out, errors.New("Speichern fehlgeschlagen")
	}
	out.New = true
	return out, nil
}

type limitedBuf struct {
	b   *bytes.Buffer
	max int
}

func (l *limitedBuf) Write(p []byte) (int, error) {
	if room := l.max - l.b.Len(); room > 0 {
		l.b.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

func looksHTML(b []byte) bool {
	s := strings.ToLower(strings.TrimSpace(string(b[:min(len(b), 256)])))
	return strings.HasPrefix(s, "<!doctype html") || strings.HasPrefix(s, "<html") || strings.HasPrefix(s, "<head")
}

// ---- Prüfung von Adressen (Melden und Holen) ----

// callbackDomains: Rückruf-Dienste von Scannern und Testwerkzeugen (interactsh, Burp …):
// keine Schadsoftware, nie melden und nie holen.
var callbackDomains = []string{"oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me", "interact.sh",
	"interactsh.com", "burpcollaborator.net", "oastify.com", "dnslog.cn", "dnslog.link", "ceye.io", "requestbin.net",
	"pipedream.net", "canarytokens.com", "webhook.site", "bxss.me", "xss.ht", "r87.me", "eyes.sh"}

// localSuffixes: Namen, die nur im eigenen Netz oder gar nicht auflösbar sind.
// numLabelRe: Endung aus Ziffern oder 0x…: kein Name, sondern eine IP in anderer Schreibweise.
var numLabelRe = regexp.MustCompile(`^(0x[0-9a-f]*|[0-9]+)$`)

var localSuffixes = []string{"localhost", "local", "lan", "home", "internal", "intranet", "localdomain", "home.arpa",
	"corp", "private", "test", "example", "invalid", "onion", "arpa"}

// hostProblem: Grund, warum der Host kein Ziel ist ("" = in Ordnung).
func hostProblem(u *url.URL, own string) string {
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return "ohne Host"
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "ungültiger Port"
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return specialIP(ip, own)
	}
	// Zahlen in anderer Schreibweise (0x7f.1, 2130706433) lösen manche Programme als IP auf
	labels := strings.Split(host, ".")
	if len(labels) < 2 || numLabelRe.MatchString(labels[len(labels)-1]) {
		return "kein gültiger Name"
	}
	for _, r := range host {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_') {
			return "kein gültiger Name"
		}
	}
	for _, s := range localSuffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return "lokaler Name"
		}
	}
	for _, s := range callbackDomains {
		if host == s || strings.HasSuffix(host, "."+s) {
			return "Rückruf-Adresse eines Scanners"
		}
	}
	return ""
}

// shareURLProblem: Darf die Adresse als Nachlade-Adresse gemeldet werden? Erlaubt sind
// http, https, ftp und tftp.
func shareURLProblem(raw, own string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 1024 {
		return "", "Länge"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "Adresse unlesbar"
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "http", "https", "ftp", "tftp":
	default:
		return "", "Schema " + u.Scheme
	}
	if why := hostProblem(u, own); why != "" {
		return "", why
	}
	return u.String(), ""
}
