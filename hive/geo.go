package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// Geo ordnet IP-Adressen Land, Stadt, Koordinaten und Netzbetreiber (ASN) zu.
// Datenquelle: DB-IP Lite (CC BY 4.0), monatlich aktualisiert, ohne Konto.
type Geo struct {
	mu      sync.RWMutex
	dir     string
	city    *maxminddb.Reader
	asn     *maxminddb.Reader
	updated time.Time
	status  string
}

type cityRec struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Lat float64 `maxminddb:"latitude"`
		Lon float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

type asnRec struct {
	Num uint   `maxminddb:"autonomous_system_number"`
	Org string `maxminddb:"autonomous_system_organization"`
}

func NewGeo(dir string) *Geo {
	g := &Geo{dir: dir, status: "nicht geladen"}
	os.MkdirAll(dir, 0o755)
	g.load()
	return g
}

func (g *Geo) file(kind string) string { return filepath.Join(g.dir, "dbip-"+kind+"-lite.mmdb") }

func (g *Geo) load() {
	city, err1 := maxminddb.Open(g.file("city"))
	asn, err2 := maxminddb.Open(g.file("asn"))
	g.mu.Lock()
	defer g.mu.Unlock()
	if err1 == nil {
		if g.city != nil {
			g.city.Close()
		}
		g.city = city
		if fi, err := os.Stat(g.file("city")); err == nil {
			g.updated = fi.ModTime()
		}
	}
	if err2 == nil {
		if g.asn != nil {
			g.asn.Close()
		}
		g.asn = asn
	}
	switch {
	case g.city != nil && g.asn != nil:
		g.status = "geladen"
	case g.city != nil || g.asn != nil:
		g.status = "teilweise geladen"
	}
}

func (g *Geo) Status() (string, time.Time) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.status, g.updated
}

func pickName(names map[string]string) string {
	if n := names["de"]; n != "" {
		return n
	}
	return names["en"]
}

func (g *Geo) Enrich(e *Event) {
	ip := net.ParseIP(e.SrcIP)
	if ip == nil {
		return
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		e.Country, e.CountryName = "LAN", "Lokales Netz"
		return
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.city != nil {
		var r cityRec
		if g.city.Lookup(ip, &r) == nil {
			e.Country = r.Country.ISOCode
			e.CountryName = pickName(r.Country.Names)
			e.City = pickName(r.City.Names)
			e.Lat, e.Lon = r.Location.Lat, r.Location.Lon
		}
	}
	if g.asn != nil {
		var a asnRec
		if g.asn.Lookup(ip, &a) == nil {
			e.ASN, e.ASOrg = int(a.Num), a.Org
		}
	}
}

// AutoUpdate lädt die Datenbanken, wenn sie fehlen oder älter als 32 Tage sind.
func (g *Geo) AutoUpdate() {
	for {
		changed := false
		for _, kind := range []string{"city", "asn"} {
			fi, err := os.Stat(g.file(kind))
			if err == nil && time.Since(fi.ModTime()) < 32*24*time.Hour {
				continue
			}
			if err := g.download(kind); err != nil {
				log.Printf("GeoIP %s: %v", kind, err)
				g.mu.Lock()
				if g.city == nil {
					g.status = "Download fehlgeschlagen: " + err.Error()
				}
				g.mu.Unlock()
			} else {
				changed = true
			}
		}
		if changed {
			g.load()
			log.Printf("GeoIP-Datenbanken aktualisiert")
		}
		time.Sleep(24 * time.Hour)
	}
}

func (g *Geo) download(kind string) error {
	client := &http.Client{Timeout: 10 * time.Minute}
	var lastErr error
	now := time.Now().UTC()
	firstOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	for back := 0; back < 2; back++ {
		ym := firstOfMonth.AddDate(0, -back, 0).Format("2006-01") // vom Monatsersten aus, sonst springt der 31. falsch
		url := fmt.Sprintf("https://download.db-ip.com/free/dbip-%s-lite-%s.mmdb.gz", kind, ym)
		log.Printf("Lade GeoIP-Datenbank %s", url)
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			lastErr = fmt.Errorf("%s: %s", url, resp.Status)
			continue
		}
		err = func() error {
			defer resp.Body.Close()
			zr, err := gzip.NewReader(resp.Body)
			if err != nil {
				return err
			}
			tmp := g.file(kind) + ".tmp"
			f, err := os.Create(tmp)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, io.LimitReader(zr, 1<<30)); err != nil {
				f.Close()
				os.Remove(tmp)
				return err
			}
			f.Close()
			chk, err := maxminddb.Open(tmp)
			if err != nil {
				os.Remove(tmp)
				return fmt.Errorf("Datei ungültig: %w", err)
			}
			chk.Close()
			return os.Rename(tmp, g.file(kind))
		}()
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return lastErr
}
