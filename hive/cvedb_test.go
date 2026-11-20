package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCVESources stellt KEV, NVD und EPSS nach und merkt sich jede Anfrage.
type fakeCVESources struct {
	mu      sync.Mutex
	queries []string
	kevHits int
	failNVD bool
}

func (f *fakeCVESources) start(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.queries = append(f.queries, r.URL.Path+"?"+r.URL.RawQuery+" "+r.Header.Get("If-None-Match"))
		fail := f.failNVD
		f.mu.Unlock()
		switch r.URL.Path {
		case "/kev.json":
			f.mu.Lock()
			f.kevHits++
			f.mu.Unlock()
			if r.Header.Get("If-None-Match") == `"v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			var vs []string
			vs = append(vs, `{"cveID":"CVE-2021-36260","vendorProject":"Hikvision","product":"Various Products","vulnerabilityName":"Hikvision Improper Input Validation","dateAdded":"2022-01-10","shortDescription":"x","requiredAction":"Apply updates","dueDate":"2022-01-24","knownRansomwareCampaignUse":"Known","cwes":["CWE-20"]}`)
			for i := 0; i < 20; i++ {
				vs = append(vs, fmt.Sprintf(`{"cveID":"CVE-2020-%04d","vendorProject":"V","product":"P","vulnerabilityName":"N","dateAdded":"2022-01-01","knownRansomwareCampaignUse":"Unknown"}`, 1000+i))
			}
			w.Header().Set("ETag", `"v1"`)
			io.WriteString(w, `{"catalogVersion":"2026.11.18","count":21,"vulnerabilities":[`+strings.Join(vs, ",")+`]}`)
		case "/nvd":
			if fail {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			id := r.URL.Query().Get("cveId")
			if id == "CVE-2099-0001" {
				io.WriteString(w, `{"totalResults":0,"vulnerabilities":[]}`)
				return
			}
			io.WriteString(w, `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"`+id+`","published":"2021-09-18T18:15:00.000",
				"descriptions":[{"lang":"es","value":"no"},{"lang":"en","value":"A command injection vulnerability in the web server."}],
				"metrics":{"cvssMetricV31":[{"source":"other","type":"Secondary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:H","baseScore":7.0,"baseSeverity":"HIGH"}},
				{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.8,"baseSeverity":"CRITICAL"}}],
				"cvssMetricV2":[{"cvssData":{"version":"2.0","baseScore":9.3}}]},
				"weaknesses":[{"description":[{"lang":"en","value":"CWE-78"}]}],
				"configurations":[{"nodes":[{"cpeMatch":[{"criteria":"cpe:2.3:o:hikvision:ds-2cd2026g2-i_firmware:*:*:*:*:*:*:*:*"}]}]}],
				"references":[{"url":"http://insecure.example/x"},{"url":"https://example.org/advisory"},{"url":"javascript:alert(1)"}]}}]}`)
		case "/epss":
			var data []string
			for _, id := range strings.Split(r.URL.Query().Get("cve"), ",") {
				if id != "CVE-2099-0001" {
					data = append(data, `{"cve":"`+id+`","epss":"0.943210000","percentile":"0.999","date":"2026-11-18"}`)
				}
			}
			io.WriteString(w, `{"status":"OK","data":[`+strings.Join(data, ",")+`]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	oldK, oldN, oldE, oldG := kevURL, nvdBase, epssBase, nvdGap
	kevURL, nvdBase, epssBase, nvdGap = srv.URL+"/kev.json", srv.URL+"/nvd", srv.URL+"/epss", 0
	t.Cleanup(func() { kevURL, nvdBase, epssBase, nvdGap = oldK, oldN, oldE, oldG })
	resetCVEQueue()
	t.Cleanup(resetCVEQueue)
}

func resetCVEQueue() {
	cveQ.mu.Lock()
	cveQ.pending, cveQ.set, cveQ.pause, cveQ.lastErr, cveQ.lastNVD = nil, map[string]bool{}, time.Time{}, "", time.Time{}
	cveQ.mu.Unlock()
}

func TestCVEDB(t *testing.T) {
	f := &fakeCVESources{}
	f.start(t)
	h := testHive(t)
	ctx := context.Background()

	// KEV: einlesen, beim zweiten Mal unverändert (ETag)
	if err := h.updateKEV(ctx); err != nil {
		t.Fatal(err)
	}
	if m := h.kevMeta(); m.Count != 21 || m.Version != "2026.11.18" || m.ETag != `"v1"` {
		t.Fatalf("KEV-Stand: %+v", m)
	}
	if err := h.updateKEV(ctx); err != nil || h.kevMeta().Count != 21 {
		t.Fatalf("unverändert: %v %+v", err, h.kevMeta())
	}

	// Abruf: KEV sofort da, NVD und EPSS stehen aus
	ids := []string{"CVE-2021-36260", "CVE-2099-0001"}
	info := h.cveInfos(ctx, ids)
	if x := info["CVE-2021-36260"]; !x.KEV || !x.Ransomware || x.KEVAdded != "2022-01-10" || !x.Pending || x.NVD {
		t.Fatalf("vor dem Abruf: %+v", x)
	}
	if st := h.cveStatus(); st.Pending != 2 || st.KEVCount != 21 {
		t.Fatalf("Status: %+v", st)
	}
	h.workCVEQueue(make(chan struct{}))
	info = h.cveInfos(ctx, ids)
	x := info["CVE-2021-36260"]
	if !x.NVD || x.Pending || x.CVSS != 9.8 || x.Severity != "CRITICAL" || x.CVSSVer != "3.1" || x.EPSS < 0.94 || x.EPSSPct != 0.999 ||
		!strings.HasPrefix(x.Desc, "A command injection") || len(x.CWE) != 1 || x.Published != "2021-09-18" || x.Vendor != "Hikvision" {
		t.Fatalf("nach dem Abruf: %+v", x)
	}
	if len(x.Refs) != 1 || x.Refs[0] != "https://example.org/advisory" {
		t.Fatalf("Verweise nur https: %v", x.Refs)
	}
	if u := info["CVE-2099-0001"]; !u.Unknown || u.Pending || u.NVD {
		t.Fatalf("unbekannte CVE: %+v", u)
	}
	if h.cveCheck(ctx, "CVE-2021-36260") != "kev" || h.cveCheck(ctx, "CVE-2099-0001") != "unbekannt" || h.cveCheck(ctx, "CVE-2021-x") != "ungültig" {
		t.Fatal("Prüfung der Nummern")
	}
	// Hinaus gingen nur CVE-Nummern
	f.mu.Lock()
	for _, q := range f.queries {
		q = strings.TrimSpace(q)
		if !strings.HasPrefix(q, "/kev.json?") && !strings.HasPrefix(q, "/nvd?cveId=CVE-") && !strings.HasPrefix(q, "/epss?cve=CVE-") {
			t.Errorf("unerwartete Anfrage: %q", q)
		}
	}
	n := len(f.queries)
	f.mu.Unlock()
	// Zwischenspeicher: erneuter Abruf fragt nichts nach
	if info := h.cveInfos(ctx, ids); info["CVE-2021-36260"].Pending {
		t.Fatal("frische Daten erneut angefragt")
	}
	h.workCVEQueue(make(chan struct{}))
	f.mu.Lock()
	if len(f.queries) != n {
		t.Errorf("weitere Anfragen trotz Zwischenspeicher: %v", f.queries[n:])
	}
	f.mu.Unlock()
}

// Absage der NVD: Pause, Fehler im Status; ausgeschaltet: nichts in der Warteschlange.
func TestCVEDBFailureAndOff(t *testing.T) {
	f := &fakeCVESources{failNVD: true}
	f.start(t)
	h := testHive(t)
	ctx := context.Background()
	h.cveInfos(ctx, []string{"CVE-2022-1388"})
	h.workCVEQueue(make(chan struct{}))
	st := h.cveStatus()
	if !strings.Contains(st.LastError, "403") || st.PausedTill.IsZero() || st.Pending != 1 {
		t.Fatalf("Status nach Absage: %+v", st)
	}
	resetCVEQueue()
	x := h.Extras()
	x.CVEDB.Enabled = false
	h.extras.x = x
	if info := h.cveInfos(ctx, []string{"CVE-2022-1388"}); info["CVE-2022-1388"].Pending || h.cveStatus().Pending != 0 {
		t.Fatal("ausgeschaltet, aber angefragt")
	}
	rec := httptest.NewRecorder()
	h.cveRefreshAPI(rec, httptest.NewRequest("POST", "/api/cve/refresh", nil))
	if rec.Code != 400 {
		t.Fatalf("Aktualisieren trotz Abschaltung: %d", rec.Code)
	}
	// API: ungültige Nummern fallen weg
	rec = httptest.NewRecorder()
	h.cveInfoAPI(rec, httptest.NewRequest("GET", "/api/cve/info?ids=CVE-2022-1388,foo,cve-2021-44228,CVE-2022-1388", nil))
	var out struct {
		Info map[string]*CVEInfo `json:"info"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &out) != nil || len(out.Info) != 2 || out.Info["CVE-2021-44228"] == nil {
		t.Fatalf("API: %s", rec.Body.String())
	}
}

func TestParseNVDVersions(t *testing.T) {
	d, err := parseNVD([]byte(`{"vulnerabilities":[{"cve":{"metrics":{"cvssMetricV2":[{"baseSeverity":"HIGH","cvssData":{"version":"2.0","baseScore":7.5}}]}}}]}`))
	if err != nil || d.CVSS != 7.5 || d.Severity != "HIGH" || d.Version != "2.0" {
		t.Fatalf("CVSS 2: %+v %v", d, err)
	}
	if _, err := parseNVD([]byte(`<html>`)); err == nil {
		t.Fatal("kein JSON")
	}
}
