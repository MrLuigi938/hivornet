package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAbuseChLookups(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		got = append(got, r.URL.Path+" "+r.Header.Get("Auth-Key")+" "+r.Form.Encode())
		if strings.HasPrefix(r.URL.Path, "/v1/url") {
			w.Write([]byte(`{"query_status":"ok","url_status":"online","threat":"malware_download","tags":["mirai"],"payloads":[{"signature":"Mirai"},{"signature":"Mirai"}],"secret":"x"}`))
			return
		}
		w.Write([]byte(`{"query_status":"ok","data":[{"signature":"Mirai","file_type":"elf","tags":["arm"],"first_seen":"2026-11-01 10:00:00"}]}`))
	}))
	defer srv.Close()
	ou, ob := urlhausBase, bazaarBase
	urlhausBase, bazaarBase = srv.URL, srv.URL
	t.Cleanup(func() { urlhausBase, bazaarBase = ou, ob })

	h := testHive(t)
	w, wait := testWriter(t, h.st)
	sum := strings.Repeat("ab", 32)
	w.Submit(evAt(time.Now(), "download", "ssh", "203.0.113.5", 22, map[string]any{"url": "http://198.51.100.9/bins/x86", "sha256": sum}))
	wait()
	get := func(f http.HandlerFunc, q string) (int, map[string]any) {
		rec := httptest.NewRecorder()
		f(rec, httptest.NewRequest("GET", "/x?"+q, nil))
		var out struct{ Data map[string]any }
		json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out.Data
	}
	if c, _ := get(h.lookupURLhaus, "url="+url.QueryEscape("http://198.51.100.9/bins/x86")); c != 400 {
		t.Fatalf("ohne Schlüssel: %d", c)
	}
	x := h.Extras()
	x.AbuseChKey = "k1"
	h.extras.x = x
	c, d := get(h.lookupURLhaus, "url="+url.QueryEscape("http://198.51.100.9/bins/x86"))
	if c != 200 || d["url_status"] != "online" || d["secret"] != nil || d["payloads"].(float64) != 2 {
		t.Fatalf("URLhaus: %d %v", c, d)
	}
	if c, _ := get(h.lookupURLhaus, "url="+url.QueryEscape("http://fremd.example/")); c != 400 {
		t.Fatalf("fremde Adresse abgefragt: %d", c)
	}
	c, d = get(h.lookupBazaar, "hash="+sum)
	if c != 200 || d["signature"] != "Mirai" {
		t.Fatalf("MalwareBazaar: %d %v", c, d)
	}
	get(h.lookupBazaar, "hash="+sum) // aus dem Zwischenspeicher
	if len(got) != 2 || !strings.Contains(got[0], " k1 url=") || !strings.Contains(got[1], "query=get_info") {
		t.Fatalf("Anfragen: %v", got)
	}
}
