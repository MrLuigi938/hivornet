package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeDisk ersetzt den Datenträger für einen Test.
func fakeDisk(t *testing.T, total, free int64) {
	t.Helper()
	old := dbDiskStat
	dbDiskStat = func(string) (int64, int64) { return total, free }
	t.Cleanup(func() { dbDiskStat = old })
}

func TestDBDiskCap(t *testing.T) {
	for _, x := range []struct {
		name                       string
		total, free, file, minFree int64
		wantCap, wantReserve       int64
	}{
		// Pi mit 16-GB-Karte (rund 14,8 GB nutzbar), 10 GB frei: die Hälfte der Karte begrenzt.
		{"pi16", 14800 * mib, 10 * gib, 44 * mib, 512 * mib, 7168 * mib, 14800 * mib * 15 / 100},
		// Fast voll: was frei ist minus Reserve, mindestens 256 MB.
		{"knapp", 14800 * mib, 3 * gib, 1 * gib, 512 * mib, 1792 * mib, 14800 * mib * 15 / 100},
		{"voll", 14800 * mib, 1 * gib, 100 * mib, 512 * mib, dbLimitMin, 14800 * mib * 15 / 100},
		// Kleiner Datenträger: 2 GB Reserve gilt immer.
		{"klein", 8 * gib, 6 * gib, 0, 512 * mib, 4 * gib, 2 * gib},
		// Großer Docker-Host: Prozentanteil der Reserve höchstens 20 GB.
		{"host", 1000 * gib, 100 * gib, 2 * gib, gib, 82 * gib, 20 * gib},
		// HIVE_MIN_FREE_MB größer als der Rest.
		{"minfree", 100 * gib, 50 * gib, 0, 30 * gib, 20 * gib, 30 * gib},
		// Unbekannter Datenträger (nicht Linux).
		{"unbekannt", 0, 0, 0, gib, dbNoDiskCap, 0},
	} {
		c, r := dbDiskCap(x.total, x.free, x.file, x.minFree)
		if c != x.wantCap || r != x.wantReserve {
			t.Errorf("%s: Obergrenze %d MB, Reserve %d MB; erwartet %d MB, %d MB", x.name, c/mib, r/mib, x.wantCap/mib, x.wantReserve/mib)
		}
		if c%(256*mib) != 0 {
			t.Errorf("%s: Obergrenze nicht auf 256 MB gerundet: %d", x.name, c)
		}
	}
}

func TestFmtGB(t *testing.T) {
	for b, want := range map[int64]string{512 * mib: "512 MB", gib: "1 GB", 1536 * mib: "1,5 GB", 7168 * mib: "7 GB"} {
		if got := fmtGB(b); got != want {
			t.Errorf("fmtGB(%d) = %q, erwartet %q", b, got, want)
		}
	}
}

func TestDBSuggest(t *testing.T) {
	if s := dbSuggest(14800*mib, 7*gib); s != 3*gib {
		t.Errorf("Pi: %d MB", s/mib)
	}
	if s := dbSuggest(2*gib, 512*mib); s != 512*mib {
		t.Errorf("nie über der Obergrenze: %d MB", s/mib)
	}
	if s := dbSuggest(1000*gib, 400*gib); s != 10*gib {
		t.Errorf("großer Datenträger: %d MB", s/mib)
	}
	if s := dbSuggest(0, dbNoDiskCap); s != gib {
		t.Errorf("unbekannt: %d MB", s/mib)
	}
}

func TestDBNextLimit(t *testing.T) {
	for _, x := range []struct {
		limit, used, ceiling, want int64
		ok                         bool
	}{
		{gib, 800 * mib, 8 * gib, gib, false},            // unter 90 %
		{gib, 922 * mib, 8 * gib, 1536 * mib, true},      // 90 %: +512 MB
		{4 * gib, 4 * gib, 8 * gib, 5 * gib, true},       // ein Viertel
		{3 * gib, 3 * gib, 8 * gib, 4 * gib, true},       // 3840 MB auf 512 MB aufgerundet
		{7 * gib, 7 * gib, 7680 * mib, 7680 * mib, true}, // bis zur Obergrenze
		{8 * gib, 8 * gib, 8 * gib, 8 * gib, false},      // Obergrenze erreicht
		{9 * gib, 9 * gib, 8 * gib, 9 * gib, false},      // schon darüber: nie verkleinern
	} {
		got, ok := dbNextLimit(x.limit, x.used, x.ceiling)
		if got != x.want || ok != x.ok {
			t.Errorf("dbNextLimit(%d, %d, %d) = %d, %v; erwartet %d, %v", x.limit/mib, x.used/mib, x.ceiling/mib, got/mib, ok, x.want/mib, x.ok)
		}
	}
}

func TestDBLimitPrecedence(t *testing.T) {
	fakeDisk(t, 14800*mib, 10*gib)
	h := testHive(t)
	h.maxDBBytes, h.minFreeBytes = gib, 512*mib
	in := h.dbLimitInfo()
	if in.Limit != gib || in.Source != "env" || in.Ceiling != 7168*mib || in.Suggest != 3*gib {
		t.Fatalf("Vorgabe: %+v", in)
	}
	five := int64(5 * 1024)
	if _, err := h.setDBLimit(&five, nil); err != nil {
		t.Fatal(err)
	}
	if in = h.dbLimitInfo(); in.Limit != 5*gib || in.Source != "setting" || h.policy().MaxDBBytes != 5*gib {
		t.Fatalf("Einstellung hat keinen Vorrang: %+v", in)
	}
	// HIVE_MAX_DB_CAP_MB begrenzt Einstellung und Vorgabe.
	h.maxDBCapBytes = 2 * gib
	if in = h.dbLimitInfo(); in.Limit != 2*gib || in.Ceiling != 2*gib {
		t.Fatalf("harte Obergrenze: %+v", in)
	}
	h.maxDBCapBytes = 0
	// Datenträger läuft voll (andere Daten): die Einstellung schrumpft mit, die Vorgabe bleibt.
	fakeDisk(t, 14800*mib, 2500*mib)
	if in = h.dbLimitInfo(); in.Limit != gib {
		t.Fatalf("knapper Datenträger: Grenze %d MB, erwartet die Vorgabe 1024 MB", in.Limit/mib)
	}
	zero := int64(0)
	if in, _ = h.setDBLimit(&zero, nil); in.Source != "env" || in.Limit != gib {
		t.Fatalf("zurück zur Vorgabe: %+v", in)
	}
}

func TestDBLimitValidation(t *testing.T) {
	fakeDisk(t, 14800*mib, 10*gib)
	h := testHive(t)
	h.maxDBBytes, h.minFreeBytes = gib, 512*mib
	for _, mb := range []int64{-1, 100, 255, 7169, 20000, 1 << 40} {
		v := mb
		if _, err := h.setDBLimit(&v, nil); err == nil {
			t.Errorf("%d MB angenommen", mb)
		}
	}
	for _, mb := range []int64{256, 2048, 7168} {
		v := mb
		if in, err := h.setDBLimit(&v, nil); err != nil || in.Limit != mb*mib {
			t.Errorf("%d MB: %v %+v", mb, err, in)
		}
	}
	on := true
	if in, err := h.setDBLimit(nil, &on); err != nil || !in.AutoGrow || in.Limit != 7168*mib {
		t.Errorf("nur Schalter: %v %+v", err, in)
	}
}

func TestAutoGrowDB(t *testing.T) {
	fakeDisk(t, 14800*mib, 10*gib)
	h := testHive(t)
	h.maxDBBytes, h.minFreeBytes = 256*mib, 512*mib
	// Datenbank künstlich füllen, bis sie über 90 % von 256 MB liegt, ist zu teuer;
	// stattdessen die Vorgabe unter die Belegung legen.
	_, used := h.st.Size()
	h.maxDBBytes = used // 100 % belegt
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	if _, ok := h.autoGrowDB(now); ok {
		t.Fatal("erweitert, obwohl ausgeschaltet")
	}
	on := true
	h.setDBLimit(nil, &on)
	e, ok := h.autoGrowDB(now)
	if !ok || e.From != used || e.To <= used || e.To%dbGrowMin != 0 {
		t.Fatalf("keine Erweiterung: %+v %v", e, ok)
	}
	in := h.dbLimitInfo()
	if in.Limit != e.To || in.Source != "setting" || len(in.GrowLog) != 1 || !in.GrowLog[0].At.Equal(now) {
		t.Fatalf("nicht gespeichert oder protokolliert: %+v", in)
	}
	if _, ok := h.autoGrowDB(now); ok {
		t.Fatal("erneut erweitert, obwohl unter 90 %")
	}
	// Obergrenze erreicht: keine Erweiterung, Warnung.
	h.maxDBCapBytes = in.Limit
	if _, ok := h.autoGrowDB(now); ok {
		t.Fatal("über die Obergrenze erweitert")
	}
	if !h.dbLimitInfo().AtCeiling {
		t.Fatal("Obergrenze nicht erkannt")
	}
}

func TestDBLimitWarnings(t *testing.T) {
	fakeDisk(t, 14800*mib, 10*gib)
	h := testHive(t)
	_, used := h.st.Size()
	h.maxDBBytes, h.minFreeBytes = used, 512*mib
	w := h.dbWarnings()
	if len(w) != 1 || !strings.Contains(w[0].Text, "Einstellungen → Daten") {
		t.Fatalf("Hinweis bei voller Datenbank fehlt: %+v", w)
	}
	on := true
	h.setDBLimit(nil, &on)
	h.maxDBCapBytes = used
	if w = h.dbWarnings(); len(w) != 1 || !strings.Contains(w[0].Text, "Obergrenze") {
		t.Fatalf("Warnung an der Obergrenze fehlt: %+v", w)
	}
}

// Nur ein Admin darf die Grenze ändern; ein Viewer darf sie sehen.
func TestDBLimitAdminOnly(t *testing.T) {
	fakeDisk(t, 14800*mib, 10*gib)
	h := testHive(t)
	h.maxDBBytes, h.minFreeBytes = gib, 512*mib
	h.auth = NewAuth(h.st, "tok", false)
	h.auth.EnsureAdmin("admin", "adminpasswort1")
	if err := h.auth.CreateUser("gast", "gastpasswort1", "viewer"); err != nil {
		t.Fatal(err)
	}
	ui, _ := h.routes(false, "", http.NotFoundHandler())
	call := func(user, method, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		if err := h.auth.startSession(rec, httptest.NewRequest("GET", "/", nil), user); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, "/api/settings", strings.NewReader(body))
		req.Header.Set("X-Requested-With", "hivornet")
		req.AddCookie(rec.Result().Cookies()[0])
		out := httptest.NewRecorder()
		ui.ServeHTTP(out, req)
		return out
	}
	if rec := call("gast", "PUT", `{"db_limit_mb":2048,"db_autogrow":true}`); rec.Code != 403 {
		t.Fatalf("Viewer darf ändern: %d", rec.Code)
	}
	if h.dbLimitInfo().Source != "env" {
		t.Fatal("Viewer hat die Grenze geändert")
	}
	rec := call("gast", "GET", "")
	var s struct {
		DB dbLimitInfo `json:"db_limit"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &s) != nil || s.DB.Limit != gib {
		t.Fatalf("Viewer sieht die Grenze nicht: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call("admin", "PUT", `{"db_limit_mb":99999}`); rec.Code != 400 || !strings.Contains(rec.Body.String(), "höchstens") {
		t.Fatalf("zu große Grenze: %d %s", rec.Code, rec.Body.String())
	}
	if rec := call("admin", "PUT", `{"db_limit_mb":2048,"db_autogrow":true}`); rec.Code != 200 {
		t.Fatalf("Admin: %d %s", rec.Code, rec.Body.String())
	}
	if in := h.dbLimitInfo(); in.Limit != 2*gib || !in.AutoGrow {
		t.Fatalf("nicht gespeichert: %+v", in)
	}
}
