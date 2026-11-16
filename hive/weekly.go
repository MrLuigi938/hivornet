package main

// Ungewöhnliche Zugangsdaten und Wochenbericht.
//
// Ungewöhnlich ist ein Benutzername oder Passwort, das nicht in den gängigen Standard-
// und Werkslisten steht (commonCreds; Auszug aus verbreiteten Wortlisten, Werkspasswörtern
// von IoT-Geräten und Standardkonten von Linux-Diensten) und kein kurzes Zahlenpasswort
// oder gleich dem Benutzernamen ist. Solche Einträge deuten auf gezielte Angriffe oder
// auf abgeflossene Zugangsdaten hin; die UI hebt sie hervor.
//
// Der Wochenbericht geht montags ab 8 Uhr (Ortszeit des Hive) über die eingerichteten
// Benachrichtigungswege (ntfy, Telegram, Webhook), wenn er eingeschaltet ist.

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var commonCreds = func() map[string]bool {
	words := `root admin administrator user test guest ubuntu pi oracle postgres mysql ftp ftpuser support git deploy ec2-user centos debian
nagios hadoop ansible jenkins tomcat www-data www web sa operator service default supervisor adm daemon bin sys nobody mother enable system shell sh
telecomadmin manager info test1 testuser user1 admin1 demo dev developer steam minecraft server backup vagrant docker es elasticsearch kafka redis
odoo solr zabbix apache nginx ubnt uucp vyos cisco monitor guest1 usuario public private community anonymous postmaster webmaster mail
password 123456 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon 123123 baseball abc123 football monkey letmein 696969 shadow master
666666 qwertyuiop 123321 mustang 1234567890 michael 654321 superman 1qaz2wsx 7777777 121212 000000 qazwsx 123qwe killer trustno1 jordan
jennifer zxcvbnm asdfgh hunter buster soccer harley batman andrew tigger sunshine iloveyou 2000 charlie robert thomas hockey ranger daniel
starwars klaster 112233 george computer michelle jessica pepper 1111 zxcvbn 555555 11111111 131313 freedom 777777 pass maggie 159753 aaaaaa
ginger princess joshua cheese amanda summer love ashley nicole chelsea matthew access yankees 987654321 dallas austin thunder taylor matrix
toor admin123 admin1234 password1 password123 p@ssw0rd passw0rd p@ssword changeme guest123 test123 root123 toor123 123456a a123456 qwerty123
1qaz@wsx pass123 1234qwer qwer1234 abcd1234 1q2w3e4r 1q2w3e 1q2w3e4r5t qwe123 123abc abc123456 12qwaszx letmein1 welcome welcome1 welcome123
raspberry alpine admin@123 root@123 admin@1234 xc3511 vizxv 888888 xmhdipc juantech 54321 klv123 hi3518 jvbzd anko realtek 00000000 zte521
smcadmin 4321 1111111 7ujmko0admin 7ujmko0vizxv ikwb dreambox meinsm tech zlxx. 5up hunt5759 1234qwerasdf qwerty1 secret secret123 temp
temp123 dietpi openelec libreelec osmc volumio friendlyarm orangepi bananapi nas synology qnap admin12345 adminadmin rootroot usr user123 666666666`
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[strings.ToLower(w)] = true
	}
	return m
}()

var shortDigits = regexp.MustCompile(`^\d{1,8}$`)

// rareCred: Benutzername bzw. Passwort steht in keiner gängigen Liste.
func rareCred(s, user string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	if l == "" || commonCreds[l] || shortDigits.MatchString(l) || user != "" && l == strings.ToLower(user) {
		return false
	}
	return true
}

// rareRow: Zeile einer Top-Liste (username, password, cred) ungewöhnlich?
func rareRow(field, key string) bool {
	switch field {
	case "username", "password":
		return rareCred(key, "")
	case "cred":
		u, p, ok := strings.Cut(key, " / ")
		return ok && (rareCred(p, u) || rareCred(u, ""))
	}
	return false
}

// ---- Wochenbericht ----

type weeklyData struct {
	From, To                                    time.Time
	Connects, Logins, Requests, Commands, Downl int64
	IPs, Success, AbuseSent                     int64
	Countries, Passwords, Tags, CVEs, RareCreds []Count
}

func (h *Hive) weeklyStats(ctx context.Context, to time.Time) weeklyData {
	d := weeklyData{From: to.Add(-7 * 24 * time.Hour), To: to}
	from, toH := d.From.UnixMilli()/3600000, to.UnixMilli()/3600000
	rows, _ := h.rows(ctx, `SELECT type, SUM(cnt) AS n FROM hourly WHERE hour >= ? AND hour < ? GROUP BY type`, from, toH)
	for _, r := range rows {
		n, _ := r["n"].(int64)
		switch fmt.Sprint(r["type"]) {
		case "connect":
			d.Connects = n
		case "login":
			d.Logins = n
		case "request":
			d.Requests = n
		case "command":
			d.Commands = n
		case "download":
			d.Downl = n
		}
	}
	h.st.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT key) FROM top_hourly WHERE field = 'ip' AND hour >= ? AND hour < ?`, from, toH).Scan(&d.IPs)
	if rs, err := h.rows(ctx, `SELECT src_ip FROM events WHERE ts >= ? AND ts < ? AND type = 'login'
		AND (json_extract(data, '$.success') = 1 OR json_extract(data, '$.accepted') = 1) LIMIT 100000`, d.From.UnixMilli(), to.UnixMilli()); err == nil {
		for _, r := range rs {
			if !ownHidden(fmt.Sprint(r["src_ip"])) {
				d.Success++
			}
		}
	}
	top := func(field string, n int) []Count {
		var out []Count
		rs, _ := h.rows(ctx, `SELECT key, MAX(label) AS label, SUM(n) AS n FROM top_hourly WHERE field = ? AND hour >= ? AND hour < ?
			GROUP BY key ORDER BY n DESC LIMIT ?`, field, from, toH, n)
		for _, r := range rs {
			c, _ := r["n"].(int64)
			l, _ := r["label"].(string)
			out = append(out, Count{Key: fmt.Sprint(r["key"]), N: int(c), Label: l})
		}
		return out
	}
	d.Countries, d.Passwords, d.Tags, d.CVEs = top("country", 5), top("password", 5), top("tag", 5), top("cve", 3)
	for _, c := range top("cred", 200) {
		if rareRow("cred", c.Key) && len(d.RareCreds) < 5 {
			d.RareCreds = append(d.RareCreds, c)
		}
	}
	h.abuse.mu.Lock()
	for _, e := range h.abuse.log {
		if e.Status == "ok" && e.Time.After(d.From) && e.Time.Before(to) {
			d.AbuseSent++
		}
	}
	h.abuse.mu.Unlock()
	return d
}

func (d weeklyData) Text() string {
	var b strings.Builder
	f := func(n int64) string { return fmtThousands(n) }
	fmt.Fprintf(&b, "%s bis %s\n", d.From.Format("02.01."), d.To.Add(-time.Minute).Format("02.01.2006"))
	fmt.Fprintf(&b, "%s Verbindungen von %s IPs; %s Login-Versuche, davon %s angenommen; %s Web-Anfragen; %s Befehle; %s Downloads.\n",
		f(d.Connects), f(d.IPs), f(d.Logins), f(d.Success), f(d.Requests), f(d.Commands), f(d.Downl))
	list := func(title string, c []Count, label bool) {
		if len(c) == 0 {
			return
		}
		var p []string
		for _, x := range c {
			k := x.Key
			if label && x.Label != "" {
				k = x.Label
			}
			p = append(p, fmt.Sprintf("%s (%d)", clip(k, 60), x.N))
		}
		fmt.Fprintf(&b, "%s: %s\n", title, strings.Join(p, ", "))
	}
	list("Länder", d.Countries, false)
	list("Passwörter", d.Passwords, false)
	list("Ungewöhnliche Zugangsdaten", d.RareCreds, false)
	list("Muster", d.Tags, true)
	list("Bekannte Lücken", d.CVEs, false)
	if d.AbuseSent > 0 {
		fmt.Fprintf(&b, "An AbuseIPDB gemeldet: %s\n", f(d.AbuseSent))
	}
	return strings.TrimSpace(b.String())
}

func fmtThousands(n int64) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "." + s[i:]
	}
	return s
}

// isoWeek: Kennung der Woche ("2026-W47").
func isoWeek(t time.Time) string {
	y, w := t.ISOWeek()
	return fmt.Sprintf("%d-W%02d", y, w)
}

// weeklyDue: Montag ab 8 Uhr, noch nicht für diese Woche gesendet.
func weeklyDue(now time.Time, last string) bool {
	return now.Weekday() == time.Monday && now.Hour() >= 8 && last != isoWeek(now)
}

func (h *Hive) runWeekly(stop <-chan struct{}) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		c := h.Extras().Notify
		if !c.Enabled || !c.WeeklyReport {
			continue
		}
		last, _ := h.st.GetKV("weekly_last")
		now := time.Now()
		if !weeklyDue(now, last) {
			continue
		}
		h.st.SetKV("weekly_last", isoWeek(now)) // vorher setzen: nie doppelt senden
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		to := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		d := h.weeklyStats(ctx, to)
		cancel()
		h.notifier.Report("Hivornet: Wochenbericht", d.Text())
	}
}

// weeklyPreview: GET /api/weekly – der Bericht der letzten 7 Tage (Vorschau in den Einstellungen).
func (h *Hive) weeklyPreview(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := qctx(r)
	defer cancel()
	d := h.weeklyStats(ctx, time.Now())
	writeJSON(w, map[string]any{"text": d.Text()})
}
