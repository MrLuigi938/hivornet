package main

// Geräteprofile: Ein Profil legt fest, wie die Dienste sich ausweisen (Webserver,
// FTP- und SMTP-Banner, Versionen von MySQL, Redis und Docker, Kernel), damit ein Gerät
// von außen stimmig wirkt. Welche Dienste laufen und der Hostname werden in der Web-UI
// zusammen mit dem Profil gesetzt (Einstellungen → Geräteprofil); hier stehen nur die
// Kennungen. Das leere Profil ("") ist das bisherige Verhalten: Bestehende Installationen
// ändern sich erst, wenn der Nutzer ein Profil wählt.
//
// Cowrie (SSH/Telnet) hat eigene Einstellungen und ist davon nicht betroffen.

type deviceProfile struct {
	HTTPServer   string // Server-Kopfzeile und Fehlerseiten ("" = keine Kopfzeile)
	FTPBanner    string // ohne "220 "; %s = Hostname
	SMTPBanner   string // nach dem Hostnamen
	MySQLVersion string
	RedisVersion string
	Kernel       string // uname -r (Redis, Docker)
	OSName       string // Docker /info
	SSHBanner    string // ssh-tarpit
	DockerVer    string
	TelnetShell  string // Begrüßung nach dem Telnet-Login
}

var profiles = map[string]deviceProfile{
	"": { // bisher: NAS-ähnlich, gemischte Kennungen
		HTTPServer: "nginx/1.24.0", FTPBanner: "(vsFTPd 3.0.5)", SMTPBanner: "ESMTP Postfix (Ubuntu)", MySQLVersion: "5.7.44-log",
		RedisVersion: "6.2.14", Kernel: "5.15.0-91-generic", OSName: "Ubuntu 22.04.3 LTS", SSHBanner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
		DockerVer: "24.0.7", TelnetShell: "BusyBox v1.30.1 (2021-04-19 13:01:22 UTC) built-in shell (ash)",
	},
	"linux-server": { // Ubuntu 22.04 LTS als Web- und Datenbankserver
		HTTPServer: "nginx/1.18.0 (Ubuntu)", FTPBanner: "(vsFTPd 3.0.5)", SMTPBanner: "ESMTP Postfix (Ubuntu)", MySQLVersion: "8.0.36-0ubuntu0.22.04.1",
		RedisVersion: "6.0.16", Kernel: "5.15.0-97-generic", OSName: "Ubuntu 22.04.4 LTS", SSHBanner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
		DockerVer: "24.0.7", TelnetShell: "Ubuntu 22.04.4 LTS",
	},
	"nas": { // Heim-NAS mit Weboberfläche, MariaDB und FTP
		HTTPServer: "nginx", FTPBanner: "%s FTP server ready.", SMTPBanner: "ESMTP Postfix", MySQLVersion: "5.5.5-10.3.39-MariaDB",
		RedisVersion: "6.2.14", Kernel: "4.4.302+", OSName: "Debian GNU/Linux 11 (bullseye)", SSHBanner: "SSH-2.0-OpenSSH_8.2",
		DockerVer: "20.10.23", TelnetShell: "BusyBox v1.30.1 built-in shell (ash)",
	},
	"router": { // Router oder IP-Kamera mit BusyBox
		HTTPServer: "lighttpd/1.4.59", FTPBanner: "(vsFTPd 2.3.4)", SMTPBanner: "ESMTP", MySQLVersion: "5.5.62",
		RedisVersion: "5.0.7", Kernel: "3.10.14", OSName: "Linux", SSHBanner: "SSH-2.0-dropbear_2019.78",
		DockerVer: "19.03.12", TelnetShell: "BusyBox v1.30.1 (2021-04-19 13:01:22 UTC) built-in shell (ash)",
	},
}

func profileByName(name string) deviceProfile {
	if p, ok := profiles[name]; ok {
		return p
	}
	return profiles[""]
}

// prof: Profil der laufenden Konfiguration.
func (m *Manager) prof() deviceProfile {
	if p := m.profile.Load(); p != nil {
		return profileByName(*p)
	}
	return profiles[""]
}
