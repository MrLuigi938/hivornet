package main

import (
	"fmt"
	"strings"
)

// Geräteprofile: Ein Profil legt fest, wie die Dienste sich ausweisen (Webserver,
// FTP- und SMTP-Banner, Versionen von MySQL, Redis und Docker, Kernel, Architektur),
// damit ein Gerät von außen stimmig wirkt. Welche Dienste laufen und der Hostname werden
// in der Web-UI zusammen mit dem Profil gesetzt (Einstellungen → Geräteprofil); hier
// stehen nur die Kennungen. Das leere Profil ("") ist das bisherige Verhalten: Bestehende
// Installationen ändern sich erst, wenn der Nutzer ein Profil wählt.
//
// Stimmigkeit: Kernel, Architektur und Betriebssystem erscheinen an mehreren Stellen
// (Telnet uname und /proc/cpuinfo, Redis INFO, Docker /version und /info, PostgreSQL
// version(), Kubernetes /version). Alle lesen dieselben Felder; die Paketversionen eines
// Profils stammen aus derselben Distribution (TestProfilesConsistent).
//
// Cowrie (SSH/Telnet) hat eigene Einstellungen und ist davon nicht betroffen.

type deviceProfile struct {
	HTTPServer   string // Server-Kopfzeile und Fehlerseiten ("" = keine Kopfzeile)
	FTPBanner    string // ohne "220 "; %s = Hostname. Der Dialog danach ist vsftpd: andere Server passen nicht
	SMTPBanner   string // nach dem Hostnamen; der Dialog danach ist Postfix
	MySQLVersion string
	RedisVersion string
	GCC          string // Redis INFO gcc_version (Compiler der Distribution)
	Kernel       string // uname -r (Telnet, Redis, Docker)
	KernelBuild  string // uname -v (Telnet)
	Arch         string // uname -m: x86_64, aarch64, armv7l, mips
	CPUInfo      string // /proc/cpuinfo (Zeilenende \n); Anzahl "processor" = Docker NCPU
	Mounts       string // /proc/mounts (Zeilenende \n)
	MemTotal     int64  // Docker /info, Bytes
	OSName       string // Docker /info; beginnt es mit "Ubuntu", zeigt uname -a auch -p und -i
	SSHBanner    string // ssh-tarpit
	DockerVer    string // muss in dockerBuilds stehen
	TelnetShell  string // Begrüßung nach dem Telnet-Login
}

var profiles = map[string]deviceProfile{
	"": { // bisher: NAS-ähnlich, gemischte Kennungen (Telnet meldete früher MIPS, Redis/Docker x86_64; jetzt überall x86_64)
		HTTPServer: "nginx/1.24.0", FTPBanner: "(vsFTPd 3.0.5)", SMTPBanner: "ESMTP Postfix (Ubuntu)", MySQLVersion: "5.7.44-log",
		RedisVersion: "6.2.14", GCC: "11.4.0", Kernel: "5.15.0-91-generic", KernelBuild: "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023",
		Arch: "x86_64", CPUInfo: cpuCeleronJ4125, Mounts: mountsFlash, MemTotal: 8232407040,
		OSName: "Ubuntu 22.04.3 LTS", SSHBanner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
		DockerVer: "24.0.7", TelnetShell: "BusyBox v1.30.1 (2021-04-19 13:01:22 UTC) built-in shell (ash)",
	},
	"linux-server": { // Ubuntu 22.04 LTS als virtueller Web- und Datenbankserver
		HTTPServer: "nginx/1.18.0 (Ubuntu)", FTPBanner: "(vsFTPd 3.0.5)", SMTPBanner: "ESMTP Postfix (Ubuntu)", MySQLVersion: "8.0.36-0ubuntu0.22.04.1",
		RedisVersion: "6.0.16", GCC: "11.2.0", Kernel: "5.15.0-97-generic", KernelBuild: "#107-Ubuntu SMP Wed Feb 7 13:26:48 UTC 2024",
		Arch: "x86_64", CPUInfo: cpuXeonVPS, Mounts: mountsDisk("/dev/vda1"), MemTotal: 8323137536,
		OSName: "Ubuntu 22.04.4 LTS", SSHBanner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
		DockerVer: "24.0.7", TelnetShell: "Ubuntu 22.04.4 LTS",
	},
	"nas": { // Heim-NAS auf Debian 11 (wie openmediavault 6): Weboberfläche, MariaDB, FTP, Docker
		HTTPServer: "nginx", FTPBanner: "%s FTP server ready.", SMTPBanner: "ESMTP Postfix (Debian/GNU)", MySQLVersion: "5.5.5-10.5.23-MariaDB-0+deb11u1",
		RedisVersion: "6.0.16", GCC: "10.2.1", Kernel: "5.10.0-28-amd64", KernelBuild: "#1 SMP Debian 5.10.209-2 (2024-01-31)",
		Arch: "x86_64", CPUInfo: cpuCeleronJ4125, Mounts: mountsDisk("/dev/sda1") + "/dev/md0 /srv/dev-disk-by-uuid-6c1f0e2a-93d4-4c47-8f0e-2b7d1a9e4c55 ext4 rw,relatime,jqfmt=vfsv0,usrjquota=aquota.user,grpjquota=aquota.group 0 0\n",
		MemTotal: 8232407040, OSName: "Debian GNU/Linux 11 (bullseye)", SSHBanner: "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
		DockerVer: "20.10.23", TelnetShell: "BusyBox v1.30.1 (Debian 1:1.30.1-6+b3) built-in shell (ash)\r\nEnter 'help' for a list of built-in commands.",
	},
	"router": { // WLAN-Router mit Hersteller-Firmware (MediaTek-SDK, BusyBox, MIPS)
		HTTPServer: "lighttpd/1.4.59", FTPBanner: "(vsFTPd 3.0.3)", SMTPBanner: "ESMTP", MySQLVersion: "5.5.62",
		RedisVersion: "5.0.7", GCC: "4.8.5", Kernel: "3.10.14", KernelBuild: "#1 Thu Apr 15 09:12:41 CST 2021",
		Arch: "mips", CPUInfo: cpuMT7620, Mounts: mountsFlash, MemTotal: 61734912,
		OSName: "Linux", SSHBanner: "SSH-2.0-dropbear_2019.78",
		DockerVer: "19.03.12", TelnetShell: "BusyBox v1.30.1 (2021-04-19 13:01:22 UTC) built-in shell (ash)",
	},
	"ip-camera": { // Billige IP-Kamera (HiSilicon-SoC, ARMv7, BusyBox, Boa-Webserver)
		HTTPServer: "Boa/0.94.14rc21", FTPBanner: "(vsFTPd 3.0.2)", SMTPBanner: "ESMTP", MySQLVersion: "5.5.62",
		RedisVersion: "5.0.7", GCC: "6.3.0", Kernel: "4.9.37", KernelBuild: "#1 SMP Fri Sep 24 10:41:37 CST 2021",
		Arch: "armv7l", CPUInfo: cpuHi3516, Mounts: mountsCamera, MemTotal: 63508480,
		OSName: "Linux", SSHBanner: "SSH-2.0-dropbear_2017.75",
		DockerVer: "19.03.12", TelnetShell: "BusyBox v1.26.2 (2021-09-24 10:43:52 CST) built-in shell (ash)",
	},
	"smart-home": { // Raspberry Pi 4 mit Raspberry Pi OS (Debian 12, 64 Bit) als Smart-Home-Zentrale
		HTTPServer: "nginx/1.22.1", FTPBanner: "(vsFTPd 3.0.3)", SMTPBanner: "ESMTP Postfix (Debian/GNU)", MySQLVersion: "5.5.5-10.11.6-MariaDB-0+deb12u1",
		RedisVersion: "7.0.15", GCC: "12.2.0", Kernel: "6.6.51+rpt-rpi-v8", KernelBuild: "#1 SMP PREEMPT Debian 1:6.6.51-1+rpt3 (2024-10-08)",
		Arch: "aarch64", CPUInfo: cpuPi4, Mounts: mountsPi, MemTotal: 3974836224,
		OSName: "Debian GNU/Linux 12 (bookworm)", SSHBanner: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
		DockerVer: "27.5.1", TelnetShell: "Debian GNU/Linux 12 (bookworm)",
	},
	"dev-server": { // Entwicklungs- und KI-Server: Ubuntu 24.04 mit Docker, Kubernetes, Ollama, Datenbanken
		HTTPServer: "nginx/1.24.0 (Ubuntu)", FTPBanner: "(vsFTPd 3.0.5)", SMTPBanner: "ESMTP Postfix (Ubuntu)", MySQLVersion: "8.0.43-0ubuntu0.24.04.2",
		RedisVersion: "7.0.15", GCC: "13.2.0", Kernel: "6.8.0-85-generic", KernelBuild: "#85-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 18 15:26:59 UTC 2025",
		Arch: "x86_64", CPUInfo: cpuRyzen5800X, Mounts: mountsDisk("/dev/nvme0n1p2"), MemTotal: 67206352896,
		OSName: "Ubuntu 24.04.3 LTS", SSHBanner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14",
		DockerVer: "27.5.1", TelnetShell: "Ubuntu 24.04.3 LTS",
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

// archBits: Wortbreite für Redis arch_bits und PostgreSQL version().
func (p deviceProfile) archBits() int {
	switch p.Arch {
	case "x86_64", "aarch64":
		return 64
	}
	return 32
}

// goArch: Architektur in der Schreibweise von Go (Docker /version, Kubernetes platform).
func (p deviceProfile) goArch() string {
	switch p.Arch {
	case "x86_64":
		return "amd64"
	case "aarch64":
		return "arm64"
	case "armv7l":
		return "arm"
	case "mips":
		return "mipsle"
	}
	return p.Arch
}

// gnuTriple: Zielsystem, wie gcc es nennt (PostgreSQL version()).
func (p deviceProfile) gnuTriple() string {
	switch p.Arch {
	case "x86_64":
		return "x86_64-pc-linux-gnu"
	case "armv7l":
		return "arm-unknown-linux-gnueabihf"
	case "mips":
		return "mipsel-unknown-linux-gnu"
	}
	return p.Arch + "-unknown-linux-gnu"
}

// nCPU: Zahl der Prozessoren in CPUInfo (Docker /info NCPU).
func (p deviceProfile) nCPU() int {
	n := 0
	for _, l := range strings.Split(p.CPUInfo, "\n") {
		if strings.HasPrefix(l, "processor\t") {
			n++
		}
	}
	return max(n, 1)
}

// uname bildet uname mit den Schaltern aus args nach (BusyBox und coreutils geben dieselben
// Felder aus; nur Ubuntu-coreutils kennen -p und -i, sonst "unknown" und bei -a weggelassen).
func (p deviceProfile) uname(host string, args []string) string {
	flags := ""
	for _, a := range args {
		switch {
		case a == "--all":
			flags += "a"
		case strings.HasPrefix(a, "--"):
		case strings.HasPrefix(a, "-"):
			flags += a[1:]
		}
	}
	if flags == "" {
		return "Linux"
	}
	ubuntu := strings.HasPrefix(p.OSName, "Ubuntu")
	proc := "unknown"
	if ubuntu {
		proc = p.Arch
	}
	var f []string
	for _, x := range []struct {
		c byte
		v string
	}{{'s', "Linux"}, {'n', host}, {'r', p.Kernel}, {'v', p.KernelBuild}, {'m', p.Arch}, {'p', proc}, {'i', proc}, {'o', "GNU/Linux"}} {
		if strings.IndexByte(flags, x.c) >= 0 || strings.IndexByte(flags, 'a') >= 0 && (ubuntu || x.c != 'p' && x.c != 'i') {
			f = append(f, x.v)
		}
	}
	for _, c := range flags {
		if !strings.ContainsRune("asnrvmpio", c) {
			return fmt.Sprintf("uname: invalid option -- '%c'", c)
		}
	}
	return strings.Join(f, " ")
}

// dockerBuild: Kennungen eines Docker-Engine-Releases (Docker /version, Api-Version).
type dockerBuild struct {
	API, MinAPI, Commit, Go, Built string
}

var dockerBuilds = map[string]dockerBuild{
	"19.03.12": {"1.40", "1.12", "48a66213fe", "go1.13.10", "2020-06-22T15:45:28.000000000+00:00"},
	"20.10.23": {"1.41", "1.12", "6051f14", "go1.18.10", "2023-01-19T17:32:04.000000000+00:00"},
	"24.0.7":   {"1.43", "1.12", "311b9ff", "go1.20.10", "2023-10-26T09:08:02.000000000+00:00"},
	"27.5.1":   {"1.47", "1.24", "4c9b3b0", "go1.22.11", "2025-01-22T13:41:24.000000000+00:00"},
}

func (p deviceProfile) docker() dockerBuild {
	if b, ok := dockerBuilds[p.DockerVer]; ok {
		return b
	}
	return dockerBuilds["24.0.7"]
}

// cpuX86 erzeugt /proc/cpuinfo eines x86-Prozessors mit threads logischen Kernen.
func cpuX86(vendor, name string, family, model, stepping int, mhz, cache string, cores, threads int, bogo, addr, flags string) string {
	var b strings.Builder
	for i := 0; i < threads; i++ {
		fmt.Fprintf(&b, "processor\t: %d\nvendor_id\t: %s\ncpu family\t: %d\nmodel\t\t: %d\nmodel name\t: %s\nstepping\t: %d\n"+
			"cpu MHz\t\t: %s\ncache size\t: %s\nphysical id\t: 0\nsiblings\t: %d\ncore id\t\t: %d\ncpu cores\t: %d\napicid\t\t: %d\n"+
			"fpu\t\t: yes\nfpu_exception\t: yes\ncpuid level\t: 24\nwp\t\t: yes\nflags\t\t: %s\nbogomips\t: %s\n"+
			"clflush size\t: 64\ncache_alignment\t: 64\naddress sizes\t: %s\npower management:\n\n",
			i, vendor, family, model, name, stepping, mhz, cache, threads, i%cores, cores, i, flags, bogo, addr)
	}
	return b.String()
}

const x86Flags = "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx " +
	"rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid pni pclmulqdq ssse3 cx16 sse4_1 sse4_2 x2apic movbe popcnt " +
	"tsc_deadline_timer aes xsave rdrand lahf_lm 3dnowprefetch ssbd ibrs ibpb stibp fsgsbase tsc_adjust smep erms rdseed smap " +
	"clflushopt xsaveopt xsavec xgetbv1 xsaves arat md_clear arch_capabilities"

var (
	cpuCeleronJ4125 = cpuX86("GenuineIntel", "Intel(R) Celeron(R) J4125 CPU @ 2.00GHz", 6, 122, 8, "1996.800", "4096 KB", 4, 4, "3993.60",
		"39 bits physical, 48 bits virtual", x86Flags+" vmx est tm2 sha_ni umip rdpid")
	cpuXeonVPS = cpuX86("GenuineIntel", "Intel Xeon Processor (Skylake, IBRS)", 6, 85, 4, "2194.842", "16384 KB", 4, 4, "4389.68",
		"40 bits physical, 48 bits virtual", x86Flags+" hypervisor avx f16c avx2 bmi1 bmi2 avx512f avx512dq avx512cd avx512bw avx512vl")
	cpuRyzen5800X = cpuX86("AuthenticAMD", "AMD Ryzen 7 5800X 8-Core Processor", 25, 33, 0, "3800.000", "512 KB", 8, 16, "7600.39",
		"48 bits physical, 48 bits virtual", x86Flags+" svm extapic cr8_legacy abm sse4a misalignsse avx f16c avx2 bmi1 bmi2 sha_ni clzero vaes vpclmulqdq umip rdpid")
)

const cpuMT7620 = "system type\t\t: MT7620\nmachine\t\t\t: Ralink MT7620 SoC\nprocessor\t\t: 0\ncpu model\t\t: MIPS 24KEc V5.0\n" +
	"BogoMIPS\t\t: 385.84\nwait instruction\t: yes\nmicrosecond timers\t: yes\ntlb_entries\t\t: 32\nextra interrupt vector\t: yes\n" +
	"hardware watchpoint\t: yes, count: 4, address/irw mask: [0x0ffc, 0x0ffc, 0x0ffb, 0x0ffb]\nisa\t\t\t: mips1 mips2 mips32r1 mips32r2\n" +
	"ASEs implemented\t: mips16 dsp\nshadow register sets\t: 1\nkscratch registers\t: 0\ncore\t\t\t: 0\nVCED exceptions\t\t: not available\n" +
	"VCEI exceptions\t\t: not available\n\n"

const cpuHi3516 = "processor\t: 0\nmodel name\t: ARMv7 Processor rev 5 (v7l)\nBogoMIPS\t: 100.00\n" +
	"Features\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm\nCPU implementer\t: 0x41\n" +
	"CPU architecture: 7\nCPU variant\t: 0x0\nCPU part\t: 0xc07\nCPU revision\t: 5\n\nHardware\t: Generic DT based system\nRevision\t: 0000\nSerial\t\t: 0000000000000000\n"

// cpuPi4: Raspberry Pi 4 (vier Cortex-A72) unter einem 64-Bit-Kernel.
var cpuPi4 = func() string {
	var b strings.Builder
	for i := 0; i < 4; i++ {
		fmt.Fprintf(&b, "processor\t: %d\nBogoMIPS\t: 108.00\nFeatures\t: fp asimd evtstrm crc32 cpuid\nCPU implementer\t: 0x41\n"+
			"CPU architecture: 8\nCPU variant\t: 0x0\nCPU part\t: 0xd08\nCPU revision\t: 3\n\n", i)
	}
	return b.String() + "Revision\t: c03114\nSerial\t\t: 100000006b2f9e14\nModel\t\t: Raspberry Pi 4 Model B Rev 1.4\n"
}()

// Einhängepunkte (/proc/mounts) je Gerätetyp.
const mountsFlash = "rootfs / rootfs rw 0 0\n/dev/root / squashfs ro,relatime 0 0\nproc /proc proc rw,relatime 0 0\n" +
	"tmpfs /tmp tmpfs rw,relatime 0 0\ntmpfs /var tmpfs rw,relatime 0 0\n"

const mountsCamera = "/dev/root / squashfs ro,relatime 0 0\nproc /proc proc rw,relatime 0 0\nsysfs /sys sysfs rw,relatime 0 0\n" +
	"tmpfs /dev tmpfs rw,relatime 0 0\ntmpfs /tmp tmpfs rw,relatime 0 0\n/dev/mtdblock4 /mnt/mtd jffs2 rw,relatime 0 0\n"

const mountsPi = "/dev/mmcblk0p2 / ext4 rw,noatime 0 0\ndevtmpfs /dev devtmpfs rw,relatime,size=1658368k,nr_inodes=414592,mode=755 0 0\n" +
	"proc /proc proc rw,relatime 0 0\nsysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\ntmpfs /run tmpfs rw,nosuid,nodev,size=775616k,nr_inodes=819200,mode=755 0 0\n" +
	"/dev/mmcblk0p1 /boot/firmware vfat rw,relatime,fmask=0022,dmask=0022,codepage=437,iocharset=ascii,shortname=mixed,errors=remount-ro 0 0\n"

func mountsDisk(root string) string {
	return "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n" +
		"udev /dev devtmpfs rw,nosuid,relatime,size=4013480k,nr_inodes=1003370,mode=755 0 0\n" +
		"tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,size=812904k,mode=755 0 0\n" +
		root + " / ext4 rw,relatime,errors=remount-ro 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"
}
