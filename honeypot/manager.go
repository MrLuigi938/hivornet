package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type runListener struct {
	cfg        atomic.Pointer[ListenerConfig]
	ln         net.Listener
	active     atomic.Int64
	tarpitting atomic.Int64
	total      atomic.Int64
	rejected   atomic.Int64
}

// Manager startet und stoppt Listener passend zur aktuellen Konfiguration.
// Ändert sich nur der Modus, läuft der Listener ohne Neustart weiter.
type Manager struct {
	mu        sync.Mutex
	em        *Emitter
	bind      string
	lowOffset int
	running   map[int]*runListener
	failed    map[int]string
	current   Config
	tarpit    atomic.Pointer[TarpitConfig]
	hostname  atomic.Value // string
	limits    *Limits
	rate      *RateLimiter
	tlsConf   atomic.Pointer[tls.Config]
	certUntil time.Time

	ownNets []*net.IPNet // eigene Container-Netze (Erkennung Userland-Proxy)
	proxied atomic.Int64 // Verbindungen, die aus dem eigenen Docker-Netz zu kommen scheinen
}

func NewManager(em *Emitter, bind string, lowOffset int) *Manager {
	m := &Manager{em: em, bind: bind, lowOffset: lowOffset, running: map[int]*runListener{}, failed: map[int]string{},
		limits: NewLimits(), rate: NewRateLimiter(10, 300)}
	d := DefaultConfig()
	m.tarpit.Store(&d.Tarpit)
	m.hostname.Store(d.Hostname)
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
				m.ownNets = append(m.ownNets, n)
			}
		}
	}
	return m
}

func (m *Manager) Hostname() string        { return m.hostname.Load().(string) }
func (m *Manager) TarpitCfg() TarpitConfig { return *m.tarpit.Load() }

// Apply übernimmt eine neue Konfiguration. Liefert true, wenn sie sich geändert hat.
func (m *Manager) Apply(c Config) bool {
	for _, w := range c.Normalize(m.lowOffset) {
		log.Printf("Konfiguration: %s", w)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	changed := !reflect.DeepEqual(c, m.current)
	certDue := m.tlsConf.Load() == nil || c.Hostname != m.Hostname() || time.Until(m.certUntil) < 30*24*time.Hour
	if !changed && len(m.failed) == 0 && !certDue {
		return false
	}
	if certDue {
		tc, until, err := selfSignedTLS(c.Hostname)
		if err != nil {
			log.Printf("TLS-Zertifikat: %v", err)
		} else {
			m.tlsConf.Store(tc)
			m.certUntil = until
		}
	}
	prevFailed := m.failed
	m.current = c
	tc := c.Tarpit
	m.tarpit.Store(&tc)
	m.hostname.Store(c.Hostname)
	m.limits.Set(tc)

	want := map[int]ListenerConfig{}
	for _, l := range c.Listeners {
		if l.Enabled {
			want[l.Port] = l
		}
	}
	for port, rl := range m.running {
		w, ok := want[port]
		if !ok || w.Service != rl.cfg.Load().Service {
			rl.ln.Close()
			delete(m.running, port)
			log.Printf("Port %d gestoppt", port)
		}
	}
	m.failed = map[int]string{}
	for port, w := range want {
		lc := w
		if rl, ok := m.running[port]; ok {
			if old := rl.cfg.Load(); *old != lc {
				rl.cfg.Store(&lc)
				log.Printf("Port %d (%s): Modus jetzt %s", port, lc.Service, lc.Mode)
			}
			continue
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(m.bind, fmt.Sprint(BindPort(port, m.lowOffset))))
		if err != nil {
			m.failed[port] = err.Error()
			if prevFailed[port] != err.Error() { // jeden Fehler nur einmal melden, Neuversuch still
				log.Printf("Port %d (%s) kann nicht geöffnet werden: %v", port, lc.Service, err)
			}
			continue
		}
		rl := &runListener{ln: ln}
		rl.cfg.Store(&lc)
		m.running[port] = rl
		log.Printf("Port %d: %s im Modus %s", port, lc.Service, lc.Mode)
		go m.serve(rl)
	}
	return changed
}

// Recheck wendet die aktuelle Konfiguration erneut an (Neuversuch für Ports, Zertifikat).
func (m *Manager) Recheck() {
	m.mu.Lock()
	c := m.current
	c.Listeners = append([]ListenerConfig(nil), m.current.Listeners...)
	m.mu.Unlock()
	m.Apply(c)
}

func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for port, rl := range m.running {
		rl.ln.Close()
		delete(m.running, port)
	}
}

func (m *Manager) serve(rl *runListener) {
	for {
		c, err := rl.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go m.handle(rl, c)
	}
}

type ListenerStatus struct {
	Port       int    `json:"port"`
	Service    string `json:"service"`
	Mode       string `json:"mode"`
	Running    bool   `json:"running"`
	Error      string `json:"error,omitempty"`
	Active     int64  `json:"active"`
	Tarpitting int64  `json:"tarpitting"`
	Total      int64  `json:"total"`
	Rejected   int64  `json:"rejected"`
}

func (m *Manager) Status() (Config, []ListenerStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ListenerStatus
	for _, l := range m.current.Listeners {
		st := ListenerStatus{Port: l.Port, Service: l.Service, Mode: l.Mode}
		if rl, ok := m.running[l.Port]; ok {
			st.Running = true
			st.Active, st.Tarpitting, st.Total, st.Rejected = rl.active.Load(), rl.tarpitting.Load(), rl.total.Load(), rl.rejected.Load()
		}
		if e, ok := m.failed[l.Port]; ok {
			st.Error = e
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return m.current, out
}

// handlers ist das Register aller Dienste: Name -> Handler. Ein neues Protokoll
// wird hier eingetragen (Schritte: docs/ARCHITEKTUR.md, „Neues Protokoll“).
var handlers = map[string]func(*Session){
	"http":       handleHTTP,
	"https":      handleHTTPS,
	"dockerapi":  handleDockerAPI,
	"ftp":        handleFTP,
	"redis":      handleRedis,
	"mysql":      handleMySQL,
	"ssh-tarpit": handleSSHTarpit,
	"raw":        handleRaw,
	"telnet":     handleTelnet,
	"smtp":       handleSMTP,
	"vnc":        handleVNC,
	"rdp":        handleRDP,
}

func (m *Manager) fromOwnNet(ip net.IP) bool {
	for _, n := range m.ownNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (m *Manager) handle(rl *runListener, c net.Conn) {
	cfg := *rl.cfg.Load()
	ip, sport := splitAddr(c.RemoteAddr())
	if rl.active.Load() >= maxConnsPerPort {
		rl.rejected.Add(1)
		m.limits.rejected.Add(1)
		c.Close()
		return
	}
	if !m.limits.AcquireConn(ip) {
		rl.rejected.Add(1)
		c.Close()
		return
	}
	defer m.limits.ReleaseConn(ip)
	rl.active.Add(1)
	defer rl.active.Add(-1)
	rl.total.Add(1)
	if pip := net.ParseIP(ip); pip != nil && m.fromOwnNet(pip) {
		m.proxied.Add(1)
	}

	s := &Session{
		m: m, rl: rl, Conn: c, Service: cfg.Service, Mode: cfg.Mode,
		ID: randHex(6), SrcIP: ip, SrcPort: sport, DstPort: cfg.Port, Start: time.Now(),
	}
	s.Emit(Event{Type: "connect", Data: map[string]any{"mode": cfg.Mode}})
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Fehler im Handler %s: %v", cfg.Service, r)
		}
		s.Conn.Close()
		ev := Event{Type: "disconnect", DurationMs: time.Since(s.Start).Milliseconds(), Data: map[string]any{"bytes_out": s.bytesOut}}
		if s.tarpitted {
			ev.Tarpit = true
			ev.TarpitMs = time.Since(s.tarpitStart).Milliseconds()
		}
		s.Emit(ev)
	}()
	if h := handlers[cfg.Service]; h != nil {
		h(s)
	}
}

func splitAddr(a net.Addr) (string, int) {
	if ta, ok := a.(*net.TCPAddr); ok {
		ip := ta.IP
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		return ip.String(), ta.Port
	}
	host, _, _ := net.SplitHostPort(a.String())
	return host, 0
}
