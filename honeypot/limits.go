package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// Limits schützt den Honeypot vor Überlastung: Verbindungen gesamt und pro IP,
// getrennt für normale Verbindungen und festgehaltene Tarpit-Verbindungen.
type Limits struct {
	mu        sync.Mutex
	conns     map[string]int
	connTotal int
	tarp      map[string]int
	tarpTotal int

	maxTarpit      int
	maxTarpitPerIP int

	rejected atomic.Int64 // abgewiesene Verbindungen (Limit erreicht)
}

const (
	extraConns      = 512 // normale Verbindungen zusätzlich zu den Tarpit-Plätzen
	extraConnsPerIP = 16
	maxConnsPerPort = 2048 // ein einzelner Port darf nicht alle Plätze belegen
)

func NewLimits() *Limits {
	return &Limits{conns: map[string]int{}, tarp: map[string]int{}, maxTarpit: 4096, maxTarpitPerIP: 32}
}

func (l *Limits) Set(t TarpitConfig) {
	l.mu.Lock()
	l.maxTarpit, l.maxTarpitPerIP = t.MaxConns, t.MaxPerIP
	l.mu.Unlock()
}

func (l *Limits) AcquireConn(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.connTotal >= l.maxTarpit+extraConns || l.conns[ip] >= l.maxTarpitPerIP+extraConnsPerIP {
		l.rejected.Add(1)
		return false
	}
	l.connTotal++
	l.conns[ip]++
	return true
}

func (l *Limits) ReleaseConn(ip string) {
	l.mu.Lock()
	l.connTotal--
	if l.conns[ip]--; l.conns[ip] <= 0 {
		delete(l.conns, ip)
	}
	l.mu.Unlock()
}

func (l *Limits) AcquireTarpit(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.tarpTotal >= l.maxTarpit || l.tarp[ip] >= l.maxTarpitPerIP {
		l.rejected.Add(1)
		return false
	}
	l.tarpTotal++
	l.tarp[ip]++
	return true
}

func (l *Limits) ReleaseTarpit(ip string) {
	l.mu.Lock()
	l.tarpTotal--
	if l.tarp[ip]--; l.tarp[ip] <= 0 {
		delete(l.tarp, ip)
	}
	l.mu.Unlock()
}

func (l *Limits) Counts() (conns, tarpits int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.connTotal, l.tarpTotal
}

// RateLimiter drosselt Ereignisse pro Quell-IP (Token-Bucket), damit ein
// einzelner Angreifer die Datenbank nicht fluten kann. Darüber wird nur gezählt.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // Ereignisse pro Sekunde
	burst   float64
	max     int // höchstens so viele Quell-IPs; weitere teilen sich einen Eintrag
}

// rateMaxIPs begrenzt die Tabelle: UDP-Absender sind fälschbar, ohne Grenze ließe sich der
// Speicher mit erfundenen Adressen füllen (etwa 100 Byte je Eintrag, hier höchstens rund 6 MB).
const rateMaxIPs = 50000

// rateOverflow: gemeinsamer Eintrag für alle Adressen, die bei voller Tabelle neu dazukommen.
const rateOverflow = "(voll)"

type bucket struct {
	tokens float64
	last   time.Time
}

func NewRateLimiter(rate, burst float64) *RateLimiter {
	r := &RateLimiter{buckets: map[string]*bucket{}, rate: rate, burst: burst, max: rateMaxIPs}
	go func() {
		for range time.Tick(time.Minute) {
			r.cleanup()
		}
	}()
	return r
}

func (r *RateLimiter) Allow(ip string) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.buckets[ip]
	if b == nil && len(r.buckets) >= r.max {
		ip = rateOverflow
		b = r.buckets[ip]
	}
	if b == nil {
		b = &bucket{tokens: r.burst, last: now}
		r.buckets[ip] = b
	}
	b.tokens = min(r.burst, b.tokens+now.Sub(b.last).Seconds()*r.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (r *RateLimiter) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for ip, b := range r.buckets {
		if time.Since(b.last) > 10*time.Minute {
			delete(r.buckets, ip)
		}
	}
}
