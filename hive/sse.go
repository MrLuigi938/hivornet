package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Broker verteilt neue Ereignisse live an offene Browser (Server-Sent Events).
type Broker struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

func NewBroker() *Broker { return &Broker{subs: map[chan []byte]struct{}{}} }

func (b *Broker) Publish(e *Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.subs) == 0 {
		return
	}
	msg, err := json.Marshal(e)
	if err != nil {
		return
	}
	for ch := range b.subs {
		select {
		case ch <- msg:
		default: // langsamer Browser: Ereignis auslassen
		}
	}
}

func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		httpErr(w, 500, "Streaming nicht unterstützt")
		return
	}
	ch := make(chan []byte, 256)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
	}()
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.Write([]byte(": ok\n\n"))
	fl.Flush()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-ch:
			w.Write([]byte("data: "))
			w.Write(msg)
			w.Write([]byte("\n\n"))
			// weitere wartende Ereignisse gleich mitschicken
			for n := 0; n < 50; n++ {
				select {
				case m := <-ch:
					w.Write([]byte("data: "))
					w.Write(m)
					w.Write([]byte("\n\n"))
					continue
				default:
				}
				break
			}
			fl.Flush()
		case <-ping.C:
			w.Write([]byte(": ping\n\n"))
			fl.Flush()
		}
	}
}
