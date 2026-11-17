package main

// IoT-Protokolle:
//   - adb:  Android Debug Bridge (Port 5555). Offene Fernseher, Boxen und Telefone werden
//           massenhaft mit Minern und Botnetz-Ladern bespielt ("shell:cd /data/local/tmp; …").
//           Aufgezeichnet werden Verbindungsdaten des Clients, Shell-Befehle und Dateiablagen
//           (Pfad und Größe, nie der Inhalt).
//   - mqtt: MQTT 3.1/3.1.1/5 (Port 1883). Suche nach offenen Brokern: Anmeldung, abonnierte
//           Themen, veröffentlichte Nachrichten.
// Beide spielen nur das Nötigste nach und führen nichts aus.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// ---------- ADB ----------

const (
	adbCNXN = 0x4e584e43
	adbOPEN = 0x4e45504f
	adbOKAY = 0x59414b4f
	adbCLSE = 0x45534c43
	adbWRTE = 0x45545257
	adbAUTH = 0x48545541

	adbMaxData = 256 << 10 // größere Nachrichten: Verbindung beenden
)

type adbMsg struct {
	cmd, arg0, arg1 uint32
	data            []byte
}

func readADB(r io.Reader) (adbMsg, error) {
	var hdr [24]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return adbMsg{}, err
	}
	le := binary.LittleEndian
	m := adbMsg{cmd: le.Uint32(hdr[0:]), arg0: le.Uint32(hdr[4:]), arg1: le.Uint32(hdr[8:])}
	n := le.Uint32(hdr[12:])
	if le.Uint32(hdr[20:]) != m.cmd^0xffffffff {
		return m, errors.New("adb: falsche Magic")
	}
	if n > adbMaxData {
		return m, errors.New("adb: Nachricht zu groß")
	}
	var err error
	m.data, err = readN(r, int(n))
	return m, err
}

func adbPacket(cmd, a0, a1 uint32, data []byte) []byte {
	b := make([]byte, 24+len(data))
	le := binary.LittleEndian
	var sum uint32
	for _, c := range data {
		sum += uint32(c)
	}
	le.PutUint32(b[0:], cmd)
	le.PutUint32(b[4:], a0)
	le.PutUint32(b[8:], a1)
	le.PutUint32(b[12:], uint32(len(data)))
	le.PutUint32(b[16:], sum)
	le.PutUint32(b[20:], cmd^0xffffffff)
	copy(b[24:], data)
	return b
}

// adbShellOutput: glaubwürdige Antworten auf die häufigsten Erkundungsbefehle.
func adbShellOutput(cmd string) string {
	c := strings.TrimSpace(cmd)
	switch {
	case strings.HasPrefix(c, "getprop ro.product.model"):
		return "SHIELD Android TV\n"
	case strings.HasPrefix(c, "getprop ro.product.cpu.abi"):
		return "arm64-v8a\n"
	case c == "getprop ro.build.version.release":
		return "11\n"
	case strings.HasPrefix(c, "uname"):
		return "Linux localhost 4.9.140-tegra #1 SMP PREEMPT Wed Mar 13 00:32:22 PDT 2024 aarch64\n"
	case c == "id":
		return "uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),1011(adb),1015(sdcard_rw),3003(inet) context=u:r:shell:s0\n"
	case c == "whoami":
		return "shell\n"
	case c == "pwd":
		return "/\n"
	case strings.HasPrefix(c, "echo "):
		return strings.Trim(strings.TrimPrefix(c, "echo "), `"'`) + "\n"
	}
	return ""
}

func handleADB(s *Session) {
	drip := func() []byte { return []byte(randWord(1, 4)) }
	if s.Mode == "tarpit" {
		s.Tarpit(adbPacket(adbCNXN, 0x01000000, 4096, nil)[:12], drip)
		return
	}
	br := bufio.NewReader(s.Conn)
	connected := false
	var sync map[uint32]bool // offene sync:-Kanäle (Datei-Ablage)
	var nextID uint32 = 1
	for i := 0; i < 300; i++ {
		s.ReadDeadline(60 * time.Second)
		if i == 0 && s.sniffTLS(br) {
			return
		}
		m, err := readADB(br)
		if err != nil {
			if i == 0 && br.Buffered() > 0 {
				b, _ := br.Peek(min(br.Buffered(), 512))
				s.Emit(Event{Type: "payload", Data: map[string]any{"text": printable(b, budgetText)}})
			}
			return
		}
		switch m.cmd {
		case adbCNXN:
			if !connected {
				connected = true
				s.Emit(Event{Type: "client_version", Data: map[string]any{"version": printable(m.data, budgetShort), "protocol": fmt.Sprintf("ADB %08x", m.arg0)}})
			}
			banner := "device::ro.product.name=mdarcy;ro.product.model=SHIELD Android TV;ro.product.device=mdarcy;features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir"
			if s.Write(adbPacket(adbCNXN, 0x01000000, 4096, []byte(banner))) != nil {
				return
			}
		case adbAUTH: // keine Schlüsselprüfung: wie ein Gerät mit "ADB ohne Freigabe"
			continue
		case adbOPEN:
			dest := strings.TrimRight(string(m.data), "\x00")
			local, remote := nextID, m.arg0
			nextID++
			switch {
			case strings.HasPrefix(dest, "shell:") || strings.HasPrefix(dest, "shell,") || strings.HasPrefix(dest, "exec:"):
				cmd := dest[strings.IndexAny(dest, ":")+1:]
				if cmd != "" {
					s.Command(printable([]byte(cmd), budgetCommand), map[string]any{"channel": "shell"})
				}
				if s.Mode == "hybrid" {
					s.Tarpit(nil, drip)
					return
				}
				s.Write(adbPacket(adbOKAY, local, remote, nil))
				if out := adbShellOutput(cmd); out != "" {
					s.Write(adbPacket(adbWRTE, local, remote, []byte(out)))
				}
				if cmd != "" {
					s.Write(adbPacket(adbCLSE, local, remote, nil))
				}
			case strings.HasPrefix(dest, "sync:"):
				if sync == nil {
					sync = map[uint32]bool{}
				}
				sync[local] = true
				s.Write(adbPacket(adbOKAY, local, remote, nil))
			default:
				s.Command(printable([]byte("open "+dest), budgetCommand), map[string]any{"channel": "service"})
				s.Write(adbPacket(adbCLSE, 0, remote, nil))
			}
		case adbWRTE:
			local, remote := m.arg1, m.arg0
			if sync[local] {
				// sync-Protokoll: "SEND" + Länge + "pfad,modus" leitet eine Datei-Ablage ein
				if len(m.data) >= 8 && string(m.data[:4]) == "SEND" {
					// Länge ohne int-Überlauf (32 Bit)
					end := len(m.data)
					if n := binary.LittleEndian.Uint32(m.data[4:8]); uint64(n) < uint64(end-8) {
						end = 8 + int(n)
					}
					path := string(m.data[8:end])
					if k := strings.LastIndexByte(path, ','); k > 0 {
						path = path[:k]
					}
					s.Command(printable([]byte("push "+path), budgetCommand), map[string]any{"channel": "sync"})
				}
				s.Write(adbPacket(adbOKAY, local, remote, nil))
				if k := bytes.LastIndex(m.data, []byte("DONE")); k >= 0 && len(m.data)-k == 8 {
					s.Write(adbPacket(adbWRTE, local, remote, []byte("OKAY\x00\x00\x00\x00")))
				}
				continue
			}
			// interaktive Shell: Eingaben zeilenweise als Befehle
			for _, line := range strings.Split(string(m.data), "\n") {
				if l := strings.TrimSpace(line); l != "" {
					s.Command(printable([]byte(l), budgetCommand), map[string]any{"channel": "shell"})
				}
			}
			s.Write(adbPacket(adbOKAY, local, remote, nil))
		case adbCLSE:
			delete(sync, m.arg1)
		}
	}
}

// ---------- MQTT ----------

const mqttMaxPacket = 64 << 10

func readVarint(r io.ByteReader) (int, error) {
	n, mul := 0, 1
	for i := 0; i < 4; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		n += int(b&0x7f) * mul
		if b&0x80 == 0 {
			return n, nil
		}
		mul *= 128
	}
	return 0, errors.New("mqtt: Länge ungültig")
}

// mqttReader liest Felder aus einem Paketrumpf; Fehler bleiben haften.
type mqttReader struct {
	b   []byte
	err bool
}

func (r *mqttReader) bytes(n int) []byte {
	if r.err || n < 0 || n > len(r.b) {
		r.err = true
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}
func (r *mqttReader) u8() byte {
	b := r.bytes(1)
	if b == nil {
		return 0
	}
	return b[0]
}
func (r *mqttReader) u16() int {
	b := r.bytes(2)
	if b == nil {
		return 0
	}
	return int(b[0])<<8 | int(b[1])
}
func (r *mqttReader) str() string { return string(r.bytes(r.u16())) }
func (r *mqttReader) props() { // MQTT 5: Eigenschaften überspringen
	n, mul := 0, 1
	for i := 0; i < 4; i++ {
		b := r.u8()
		n += int(b&0x7f) * mul
		if b&0x80 == 0 {
			break
		}
		mul *= 128
	}
	r.bytes(n)
}

func mqttPublish(topic, payload string) []byte {
	body := append([]byte{byte(len(topic) >> 8), byte(len(topic))}, topic...)
	body = append(body, payload...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

func handleMQTT(s *Session) {
	drip := func() []byte { return []byte{0xd0, 0x00} }
	if s.Mode == "tarpit" {
		s.Tarpit([]byte{0x20}, drip)
		return
	}
	br := bufio.NewReader(s.Conn)
	v5 := false
	for i := 0; i < 200; i++ {
		s.ReadDeadline(90 * time.Second)
		if i == 0 && s.sniffTLS(br) {
			return
		}
		typ, err := br.ReadByte()
		if err != nil {
			return
		}
		n, err := readVarint(br)
		if err != nil || n > mqttMaxPacket {
			return
		}
		body, err := readN(br, n)
		if err != nil {
			return
		}
		r := &mqttReader{b: body}
		switch typ >> 4 {
		case 1: // CONNECT
			proto := r.str()
			level := r.u8()
			flags := r.u8()
			r.u16() // keepalive
			v5 = level == 5
			if v5 {
				r.props()
			}
			client := r.str()
			if flags&0x04 != 0 { // Will
				if v5 {
					r.props()
				}
				r.str()
				r.bytes(r.u16())
			}
			var user, pass string
			if flags&0x80 != 0 {
				user = r.str()
			}
			if flags&0x40 != 0 {
				pass = string(r.bytes(r.u16()))
			}
			if r.err || (proto != "MQTT" && proto != "MQIsdp") {
				s.Emit(Event{Type: "payload", Data: map[string]any{"text": printable(body, budgetText)}})
				return
			}
			info := map[string]any{"client_id": printable([]byte(client), budgetShort), "protocol": fmt.Sprintf("%s %d", proto, level)}
			s.Emit(Event{Type: "client_version", Data: map[string]any{"version": printable([]byte("MQTT client "+client), budgetShort)}})
			if flags&0xc0 != 0 {
				s.Login(user, pass, info)
			}
			if s.Mode == "hybrid" {
				s.Tarpit([]byte{0x20}, drip)
				return
			}
			if v5 {
				s.Write([]byte{0x20, 0x03, 0x00, 0x00, 0x00})
			} else {
				s.Write([]byte{0x20, 0x02, 0x00, 0x00})
			}
		case 3: // PUBLISH
			topic := r.str()
			qos := (typ >> 1) & 3
			pid := 0
			if qos > 0 {
				pid = r.u16()
			}
			if v5 {
				r.props()
			}
			s.Command(printable([]byte("publish "+topic+" "+string(r.b)), budgetCommand), nil)
			if qos == 1 {
				s.Write([]byte{0x40, 0x02, byte(pid >> 8), byte(pid)})
			} else if qos == 2 {
				s.Write([]byte{0x50, 0x02, byte(pid >> 8), byte(pid)})
			}
		case 6: // PUBREL
			if len(body) >= 2 {
				s.Write([]byte{0x70, 0x02, body[0], body[1]})
			}
		case 8: // SUBSCRIBE
			pid := r.u16()
			if v5 {
				r.props()
			}
			var topics []string
			for len(r.b) > 0 && !r.err && len(topics) < 32 {
				topics = append(topics, r.str())
				r.u8()
			}
			s.Command(printable([]byte("subscribe "+strings.Join(topics, " ")), budgetCommand), nil)
			ack := []byte{0x90, byte(2 + len(topics)), byte(pid >> 8), byte(pid)}
			if v5 {
				ack = []byte{0x90, byte(3 + len(topics)), byte(pid >> 8), byte(pid), 0}
			}
			for range topics {
				ack = append(ack, 0)
			}
			s.Write(ack)
			// Wer alles abonniert, bekommt ein paar typische Hausautomations-Werte
			for _, t := range topics {
				if t == "#" || strings.HasPrefix(t, "home/") {
					s.Write(mqttPublish("home/livingroom/temperature", "21.4"))
					s.Write(mqttPublish("home/door/front", `{"state":"closed","battery":87}`))
					break
				}
			}
		case 12: // PINGREQ
			s.Write([]byte{0xd0, 0x00})
		case 14: // DISCONNECT
			return
		}
	}
}
