//go:build linux

// This program demonstrates attaching an eBPF program to a network interface
// with Linux TCX (Traffic Control with eBPF). The program counts ingress and egress
// packets using two variables. The userspace program (Go code in this file)
// prints the contents of the two variables to stdout every second.
// This example depends on tcx bpf_link, available in Linux kernel version 6.6 or newer.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -tags linux bpf tcx.c -- -I./headers

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>TCX Packet Dashboard</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0f172a;
      --panel: #111827;
      --panel-2: #1f2937;
      --text: #e5e7eb;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --border: #334155;
      --good: #22c55e;
      --warn: #f59e0b;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: linear-gradient(180deg, #020617 0%, var(--bg) 100%);
      color: var(--text);
      font: 14px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .wrap {
      max-width: 1600px;
      margin: 0 auto;
      padding: 24px;
    }
    h1 {
      margin: 0 0 8px;
      font-size: 28px;
    }
    .subtitle {
      color: var(--muted);
      margin-bottom: 16px;
    }
    .cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }
    .card {
      background: rgba(17, 24, 39, 0.88);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 14px 16px;
      backdrop-filter: blur(10px);
    }
    .card .label {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .08em;
    }
    .card .value {
      margin-top: 6px;
      font-size: 22px;
      font-weight: 700;
    }
    .status.connected { color: var(--good); }
    .status.disconnected { color: #ef4444; }
    .status.connecting { color: var(--warn); }
			.switch-row {
			  margin-top: 8px;
			  display: flex;
			  align-items: center;
			  justify-content: space-between;
			  gap: 10px;
			}
			.switch-label {
			  font-size: 13px;
			  color: var(--muted);
			  user-select: none;
			}
			.switch {
			  position: relative;
			  display: inline-block;
			  width: 52px;
			  height: 30px;
			  flex-shrink: 0;
			}
			.switch input {
			  opacity: 0;
			  width: 0;
			  height: 0;
			}
			.slider {
			  position: absolute;
			  cursor: pointer;
			  inset: 0;
			  background-color: #334155;
			  transition: .2s;
			  border-radius: 30px;
			  border: 1px solid #475569;
			}
			.slider:before {
			  position: absolute;
			  content: "";
			  height: 22px;
			  width: 22px;
			  left: 3px;
			  top: 3px;
			  background-color: #f8fafc;
			  transition: .2s;
			  border-radius: 50%;
			}
			.switch input:checked + .slider {
			  background-color: rgba(56, 189, 248, 0.35);
			  border-color: var(--accent);
			}
			.switch input:checked + .slider:before {
			  transform: translateX(22px);
			  background-color: var(--accent);
			}
    .table-wrap {
      background: rgba(17, 24, 39, 0.88);
      border: 1px solid var(--border);
      border-radius: 16px;
      overflow: hidden;
    }
	.tabs {
	  display: flex;
	  gap: 8px;
	  margin: 0 0 12px;
	}
	.tab-btn {
	  border: 1px solid var(--border);
	  background: rgba(17, 24, 39, 0.88);
	  color: var(--text);
	  border-radius: 999px;
	  padding: 7px 12px;
	  cursor: pointer;
	  font-size: 13px;
	}
	.tab-btn.active {
	  border-color: var(--accent);
	  color: var(--accent);
	  background: rgba(56, 189, 248, 0.12);
	}
    table {
      width: 100%;
      border-collapse: collapse;
    }
    thead th {
      position: sticky;
      top: 0;
      z-index: 1;
      background: #0b1220;
      color: #cbd5e1;
      text-align: left;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .08em;
    }
    th, td {
      padding: 10px 12px;
      border-bottom: 1px solid rgba(51, 65, 85, 0.55);
      vertical-align: top;
    }
    tbody tr:hover { background: rgba(30, 41, 59, 0.45); }
    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .tag {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      background: rgba(56, 189, 248, 0.12);
      color: var(--accent);
      border: 1px solid rgba(56, 189, 248, 0.35);
      font-size: 12px;
      font-weight: 600;
    }
    .muted { color: var(--muted); }
    .empty {
      padding: 28px;
      text-align: center;
      color: var(--muted);
    }
			.drop-switch-wrap {
			  display: flex;
			  align-items: center;
			  gap: 8px;
			}
			.drop-switch {
			  position: relative;
			  display: inline-block;
			  width: 44px;
			  height: 24px;
			  flex-shrink: 0;
			}
			.drop-switch-input {
			  opacity: 0;
			  width: 0;
			  height: 0;
			}
			.drop-switch-slider {
			  position: absolute;
			  cursor: pointer;
			  inset: 0;
			  background: #334155;
			  border: 1px solid #475569;
			  border-radius: 24px;
			  transition: .2s;
			}
			.drop-switch-slider:before {
			  position: absolute;
			  content: "";
			  width: 18px;
			  height: 18px;
			  left: 2px;
			  top: 2px;
			  border-radius: 50%;
			  background: #e2e8f0;
			  transition: .2s;
			}
			.drop-switch-input:checked + .drop-switch-slider {
			  background: rgba(239, 68, 68, 0.35);
			  border-color: #ef4444;
			}
			.drop-switch-input:checked + .drop-switch-slider:before {
			  transform: translateX(20px);
			  background: #fecaca;
			}
			.drop-switch-input:disabled + .drop-switch-slider {
			  opacity: 0.6;
			  cursor: not-allowed;
			}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>TCX Packet Dashboard</h1>

    <div class="cards">
      <div class="card">
        <div class="label">Connection</div>
        <div class="value status connecting" id="connStatus">Connecting...</div>
      </div>
      <div class="card">
        <div class="label">Unique Packets</div>
        <div class="value" id="uniqueCount">0</div>
      </div>
      <div class="card">
        <div class="label">Total Observations</div>
        <div class="value" id="totalCount">0</div>
      </div>
			  <div class="card">
				<div class="label">Refresh</div>
				<div class="value" id="refreshStatus">Running</div>
				<div class="switch-row">
				  <span class="switch-label" id="pauseLabel">Live</span>
				  <label class="switch" aria-label="Pause live refresh">
					<input id="pauseToggle" type="checkbox" />
					<span class="slider"></span>
				  </label>
				</div>
			  </div>
    </div>

	<div class="tabs" id="tabs">
	  <button class="tab-btn active" type="button" data-tab="all">All</button>
	  <button class="tab-btn" type="button" data-tab="ingress">Ingress</button>
	  <button class="tab-btn" type="button" data-tab="egress">Egress</button>
	</div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Ifindex</th>
	  <th>Direction</th>
			<th>Src IP</th>
			<th>Dst IP</th>
	  <th>Domain</th>
            <th>Type</th>
            <th>Length</th>
            <th>Count</th>
			<th>Dropped</th>
			<th>Action</th>
            <th>Last Seen</th>
            <th>Summary</th>
          </tr>
        </thead>
        <tbody id="packetBody">
  <tr><td class="empty" colspan="12">Waiting for packets...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <script>
	const MAX_RENDER_ROWS = 300;
	const RENDER_INTERVAL_MS = 200;
    const rows = new Map();
    const body = document.getElementById('packetBody');
    const connStatus = document.getElementById('connStatus');
    const uniqueCount = document.getElementById('uniqueCount');
    const totalCount = document.getElementById('totalCount');
	const refreshStatus = document.getElementById('refreshStatus');
	const pauseToggle = document.getElementById('pauseToggle');
	const pauseLabel = document.getElementById('pauseLabel');
	const tabs = document.getElementById('tabs');
	pauseToggle.checked = true;
	let isPaused = false;
	let dirtyWhilePaused = false;
	let renderTimer = null;
	let activeTab = 'all';

    const escapeHTML = (value) => String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');

	const formatTime = (unixMs) => {
	  if (!unixMs) return '-';
	  const d = new Date(unixMs);
	  return Number.isNaN(d.getTime()) ? String(unixMs) : d.toLocaleString();
    };

	const scheduleRender = () => {
	  if (isPaused) {
		dirtyWhilePaused = true;
		refreshStatus.textContent = 'Paused (buffering)';
		return;
	  }
	  if (renderTimer) return;
	  renderTimer = setTimeout(() => {
		renderTimer = null;
		render();
	  }, RENDER_INTERVAL_MS);
	};

	const setPause = (paused) => {
	  isPaused = paused;
	  pauseToggle.checked = !paused;
	  if (isPaused) {
		refreshStatus.textContent = 'Paused';
		pauseLabel.textContent = 'Paused';
		return;
	  }

	  refreshStatus.textContent = 'Running';
	  pauseLabel.textContent = 'Live';
	  if (dirtyWhilePaused) {
		dirtyWhilePaused = false;
		scheduleRender();
	  }
	};

    const render = () => {
	  const packets = [...rows.values()].sort((a, b) => (b.lastSeenUnix || 0) - (a.lastSeenUnix || 0));
	  const filteredPackets = activeTab === 'all'
		? packets
		: packets.filter((packet) => packet.direction === activeTab);
	  const visiblePackets = filteredPackets.slice(0, MAX_RENDER_ROWS);
	  uniqueCount.textContent = filteredPackets.length;
	  totalCount.textContent = filteredPackets.reduce((sum, packet) => sum + (packet.count || 0), 0);

	  if (!visiblePackets.length) {
		body.innerHTML = '<tr><td class="empty" colspan="12">No packets for current tab.</td></tr>';
        return;
      }

	  body.innerHTML = visiblePackets.map((packet) => {
		const payloadType = packet.payloadType
		  ? '<div class="muted">payload: ' + escapeHTML(packet.payloadType) + '</div>'
		  : '';
		const ipProtocol = packet.ipProtocol
		  ? '<div class="muted">ip: ' + escapeHTML(packet.ipProtocol) + '</div>'
		  : '';

		return '' +
		  '<tr>' +
			'<td class="mono">' + escapeHTML(packet.ifindex) + '</td>' +
			'<td><span class="tag">' + escapeHTML(packet.direction || '-') + '</span></td>' +
			'<td class="mono">' + escapeHTML(packet.srcIP || '-') + '</td>' +
			'<td class="mono">' + escapeHTML(packet.dstIP || '-') + '</td>' +
			'<td class="mono">' + escapeHTML(packet.dstDomain || '-') + '</td>' +
			'<td>' +
			  '<div>' + escapeHTML(packet.etherType || '-') + '</div>' +
			  payloadType +
			  ipProtocol +
			'</td>' +
			'<td>' +
			  '<div>' + escapeHTML(packet.packetLen) + ' bytes</div>' +
			  '<div class="muted">captured: ' + escapeHTML(packet.capturedLen) + ' bytes</div>' +
			'</td>' +
			'<td>' + escapeHTML(packet.count) + '</td>' +
			'<td>' + escapeHTML(packet.droppedCount || 0) + '</td>' +
			'<td>' +
			  (packet.dstIP && !String(packet.dstIP).includes(':')
				? '<div class="drop-switch-wrap">' +
				    '<label class="drop-switch" title="Block this destination IP">' +
				      '<input class="drop-switch-input" type="checkbox" data-dst="' + encodeURIComponent(packet.dstIP) + '" ' + (packet.dropEnabled ? 'checked' : '') + ' />' +
				      '<span class="drop-switch-slider"></span>' +
				    '</label>' +
				    '<span class="muted">' + (packet.dropEnabled ? 'Block' : 'Allow') + '</span>' +
				  '</div>'
				: '<span class="muted">-</span>') +
			'</td>' +
			'<td>' + escapeHTML(formatTime(packet.lastSeenUnix)) + '</td>' +
			'<td>' + escapeHTML(packet.summary || '-') + '</td>' +
		  '</tr>';
	  }).join('');
    };

    const setConnection = (state, text) => {
	  connStatus.className = 'value status ' + state;
      connStatus.textContent = text;
    };

    const source = new EventSource('/events');
    setConnection('connecting', 'Connecting...');
	pauseToggle.addEventListener('change', () => setPause(!pauseToggle.checked));
	tabs.addEventListener('click', (event) => {
	  const btn = event.target.closest('.tab-btn');
	  if (!btn) return;
	  activeTab = btn.dataset.tab || 'all';
	  for (const item of tabs.querySelectorAll('.tab-btn')) {
		item.classList.toggle('active', item === btn);
	  }
	  scheduleRender();
	});
	body.addEventListener('change', async (event) => {
	  const sw = event.target.closest('.drop-switch-input');
	  if (!sw || sw.disabled) return;

	  const encodedDst = sw.getAttribute('data-dst') || '';
	  const dstIP = decodeURIComponent(encodedDst);
	  const block = sw.checked;
	  if (!dstIP) return;

	  sw.disabled = true;
	  try {
		const resp = await fetch('/drop-dstip', {
		  method: 'POST',
		  headers: { 'Content-Type': 'application/json' },
		  body: JSON.stringify({ dstIP, block })
		});
		if (!resp.ok) {
		  sw.checked = !block;
		}
	  } catch (_) {
		sw.checked = !block;
	  } finally {
		sw.disabled = false;
	  }
	});

    source.onopen = () => setConnection('connected', 'Connected');
    source.onerror = () => setConnection('disconnected', 'Reconnecting...');
    source.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === 'snapshot') {
        rows.clear();
        for (const packet of message.packets || []) {
          rows.set(packet.id, packet);
        }
		scheduleRender();
        return;
      }

      if (message.type === 'upsert' && message.packet) {
        rows.set(message.packet.id, message.packet);
		scheduleRender();
      }
    };
  </script>
</body>
</html>`

type parsedPacket struct {
	EtherType   string
	PayloadType string
	IPProtocol  string
	SrcIP       string
	DstIP       string
	Summary     string
}

type packetView struct {
	ID           string    `json:"id"`
	Direction    string    `json:"direction"`
	Ifindex      uint32    `json:"ifindex"`
	PacketLen    uint32    `json:"packetLen"`
	CapturedLen  int       `json:"capturedLen"`
	EtherType    string    `json:"etherType,omitempty"`
	PayloadType  string    `json:"payloadType,omitempty"`
	IPProtocol   string    `json:"ipProtocol,omitempty"`
	SrcIP        string    `json:"srcIP,omitempty"`
	DstIP        string    `json:"dstIP,omitempty"`
	DstDomain    string    `json:"dstDomain,omitempty"`
	Summary      string    `json:"summary"`
	Count        uint64    `json:"count"`
	DroppedCount uint64    `json:"droppedCount"`
	DropEnabled  bool      `json:"dropEnabled"`
	FirstSeen    time.Time `json:"firstSeen"`
	LastSeen     time.Time `json:"lastSeen"`
	LastSeenUnix int64     `json:"lastSeenUnix"`
}

type streamMessage struct {
	Type    string       `json:"type"`
	Packet  *packetView  `json:"packet,omitempty"`
	Packets []packetView `json:"packets,omitempty"`
}

type dropDstRequest struct {
	DstIP string `json:"dstIP"`
	Block bool   `json:"block"`
}

type packetHub struct {
	mu          sync.RWMutex
	packets     map[string]*packetView
	subscribers map[chan []byte]struct{}
	blockedDst  map[string]bool
	droppedDst  map[string]uint64
	dnsMu       sync.Mutex
	dnsCache    map[string]string
	dnsQueue    chan string
}

const maxUniquePackets = 2000
const noDomain = "-"
const resolvingDomain = "<resolving>"

func newPacketHub() *packetHub {
	return &packetHub{
		packets:     make(map[string]*packetView),
		subscribers: make(map[chan []byte]struct{}),
		blockedDst:  make(map[string]bool),
		droppedDst:  make(map[string]uint64),
		dnsCache:    make(map[string]string),
		dnsQueue:    make(chan string, 1024),
	}
}

func (h *packetHub) startDNSResolvers(ctx context.Context, workers int) {
	if workers < 1 {
		workers = 1
	}

	for range workers {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case ip := <-h.dnsQueue:
					h.resolveDomain(ip)
				}
			}
		}()
	}
}

func (h *packetHub) resolveDomain(ip string) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	resolved := noDomain
	if names, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil && len(names) > 0 {
		resolved = strings.TrimSuffix(names[0], ".")
	}

	h.dnsMu.Lock()
	if existing, ok := h.dnsCache[ip]; ok && existing == resolvingDomain {
		h.dnsCache[ip] = resolved
	}
	h.dnsMu.Unlock()
}

func (h *packetHub) upsert(packet packetView) {
	packet.DstDomain = h.lookupDomain(h.domainLookupIP(packet))

	h.mu.Lock()
	droppedCount := h.droppedDst[packet.DstIP]
	packet.DroppedCount = droppedCount
	packet.DropEnabled = h.blockedDst[packet.DstIP]
	existing, ok := h.packets[packet.ID]
	if ok {
		existing.Count++
		existing.LastSeen = packet.LastSeen
		existing.LastSeenUnix = packet.LastSeenUnix
		existing.DropEnabled = packet.DropEnabled
		existing.DroppedCount = packet.DroppedCount
		if existing.DstDomain == "" {
			existing.DstDomain = packet.DstDomain
		}
		packet = *existing
	} else {
		if len(h.packets) >= maxUniquePackets {
			h.evictOldestLocked()
		}
		packet.Count = 1
		h.packets[packet.ID] = &packet
	}

	subscribers := make([]chan []byte, 0, len(h.subscribers))
	for ch := range h.subscribers {
		subscribers = append(subscribers, ch)
	}
	h.mu.Unlock()

	payload, err := json.Marshal(streamMessage{Type: "upsert", Packet: &packet})
	if err != nil {
		log.Printf("marshalling packet update: %s", err)
		return
	}

	for _, ch := range subscribers {
		select {
		case ch <- payload:
		default:
		}
	}
}

func (h *packetHub) markDropped(dstIP string) {
	if dstIP == "" {
		return
	}

	h.mu.Lock()
	if !h.blockedDst[dstIP] {
		h.mu.Unlock()
		return
	}

	count := h.droppedDst[dstIP] + 1
	h.droppedDst[dstIP] = count
	updatedPackets := make([]packetView, 0, 4)
	for _, packet := range h.packets {
		if packet.DstIP == dstIP {
			packet.DropEnabled = true
			packet.DroppedCount = count
			updatedPackets = append(updatedPackets, *packet)
		}
	}
	subscribers := make([]chan []byte, 0, len(h.subscribers))
	for ch := range h.subscribers {
		subscribers = append(subscribers, ch)
	}
	h.mu.Unlock()

	h.broadcastPacketUpdates(updatedPackets, subscribers)
}

func (h *packetHub) blockDstIP(dstIP string) {
	if dstIP == "" {
		return
	}

	h.mu.Lock()
	h.blockedDst[dstIP] = true
	count := h.droppedDst[dstIP]
	updatedPackets := make([]packetView, 0, 4)
	for _, packet := range h.packets {
		if packet.DstIP == dstIP {
			packet.DropEnabled = true
			packet.DroppedCount = count
			updatedPackets = append(updatedPackets, *packet)
		}
	}
	subscribers := make([]chan []byte, 0, len(h.subscribers))
	for ch := range h.subscribers {
		subscribers = append(subscribers, ch)
	}
	h.mu.Unlock()

	h.broadcastPacketUpdates(updatedPackets, subscribers)
}

func (h *packetHub) unblockDstIP(dstIP string) {
	if dstIP == "" {
		return
	}

	h.mu.Lock()
	delete(h.blockedDst, dstIP)
	count := h.droppedDst[dstIP]
	updatedPackets := make([]packetView, 0, 4)
	for _, packet := range h.packets {
		if packet.DstIP == dstIP {
			packet.DropEnabled = false
			packet.DroppedCount = count
			updatedPackets = append(updatedPackets, *packet)
		}
	}
	subscribers := make([]chan []byte, 0, len(h.subscribers))
	for ch := range h.subscribers {
		subscribers = append(subscribers, ch)
	}
	h.mu.Unlock()

	h.broadcastPacketUpdates(updatedPackets, subscribers)
}

func (h *packetHub) broadcastPacketUpdates(packets []packetView, subscribers []chan []byte) {
	for i := range packets {
		payload, err := json.Marshal(streamMessage{Type: "upsert", Packet: &packets[i]})
		if err != nil {
			log.Printf("marshalling packet update: %s", err)
			continue
		}

		for _, ch := range subscribers {
			select {
			case ch <- payload:
			default:
			}
		}
	}
}

func (h *packetHub) lookupDomain(dstIP string) string {
	if dstIP == "" {
		return ""
	}

	h.dnsMu.Lock()
	cached, ok := h.dnsCache[dstIP]
	if ok {
		h.dnsMu.Unlock()
		if cached == noDomain || cached == resolvingDomain {
			return ""
		}
		return cached
	}

	h.dnsCache[dstIP] = resolvingDomain
	h.dnsMu.Unlock()

	select {
	case h.dnsQueue <- dstIP:
	default:
		// If the queue is full, clear the pending marker so a later packet can retry.
		h.dnsMu.Lock()
		if existing, exists := h.dnsCache[dstIP]; exists && existing == resolvingDomain {
			delete(h.dnsCache, dstIP)
		}
		h.dnsMu.Unlock()
	}

	return ""
}

func (h *packetHub) domainLookupIP(packet packetView) string {
	if packet.Direction == "ingress" {
		return packet.SrcIP
	}
	return packet.DstIP
}

func (h *packetHub) evictOldestLocked() {
	var (
		oldestID   string
		oldestTime time.Time
		set        bool
	)

	for id, packet := range h.packets {
		if !set || packet.LastSeen.Before(oldestTime) {
			oldestID = id
			oldestTime = packet.LastSeen
			set = true
		}
	}

	if set {
		delete(h.packets, oldestID)
	}
}

func (h *packetHub) snapshot() []packetView {
	h.mu.RLock()
	packets := make([]packetView, 0, len(h.packets))
	for _, packet := range h.packets {
		packets = append(packets, *packet)
	}
	h.mu.RUnlock()

	sort.Slice(packets, func(i, j int) bool {
		return packets[i].LastSeen.After(packets[j].LastSeen)
	})
	return packets
}

func (h *packetHub) subscribe() chan []byte {
	ch := make(chan []byte, 32)
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *packetHub) unsubscribe(ch chan []byte) {
	h.mu.Lock()
	if _, ok := h.subscribers[ch]; ok {
		delete(h.subscribers, ch)
		close(ch)
	}
	h.mu.Unlock()
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock limit: %s", err)
	}

	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer func() {
		if err := objs.Close(); err != nil {
			log.Printf("closing objects: %s", err)
		}
	}()

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.IngressProgFunc,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			log.Printf("closing ingress link: %s", err)
		}
	}()
	log.Printf("Attached TCx program to INGRESS iface %q (index %d)", iface.Name, iface.Index)

	l2, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.EgressProgFunc,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}
	defer func() {
		if err := l2.Close(); err != nil {
			log.Printf("closing egress link: %s", err)
		}
	}()
	log.Printf("Attached TCx program to EGRESS iface %q (index %d)", iface.Name, iface.Index)

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer func() {
		if err := rd.Close(); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
			log.Printf("closing ringbuf reader: %s", err)
		}
	}()

	hub := newPacketHub()
	appCtx, cancelApp := context.WithCancel(context.Background())
	defer cancelApp()
	hub.startDNSResolvers(appCtx, 2)

	server := newDashboardServer(hub, objs.BlockedDstV4)
	go func() {
		log.Printf("Packet dashboard listening on http://127.0.0.1:8080")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("dashboard server error: %s", err)
		}
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("shutting down dashboard server: %s", err)
		}
	}()

	go func() {
		<-stopper
		cancelApp()
		if err := rd.Close(); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
			log.Printf("closing ringbuf reader: %s", err)
		}
	}()

	log.Printf("Press Ctrl-C to exit and remove the program")

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			_, err := formatCounters(objs.IngressPktCount, objs.EgressPktCount)
			if err != nil {
				log.Printf("Error reading map: %s", err)
				continue
			}
			//log.Printf("Packet Count: %s", s)
		}
	}()

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Printf("Received signal, exiting")
				return
			}

			log.Printf("reading ringbuf event: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		payload := capturedBytes(event)
		packet := buildPacketView(event, payload)
		if event.Dropped != 0 {
			hub.markDropped(packet.DstIP)
			continue
		}
		hub.upsert(packet)

		//log.Printf(
		//	"Packet Sample: dir=%s ifindex=%d packet_len=%d captured_len=%d %s",
		//	packet.Direction,
		//	packet.Ifindex,
		//	packet.PacketLen,
		//	packet.CapturedLen,
		//	packet.Summary,
		//)
	}
}

func newDashboardServer(hub *packetHub, blockedDstV4 *ebpf.Map) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		serveEvents(hub, w, r)
	})
	mux.HandleFunc("/drop-dstip", func(w http.ResponseWriter, r *http.Request) {
		handleDropDstIP(hub, blockedDstV4, w, r)
	})

	return &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

func serveEvents(hub *packetHub, w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	snapshot, err := json.Marshal(streamMessage{Type: "snapshot", Packets: hub.snapshot()})
	if err != nil {
		http.Error(w, fmt.Sprintf("marshal snapshot: %s", err), http.StatusInternalServerError)
		return
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", snapshot); err != nil {
		return
	}
	flusher.Flush()

	ch := hub.subscribe()
	defer hub.unsubscribe(ch)

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case payload, ok := <-ch:
			if !ok {
				return
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func handleDropDstIP(hub *packetHub, blockedDstV4 *ebpf.Map, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	defer r.Body.Close()
	var req dropDstRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %s", err), http.StatusBadRequest)
		return
	}
	ip := net.ParseIP(req.DstIP)
	ipv4 := ip.To4()
	if ipv4 == nil {
		http.Error(w, "invalid dstIP: only IPv4 is supported for kernel dropping", http.StatusBadRequest)
		return
	}

	key := binary.BigEndian.Uint32(ipv4)
	if req.Block {
		value := uint8(1)
		if err := blockedDstV4.Put(key, value); err != nil {
			http.Error(w, fmt.Sprintf("updating blocked dst map: %s", err), http.StatusInternalServerError)
			return
		}
		hub.blockDstIP(req.DstIP)
	} else {
		if err := blockedDstV4.Delete(key); err != nil {
			http.Error(w, fmt.Sprintf("deleting blocked dst map key: %s", err), http.StatusInternalServerError)
			return
		}
		hub.unblockDstIP(req.DstIP)
	}

	w.WriteHeader(http.StatusNoContent)
}

func buildPacketView(event bpfEvent, payload []byte) packetView {
	now := time.Now()
	parsed := parsePacket(payload)
	direction := directionString(event.Direction)
	return packetView{
		ID:           packetID(direction, parsed),
		Direction:    direction,
		Ifindex:      event.Ifindex,
		PacketLen:    event.PktLen,
		CapturedLen:  len(payload),
		EtherType:    parsed.EtherType,
		PayloadType:  parsed.PayloadType,
		IPProtocol:   parsed.IPProtocol,
		SrcIP:        parsed.SrcIP,
		DstIP:        parsed.DstIP,
		Summary:      parsed.Summary,
		FirstSeen:    now,
		LastSeen:     now,
		LastSeenUnix: now.UnixMilli(),
	}
}

func packetID(direction string, parsed parsedPacket) string {
	if parsed.SrcIP != "" || parsed.DstIP != "" {
		return direction + "|" + parsed.SrcIP + "->" + parsed.DstIP
	}
	return direction + "|" + parsed.Summary
}

func directionString(direction uint8) string {
	switch direction {
	case 1:
		return "ingress"
	case 2:
		return "egress"
	default:
		return fmt.Sprintf("unknown(%d)", direction)
	}
}

func capturedBytes(event bpfEvent) []byte {
	capLen := int(event.CapLen)
	if capLen < 0 {
		return nil
	}
	if capLen > len(event.Data) {
		capLen = len(event.Data)
	}
	return event.Data[:capLen]
}

func parsePacket(b []byte) parsedPacket {
	if len(b) < 14 {
		return parsedPacket{Summary: fmt.Sprintf("truncated ethernet frame: %d bytes", len(b))}
	}

	outerEtherType := binary.BigEndian.Uint16(b[12:14])
	etherType := outerEtherType
	l3Offset := 14

	parsed := parsedPacket{
		EtherType: etherTypeString(outerEtherType),
	}

	// Handle single-tag VLAN frames (802.1Q / 802.1ad).
	if etherType == 0x8100 || etherType == 0x88a8 {
		if len(b) < 18 {
			parsed.Summary = fmt.Sprintf("etherType=%s vlan frame truncated: %d bytes", etherTypeString(outerEtherType), len(b))
			return parsed
		}

		etherType = binary.BigEndian.Uint16(b[16:18])
		l3Offset = 18
		parsed.PayloadType = etherTypeString(etherType)
	}

	summaryParts := []string{
		fmt.Sprintf("etherType=%s", parsed.EtherType),
	}
	if parsed.PayloadType != "" {
		summaryParts = append(summaryParts, fmt.Sprintf("payloadType=%s", parsed.PayloadType))
	}

	switch etherType {
	case 0x0800:
		if len(b) < l3Offset+20 {
			parsed.Summary = fmt.Sprintf("%s truncated ipv4: %d bytes", strings.Join(summaryParts, " "), len(b))
			return parsed
		}

		ihl := int(b[l3Offset]&0x0f) * 4
		if ihl < 20 || len(b) < l3Offset+ihl {
			parsed.Summary = fmt.Sprintf("%s invalid ipv4 header length=%d", strings.Join(summaryParts, " "), ihl)
			return parsed
		}

		parsed.IPProtocol = ipProtocolString(b[l3Offset+9])
		parsed.SrcIP = net.IP(b[l3Offset+12 : l3Offset+16]).String()
		parsed.DstIP = net.IP(b[l3Offset+16 : l3Offset+20]).String()
		summaryParts = append(summaryParts,
			fmt.Sprintf("ipProto=%s", parsed.IPProtocol),
			fmt.Sprintf("srcIP=%s", parsed.SrcIP),
			fmt.Sprintf("dstIP=%s", parsed.DstIP),
		)
	case 0x86dd:
		if len(b) < l3Offset+40 {
			parsed.Summary = fmt.Sprintf("%s truncated ipv6: %d bytes", strings.Join(summaryParts, " "), len(b))
			return parsed
		}

		parsed.IPProtocol = ipProtocolString(b[l3Offset+6])
		parsed.SrcIP = net.IP(b[l3Offset+8 : l3Offset+24]).String()
		parsed.DstIP = net.IP(b[l3Offset+24 : l3Offset+40]).String()
		summaryParts = append(summaryParts,
			fmt.Sprintf("nextHeader=%s", parsed.IPProtocol),
			fmt.Sprintf("srcIP=%s", parsed.SrcIP),
			fmt.Sprintf("dstIP=%s", parsed.DstIP),
		)
	}

	parsed.Summary = strings.Join(summaryParts, " ")
	return parsed
}

func etherTypeString(etherType uint16) string {
	switch etherType {
	case 0x0800:
		return "IPv4(0x0800)"
	case 0x0806:
		return "ARP(0x0806)"
	case 0x86dd:
		return "IPv6(0x86dd)"
	case 0x8100:
		return "802.1Q VLAN(0x8100)"
	case 0x88a8:
		return "802.1ad VLAN(0x88a8)"
	case 0x8847:
		return "MPLS unicast(0x8847)"
	case 0x8848:
		return "MPLS multicast(0x8848)"
	case 0x8863:
		return "PPPoE discovery(0x8863)"
	case 0x8864:
		return "PPPoE session(0x8864)"
	case 0x88cc:
		return "LLDP(0x88cc)"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", etherType)
	}
}

func ipProtocolString(proto uint8) string {
	switch proto {
	case 1:
		return "ICMP(1)"
	case 2:
		return "IGMP(2)"
	case 6:
		return "TCP(6)"
	case 17:
		return "UDP(17)"
	case 41:
		return "IPv6(41)"
	case 47:
		return "GRE(47)"
	case 50:
		return "ESP(50)"
	case 51:
		return "AH(51)"
	case 58:
		return "ICMPv6(58)"
	case 89:
		return "OSPF(89)"
	case 132:
		return "SCTP(132)"
	default:
		return fmt.Sprintf("Unknown(%d)", proto)
	}
}

func formatCounters(ingressVar, egressVar *ebpf.Variable) (string, error) {
	var (
		ingressPacketCount uint64
		egressPacketCount  uint64
	)

	// retrieve value from the ingress map
	if err := ingressVar.Get(&ingressPacketCount); err != nil {
		return "", err
	}

	// retrieve value from the egress map
	if err := egressVar.Get(&egressPacketCount); err != nil {
		return "", err
	}

	return fmt.Sprintf("%10v Ingress, %10v Egress", ingressPacketCount, egressPacketCount), nil
}
