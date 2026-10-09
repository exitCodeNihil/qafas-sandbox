package events

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
)

// Filter selects which events a subscriber receives. Zero value matches everything.
type Filter struct {
	SandboxID string
	PiSession string
	Types     map[string]bool // nil/empty = all types
}

func (f Filter) match(e Event) bool {
	if f.SandboxID != "" && f.SandboxID != e.SandboxID {
		return false
	}
	if f.PiSession != "" && f.PiSession != e.PiSession {
		return false
	}
	if len(f.Types) > 0 && !f.Types[e.Type] {
		return false
	}
	return true
}

const hubShards = 16

type shard struct {
	mu   sync.Mutex
	subs map[chan Event]Filter
}

func (sh *shard) publish(e Event) (dropped int) {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	for ch, f := range sh.subs {
		if !f.match(e) {
			continue
		}
		select {
		case ch <- e:
		default: // slow consumer: drop rather than block ingest, counted below.
			dropped++
		}
	}
	return dropped
}

// Hub fans out ingested Events to live subscribers (SSE, GET /api/events/stream). Sharded
// by Filter.SandboxID (fnv-32a, 16 shards) so subscribers watching one busy sandbox don't
// serialize behind subscribers watching another; a subscriber with no SandboxID filter
// (the dashboard-wide stream) goes in its own shard and is checked on every Publish in
// addition to the event's own shard.
type Hub struct {
	shards    [hubShards]shard
	broadcast shard
	Dropped   atomic.Uint64 // sbxcp_sse_dropped_total
}

func NewHub() *Hub {
	h := &Hub{}
	for i := range h.shards {
		h.shards[i].subs = make(map[chan Event]Filter)
	}
	h.broadcast.subs = make(map[chan Event]Filter)
	return h
}

func shardFor(sandboxID string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(sandboxID))
	return h.Sum32() % hubShards
}

// Subscribe registers a new listener matching f (zero value = every event).
// The caller must call the returned cancel func exactly once when done.
func (h *Hub) Subscribe(f Filter) (ch chan Event, cancel func()) {
	ch = make(chan Event, 32)
	sh := &h.broadcast
	if f.SandboxID != "" {
		sh = &h.shards[shardFor(f.SandboxID)]
	}
	sh.mu.Lock()
	sh.subs[ch] = f
	sh.mu.Unlock()
	return ch, func() {
		sh.mu.Lock()
		delete(sh.subs, ch)
		sh.mu.Unlock()
		close(ch)
	}
}

// Publish delivers e to every matching subscriber, dropping it for any subscriber whose
// buffer is full rather than blocking the ingest path.
func (h *Hub) Publish(e Event) {
	dropped := h.broadcast.publish(e)
	if e.SandboxID != "" {
		dropped += h.shards[shardFor(e.SandboxID)].publish(e)
	}
	if dropped > 0 {
		h.Dropped.Add(uint64(dropped))
	}
}
