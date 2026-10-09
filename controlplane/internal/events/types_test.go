package events

import (
	"strings"
	"testing"
)

// Same rules as proto::sizes::resolve (crates/proto/src/lib.rs, test v5_sizes).
func TestResolveSize(t *testing.T) {
	table := DefaultSizes()
	name, l, err := ResolveSize("", nil, table)
	if err != nil || name != "medium" || l.Cpus != 2 || l.MemMiB != 2048 || l.Pids != 512 {
		t.Fatalf("default must be the pre-v5 unit: %s %+v %v", name, l, err)
	}
	if _, _, err := ResolveSize("mini", &l, table); err == nil {
		t.Fatal("size and limits together accepted")
	}
	if _, _, err := ResolveSize("huge", nil, table); err == nil || !strings.Contains(err.Error(), "micro") {
		t.Fatalf("unknown size should list the table: %v", err)
	}
	name, c, err := ResolveSize("", &SandboxLimits{Cpus: 0.75, MemMiB: 900, DiskMiB: 100}, table)
	if err != nil || name != "custom" || c.Pids != 256 {
		t.Fatalf("custom pids should default to the nearest size by memory: %s %+v %v", name, c, err)
	}
	if _, _, err := ResolveSize("", &SandboxLimits{Cpus: 0.3, MemMiB: 900, DiskMiB: 100}, table); err == nil {
		t.Fatal("cpus off the 0.25 grid accepted")
	}
	if !c.Fits(table["mini"]) || table["high"].Fits(table["mini"]) {
		t.Fatal("Fits")
	}
}

// TestNewULID checks encodeCrockford's fixed bit-shift layout against the two vectors
// that pin it down (all-zero and all-one bytes -> ULID's own known min/max strings), then
// sanity-checks NewULID's shape.
func TestNewULID(t *testing.T) {
	var zero, ones [16]byte
	for i := range ones {
		ones[i] = 0xFF
	}
	if got := encodeCrockford(zero); got != strings.Repeat("0", 26) {
		t.Fatalf("zero vector: %s", got)
	}
	if got := encodeCrockford(ones); got != "7ZZZZZZZZZZZZZZZZZZZZZZZZZ" {
		t.Fatalf("max vector: %s", got)
	}
	id := NewULID()
	if len(id) != 26 {
		t.Fatalf("want 26 chars, got %d: %s", len(id), id)
	}
	for _, c := range id {
		if !strings.ContainsRune(crockford, c) {
			t.Fatalf("char %q not in the crockford alphabet: %s", c, id)
		}
	}
}
