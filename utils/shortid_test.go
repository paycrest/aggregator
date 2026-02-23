package utils

import (
	"testing"

	"github.com/google/uuid"
)

func TestUUIDToShortID(t *testing.T) {
	id := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	short := UUIDToShortID(id)
	if len(short) != shortIDLength {
		t.Errorf("expected length %d, got %d", shortIDLength, len(short))
	}
	for _, c := range short {
		if !isBase62(c) {
			t.Errorf("invalid base62 character %q in %q", c, short)
		}
	}
	// Determinism: same UUID must yield same shortId
	short2 := UUIDToShortID(id)
	if short != short2 {
		t.Errorf("determinism failed: %q != %q", short, short2)
	}
}

func TestUUIDToShortID_DifferentUUIDsDifferentShortIds(t *testing.T) {
	// Use UUIDs that differ in the first 9 bytes (shortId only uses first 9 bytes)
	id1 := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	id2 := uuid.MustParse("650e8400-e29b-41d4-a716-446655440000") // different first byte (within first 9)
	s1 := UUIDToShortID(id1)
	s2 := UUIDToShortID(id2)
	if s1 == s2 {
		t.Errorf("different UUIDs should produce different shortIds: %q", s1)
	}
}

func TestValidateShortID(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"valid 12 chars", "0123456789AB", true},
		{"valid all base62", "0AaZz9", false}, // only 6 chars
		{"valid 12 base62", "0AaZz9123456", true},
		{"too short", "abc", false},
		{"too long", "0123456789ABC", false},
		{"empty", "", false},
		{"invalid char hyphen", "0123456789A-", false},
		{"invalid char space", "0123456789A ", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateShortID(tt.s)
			if got != tt.want {
				t.Errorf("ValidateShortID(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestShortIDRedisKey(t *testing.T) {
	key := ShortIDRedisKey("abc123xyz789")
	if key != "short_id_to_uuid:abc123xyz789" {
		t.Errorf("ShortIDRedisKey = %q, want short_id_to_uuid:abc123xyz789", key)
	}
}
