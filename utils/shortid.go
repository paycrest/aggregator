package utils

import (
	"context"
	"math/big"

	"github.com/google/uuid"
	"github.com/paycrest/aggregator/storage"
	"github.com/paycrest/aggregator/types"
)

func init() {
	types.OnPaymentOrderTerminalStatus = DeleteShortIDMapping
}

const (
	shortIDLength      = 12
	base62Alphabet     = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	shortIDRedisPrefix = "short_id_to_uuid:"
)

// UUIDToShortID returns a deterministic 12-character base62 string from the order UUID.
// It uses the first 9 bytes of the UUID: 8 bytes encoded as base62 (11 chars) + 1 byte for the 12th character.
func UUIDToShortID(id uuid.UUID) string {
	b := id[:9]
	// First 8 bytes as 64-bit big-endian integer
	n := new(big.Int).SetBytes(b[:8])
	// Encode to base62 (produces up to 11 chars for 2^64)
	var buf [shortIDLength]byte
	i := shortIDLength - 1
	base := big.NewInt(62)
	zero := big.NewInt(0)
	for n.Cmp(zero) > 0 && i >= 0 {
		var mod big.Int
		n.DivMod(n, base, &mod)
		buf[i] = base62Alphabet[mod.Int64()]
		i--
	}
	// Pad with zeros (leading chars) so we have 11 chars from the 8 bytes
	for i >= 1 {
		buf[i] = base62Alphabet[0]
		i--
	}
	// 12th character from 9th byte
	buf[0] = base62Alphabet[int(b[8])%62]
	return string(buf[:])
}

// ValidateShortID returns true if s is exactly 12 characters and all characters are base62.
func ValidateShortID(s string) bool {
	if len(s) != shortIDLength {
		return false
	}
	for _, c := range s {
		if !isBase62(c) {
			return false
		}
	}
	return true
}

func isBase62(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// DeleteShortIDMapping removes the short_id_to_uuid mapping for the given order ID from Redis.
// Safe to call if the key is already missing (idempotent).
func DeleteShortIDMapping(ctx context.Context, orderID uuid.UUID) {
	shortId := UUIDToShortID(orderID)
	key := shortIDRedisPrefix + shortId
	_ = storage.RedisClient.Del(ctx, key).Err()
}

// ShortIDRedisKey returns the Redis key for a short ID (for use by callers that need to GET/SET).
func ShortIDRedisKey(shortId string) string {
	return shortIDRedisPrefix + shortId
}
