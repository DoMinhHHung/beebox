package publicid

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var ErrGeneration = errors.New("public identifier generation failure")

// NewUUIDv4 returns a BeeBox-owned type-prefixed random UUIDv4 identifier.
// The prefix is semantic only; the UUID body carries no authority or tenant data.
func NewUUIDv4(prefix string) (string, error) {
	if prefix == "" || strings.Contains(prefix, "_") {
		return "", ErrGeneration
	}

	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", ErrGeneration
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80

	return fmt.Sprintf(
		"%s_%s-%s-%s-%s-%s",
		prefix,
		hex.EncodeToString(raw[0:4]),
		hex.EncodeToString(raw[4:6]),
		hex.EncodeToString(raw[6:8]),
		hex.EncodeToString(raw[8:10]),
		hex.EncodeToString(raw[10:16]),
	), nil
}

func IsUUIDv4(value, prefix string) bool {
	marker := prefix + "_"
	if prefix == "" || !strings.HasPrefix(value, marker) {
		return false
	}
	body := strings.TrimPrefix(value, marker)
	if len(body) != 36 || body[8] != '-' || body[13] != '-' || body[18] != '-' || body[23] != '-' {
		return false
	}
	hexBody := strings.ReplaceAll(body, "-", "")
	if len(hexBody) != 32 {
		return false
	}
	raw, err := hex.DecodeString(hexBody)
	if err != nil || len(raw) != 16 {
		return false
	}
	return raw[6]>>4 == 4 && raw[8]&0xc0 == 0x80
}

func UUIDBody(value, prefix string) (string, bool) {
	if !IsUUIDv4(value, prefix) {
		return "", false
	}
	return strings.TrimPrefix(value, prefix+"_"), true
}
