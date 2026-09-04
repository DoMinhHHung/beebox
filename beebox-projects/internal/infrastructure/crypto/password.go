package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

type Argon2id struct{}

func (Argon2id) Hash(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, uint8(argonThreads), argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	), nil
}

func (Argon2id) Verify(password, encoded string) bool {
	salt, want, timeCost, memory, threads, keyLen, ok := parseArgon2id(encoded)
	if !ok {
		dummy := make([]byte, argonKeyLen)
		got := argon2.IDKey([]byte(password), make([]byte, argonSaltLen), argonTime, argonMemory, uint8(argonThreads), argonKeyLen)
		subtle.ConstantTimeCompare(got, dummy)
		return false
	}
	got := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, keyLen)
	if len(got) != len(want) {
		subtle.ConstantTimeCompare(got, got)
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

func parseArgon2id(encoded string) (salt, hash []byte, timeCost, memory uint32, threads uint8, keyLen uint32, ok bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, nil, 0, 0, 0, 0, false
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) && parts[2] != "v=19" {
		return nil, nil, 0, 0, 0, 0, false
	}
	var m, t, p int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return nil, nil, 0, 0, 0, 0, false
	}
	if m <= 0 || t <= 0 || p <= 0 {
		return nil, nil, 0, 0, 0, 0, false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		salt, err = base64.StdEncoding.DecodeString(parts[4])
		if err != nil {
			return nil, nil, 0, 0, 0, 0, false
		}
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		hash, err = base64.StdEncoding.DecodeString(parts[5])
		if err != nil {
			return nil, nil, 0, 0, 0, 0, false
		}
	}
	if len(salt) == 0 || len(hash) == 0 {
		return nil, nil, 0, 0, 0, 0, false
	}
	return salt, hash, uint32(t), uint32(m), uint8(p), uint32(len(hash)), true
}
