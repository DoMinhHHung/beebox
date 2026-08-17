package postgres

import cryptosha256 "crypto/sha256"

type sha256Package struct{}

func (sha256Package) Sum256(input []byte) [32]byte {
	return cryptosha256.Sum256(input)
}

var sha256 sha256Package
