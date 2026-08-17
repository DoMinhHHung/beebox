package session

import "github.com/DoMinhHHung/beebox/internal/platform/publicid"

func NewPublicID() (string, error) {
	return publicid.NewUUIDv4("ses")
}

func ValidPublicID(value string) bool {
	return publicid.IsUUIDv4(value, "ses")
}
