package application

import (
	"regexp"
	"strings"
)

var slugRE = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func validSlug(slug string) bool {
	n := len(slug)
	return n >= 3 && n <= 48 && slugRE.MatchString(slug)
}

func validEmail(email string) bool {
	email = strings.TrimSpace(email)
	at := strings.IndexByte(email, '@')
	return at > 0 && at < len(email)-1 && !strings.Contains(email, " ")
}
