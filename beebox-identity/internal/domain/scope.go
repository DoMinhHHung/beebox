package domain

import (
	"strings"

	"github.com/google/uuid"
)

type Scope struct {
	ProjectID uuid.UUID
	Env       string
	Modules   []string
	Disabled  bool
}

func ValidEnv(env string) bool {
	return env == EnvTest || env == EnvLive
}

func (s Scope) HasModule(name string) bool {
	for _, item := range s.Modules {
		if item == name {
			return true
		}
	}
	return false
}

func SplitModules(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return []string{}
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return out
}
