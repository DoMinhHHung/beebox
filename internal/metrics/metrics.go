package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Recorder stores bounded operation/outcome counters for Phase 1 authentication.
// Callers must only pass fixed vocabulary values; resource identifiers, email,
// tokens, credential IDs, and raw errors are intentionally excluded.
type Recorder struct {
	mu      sync.RWMutex
	counts  map[string]uint64
}

func New() *Recorder {
	return &Recorder{counts: make(map[string]uint64)}
}

func (r *Recorder) Observe(operation, outcome string) {
	if r == nil || !validLabel(operation) || !validLabel(outcome) {
		return
	}
	key := operation + "\x00" + outcome
	r.mu.Lock()
	r.counts[key]++
	r.mu.Unlock()
}

func (r *Recorder) Snapshot() map[string]uint64 {
	if r == nil {
		return map[string]uint64{}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]uint64, len(r.counts))
	for key, count := range r.counts {
		out[key] = count
	}
	return out
}

func (r *Recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintln(w, "# HELP beebox_auth_operations_total BeeBox Phase 1 authentication operation outcomes.")
	_, _ = fmt.Fprintln(w, "# TYPE beebox_auth_operations_total counter")
	keys := make([]string, 0, len(r.Snapshot()))
	for key := range r.Snapshot() {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	snapshot := r.Snapshot()
	for _, key := range keys {
		parts := strings.SplitN(key, "\x00", 2)
		_, _ = fmt.Fprintf(w, "beebox_auth_operations_total{operation=%q,outcome=%q} %d\n", parts[0], parts[1], snapshot[key])
	}
}

func validLabel(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' {
			continue
		}
		return false
	}
	return true
}
