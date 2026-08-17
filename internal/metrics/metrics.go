package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

type DatabaseStats struct {
	AcquiredConns int32
	IdleConns     int32
	TotalConns    int32
	MaxConns      int32
}

// Recorder stores bounded operation/outcome counters for Phase 1 authentication.
// Callers must only pass fixed vocabulary values; resource identifiers, email,
// tokens, credential IDs, and raw errors are intentionally excluded.
type Recorder struct {
	mu            sync.RWMutex
	counts        map[string]uint64
	databaseStats func() DatabaseStats
}

func New() *Recorder {
	return &Recorder{counts: make(map[string]uint64)}
}

func (r *Recorder) SetDatabaseStatsProvider(provider func() DatabaseStats) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.databaseStats = provider
	r.mu.Unlock()
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
	snapshot := r.Snapshot()
	keys := make([]string, 0, len(snapshot))
	for key := range snapshot {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts := strings.SplitN(key, "\x00", 2)
		_, _ = fmt.Fprintf(w, "beebox_auth_operations_total{operation=%q,outcome=%q} %d\n", parts[0], parts[1], snapshot[key])
	}

	r.mu.RLock()
	provider := r.databaseStats
	r.mu.RUnlock()
	if provider != nil {
		stats := provider()
		_, _ = fmt.Fprintln(w, "# TYPE beebox_database_pool_connections gauge")
		_, _ = fmt.Fprintf(w, "beebox_database_pool_connections{state=\"acquired\"} %d\n", stats.AcquiredConns)
		_, _ = fmt.Fprintf(w, "beebox_database_pool_connections{state=\"idle\"} %d\n", stats.IdleConns)
		_, _ = fmt.Fprintf(w, "beebox_database_pool_connections{state=\"total\"} %d\n", stats.TotalConns)
		_, _ = fmt.Fprintf(w, "beebox_database_pool_connections{state=\"max\"} %d\n", stats.MaxConns)
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
