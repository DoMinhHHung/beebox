package database

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

var (
	errInvalidConfiguration = errors.New("invalid PostgreSQL pool configuration")
	errUnavailable          = errors.New("PostgreSQL is unavailable")
)

// Pool owns the process-wide PostgreSQL connection pool.
type Pool struct {
	pool *pgxpool.Pool
}

type Stats struct {
	AcquiredConns int32
	IdleConns     int32
	TotalConns    int32
	MaxConns      int32
}

// Open parses the PostgreSQL configuration and creates a pool without
// establishing a connection. Call Ping with a bounded context before serving.
func Open(ctx context.Context, databaseURL string) (*Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, errInvalidConfiguration
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errInvalidConfiguration
	}

	return &Pool{pool: pool}, nil
}

// Ping verifies that PostgreSQL is currently reachable. Provider details are
// intentionally discarded so callers cannot expose credentials or topology.
func (p *Pool) Ping(ctx context.Context) error {
	if err := p.pool.Ping(ctx); err != nil {
		return errUnavailable
	}

	return nil
}

// Stats returns bounded process-pool occupancy values suitable for operational
// metrics. It exposes no database URL, credentials, SQL text, tenant or resource
// identifiers.
func (p *Pool) Stats() Stats {
	if p == nil || p.pool == nil {
		return Stats{}
	}
	stats := p.pool.Stat()
	return Stats{
		AcquiredConns: stats.AcquiredConns(),
		IdleConns:     stats.IdleConns(),
		TotalConns:    stats.TotalConns(),
		MaxConns:      stats.MaxConns(),
	}
}

// OpenSQLDB returns a database/sql adapter backed by this pool. Closing the
// adapter does not close the underlying pgx pool; callers own the adapter and
// must close it exactly once.
func (p *Pool) OpenSQLDB() *sql.DB {
	return stdlib.OpenDBFromPool(p.pool)
}

// Close releases every connection and background resource owned by the pool.
func (p *Pool) Close() {
	p.pool.Close()
}
