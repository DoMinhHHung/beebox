package database

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	errInvalidConfiguration = errors.New("invalid PostgreSQL pool configuration")
	errUnavailable          = errors.New("PostgreSQL is unavailable")
)

// Pool owns the process-wide PostgreSQL connection pool.
type Pool struct {
	pool *pgxpool.Pool
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

// Close releases every connection and background resource owned by the pool.
func (p *Pool) Close() {
	p.pool.Close()
}
