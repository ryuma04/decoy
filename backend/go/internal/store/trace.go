package store

import (
	"context"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
)

// Round-trip counting for performance work: a caller puts a counter in the context (WithQueryCounter) and every
// query made with that context increments it. Costs one context lookup per query when unused.

type counterKey struct{}

// WithQueryCounter returns a context whose queries are counted into n.
func WithQueryCounter(ctx context.Context, n *atomic.Int64) context.Context {
	return context.WithValue(ctx, counterKey{}, n)
}

type queryCounter struct{}

func (queryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	if n, ok := ctx.Value(counterKey{}).(*atomic.Int64); ok {
		n.Add(1)
	}
	return ctx
}

func (queryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
