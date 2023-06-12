package signal

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// WithSignals returns a copy of the parent context cancelable by the given system signals. The signals are reset when the context's Done channel is closed.
func WithSignals(parent context.Context, signals ...os.Signal) (context.Context, context.CancelFunc) {
	keep := keeper{}
	ctx, cancel := context.WithCancel(context.WithValue(parent, wrap{}, &keep))
	sigCh := make(chan os.Signal, 1)

	// NOTE: Be aware signal handling is vulnerable to race conditions.
	signal.Notify(sigCh, signals...)
	go withSignalsHandler(ctx, cancel, sigCh, &keep)

	return ctx, cancel
}

func withSignalsHandler(ctx context.Context, cancel context.CancelFunc, sigCh chan os.Signal, internal *keeper) {
	select {
	case sig := <-sigCh:
		internal.mu.Lock()
		internal.sig = sig
		internal.mu.Unlock()

		signal.Stop(sigCh)
		cancel()
		return
	case <-ctx.Done():
		signal.Stop(sigCh)
	}
}

type wrap struct{}

type keeper struct {
	mu  sync.RWMutex
	sig os.Signal
}

// WithTermination creates a context canceled on signals SIGINT or SIGTERM.
func WithTermination(ctx context.Context) (context.Context, context.CancelFunc) {
	return WithSignals(ctx, syscall.SIGINT, syscall.SIGTERM)
}

// Closed gets the signal that closed a context channel.
func Closed(ctx context.Context) (os.Signal, error) {
	if value := ctx.Value(wrap{}); value != nil {
		if keep, ok := value.(*keeper); ok {
			keep.mu.RLock()
			osSig := keep.sig
			keep.mu.RUnlock()

			if osSig != nil {
				return osSig, nil
			}
		}
	}

	var s os.Signal
	return s, errors.New("context not closed by signal")
}
