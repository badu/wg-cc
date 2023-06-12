package runner

import (
	"context"
	"fmt"
)

type Runner func() error
type Erroer func(error)

type funcPair struct {
	execute   Runner
	interrupt Erroer
}

type Group struct {
	fns []funcPair
}

func (g *Group) Add(execute Runner, interrupt Erroer) {
	g.fns = append(g.fns, funcPair{execute, interrupt})
}

func (g *Group) Wait(ctx context.Context, cancel context.CancelFunc) error {
	if len(g.fns) == 0 {
		return nil
	}

	// Wait each funcPair.
	errors := make(chan error, len(g.fns))
	for _, fn := range g.fns {
		go func(a funcPair) {
			errors <- a.execute()
		}(fn)
	}

	var err error
	select {
	case <-ctx.Done():
		err = fmt.Errorf("context done")
	case err = <-errors:
		// Wait for the first funcPair to stop.
		cancel()
	}

	// Signal all fns to stop.
	for _, fn := range g.fns {
		fn.interrupt(err)
	}

	// Wait for all fns to stop.
	for i := 1; i < cap(errors); i++ {
		<-errors
	}

	// Return the original error.
	return err
}
