package runner_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/badu/wg-cc/pkg/runner"
)

func ExampleGroup_Add_basic() {
	var g runner.Group
	{
		cancel := make(chan struct{})
		g.Add(func() error {
			select {
			case <-time.After(time.Second):
				fmt.Printf("The first funcPair had its time elapsed\n")
				return nil
			case <-cancel:
				fmt.Printf("The first funcPair was canceled\n")
				return nil
			}
		}, func(err error) {
			fmt.Printf("The first funcPair was interrupted with: %v\n", err)
			close(cancel)
		})
	}
	{
		g.Add(func() error {
			fmt.Printf("The second funcPair is returning immediately\n")
			return errors.New("immediate teardown")
		}, func(err error) {
			// Note that this interrupt function is called, even though the
			// corresponding execute function has already returned.
			fmt.Printf("The second funcPair was interrupted with: %v\n", err)
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	fmt.Printf("The group was terminated with: %v\n", g.Wait(ctx, cancel))
	// Output:
	// The second funcPair is returning immediately
	// The first funcPair was interrupted with: immediate teardown
	// The second funcPair was interrupted with: immediate teardown
	// The first funcPair was canceled
	// The group was terminated with: immediate teardown
}

func ExampleGroup_Add_context() {
	ctx, cancel := context.WithCancel(context.Background())
	var g runner.Group
	{
		ctx, cancel := context.WithCancel(ctx) // note: shadowed
		g.Add(func() error {
			return runUntilCanceled(ctx)
		}, func(error) {
			cancel()
		})
	}
	go cancel()
	fmt.Printf("The group was terminated with: %v\n", g.Wait(ctx, cancel))
	// Output:
	// The group was terminated with: context done
}

func ExampleGroup_Add_listener() {
	var g runner.Group
	{
		ln, _ := net.Listen("tcp", ":0")
		g.Add(func() error {
			defer fmt.Printf("http.Serve returned\n")
			return http.Serve(ln, http.NewServeMux())
		}, func(error) {
			ln.Close()
		})
	}
	{
		g.Add(func() error {
			return errors.New("immediate teardown")
		}, func(error) {
			//
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	fmt.Printf("The group was terminated with: %v\n", g.Wait(ctx, cancel))
	// Output:
	// http.Serve returned
	// The group was terminated with: immediate teardown
}

func runUntilCanceled(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestZero(t *testing.T) {
	var g runner.Group
	res := make(chan error)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { res <- g.Wait(ctx, cancel) }()
	select {
	case err := <-res:
		if err != nil {
			t.Errorf("%v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout")
	}
}

func TestOne(t *testing.T) {
	myError := errors.New("foobar")
	var g runner.Group
	g.Add(func() error { return myError }, func(error) {})
	res := make(chan error)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { res <- g.Wait(ctx, cancel) }()
	select {
	case err := <-res:
		if want, have := myError, err; want != have {
			t.Errorf("want %v, have %v", want, have)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout")
	}
}

func TestMany(t *testing.T) {
	interrupt := errors.New("interrupt")
	var g runner.Group
	g.Add(func() error { return interrupt }, func(error) {})
	cancel := make(chan struct{})
	g.Add(func() error { <-cancel; return nil }, func(error) { close(cancel) })
	res := make(chan error)

	ctx, cancel2 := context.WithCancel(context.Background())
	go func() { res <- g.Wait(ctx, cancel2) }()
	select {
	case err := <-res:
		if want, have := interrupt, err; want != have {
			t.Errorf("want %v, have %v", want, have)
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("timeout")
	}
}
