package clients

import (
	"context"
	"log/slog"
	"sync"
	"errors"

	"github.com/miekg/dns"
)

// QueryFunc represents the signature of a query function
type QueryFunc func(ctx context.Context, dst Destination, question dns.Question, flags QueryFlags) (*dns.Msg, error)

// ConcurrentLookup performs concurrent DNS lookups
func ConcurrentLookup(ctx context.Context, dst Destination, questions []dns.Question, flags QueryFlags, queryFunc QueryFunc, logger *slog.Logger) ([]*dns.Msg, error) {
	var wg sync.WaitGroup
	responses := make([]*dns.Msg, len(questions))
	errs := make([]error, len(questions))
	done := make(chan struct{})

	for i, q := range questions {
		wg.Add(1)
		go func(i int, q dns.Question) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				errs[i] = ctx.Err()
			default:
				resp, err := queryFunc(ctx, dst, q, flags)
				responses[i] = resp
				errs[i] = err
			}
		}(i, q)
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		// All goroutines have finished
	}

	// Collect non-nil responses and handle errors
	var validResponses []*dns.Msg
	var err error
	for i, resp := range responses {
		if errs[i] != nil {
			err = errors.Join(err, errs[i])
			if errs[i] != context.Canceled && errs[i] != context.DeadlineExceeded {
				logger.Error("error in lookup", "error", errs[i])
			}
		} else {
			validResponses = append(validResponses, resp)
		}
	}

	// NOTE: not sure when this would happen
	if ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}

	return validResponses, err
}
