package agent

import (
	"context"
	"errors"
	"time"
)

// Outcome classifies a probe result into contract codes.
type Outcome int

const (
	OutcomeOK Outcome = iota
	OutcomeUnavailable
	OutcomeProtocolError
	OutcomeRefused
	OutcomeCancelled
)

// Result of a probe. Detail is a diagnostic for stderr; it never contains
// response bytes.
type Result struct {
	Outcome    Outcome
	Identities []Identity
	Detail     string
}

// Probe connects to the endpoint (Unix socket or Windows named pipe, see
// dial_*.go), sends exactly one REQUEST_IDENTITIES frame, and reads one
// response. cancel is the user-cancellation context (SIGINT / console Ctrl-C);
// timeout bounds connect plus the complete response.
func Probe(cancel context.Context, path string, timeout time.Duration) Result {
	ctx, stop := context.WithTimeout(cancel, timeout)
	defer stop()

	classify := func(err error, what string) Result {
		if cancel.Err() != nil {
			return Result{Outcome: OutcomeCancelled, Detail: "cancelled"}
		}
		if errors.Is(err, ErrRefused) {
			return Result{Outcome: OutcomeRefused, Detail: "agent returned SSH_AGENT_FAILURE"}
		}
		if errors.Is(err, ErrProtocol) {
			return Result{Outcome: OutcomeProtocolError, Detail: err.Error()}
		}
		if ctx.Err() != nil {
			return Result{Outcome: OutcomeUnavailable, Detail: what + ": no complete response within timeout"}
		}
		if errors.Is(err, ErrNoResponse) {
			return Result{Outcome: OutcomeUnavailable, Detail: ErrNoResponse.Error()}
		}
		return Result{Outcome: OutcomeUnavailable, Detail: what + " failed"}
	}

	conn, err := dial(ctx, path)
	if err != nil {
		return classify(err, "connect")
	}
	defer conn.Close()
	// Close the connection as soon as the user cancels or the deadline passes;
	// this unblocks any pending read/write immediately.
	stopAfter := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopAfter()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	if _, err := conn.Write(RequestIdentitiesFrame); err != nil {
		return classify(err, "write")
	}
	body, err := ReadFrame(conn)
	if err != nil {
		// A closed-by-us connection surfaces as a generic net error; cancel
		// and timeout are checked first in classify.
		if ctx.Err() != nil && !errors.Is(err, ErrProtocol) {
			return classify(ctx.Err(), "read")
		}
		return classify(err, "read")
	}
	ids, err := ParseResponse(body)
	if err != nil {
		return classify(err, "parse")
	}
	if cancel.Err() != nil {
		return Result{Outcome: OutcomeCancelled, Detail: "cancelled"}
	}
	return Result{Outcome: OutcomeOK, Identities: ids}
}
