// Package result implements the G02 prototype result envelope
// (docs/g02/slice-contract.md §1, schemas/g02/result.schema.json).
// Shared by every CLI subcommand; the TUI does not emit JSON.
package result

import (
	"encoding/json"
	"io"
)

// Codes (prototype-local, contract §1).
const (
	ProfileOK          = "PROFILE_OK"
	AgentOK            = "AGENT_OK"
	VersionOK          = "VERSION_OK"
	ChildExited        = "CHILD_EXITED"
	ChildLaunchFailed  = "CHILD_LAUNCH_FAILED"
	UsageError         = "USAGE_ERROR"
	SchemaInvalid      = "SCHEMA_INVALID"
	InputTooLarge      = "INPUT_TOO_LARGE"
	AgentUnavailable   = "AGENT_UNAVAILABLE"
	AgentProtocolError = "AGENT_PROTOCOL_ERROR"
	AgentRefused       = "AGENT_REFUSED"
	Cancelled          = "CANCELLED"
	Internal           = "INTERNAL"
)

// States.
const (
	Succeeded       = "succeeded"
	Failed          = "failed"
	StateCancelled  = "cancelled"
	SchemaVersion   = "1"
	ExitOK          = 0
	ExitInternal    = 1
	ExitUsage       = 2
	ExitUnavailable = 5
	ExitCancelled   = 130
)

// Envelope is the single JSON document written to stdout.
type Envelope struct {
	SchemaVersion string         `json:"schema_version"`
	State         string         `json:"state"`
	Code          string         `json:"code"`
	Data          any            `json:"data"`
	Warnings      []string       `json:"warnings"`
	Next          map[string]any `json:"next"`
}

// ErrorInfo is the contract's error data shape. KeyPath is nil when no key
// path applies. Message must never contain an input value.
type ErrorInfo struct {
	KeyPath *string `json:"key_path"`
	Message string  `json:"message"`
}

// ExitCode maps a code to the contract exit status (run is handled separately).
func ExitCode(code string) int {
	switch code {
	case ProfileOK, AgentOK, VersionOK:
		return ExitOK
	case UsageError, SchemaInvalid, InputTooLarge:
		return ExitUsage
	case AgentUnavailable, AgentProtocolError, AgentRefused:
		return ExitUnavailable
	case Cancelled:
		return ExitCancelled
	default:
		return ExitInternal
	}
}

// OK builds a success envelope.
func OK(code string, data any) Envelope {
	return Envelope{SchemaVersion: SchemaVersion, State: Succeeded, Code: code, Data: data, Warnings: []string{}}
}

// Fail builds a failure envelope with the contract error data shape.
func Fail(code string, keyPath *string, message string, warnings ...string) Envelope {
	if warnings == nil {
		warnings = []string{}
	}
	return Envelope{
		SchemaVersion: SchemaVersion, State: Failed, Code: code,
		Data:     map[string]any{"error": ErrorInfo{KeyPath: keyPath, Message: message}},
		Warnings: warnings,
	}
}

// CancelledEnvelope builds the cancellation envelope.
func CancelledEnvelope() Envelope {
	return Envelope{SchemaVersion: SchemaVersion, State: StateCancelled, Code: Cancelled, Data: nil, Warnings: []string{}}
}

// Write emits exactly one JSON document followed by "\n". HTML escaping is
// disabled; Go's encoder escapes control characters as \u00XX, so no raw ESC
// byte can reach the output stream.
func Write(w io.Writer, e Envelope) error {
	if e.Warnings == nil {
		e.Warnings = []string{}
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(e)
}
