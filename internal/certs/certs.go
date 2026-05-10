package certs

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/athanvi/heimdall/internal/model"
	"github.com/athanvi/heimdall/internal/openssh"
)

var validLine = regexp.MustCompile(`Valid:\s+from\s+(.+?)\s+to\s+(.+)$`)

type RefreshResult struct {
	Name     string   `json:"name"`
	Command  []string `json:"command"`
	Executed bool     `json:"executed"`
	Stdout   string   `json:"stdout,omitempty"`
	Stderr   string   `json:"stderr,omitempty"`
	ExitCode int      `json:"exit_code,omitempty"`
}

func Inspect(ctx context.Context, runner openssh.Runner, path string, now time.Time) model.Certificate {
	cert := model.Certificate{Path: path}
	if runner == nil {
		runner = openssh.ExecRunner{}
	}
	res, err := runner.Run(ctx, "ssh-keygen", []string{"-L", "-f", path})
	if err != nil {
		cert.Error = strings.TrimSpace(res.Stderr)
		if cert.Error == "" {
			cert.Error = err.Error()
		}
		return cert
	}
	cert.RawSummary = strings.TrimSpace(res.Stdout)
	parseCertificateOutput(&cert, res.Stdout, now)
	return cert
}

func parseCertificateOutput(cert *model.Certificate, output string, now time.Time) {
	lines := strings.Split(output, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		switch {
		case strings.HasPrefix(line, "Key ID:"):
			cert.KeyID = trimQuoted(strings.TrimSpace(strings.TrimPrefix(line, "Key ID:")))
		case strings.HasPrefix(line, "Serial:"):
			cert.Serial = strings.TrimSpace(strings.TrimPrefix(line, "Serial:"))
		case strings.HasPrefix(line, "Valid:"):
			m := validLine.FindStringSubmatch(line)
			if len(m) == 3 {
				cert.ValidAfter = parseOpenSSHTime(m[1])
				cert.ValidBefore = parseOpenSSHTime(m[2])
				if !cert.ValidBefore.IsZero() {
					cert.Expired = !now.Before(cert.ValidBefore)
					cert.NearExpiry = now.Before(cert.ValidBefore) && now.Add(14*24*time.Hour).After(cert.ValidBefore)
				}
			}
		case strings.HasPrefix(line, "Principals:"):
			for j := i + 1; j < len(lines); j++ {
				next := strings.TrimSpace(lines[j])
				if next == "" || strings.Contains(next, ":") {
					break
				}
				cert.Principals = append(cert.Principals, next)
				i = j
			}
		}
	}
}

func parseOpenSSHTime(value string) time.Time {
	formats := []string{
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05Z",
		time.RFC3339,
	}
	value = strings.TrimSpace(value)
	for _, format := range formats {
		if t, err := time.Parse(format, value); err == nil {
			return t
		}
	}
	return time.Time{}
}

func trimQuoted(value string) string {
	return strings.Trim(value, `"`)
}

func Refresh(ctx context.Context, runner openssh.Runner, name string, ref model.CertificateRef, execute bool) (RefreshResult, error) {
	result := RefreshResult{Name: name, Command: append([]string(nil), ref.RefreshHook...), Executed: execute}
	if len(ref.RefreshHook) == 0 {
		return result, fmt.Errorf("certificate %q has no refresh_hook", name)
	}
	if err := validateHook(ref.RefreshHook); err != nil {
		return result, err
	}
	if !execute {
		return result, nil
	}
	if runner == nil {
		runner = openssh.ExecRunner{}
	}
	res, err := runner.Run(ctx, ref.RefreshHook[0], ref.RefreshHook[1:])
	result.Stdout = res.Stdout
	result.Stderr = res.Stderr
	result.ExitCode = res.ExitCode
	if err != nil {
		return result, err
	}
	return result, nil
}

func validateHook(argv []string) error {
	if len(argv) == 0 || argv[0] == "" {
		return fmt.Errorf("refresh hook command is required")
	}
	for _, arg := range argv {
		if strings.ContainsRune(arg, '\x00') || strings.ContainsAny(arg, "\n\r") {
			return fmt.Errorf("refresh hook contains invalid control characters")
		}
		if strings.Contains(arg, "-----BEGIN") || strings.Contains(strings.ToLower(arg), "private key") {
			return fmt.Errorf("refresh hook must not contain private key material")
		}
	}
	return nil
}
