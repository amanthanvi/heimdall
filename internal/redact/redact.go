package redact

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Level string

const (
	Low     Level = "low"
	Default Level = "default"
	High    Level = "high"
)

var tokenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(token|secret|password|passphrase|refresh[_-]?token)=([^ \n\t]+)`),
	regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
}

func String(s string, level Level) string {
	out := s
	for _, re := range tokenPatterns {
		out = re.ReplaceAllString(out, `$1=<redacted>`)
	}
	if level == Low {
		return out
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		out = strings.ReplaceAll(out, home, "~")
	}
	if level == High {
		out = redactAbsolutePaths(out)
	}
	return out
}

func Slice(values []string, level Level) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = String(value, level)
	}
	return out
}

func Path(path string, level Level) string {
	if level == Low || path == "" {
		return path
	}
	home, err := os.UserHomeDir()
	if err == nil {
		if rel, relErr := filepath.Rel(home, path); relErr == nil && !strings.HasPrefix(rel, "..") {
			return filepath.Join("~", rel)
		}
	}
	if level == High && filepath.IsAbs(path) {
		return filepath.Join("<path>", filepath.Base(path))
	}
	return path
}

func redactAbsolutePaths(s string) string {
	fields := strings.Fields(s)
	for i, field := range fields {
		cleaned := strings.Trim(field, `"',;:()[]{}<>`)
		if filepath.IsAbs(cleaned) {
			fields[i] = strings.Replace(field, cleaned, filepath.Join("<path>", filepath.Base(cleaned)), 1)
		}
	}
	return strings.Join(fields, " ")
}
