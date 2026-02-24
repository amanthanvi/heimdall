package sshconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func EnsureInclude(configPath, includePath string) error {
	configPath = strings.TrimSpace(configPath)
	includePath = strings.TrimSpace(includePath)
	if configPath == "" {
		return fmt.Errorf("ssh config include: config path is required")
	}
	if includePath == "" {
		return fmt.Errorf("ssh config include: include path is required")
	}

	content, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("ssh config include: read config: %w", err)
	}

	lines := splitLines(string(content))
	if hasInclude(lines, includePath) {
		return nil
	}

	line := includeDirectiveLine(includePath)
	if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
		lines = append(lines, "")
	}
	lines = append(lines, line)

	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return fmt.Errorf("ssh config include: create directory: %w", err)
	}
	out := strings.Join(lines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	if err := os.WriteFile(configPath, []byte(out), 0o600); err != nil {
		return fmt.Errorf("ssh config include: write config: %w", err)
	}
	return nil
}

func RemoveInclude(configPath, includePath string) error {
	configPath = strings.TrimSpace(configPath)
	includePath = strings.TrimSpace(includePath)
	if configPath == "" {
		return fmt.Errorf("ssh config include: config path is required")
	}
	if includePath == "" {
		return fmt.Errorf("ssh config include: include path is required")
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("ssh config include: read config: %w", err)
	}
	lines := splitLines(string(content))
	filtered := make([]string, 0, len(lines))
	changed := false
	for _, line := range lines {
		if includeLineMatches(line, includePath) {
			changed = true
			continue
		}
		filtered = append(filtered, line)
	}
	if !changed {
		return nil
	}
	out := strings.Join(filtered, "\n")
	if strings.TrimSpace(out) != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	if err := os.WriteFile(configPath, []byte(out), 0o600); err != nil {
		return fmt.Errorf("ssh config include: write config: %w", err)
	}
	return nil
}

func hasInclude(lines []string, includePath string) bool {
	for _, line := range lines {
		if includeLineMatches(line, includePath) {
			return true
		}
	}
	return false
}

func includeLineMatches(line, includePath string) bool {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return false
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "Include") {
		return false
	}
	value := strings.Trim(strings.Join(fields[1:], " "), `"`)
	return strings.TrimSpace(value) == strings.TrimSpace(includePath)
}

func includeDirectiveLine(includePath string) string {
	if strings.Contains(includePath, " ") {
		return fmt.Sprintf("Include %q", includePath)
	}
	return "Include " + includePath
}

func splitLines(content string) []string {
	if content == "" {
		return nil
	}
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.TrimSuffix(content, "\n")
	if content == "" {
		return nil
	}
	return strings.Split(content, "\n")
}
