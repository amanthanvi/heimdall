package ssh

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type BinaryInfo struct {
	Path              string
	Version           string
	SupportsProxyJump bool
}

type BinaryCheckDeps struct {
	LookPath   func(file string) (string, error)
	GetVersion func(path string) (string, error)
}

func CheckBinary(deps BinaryCheckDeps) (*BinaryInfo, error) {
	lookPath := deps.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	getVersion := deps.GetVersion
	if getVersion == nil {
		getVersion = defaultVersionReader
	}

	path, err := lookPath("ssh")
	if err != nil {
		return nil, &ExitError{
			Code:    ExitCodeDependencyUnavailable,
			Message: "OpenSSH client not found; install OpenSSH and retry",
			Err:     ErrDependencyUnavailable,
		}
	}
	version, err := getVersion(path)
	if err != nil {
		return nil, fmt.Errorf("check ssh binary version: %w", err)
	}

	return &BinaryInfo{
		Path:              path,
		Version:           version,
		SupportsProxyJump: supportsProxyJump(version),
	}, nil
}

func defaultVersionReader(path string) (string, error) {
	cmd := exec.Command(path, "-V")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("run %s -V: %w", path, err)
	}
	return strings.TrimSpace(string(output)), nil
}

var opensshVersionRe = regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)

func supportsProxyJump(version string) bool {
	matches := opensshVersionRe.FindStringSubmatch(version)
	if len(matches) != 3 {
		return false
	}
	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return false
	}
	minor, err := strconv.Atoi(matches[2])
	if err != nil {
		return false
	}

	if major > 7 {
		return true
	}
	return major == 7 && minor >= 3
}
