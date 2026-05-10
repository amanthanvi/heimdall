package transport

import (
	"context"
	"os/exec"
	"strings"

	"github.com/athanvi/heimdall/internal/model"
)

func RenderProxyCommand(tr model.ExternalTransport) string {
	if tr.Type != "proxy_command" {
		return ""
	}
	parts := append([]string{tr.Binary}, tr.Args...)
	return strings.Join(parts, " ")
}

func SuspiciousProxyCommand(command string) bool {
	return strings.ContainsAny(command, "|&;<>()`$\\\n\r")
}

func MissingBinary(_ context.Context, tr model.ExternalTransport) bool {
	if tr.Binary == "" {
		return true
	}
	_, err := exec.LookPath(tr.Binary)
	return err != nil
}
