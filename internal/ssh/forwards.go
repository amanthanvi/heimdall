package ssh

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func parseForward(raw string) (string, string, error) {
	parts := strings.SplitN(strings.TrimSpace(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid forward %q", raw)
	}
	mode := strings.ToUpper(strings.TrimSpace(parts[0]))
	spec := strings.TrimSpace(parts[1])
	if spec == "" {
		return "", "", fmt.Errorf("invalid forward %q", raw)
	}

	switch mode {
	case "L":
		if err := validateLocalOrRemoteForward(spec); err != nil {
			return "", "", err
		}
		return "-L", spec, nil
	case "R":
		if err := validateLocalOrRemoteForward(spec); err != nil {
			return "", "", err
		}
		return "-R", spec, nil
	case "D":
		if err := validateDynamicForward(spec); err != nil {
			return "", "", err
		}
		return "-D", spec, nil
	default:
		return "", "", fmt.Errorf("unsupported forward mode %q", mode)
	}
}

func validateLocalOrRemoteForward(spec string) error {
	parts := strings.Split(spec, ":")
	if len(parts) != 3 && len(parts) != 4 {
		return fmt.Errorf("invalid forward address %q", spec)
	}
	idx := 0
	if len(parts) == 4 {
		if err := validateAddress(parts[0]); err != nil {
			return err
		}
		idx = 1
	}
	if err := validatePort(parts[idx]); err != nil {
		return err
	}
	if err := validateAddress(parts[idx+1]); err != nil {
		return err
	}
	if err := validatePort(parts[idx+2]); err != nil {
		return err
	}
	return nil
}

func validateDynamicForward(spec string) error {
	parts := strings.Split(spec, ":")
	if len(parts) != 1 && len(parts) != 2 {
		return fmt.Errorf("invalid dynamic forward address %q", spec)
	}
	portPart := parts[0]
	if len(parts) == 2 {
		if err := validateAddress(parts[0]); err != nil {
			return err
		}
		portPart = parts[1]
	}
	return validatePort(portPart)
}

func validateAddress(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return fmt.Errorf("address is required")
	}
	if strings.ContainsAny(addr, " \t\n\r") {
		return fmt.Errorf("invalid forward address %q", addr)
	}
	if strings.Contains(addr, "[") || strings.Contains(addr, "]") {
		return fmt.Errorf("invalid forward address %q", addr)
	}
	if ip := net.ParseIP(addr); ip != nil {
		return nil
	}
	if strings.Contains(addr, "..") {
		return fmt.Errorf("invalid forward address %q", addr)
	}
	return nil
}

func validatePort(raw string) error {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid forward port %q", raw)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("forward port out of range: %d", port)
	}
	return nil
}
