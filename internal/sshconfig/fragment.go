package sshconfig

import (
	"fmt"
	"sort"
	"strings"

	"github.com/amanthanvi/heimdall/internal/storage"
)

func Generate(hosts []storage.Host) string {
	items := make([]storage.Host, 0, len(hosts))
	for _, host := range hosts {
		if strings.TrimSpace(host.Name) == "" {
			continue
		}
		items = append(items, host)
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].Name < items[j].Name
	})

	var builder strings.Builder
	for idx := range items {
		host := items[idx]
		if idx > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString("Host ")
		builder.WriteString(host.Name)
		builder.WriteByte('\n')
		builder.WriteString("  HostName ")
		builder.WriteString(host.Address)
		builder.WriteByte('\n')
		if user := strings.TrimSpace(host.User); user != "" {
			builder.WriteString("  User ")
			builder.WriteString(user)
			builder.WriteByte('\n')
		}
		port := host.Port
		if port == 0 {
			port = 22
		}
		fmt.Fprintf(&builder, "  Port %d\n", port)

		proxyJump := strings.TrimSpace(host.ProxyJump)
		if proxyJump == "" {
			proxyJump = strings.TrimSpace(host.EnvRefs["proxy_jump"])
		}
		if proxyJump != "" {
			builder.WriteString("  ProxyJump ")
			builder.WriteString(proxyJump)
			builder.WriteByte('\n')
		}

		identityFile := strings.TrimSpace(host.IdentityFile)
		if identityFile == "" {
			identityFile = strings.TrimSpace(host.EnvRefs["identity_ref"])
		}
		if identityFile != "" {
			builder.WriteString("  IdentityFile ")
			builder.WriteString(identityFile)
			builder.WriteByte('\n')
			builder.WriteString("  IdentitiesOnly yes\n")
		}
	}
	return builder.String()
}
