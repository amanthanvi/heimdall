package ssh

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCommandBuilderBasicHostProducesExpectedArgs(t *testing.T) {
	t.Parallel()

	builder := &CommandBuilder{}
	cmd, err := builder.Build(&Host{Address: "10.0.0.1", Port: 2222, User: "ubuntu"}, ConnectOpts{})
	require.NoError(t, err)
	require.Equal(t, "ssh", cmd.Binary)
	require.Equal(t, []string{"-p", "2222", "-o", "StrictHostKeyChecking=accept-new", "ubuntu@10.0.0.1"}, cmd.Args)
}

func TestCommandBuilderWithIdentityAddsIdentitiesOnly(t *testing.T) {
	t.Parallel()

	builder := &CommandBuilder{}
	cmd, err := builder.Build(&Host{Address: "10.0.0.1"}, ConnectOpts{IdentityPath: "/tmp/id_test"})
	require.NoError(t, err)
	joined := strings.Join(cmd.Args, " ")
	require.Contains(t, joined, "-i /tmp/id_test")
	require.Contains(t, joined, "-o IdentitiesOnly=yes")
}

func TestCommandBuilderWithJumpChainProducesProxyJumpList(t *testing.T) {
	t.Parallel()

	builder := &CommandBuilder{}
	cmd, err := builder.Build(&Host{Address: "10.0.0.1"}, ConnectOpts{JumpHosts: []string{"user@hop1", "user@hop2"}})
	require.NoError(t, err)
	require.Contains(t, strings.Join(cmd.Args, " "), "-J user@hop1,user@hop2")
}

func TestCommandBuilderProxyJumpNoneProducesOption(t *testing.T) {
	t.Parallel()

	builder := &CommandBuilder{}
	cmd, err := builder.Build(&Host{Address: "10.0.0.1"}, ConnectOpts{ProxyJumpNone: true})
	require.NoError(t, err)
	require.Contains(t, strings.Join(cmd.Args, " "), "-o ProxyJump=none")
}

func TestCommandBuilderLocalForwardProducesLFlag(t *testing.T) {
	t.Parallel()

	builder := &CommandBuilder{}
	cmd, err := builder.Build(&Host{Address: "10.0.0.1"}, ConnectOpts{Forwards: []string{"L:8080:localhost:80"}})
	require.NoError(t, err)
	require.Contains(t, strings.Join(cmd.Args, " "), "-L 8080:localhost:80")
}

func TestCommandBuilderRemoteForwardProducesRFlag(t *testing.T) {
	t.Parallel()

	builder := &CommandBuilder{}
	cmd, err := builder.Build(&Host{Address: "10.0.0.1"}, ConnectOpts{Forwards: []string{"R:2222:localhost:22"}})
	require.NoError(t, err)
	require.Contains(t, strings.Join(cmd.Args, " "), "-R 2222:localhost:22")
}

func TestCommandBuilderDynamicForwardProducesDFlag(t *testing.T) {
	t.Parallel()

	builder := &CommandBuilder{}
	cmd, err := builder.Build(&Host{Address: "10.0.0.1"}, ConnectOpts{Forwards: []string{"D:1080"}})
	require.NoError(t, err)
	require.Contains(t, strings.Join(cmd.Args, " "), "-D 1080")
}

func TestCommandBuilderMultipleForwardsCombinedCorrectly(t *testing.T) {
	t.Parallel()

	builder := &CommandBuilder{}
	cmd, err := builder.Build(&Host{Address: "10.0.0.1"}, ConnectOpts{
		Forwards: []string{"L:8080:localhost:80", "R:2222:localhost:22", "D:1080"},
	})
	require.NoError(t, err)
	joined := strings.Join(cmd.Args, " ")
	require.Contains(t, joined, "-L 8080:localhost:80")
	require.Contains(t, joined, "-R 2222:localhost:22")
	require.Contains(t, joined, "-D 1080")
}

func TestCommandBuilderAgentForwardingYesProducesAFlag(t *testing.T) {
	t.Parallel()

	builder := &CommandBuilder{}
	cmd, err := builder.Build(&Host{Address: "10.0.0.1"}, ConnectOpts{ForwardAgent: true})
	require.NoError(t, err)
	require.Contains(t, cmd.Args, "-A")
}

func TestCommandBuilderKnownHostsStrictProducesExpectedOptions(t *testing.T) {
	t.Parallel()

	builder := &CommandBuilder{}
	cmd, err := builder.Build(&Host{Address: "10.0.0.1"}, ConnectOpts{KnownHostsPolicy: "strict", KnownHostsFile: "/tmp/known_hosts"})
	require.NoError(t, err)
	joined := strings.Join(cmd.Args, " ")
	require.Contains(t, joined, "-o StrictHostKeyChecking=yes")
	require.Contains(t, joined, "-o UserKnownHostsFile=/tmp/known_hosts")
}

func TestCommandBuilderKnownHostsOffRejectedWithoutInsecureHostKey(t *testing.T) {
	t.Parallel()

	builder := &CommandBuilder{}
	_, err := builder.Build(&Host{Address: "10.0.0.1"}, ConnectOpts{KnownHostsPolicy: "off"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "--insecure-hostkey")
}

func TestCommandBuilderIgnoreSSHConfigProducesDevNullConfig(t *testing.T) {
	t.Parallel()

	builder := &CommandBuilder{}
	cmd, err := builder.Build(&Host{Address: "10.0.0.1"}, ConnectOpts{IgnoreSSHConfig: true})
	require.NoError(t, err)
	require.Contains(t, strings.Join(cmd.Args, " "), "-F /dev/null")
}

func TestForwardSpecValidationRejectsMalformedAddress(t *testing.T) {
	t.Parallel()

	_, _, err := parseForward("L:bad address:localhost:80")
	require.Error(t, err)
}

func TestForwardSpecValidationRejectsPortOutOfRange(t *testing.T) {
	t.Parallel()

	_, _, err := parseForward("L:0:localhost:80")
	require.Error(t, err)

	_, _, err = parseForward("L:65536:localhost:80")
	require.Error(t, err)
}
