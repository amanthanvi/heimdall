package ssh

type Host struct {
	Name             string
	Address          string
	Port             int
	User             string
	JumpHosts        []string
	IdentityPath     string
	ForwardAgent     bool
	KnownHostsPolicy string
}

type ConnectOpts struct {
	User             string
	Port             int
	JumpHosts        []string
	ProxyJumpNone    bool
	Forwards         []string
	IdentityPath     string
	ForwardAgent     bool
	KnownHostsPolicy string
	KnownHostsFile   string
	InsecureHostKey  bool
	IgnoreSSHConfig  bool
	Env              []string
}

type SSHCommand struct {
	Binary    string
	Args      []string
	Env       []string
	TempFiles []string
}

type CommandBuilder struct {
	Binary string
}

type KnownHostsResult string

const (
	KnownHostsMatch    KnownHostsResult = "match"
	KnownHostsMismatch KnownHostsResult = "mismatch"
	KnownHostsUnknown  KnownHostsResult = "unknown"
)
