# External Transports

Heimdall does not implement reachability. It renders OpenSSH routes for external tools such as `iroh-ssh`.

Example:

```yaml
transports:
  iroh-ssh:
    type: proxy_command
    binary: iroh-ssh
    args: ["proxy", "%h"]
```

Rendered:

```sshconfig
ProxyCommand iroh-ssh proxy %h
```

Passive diagnostics check local command shape and binary presence. Running the transport or contacting a host requires `--active-probe`.

