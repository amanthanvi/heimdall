# SSH Certificates

Heimdall inspects public certificate files with `ssh-keygen -L -f`.

It reports:

- key ID;
- serial;
- principals;
- validity period;
- expiry and near-expiry.

Heimdall does not operate a certificate authority and does not store provider refresh tokens.

Refresh hooks are explicit argv arrays and preview by default:

```yaml
certificates:
  github:
    path: ~/.ssh/github-cert.pub
    refresh_hook: ["step", "ssh", "renew", "~/.ssh/github-cert.pub"]
```

```sh
heimdall certs refresh github
heimdall certs refresh github --execute
```

The default command prints the command that would run. `--execute` is required to run it. Hooks must not include tokens, passphrases, or private key material.
