# Security Model

Heimdall reduces accidental misuse of SSH identities. It is not a hard boundary against same-user processes or root/admin.

Core rules:

- no private-key custody;
- no passphrase/token storage;
- passive diagnostics by default;
- explicit active-probe consent;
- argv arrays for subprocesses;
- redaction before output;
- restrictive permissions for generated files and backups;
- fail closed when selected agents are missing;
- bridge exposure treated as credential delegation;
- bridge sockets scoped to sessions with private runtime directories and TTL cleanup.

Agent forwarding and socket mounts delegate signing capability to another environment. Heimdall warns and requires explicit user intent. The bridge relays bytes only; it does not interpret, log, store, or authorize agent protocol payloads.
