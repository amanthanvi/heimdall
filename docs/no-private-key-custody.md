# No Private Key Custody

Heimdall stores only path references such as `private_key_path_ref`.

Allowed:

- read public key files;
- read public certificate files;
- call `ssh-add -l`, `ssh-add -L`, `ssh-keygen -l`, and `ssh-keygen -L`;
- `stat` private key references for existence and permissions;
- render `IdentityFile` path references into OpenSSH config.

Forbidden:

- reading private key bytes;
- importing, copying, encrypting, decrypting, backing up, or parsing private keys;
- storing passphrases or refresh tokens;
- hiding key operations behind convenience commands.

The test fixture `testdata/keys/id_ed25519` contains sentinel text. Inventory tests fail if private-key-looking paths are opened for reading.

