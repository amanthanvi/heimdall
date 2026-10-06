# Scratch helper (not in repo): authorize the run's ephemeral probe public key on the
# disposable loopback fixture sshd (AuthorizedKeysFile lives in this scratch dir).
param([Parameter(Mandatory=$true)][string]$PublicKeyPath)
$line = ([IO.File]::ReadAllText($PublicKeyPath)).Trim()
if ($line -notmatch '^(ecdsa-sha2-nistp256 [A-Za-z0-9+/=]+ heimdall-g03-probe-\d+|ssh-ed25519 [A-Za-z0-9+/=]+ heimdall-g03-perm)$') { throw 'unexpected public key format' }
$ak = Join-Path (Split-Path -Parent $PSCommandPath) 'fixture\authorized_keys'
[IO.File]::AppendAllText($ak, 'restrict ' + $line + "`n", (New-Object Text.UTF8Encoding($false)))
