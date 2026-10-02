# Claim / evidence template

Use one block per capability or guarantee claim (spec §4.3, §3.3). A claim with
no executed evidence is `not-tested`, whatever the code does.

```yaml
claim_id: CLM-<area>-<nn>
statement: "<exact user-facing sentence, as it will appear in docs/UI>"
label: verified | supported-with-limitations | experimental | unsupported | not-tested
scope:
  provider: <name + version>
  client: <executable path/kind + version>
  environment: <OS build / distro / WSL mode / container runtime>
  mechanism: <named enforcement mechanism, e.g. verified_server_principals>
guarantee_fields:        # spec §4.3 — fill only what this claim covers
  identity_selection: <mechanism | unknown>
  destination_scope: unenforced_intent | client_routing | authenticated_agent_restriction | verified_server_principals | isolated_execution
  credential_availability: current_only | through_deadline | refresh_dependent | interaction_required
  expiry_effects: {new_signing: , new_authentication: , controlled_connections: , remote_processes: }
  revocation: local_applied | remote_acknowledged | pending | bounded_by_credential_expiry
  isolation: shared_os_user | separate_service_boundary | tested_isolated_workload
evidence:
  - record: tests/evidence/<file>.json   # must exist, status verified
    build_commit: <sha>
    observed_at: <RFC 3339>
requirement_ids: [R-XX-NN]
acceptance_cases: [ANN]
limitations:
  - "<plain statement of what is not covered>"
reopen_if:
  - "<version change / evidence that would invalidate the claim>"
```

Rules: a detected executable is not support; a reachable socket is not signing
permission; a successful login is not post-lock or post-expiry capability
(spec §3.3). Unknown is a valid value; omission is not.
