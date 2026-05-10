# Contributing

Keep Heimdall narrow:

- no vault behavior;
- no SSH client implementation;
- no remote inventory scanning;
- no transport implementation;
- no silent agent socket exposure.

Security-sensitive changes need tests for refusal, redaction, and failure modes.

