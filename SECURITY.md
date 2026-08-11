# Security Policy

Axven Core is currently a canonical devnet implementation undergoing public
release hardening.

## Reporting vulnerabilities

Do not publish exploitable consensus, wallet-key, RPC, or P2P vulnerabilities
before maintainers have had a reasonable opportunity to investigate and fix
them.

For the first public release, publish a dedicated security contact before
accepting third-party reports.

## Current exposure boundary

- RPC: loopback only
- Explorer: loopback only
- P2P: operator-controlled binding
- wallet backups: encrypted with scrypt + AES-256-GCM
- no fake ML-DSA backend is permitted

The devnet should not be marketed as audited or production-safe unless an
independent security review has actually been completed.
