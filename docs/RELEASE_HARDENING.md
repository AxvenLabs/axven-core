# Release hardening checklist

- GitHub Actions green on current `main`
- release tag points to a green commit
- source release is marked devnet/pre-release
- canonical identity is present in release notes
- release-manifest verification passes
- no wallet/datadir/private material is committed
- issue and PR templates installed
- CODEOWNERS installed
- `main` protection/ruleset configured
- RPC remains loopback-only
- public P2P is tested from a physically separate network
- security-reporting channel is defined before soliciting external testing
