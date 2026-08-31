# Axven Core — hardened operator runbook

## 1. Validated environment

Axven's supported runtime is **exact Python 3.13.15**. Do not bootstrap the
operator environment with ambient dependency resolution, `pip install --upgrade
pip`, an unconstrained `pip install -e .`, or a different Python runtime.

Windows:

```text
1. install exact Python 3.13.15
2. run setup.cmd
```

Linux/macOS:

```bash
# exact Python 3.13.15 must be available as python3
bash validate_linux_macos.sh
```

The hardened validator creates/updates `.venv`, installs only the reviewed
hash-locked dependency artifacts, runs doctor + full validation + the SEC-076+
security tail, and stamps the platform-specific runtime-provenance receipt.

## 2. POSIX operator boundary

On Linux/macOS, do not invoke `.venv/bin/python`, `axven-core`, `axven-cli`, or
other Axven entrypoints directly for operator work. Use the attested launcher;
it fails closed unless the current `.venv` and release tree still match the
validated POSIX provenance receipt.

Create a wallet:

```bash
bash axven-posix.sh core --datadir ./axven-data create-wallet
```

Run a node:

```bash
bash axven-posix.sh core --datadir ./axven-data run --rpc-port 18443 --p2p-port 18444
```

Query the node from another terminal:

```bash
bash axven-posix.sh cli status
bash axven-posix.sh cli addresses
bash axven-posix.sh cli balance --scheme ed25519
```

Mine one devnet block:

```bash
bash axven-posix.sh cli mine 1 --scheme ed25519
```

For the interactive console:

```bash
bash axven-posix.sh console
```

If provenance checking reports a missing, stale, or mismatched receipt, stop and
rerun `bash validate_linux_macos.sh`; do not bypass the preflight.

## 3. Windows operator boundary

Use the repository's Windows launchers (`start-node1.cmd`, `start-node2.cmd`,
`start-public-p2p-node.cmd`, `axven-console.cmd`, and the canonical PowerShell
operator scripts). They run the Windows provenance preflight before using the
validated `.venv` runtime.

## 4. Current network status

This repository is the canonical **Axven devnet**, not a production mainnet.
Do not present the devnet package or its balances as a production/mainnet
release.

## 5. Persistent state

- Chain: `<datadir>/chain/chain.json`
- Wallet: `<datadir>/wallet.json`
- Mempool: intentionally in-memory only in this version

Back up `wallet.json` and its passphrase separately.
