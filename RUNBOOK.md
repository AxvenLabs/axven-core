# Axven Core — First-run runbook

## 1. Environment
Recommended: Python 3.11+ in a fresh virtual environment.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -e .
axven-doctor
```

`axven-doctor` must pass before creating a wallet. In particular,
`dilithium-py==1.4.0` is required for real ML-DSA-44 wallet creation/signing.
There is intentionally no fake PQ fallback.

## 2. Create wallet
```bash
axven-core --datadir ./axven-data create-wallet
```
You will be prompted for a passphrase twice.

## 3. Run node
```bash
axven-core --datadir ./axven-data run --rpc-port 18443 --p2p-port 18444
```

## 4. Query node
In another terminal:
```bash
axven-cli status
axven-cli addresses
axven-cli balance --scheme ed25519
```

## 5. Devnet mining
```bash
axven-cli mine 1 --scheme ed25519
```

## 6. Important current status
This package is a pre-activation devnet rebuild checkpoint.
CD-003 canonical activation is NOT executed.
Do not present this package as a public mainnet release.

## 7. Persistent state
- Chain: `<datadir>/chain/chain.json`
- Wallet: `<datadir>/wallet.json`
- Mempool: intentionally in-memory only in this version

Back up `wallet.json` and its passphrase separately.
