# Checkpoint 36 ? Devnet Transaction Rehearsal

Status: **GREEN**

Network: `axven-devnet-2`

This checkpoint records an end-to-end transaction rehearsal performed against
the canonical persistent devnet node after Checkpoint 35 was merged.

No consensus rules were changed by this checkpoint.

## Starting state

- Height: `102`
- Chainwork: `26368`
- Mempool size: `0`
- Wallet loaded: `true`
- Input scheme: `ed25519`
- Wallet address: `Na4aa188e4cfbb4f0aca1e4ed74aa120f0d8f9295`
- Initial spendable: `5100000000` base units
- Initial reserved: `0`

## Transaction

- Amount: `100000000` base units (`1 AXV`)
- Fee: `1000` base units (`0.00001000 AXV`)
- TXID: `5f17c503e28056c7686a1dc011acfe35f557f099fc06394761b099771658dc17`
- Input: `6591e38d9de307347e11dd8d4129826323a7b40ad9abb7f17892ce6794c1c0a1:0`
- Input amount: `5000000000`
- Output 0: `100000000`
- Output 1: `4899999000`

## Mempool / reservation verification

Before confirmation:

- Mempool size: `1`
- Transaction status: `mempool`
- Reserved: `5000000000`
- Spendable: `100000000`
- Reserved input was excluded from `list_unspent`.

## Confirmation

- Confirmation height: `103`
- Block hash: `00aeecc39324572a93337ec68e4120093c8c17513ce58e97f29a8ab174830226`
- Transaction status: `confirmed`
- Mempool size after mining: `0`
- Reserved after mining: `0`

## Post-confirmation

Spendable UTXOs:

- `f8d0359a79ced620af2e40b84e98453edfc791269cf710c1933c16bf39daf306:0` = `100000000`
- `5f17c503e28056c7686a1dc011acfe35f557f099fc06394761b099771658dc17:0` = `100000000`
- `5f17c503e28056c7686a1dc011acfe35f557f099fc06394761b099771658dc17:1` = `4899999000`

Final spendable: `5099999000` base units (`50.99999000 AXV`).

The difference from the initial `5100000000` spendable balance is exactly the
`1000` base-unit transaction fee.

## Acceptance

Checkpoint 36 is GREEN:

1. Transaction CLI submitted a real transaction.
2. Transaction entered the live mempool.
3. Pending input became reserved.
4. Reserved input disappeared from spendable UTXOs.
5. Transaction was mined.
6. Transaction became confirmed at height 103.
7. Mempool returned to zero.
8. Pending reservation was released.
9. New transaction outputs appeared as spendable UTXOs.
10. Final spendable balance accounted for the fee exactly.

This checkpoint changes no consensus parameters, activation heights, network
identity, genesis binding, or transaction-validity rules.
