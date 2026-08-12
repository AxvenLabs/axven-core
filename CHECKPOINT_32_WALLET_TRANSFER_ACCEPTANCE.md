# Checkpoint 32 — Wallet Transfer Acceptance

This checkpoint records the first confirmed AXV transfer across the public
two-node Axven devnet.

## Canonical network

- Network: `axven-devnet-2`
- Public seed: `seed.axven.org:18444`
- Decimals: `8`
- 1 AXV = `100,000,000` base units
- Initial block reward: `50 AXV`
- Coinbase maturity: `100` blocks

## Sender

Windows wallet N address:

`Nc644a8c302edef72e399e40ed63cdac78d3e77f6`

## Recipient

VPS seed wallet N address:

`Na4aa188e4cfbb4f0aca1e4ed74aa120f0d8f9295`

## Transaction

Transaction ID:

`f8d0359a79ced620af2e40b84e98453edfc791269cf710c1933c16bf39daf306`

Transfer:
- Amount: `1 AXV`
- Amount in base units: `100000000`
- Fee: `0.00001 AXV`
- Fee in base units: `1000`
- Change: `48.99999 AXV`
- Change in base units: `4899999000`

The transaction was created and signed on the Windows node, propagated over
public P2P to the VPS seed, observed in the VPS mempool, mined by the VPS, and
then observed as confirmed by the Windows node.

## Confirmation

Confirmation block:
- Height: `102`
- Block hash: `009104e354321db315c324eac7b8f0892b1d1aa13b5d7171dd5d9ab2782dcff0`
- Chainwork after confirmation: `26368`

The transaction status on the Windows node was `confirmed` at height `102`
with the same block hash.

## Recipient balance

After confirmation, the VPS Ed25519 wallet balance was:

- `10100001000` base units
- `101.00001 AXV`

This includes the wallet's pre-existing confirmed balance, the received
`1 AXV`, and the miner fee credited through the confirmation block's coinbase.

## Public-network acceptance

Verified end-to-end:

- mature coinbase spend selection;
- wallet transaction construction;
- Ed25519 input signing;
- change output creation;
- local mempool admission;
- transaction P2P propagation;
- remote mempool admission;
- mining inclusion;
- mempool removal after confirmation;
- cross-node block synchronization;
- confirmed transaction lookup;
- recipient balance update.

## Consensus boundary

This checkpoint records and tests existing consensus behavior. It does not
change transaction validity, block validity, monetary policy, coinbase
maturity, serialization, genesis, activation rules, or network identity.
