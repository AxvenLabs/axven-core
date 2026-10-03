# Axven Monetary Policy / Tokenomics Research Review

Status: **research only — no production monetary parameter is authorized to change**

Repository checkpoint: `AxvenLabs/axven-core` at exact main `641a669bb84d2f9a5d8d83b09698a0cd10ed786e`.

## 1. Current Axven monetary parameters

The current implementation is a Proof-of-Work UTXO chain. The README describes cumulative-chainwork fork choice and `axven.py` implements PoW target validation, difficulty retargeting, coinbase rewards, fees, reorg accounting, and supply tracking.

| Property | Current development behavior | Implementation evidence |
|---|---:|---|
| decimals | 8 | `axven.py: DECIMALS` |
| atomic units / AXVEN | 100,000,000 | `COIN = 10 ** DECIMALS` |
| nominal max supply | 21,000,000 AXVEN | `MAX_SUPPLY` |
| initial subsidy | 50 AXVEN/block | `INITIAL_REWARD` |
| halving interval | 210,000 blocks | `HALVING_INTERVAL` |
| target block time | **2 seconds** | `TARGET_BLOCK_TIME = 2` |
| difficulty interval | 2,016 blocks (~67.2 minutes at target) | `ADJUST_INTERVAL`, `TARGET_TIMESPAN` |
| consensus | Proof of Work; cumulative chainwork | `Block.pow_ok`, `work_of`, chainwork fork choice |
| coinbase maturity | 100 blocks (~200 s at target) | `COINBASE_MATURITY = 100` |
| fees | input value minus output value; paid to miner in coinbase | `_transition` |
| staking | none found in inspected consensus | UNKNOWN/absent from current implementation |
| protocol burn | none found | UNKNOWN/absent from current implementation |
| treasury | none found | UNKNOWN/absent from current implementation |
| developer/foundation allocation | none found | UNKNOWN/absent from current implementation |

Genesis has no transactions and therefore no genesis coin allocation in the inspected implementation. `GENESIS_MINER` contributes to genesis identity but does not receive a coinbase output. No pre-mine, founder allocation, treasury allocation, or staking issuance was found in the inspected current consensus.

### Reward and fee calculation

For height > 0:

```
halvings = (height - 1) // 210_000
subsidy = (50 * COIN) >> halvings
subsidy = min(subsidy, MAX_SUPPLY - issued)
coinbase = subsidy + transaction_fees
```

A regular transaction fee is `sum(inputs) - sum(outputs)`. Consensus requires exactly one coinbase output and requires its amount to equal subsidy plus all block fees. Fees are therefore transfers to the miner, not new issuance. `total_issued` increases only by the subsidy.

Reorg logic subtracts the disconnected block's recorded subsidy from `total_issued` and adds subsidy while applying the winning branch. Full validation recomputes issued supply from genesis and rejects `issued > MAX_SUPPLY`.

## 2. Current issuance curve

The critical observation is that **210,000 blocks does not mean four years in Axven**. At the actual 2-second target:

- blocks/day = 43,200
- blocks/year (365 d) = 15,768,000
- one 210,000-block era = 420,000 seconds = **4.8611 days**
- 50 AXVEN/block initially = **2,160,000 AXVEN/day**
- the initial rate annualized without halvings would be 788,400,000 AXVEN/year

The exact integer right-shift schedule reaches zero after 33 non-zero subsidy eras. Because of atomic-unit rounding, the theoretical emitted amount is approximately **20,999,999.9769 AXVEN**, slightly below the nominal 21M cap.

| Era | Reward AXVEN/block | Cumulative AXVEN | % of 21M | Target elapsed |
|---:|---:|---:|---:|---:|
| 0 | 50 | 10,500,000 | 50% | 4.86 d |
| 1 | 25 | 15,750,000 | 75% | 9.72 d |
| 2 | 12.5 | 18,375,000 | 87.5% | 14.58 d |
| 3 | 6.25 | 19,687,500 | 93.75% | 19.44 d |
| 4 | 3.125 | 20,343,750 | 96.875% | 24.31 d |
| 5 | 1.5625 | 20,671,875 | 98.4375% | 29.17 d |
| 6 | 0.78125 | 20,835,937.5 | 99.21875% | 34.03 d |
| 7 | 0.390625 | 20,917,968.75 | 99.609375% | 38.89 d |
| 8 | 0.1953125 | 20,958,984.375 | 99.8046875% | 43.75 d |
| 32 | 0.00000001 | 20,999,999.9769 | ~99.99999989% | 160.42 d |
| 33+ | 0 | unchanged | unchanged | fee-only subsidy regime |

Thus, under ideal target timing, the current development schedule emits roughly half the nominal supply in under five days, ~99.8% in under 44 days, and reaches zero subsidy after roughly **160 days**. This is internally deterministic, but it is not calendar-equivalent to Bitcoin's schedule.

Coinbase maturity is also calendar-short: 100 target blocks = about 200 seconds (3m20s).

## 3. Why 21M?

Current source evidence is unusually explicit: immediately above the constants, `axven.py` says:

> Monetary / consensus parameters retained from the pre-loss Axven/NOVA lineage.

No Axven-specific economic derivation for 21M, 50 AXVEN, or 210,000 blocks was found in current main. The evidence therefore supports treating these values as **historically inherited development parameters**, not as a demonstrated Axven-specific optimum.

This is not evidence that 21M is good or bad. It means the repository currently lacks a documented independent rationale connecting the cap and emission cadence to Axven's two-second PoW security requirements.

## 4. Comparative research

The comparison is about design motives, not templates to copy.

| Network/model | Monetary/security concept relevant to Axven |
|---|---|
| Bitcoin | PoW fixed-cap model; 210k-block halvings are roughly four years because Bitcoin targets ~10-minute blocks; long-run security increasingly depends on fees. |
| Litecoin | PoW fixed cap with 840k-block halvings roughly every four years; illustrates that block-count schedules must be calibrated to block interval. |
| Monero | PoW declining main emission followed by permanent 0.6 XMR/block tail emission; explicit rationale is persistent miner incentive rather than fee-only security. |
| Dogecoin | PoW permanent 10,000 DOGE/block after early schedule; predictable absolute issuance gives persistent miner subsidy while percentage inflation declines as supply grows. |
| Zcash | Bitcoin-derived fixed-cap/halving lineage, but current research explicitly studies issuance smoothing because discrete subsidy shocks can affect mining participation. |
| Ethereum | PoS issuance compensates validators while EIP-1559 burns base fees; net supply is dynamic. Security economics are stake-based, so this is not directly transferable to Axven PoW. |
| Solana | PoS inflation schedule starts higher, declines toward a terminal long-run rate; issuance is tied to staking incentives. |
| Avalanche | AVAX is hard-capped; transaction fees are burned while validator rewards are minted. This separates fee destruction from validator issuance. |
| Cosmos-style PoS | Inflationary issuance and fees reward bonded validators/delegators; designs can vary inflation to target staking participation. |
| Polkadot | PoS validator/nominator rewards are protocol issuance, with staking economics and governance/treasury considerations rather than PoW hash expenditure. |
| Cardano | PoS rewards combine transaction fees with a declining reserve expansion; part of rewards funds a treasury, producing gradual rather than cliff-like decline. |

Primary-source references used for this checkpoint:

- Bitcoin halving: https://bitcoin.org/en/halving
- Litecoin mining reward: https://litecoin.org/
- Monero tail emission: https://www.getmonero.org/resources/moneropedia/tail-emission.html
- Dogecoin monetary FAQ/source: https://github.com/dogecoin/dogecoin/blob/master/doc/FAQ.md
- Zcash economics and issuance research: https://z.cash/learn/what-are-the-economics-of-zcash/ and https://zips.z.cash/zip-0234
- Ethereum supply/issuance and EIP-1559: https://ethereum.org/eth/supply and https://eips.ethereum.org/EIPS/eip-1559
- Solana staking economics: https://solana.com/staking
- Avalanche tokenomics: https://support.avax.network/en/articles/6912428-tokenomics-faq
- Cosmos staking/incentive concepts: https://legacy.cosmos.network/validators/
- Polkadot staking rewards: https://docs.polkadot.com/infrastructure/staking-mechanics/rewards-payout
- Cardano monetary policy: https://docs.cardano.org/about-cardano/explore-more/monetary-policy

## 5. Security-budget analysis

For current Axven PoW, a useful first-order model is:

```
miner revenue = block subsidy + transaction fees
security budget over time ~= miner revenue available to support competitive hash expenditure
```

This is not a complete attack-cost model: AXVEN market value, miner hardware, energy cost, difficulty adjustment, hash-market liquidity, merged mining (if ever introduced), and miner concentration all matter. But it is the correct starting point for the current PoW design.

The current schedule makes the transition to fee-only security extraordinarily fast: about 160 target-days rather than a multi-decade horizon.

### Fee-only sensitivity after subsidy exhaustion

Illustrative assumptions only: average fee = 0.0001 AXVEN/transaction.

| Usage | tx/day | fees/day | fees/year |
|---|---:|---:|---:|
| LOW | 100 | 0.01 AXVEN | 3.65 AXVEN |
| MEDIUM | 10,000 | 1 AXVEN | 365 AXVEN |
| HIGH | 1,000,000 | 100 AXVEN | 36,500 AXVEN |

These scenarios are not forecasts. They demonstrate that "fees will replace subsidy" is an empirical assumption requiring demand, fee-market, price, miner-cost, and block-space evidence. Even the high-usage example is tiny compared with the initial 2.16M AXVEN/day subsidy. Security cannot be inferred from token count alone because the fiat purchasing power of miner revenue matters.

A halving every 4.86 days also creates repeated 50% subsidy shocks. Difficulty can adjust, but that does not guarantee constant attack cost or miner participation.

## 6. Alternative sensitivity models — not proposals

All models below assume the existing 2-second target only for comparison. None is selected for production.

### Model A — current development parameters

21M nominal cap, 50/block, 210k-block halvings. Exact integer implementation. Fast issuance and fee-only transition after ~160 days.

### Model B — alternative fixed cap sensitivity

**Assumption:** 100M cap, linearly issued over 10 years solely as a scale/control experiment. Approximate reward = 0.6342 AXVEN/block until cap. This intentionally tests whether conclusions depend on the displayed cap. It is not an allocation recommendation.

### Model C — fixed cap with Axven-specific calendar schedule

**Assumption:** retain 21M only as a controlled variable, but use four-year halving epochs calibrated to 2-second blocks (63,072,000 blocks/epoch). Initial reward is ~0.1664764 AXVEN/block so the geometric schedule asymptotically approaches 21M. This isolates schedule design from cap choice.

### Model D — declining issuance plus tail emission

**Assumption:** Model C for 12 years, then permanent 0.001 AXVEN/block tail emission. Tail issuance is ~15,768 AXVEN/year. Absolute issuance remains constant after tail activation while percentage inflation trends toward zero.

### Model E — bounded long-run security issuance

**Assumption:** research-only 21M bootstrap issued linearly over 10 years, then supply grows at a maximum 1%/year. This is a deliberately simple bounded-inflation sensitivity model, not a proposed algorithm.

| Model | 1y supply | 5y | 10y | 20y | Long-run behavior |
|---|---:|---:|---:|---:|---|
| A current | ~20,999,999.9769 | same | same | same | subsidy zero; fee-only |
| B 100M/10y | 10M | 50M | 100M | 100M | fixed cap; fee-only after 10y |
| C 21M / 4y half-life | 2.625M | 11.8125M | 17.0625M | 20.34375M | asymptotic fixed cap; subsidy trends to zero |
| D C + tail after 12y | 2.625M | 11.8125M | 17.0625M | ~18.501144M | permanent absolute subsidy; % inflation trends down |
| E bootstrap + <=1% | 2.1M | 10.5M | 21M | ~23.197065M | bounded perpetual percentage issuance |

### Security and complexity implications

- **Fixed-cap/zero-tail classes (A/B/C):** eventually require fees or another non-inflationary incentive to carry PoW security. B/C mainly change how much time the ecosystem has to develop that fee market.
- **Tail emission (D):** creates a permanent predictable miner revenue floor in AXVEN units, reducing pure fee dependence, but abandons a strict finite cap.
- **Bounded inflation (E):** can maintain a security budget proportional to supply, but requires more policy machinery and creates governance/parameter-manipulation questions.
- **Dynamic issuance:** could respond to measured security conditions, but adds the most consensus complexity and governance/measurement attack surface. It should not be considered until a robust measurable security target exists.

## 7. Distribution is separate from supply

A supply curve does not answer initial ownership.

Before production, explicit decisions are required on whether any of these exist: founder allocation, team allocation, treasury, ecosystem grants, investors, community distribution, mining distribution, vesting, lockups, or genesis allocation.

Current inspected genesis contains no coin allocation. That should not silently become the production distribution policy.

Concentration analysis should model at least: top-1/top-10/top-100 ownership, liquid versus locked ownership, miner concentration, related-party control, vesting cliffs, treasury signing/governance concentration, and the percentage of liquid supply capable of influencing markets or governance.

No allocation should be justified primarily by trying to increase displayed token price.

## 8. Unit bias

Token count is a denomination choice, not network value.

```
market capitalization = unit price * circulating supply
```

The design must distinguish:

- **maximum supply:** protocol ceiling, if one exists;
- **issued supply:** units created by protocol issuance;
- **circulating supply:** issued units considered available to market participants;
- **liquid supply:** units realistically transferable/sellable without lockups or other restrictions.

21M, 100M, or 1B units do not by themselves make a network more or less valuable. Monetary policy should be selected for security, predictability, distribution, and sustainability properties rather than unit-price optics.

## 9. Economic attack surface

| Risk | Current Axven relevance |
|---|---|
| insufficient long-term security budget | **HIGH research concern:** subsidy reaches zero in ~160 target-days; fee sufficiency unproven |
| excessive early issuance | **HIGH research concern:** 50% in ~4.86 days, >99% in weeks |
| halving shock | **HIGH research concern:** 50% subsidy shocks every 210k blocks (~4.86 days) |
| miner death spiral / hash withdrawal | plausible PoW risk; needs hash-cost/difficulty simulations |
| fee-market instability | relevant after rapid subsidy decay; no evidence yet that fees can support security |
| founder/team concentration | UNKNOWN; no current genesis allocation, production distribution undecided |
| treasury capture | currently not applicable because no treasury mechanism found; becomes relevant if added |
| inflation uncertainty | current code is deterministic, but future policy governance could introduce it |
| issuance-policy manipulation | constants are consensus-sensitive; production change process not yet defined here |
| integer rounding/boundaries | relevant; right-shift rewards reach atomic-unit floor then zero |
| supply overflow/underflow | Python integers avoid fixed-width overflow, but negative/remaining-supply boundaries remain consensus-critical |
| reorg reward accounting | implemented with undo reward subtraction/reapplication; must remain invariant-tested |
| duplicate issuance | coinbase uniqueness and exact amount checks reduce this risk |
| supply invariant violation | cap is enforced in reward function and full validation, but dedicated monetary invariant coverage should be strengthened |

## 10. Machine-testable monetary invariants

Existing implementation evidence supports:

- `block_reward(height <= 0) == 0`
- reward is capped by `MAX_SUPPLY - issued`
- exactly one first-position coinbase; extra coinbases rejected
- coinbase amount must equal exact subsidy + exact fees
- fees cannot be negative because ordinary transactions reject output sum > input sum
- coinbase maturity is enforced
- active-chain `total_issued` increments only by subsidy
- reorg disconnect subtracts recorded subsidy and winning branch adds recomputed subsidy
- full-chain validation recomputes issuance and rejects supply above `MAX_SUPPLY`
- replay/shadow tests contain evidence that replayed `total_issued` equals source-chain `total_issued`

Research gaps to make explicit before any policy change:

1. dedicated exact tests for every halving boundary, including one block before/at/after;
2. exact last-nonzero and first-zero subsidy boundary;
3. explicit remaining-supply clipping tests with adversarial `issued` values;
4. property test: any valid chain state implies `0 <= total_issued <= MAX_SUPPLY`;
5. randomized reorg property: same canonical chain -> same issued supply regardless of arrival order;
6. malformed/overpay coinbase tests specifically at monetary boundaries;
7. model-vs-consensus oracle test for a large set of heights;
8. documented distinction between issued supply and UTXO sum because fees move value but do not issue value.

## 11. Open questions

Before selecting a monetary policy, Axven needs human decisions or evidence for:

1. What minimum long-run PoW security expenditure is required?
2. Is Axven intended to remain PoW permanently?
3. What miner hardware/energy market is expected, and how concentrated could it become?
4. What block-space demand and fee revenue are plausible at low, medium, and high adoption?
5. Is a strict hard cap a non-negotiable social property, or is predictable tail/security issuance acceptable?
6. Should issuance decline smoothly or through discrete halvings?
7. What calendar horizon should bootstrap issuance cover?
8. Is two-second target spacing itself final? This review does not authorize changing it.
9. Should any treasury/ecosystem funding exist at protocol level?
10. What initial distribution constraints are acceptable?
11. What governance process, if any, may change monetary parameters after launch?
12. What migration/activation rules would preserve existing devnet history if parameters are later changed?

## 12. Parameters requiring founder/governance decision

No value is selected here. Explicit decision is required before changing: `MAX_SUPPLY`, `INITIAL_REWARD`, `HALVING_INTERVAL`, target block time, any tail-emission floor, any inflation rate, fee/burn policy, staking policy, genesis allocation, founder/team allocation, treasury allocation, vesting, or activation/migration rules.

## Recommended next experiment

The smallest uncertainty-reducing experiment is **research-only security-budget simulation**, not a consensus patch.

Extend `research/monetary_policy_model.py` with a deterministic matrix over:

- AXVEN market-value assumptions,
- miner operating cost per unit hash,
- low/medium/high transaction demand,
- several average fee levels,
- hash elasticity around subsidy changes,
- current 4.86-day halvings versus calendar-calibrated smooth/halving/tail schedules.

Output miner revenue, fee share, subsidy shock size, and a normalized hash-budget proxy through time. Then add property tests that compare the current model's exact integer issuance to `axven.block_reward` without importing the research model into production consensus.

Only after those results should a separate human decision checkpoint discuss actual production parameters.
