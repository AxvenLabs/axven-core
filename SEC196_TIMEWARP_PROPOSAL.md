# SEC-196 — Retarget time-warp hardening proposal

Status: **PROBE CONFIRMED / CONSENSUS CHANGE NOT YET AUTHORIZED**

## Confirmed vulnerability

Current Axven block context validation enforces only `timestamp > median_time_past` and the retarget uses the first and last timestamps of each 2016-block period directly. The SEC-196 probe reproduced both of the following on current consensus:

1. a single extreme terminal timestamp can drive the next target to the 4x retarget clamp; and
2. the first block of a new adjustment period can move backwards relative to the previous block while remaining above MTP.

## Proposed rules

A production fix should combine all three controls below. Applying only one is insufficient.

1. **Adjustment-period start guard**
   - At `height % ADJUST_INTERVAL == 0`, require the new timestamp to be at least the previous block timestamp (zero backward grace for the clean Axven devnet).

2. **Adjustment-period end guard**
   - At `height % ADJUST_INTERVAL == ADJUST_INTERVAL - 1`, require the timestamp to be at least the timestamp of the first block of that adjustment period.

3. **Future-time admission bound**
   - Reject newly received blocks whose timestamp is too far ahead of node time. This check must be an admission-time check, not a historical replay check.
   - Proposed Axven tolerance: 120 seconds. This is intentionally small relative to the 4032-second adjustment window while leaving substantial operational clock-skew headroom.

Candidate mining must construct timestamps satisfying the same minimum boundary rules.

## Activation / compatibility warning

Rules (1) and (2) are consensus-tightening changes. Old and upgraded nodes can disagree about validity if the rules are enabled silently under the same network identity. Therefore the implementation must not be merged until an explicit activation strategy is selected.

Preferred pre-mainnet strategy: reset/bump the devnet identity and bind the time-warp rule to the new canonical chain configuration before further public testing. Alternative: introduce a future activation height and corresponding network/version compatibility boundary.

No production consensus code is changed by this proposal document.
