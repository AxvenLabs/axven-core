#!/usr/bin/env python3
"""Research-only Axven monetary-policy model.

This file is deliberately standalone. It MUST NOT be imported by production
consensus code. All hypothetical policies are sensitivity models, not proposals.
"""
from __future__ import annotations
from dataclasses import dataclass

SECONDS_PER_YEAR = 365 * 24 * 60 * 60
BLOCK_TIME = 2
BLOCKS_PER_DAY = 24 * 60 * 60 // BLOCK_TIME
BLOCKS_PER_YEAR = SECONDS_PER_YEAR // BLOCK_TIME
COIN = 10**8

@dataclass(frozen=True)
class Snapshot:
    year: int
    supply: float
    annual_issuance: float

def current_reward(height: int, issued_atoms: int) -> int:
    max_supply = 21_000_000 * COIN
    if height <= 0:
        return 0
    halvings = (height - 1) // 210_000
    reward = (50 * COIN) >> halvings if halvings < 64 else 0
    return max(0, min(reward, max_supply - issued_atoms))

def current_supply_at_blocks(blocks: int) -> int:
    issued = 0
    for era in range(64):
        reward = (50 * COIN) >> era
        if reward == 0 or issued >= 21_000_000 * COIN:
            break
        start = era * 210_000
        if blocks <= start:
            break
        n = min(blocks - start, 210_000)
        issued += min(reward * n, 21_000_000 * COIN - issued)
    return issued

def geometric_fixed_cap_supply(years: float, cap=21_000_000.0, half_life_years=4.0) -> float:
    # Continuous sensitivity model. Initial annual issuance is chosen so the
    # geometric sequence across four-year epochs asymptotically sums to cap.
    epoch_blocks = BLOCKS_PER_YEAR * half_life_years
    reward0 = cap / (2 * epoch_blocks)
    blocks = int(years * BLOCKS_PER_YEAR)
    issued = 0.0
    epoch = int(epoch_blocks)
    while blocks > 0:
        take = min(blocks, epoch)
        issued += take * reward0
        reward0 /= 2
        blocks -= take
    return min(cap, issued)

def linear_fixed_cap_supply(years: float, cap=100_000_000.0, issuance_years=10.0) -> float:
    return min(cap, cap * years / issuance_years)

def tail_supply(years: float, tail_start_year=12.0, tail_per_block=0.001) -> float:
    base = geometric_fixed_cap_supply(min(years, tail_start_year))
    if years <= tail_start_year:
        return base
    return base + (years - tail_start_year) * BLOCKS_PER_YEAR * tail_per_block

def bounded_inflation_supply(years: float, bootstrap_cap=21_000_000.0,
                             bootstrap_years=10.0, terminal_rate=0.01) -> float:
    if years <= bootstrap_years:
        return bootstrap_cap * years / bootstrap_years
    return bootstrap_cap * ((1 + terminal_rate) ** (years - bootstrap_years))

def report():
    print("Axven monetary-policy research model; no production parameters changed")
    print(f"block_time={BLOCK_TIME}s blocks/day={BLOCKS_PER_DAY} blocks/year={BLOCKS_PER_YEAR}")
    print("\nCURRENT EXACT INTEGER CURVE")
    issued = 0
    for era in range(64):
        reward = (50 * COIN) >> era
        if reward == 0:
            print(f"subsidy_zero_from_height={era * 210_000 + 1}")
            break
        epoch = min(reward * 210_000, 21_000_000 * COIN - issued)
        issued += epoch
        days = ((era + 1) * 210_000 * BLOCK_TIME) / 86400
        print(era, reward / COIN, issued / COIN, days)
    print("\nSENSITIVITY SNAPSHOTS")
    for year in (1, 5, 10, 20):
        print({
            "year": year,
            "A_current": current_supply_at_blocks(year * BLOCKS_PER_YEAR) / COIN,
            "B_100m_linear_10y": linear_fixed_cap_supply(year),
            "C_21m_four_year_half_life": geometric_fixed_cap_supply(year),
            "D_C_plus_tail_after_12y": tail_supply(year),
            "E_21m_10y_bootstrap_then_1pct": bounded_inflation_supply(year),
        })

if __name__ == "__main__":
    report()
