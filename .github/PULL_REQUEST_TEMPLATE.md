## Summary

Describe what this changes and why.

## Scope

- [ ] Consensus-critical
- [ ] Wallet
- [ ] P2P
- [ ] RPC / CLI
- [ ] Explorer / UX
- [ ] Tests / CI
- [ ] Documentation only

## Validation

- [ ] `python run_full_validation.py`
- [ ] No canonical `axven-devnet-2` identity change unless a new explicit consensus/network decision exists
- [ ] New behavior has executable coverage
- [ ] Security-sensitive changes explain threat-model impact

## Consensus boundary

If this changes serialization, genesis, fingerprint inputs, activation heights,
authorization rules, state roots, PoW/fork choice, or transaction validity,
state the new consensus decision/network version explicitly.

## Notes

Anything reviewers should know.
