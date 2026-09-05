# Apply Checkpoint 28 overlay

Copy the contents of this overlay into the root of the current
`AxvenLabs/axven-core` checkout.

Then run:

```powershell
git status
python tools\peer_probe.py --help
git add .github docs tools
git commit -m "Add public devnet hardening and contribution controls"
git push
```

The overlay deliberately does not rewrite consensus code or the release
manifest. `.github` repository-control metadata is not part of the canonical
release-integrity manifest.

After the push is green, configure branch protection/rulesets in GitHub using
`docs/BRANCH_PROTECTION.md`.
