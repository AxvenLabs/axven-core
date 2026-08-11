# Real PQ validation gate

This checkpoint deliberately does not claim the canonical PQ release candidate
is ready until a machine with `dilithium-py==1.4.0` runs the real cryptography.

## Windows
Open PowerShell in this folder:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\validate_windows.ps1
```

## Linux/macOS
```bash
./validate_linux_macos.sh
```

The validation stops at the first failure. It runs:
1. real ML-DSA-44 dependency smoke;
2. N→M migration;
3. real M spend;
4. H creation and real Ed25519+ML-DSA AND spend;
5. H downgrade rejection;
6. H1/H2 boundary;
7. W-003 wallet/node integration;
8. packaging, daemon, wallet persistence, RPC, P2P, consensus and SMT regressions.

Do not execute CD-003 activation unless this gate is fully green and the
activation preflight is rerun afterwards.
