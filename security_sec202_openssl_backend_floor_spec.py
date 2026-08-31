#!/usr/bin/env python3
"""SEC-202: runtime cryptography must use a patched OpenSSL backend."""
from __future__ import annotations

import axven
import doctor


def main():
    checks=[]

    def green(label, condition):
        assert condition, label
        checks.append(label)
        print("[GREEN]", label)

    green(
        "patched OpenSSL 4.0 line is admitted",
        doctor._openssl_backend_supported("OpenSSL 4.0.2 25 Aug 2026")
        and doctor._openssl_backend_supported("OpenSSL 4.0.3 1 Sep 2026"),
    )
    green(
        "vulnerable OpenSSL 4.0 line is rejected",
        not doctor._openssl_backend_supported("OpenSSL 4.0.1 1 Aug 2026"),
    )
    green(
        "patched OpenSSL 3.6 and 3.5 lines are admitted",
        doctor._openssl_backend_supported("OpenSSL 3.6.4 25 Aug 2026")
        and doctor._openssl_backend_supported("OpenSSL 3.5.8 25 Aug 2026"),
    )
    green(
        "pre-security-fix 3.6 and 3.5 lines are rejected",
        not doctor._openssl_backend_supported("OpenSSL 3.6.3 1 Aug 2026")
        and not doctor._openssl_backend_supported("OpenSSL 3.5.7 1 Aug 2026"),
    )
    green(
        "unsupported or unparseable crypto backends fail closed",
        not doctor._openssl_backend_supported("LibreSSL 4.0.2")
        and not doctor._openssl_backend_supported("OpenSSL 3.4.7 25 Aug 2026")
        and not doctor._openssl_backend_supported("OpenSSL 4.0.2-dev")
        and not doctor._openssl_backend_supported(None),
    )

    live=doctor.run()["checks"]["openssl_backend"]
    green(
        "active cryptography backend satisfies the patched security floor",
        live["ok"] is True
        and live["version"].startswith("OpenSSL 4.0.2")
        and live["required"] == doctor.OPENSSL_REQUIRED,
    )

    real_version=doctor._openssl_backend_version_text
    doctor._openssl_backend_version_text=lambda: "OpenSSL 4.0.1 1 Aug 2026"
    try:
        stale=doctor.run()
    finally:
        doctor._openssl_backend_version_text=real_version
    green(
        "doctor fails closed when a vulnerable OpenSSL backend is injected",
        stale["ok"] is False
        and stale["checks"]["cryptography"]["ok"] is True
        and stale["checks"]["openssl_backend"]["ok"] is False,
    )

    green(
        "OpenSSL backend hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven._genesis().hash() == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    assert len(checks)==8, len(checks)
    print("SEC-202 OpenSSL backend security floor: 8/8 GREEN")


if __name__ == "__main__":
    main()
