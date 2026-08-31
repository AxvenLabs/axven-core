#!/usr/bin/env python3
"""SEC-203: manual POSIX validation must preserve dependency provenance."""
from __future__ import annotations

import re
from pathlib import Path

import axven

SCRIPT = Path("validate_linux_macos.sh")
LOCK = Path("requirements-ci-runtime-posix.lock")
EXPECTED_RUNTIME = {
    "cryptography": (
        "50.0.1",
        {
            "b8f852c65863251b9e3a1b8c150ce21e59b522dbb6a7d4bc80e680d38388e986",
            "53e279950892dc102c6b4e52af03ae5ea92fac572a1ddab78ca73a997f62b69f",
            "ff838d62ec1bfce4f9ba7fa16f4a7b554cd8d0c299e6be37502161a660c84eef",
            "be224a65493ec5b74a158ff22a5522ce4a5ca1e543c647a3a4730d4a09e5f959",
            "9ebcdd5519be9b652a46f507817a74591774fc3d6923ac364e4dfa64e36b291b",
        },
    ),
    "cffi": (
        "2.1.1",
        {
            "19ee6127ee34de7d83ce3d371ebc5ed91addbdcc39f9ab15ce4eb35a4e534971",
            "f16c709686a78c727bbbf059f92b0bf41c6fc60deec706d2dc19f529175a6125",
            "a931079504ecc49efed7744c476a5c343a92fabf66dec2db95edb1b2fdc770e2",
            "a2d7755bef5a12ed488f4ef1f1b69ee9191d7396083b755a5d2295f6edb4768b",
            "e0bcb7e0f677f543555d2adff3bf19c05f66cdb4796e5ff602442ab2fe3c4ef7",
        },
    ),
    "pycparser": (
        "3.0",
        {"b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992"},
    ),
    "dilithium-py": (
        "1.4.0",
        {"dda3ae43e6e3d212ae1fe1b30d5b6dffe5e25a1f389d1fea26faad4afdc33ff8"},
    ),
}


def _logical_lines(path: Path):
    out=[]
    current=""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line=raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            current += line[:-1].strip() + " "
            continue
        current += line
        out.append(current.strip())
        current=""
    if current:
        raise AssertionError(f"unterminated requirement continuation: {path}")
    return out


def _parse_lock(path: Path):
    parsed={}
    for line in _logical_lines(path):
        match=re.match(r"^([A-Za-z0-9_.-]+)==([^ ]+)(?: +--hash=sha256:[0-9a-f]{64})+$",line)
        if not match:
            raise AssertionError(f"non-canonical lock entry: {line!r}")
        name,version=match.groups()
        hashes=set(re.findall(r"--hash=sha256:([0-9a-f]{64})",line))
        if name in parsed:
            raise AssertionError(f"duplicate lock entry: {name}")
        parsed[name]=(version,hashes)
    return parsed


def main():
    checks=[]

    def green(label, condition=True):
        assert condition,label
        checks.append(label)
        print("[GREEN]",label)

    text=SCRIPT.read_text(encoding="utf-8")
    runtime=_parse_lock(LOCK)

    first_install=min(
        text.index("requirements-ci-toolchain.lock"),
        text.index("requirements-ci-runtime-posix.lock"),
    )
    runtime_probe=text.index("actual_python=")
    green(
        "exact Python 3.13.15 is isolated and checked before any POSIX dependency installation",
        'required_python="3.13.15"' in text
        and runtime_probe < first_install
        and "python3 -I -S -c" in text
        and "platform.python_version()" in text,
    )

    green(
        "POSIX validation platform scope is explicit and unsupported targets fail closed",
        "Linux:x86_64|Linux:aarch64|Linux:arm64|Darwin:arm64" in text
        and "unsupported POSIX validation platform" in text
        and "exit 2" in text,
    )

    green(
        "ambient pip upgrade and unconstrained editable bootstrap are absent",
        "pip install --upgrade pip" not in text
        and "pip install -e ." not in text,
    )

    green(
        "manual POSIX toolchain install is wheel-only and hash-locked",
        "pip install --no-deps --only-binary=:all: --require-hashes -r requirements-ci-toolchain.lock" in text,
    )

    green(
        "manual POSIX runtime install is wheel-only and hash-locked",
        "pip install --no-deps --only-binary=:all: --require-hashes -r requirements-ci-runtime-posix.lock" in text,
    )

    green(
        "POSIX runtime lock admits only the reviewed exact wheel artifacts",
        runtime == EXPECTED_RUNTIME,
    )

    green(
        "POSIX lock has bounded platform-specific binary hash coverage",
        len(runtime["cryptography"][1]) == 5
        and len(runtime["cffi"][1]) == 5
        and all(len(value)==64 for _,hashes in runtime.values() for value in hashes),
    )

    green(
        "editable Axven install cannot resolve ambient build or runtime dependencies",
        'pip install --no-build-isolation --no-deps -e ".[legacy-mldsa-recovery]"' in text,
    )

    pip_check=text.index("-m pip check")
    doctor=text.index("doctor.py")
    full=text.index("run_full_validation.py")
    tail=text.index("security_tail_runner.py")
    green(
        "dependency closure is checked before doctor, validation, and security tail",
        pip_check < doctor < full < tail,
    )

    remove=text.index("rm -rf -- .venv")
    recreate=text.index("python3 -I -S -m venv .venv")
    first_package=text.index('"$venv_python" -m pip')
    green(
        "stale POSIX virtualenv state is removed before isolated reconstruction and package mutation",
        "if [[ -L .venv ]]" in text
        and "rm -- .venv" in text
        and remove < recreate < first_package
        and "if [[ ! -d .venv ]]" not in text
        and '"$venv_python" -I -S -c' in text,
    )

    green(
        "SEC-203 leaves canonical chain and PQ activation identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2000
        and axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5000
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    assert len(checks)==11,len(checks)
    print("SEC-203 POSIX validator provenance: 11/11 GREEN")


if __name__ == "__main__":
    main()
