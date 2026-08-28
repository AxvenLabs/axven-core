#!/usr/bin/env python3
"""SEC-104 peer retry-delay domain and bounded arithmetic contract."""

from pathlib import Path
import core as core_module
from core import AxvenCore


def expect_value_error(fn, label):
    try:
        fn()
    except ValueError:
        print(f"[GREEN] {label}")
        return
    except Exception as exc:
        raise AssertionError(f"{label}: wrong exception {type(exc).__name__}: {exc}") from exc
    raise AssertionError(label)


def main():
    checks = 0
    peer = ("127.0.0.1", 19107)
    core = AxvenCore()
    core.add_outbound_peer(peer)

    for failures, expected in ((0,5.0),(1,5.0),(2,10.0),(5,60.0),(20,60.0)):
        core.peer_consecutive_failures[peer] = failures
        assert core.peer_retry_delay(peer,5.0,60.0) == expected
    checks += 1
    print("[GREEN] canonical bounded retry curve preserved")

    core.peer_consecutive_failures[peer] = 100_000
    assert core.peer_retry_delay(peer,5.0,60.0) == 60.0
    checks += 1
    print("[GREEN] large valid failure count saturates before exponentiation")

    for bad in (True,2.5,"2",None,-1,2_147_483_648):
        core.peer_consecutive_failures[peer] = bad
        expect_value_error(lambda: core.peer_retry_delay(peer,5.0,60.0), f"invalid failure counter rejected: {bad!r}")
        checks += 1

    core.peer_consecutive_failures[peer] = 0
    cases = (
        (lambda: core.set_peer_retry_schedule(peer,-0.1,5.0), "negative retry delay rejected"),
        (lambda: core.peer_retry_delay(peer,-0.1,60.0), "negative retry base rejected"),
        (lambda: core.peer_retry_delay(peer,5.0,-1.0), "negative retry cap rejected"),
        (lambda: core.peer_retry_delay(peer,True,60.0), "boolean retry timing rejected"),
        (lambda: core.peer_retry_delay(peer,"5",60.0), "string retry timing rejected"),
    )
    for fn,label in cases:
        expect_value_error(fn,label)
        checks += 1

    source = Path(core_module.__file__).read_text(encoding="utf-8")
    assert "base*(2 ** exponent)" not in source
    assert "math.ldexp(base,safe_exponent)" in source
    checks += 1
    print("[GREEN] retry arithmetic is explicitly saturation-bounded")

    print(f"SEC-104 peer retry-delay domain: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
