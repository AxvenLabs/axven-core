from core import AxvenCore


def expect_error(fn, label):
    try:
        fn()
    except (ValueError, TypeError):
        print(f"[GREEN] {label}")
        return

    raise AssertionError(label)


def main():
    # Canonical IPv4 host.
    assert AxvenCore._parse_peer(("127.0.0.1", 31337)) == (
        "127.0.0.1",
        31337,
    )
    print("[GREEN] canonical peer host preserved")

    # Canonical DNS-style host.
    assert AxvenCore._parse_peer(("node.axven.org", 31337)) == (
        "node.axven.org",
        31337,
    )
    print("[GREEN] DNS-style peer host preserved")

    # Existing normalization semantics must remain.
    assert AxvenCore._parse_peer(("  node.axven.org  ", 31337)) == (
        "node.axven.org",
        31337,
    )
    print("[GREEN] peer host whitespace normalization preserved")

    # Boundary value.
    maximum = "a" * 255
    assert AxvenCore._parse_peer((maximum, 31337)) == (
        maximum,
        31337,
    )
    print("[GREEN] maximum peer host length preserved")

    expect_error(
        lambda: AxvenCore._parse_peer(("", 31337)),
        "empty peer host rejected",
    )

    expect_error(
        lambda: AxvenCore._parse_peer(("   ", 31337)),
        "whitespace-only peer host rejected",
    )

    expect_error(
        lambda: AxvenCore._parse_peer(("a" * 256, 31337)),
        "oversized tuple peer host rejected",
    )

    expect_error(
        lambda: AxvenCore._parse_peer(("a" * 256) + ":31337"),
        "oversized string peer host rejected",
    )

    print("SEC-049 peer host bounds: 8/8 GREEN")


if __name__ == "__main__":
    main()
