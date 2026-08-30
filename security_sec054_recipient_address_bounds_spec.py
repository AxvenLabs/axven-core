from core import AxvenCore


class DummyIdentity:
    pass


def make_core():
    core = object.__new__(AxvenCore)
    core.identity = DummyIdentity()
    return core


def expect_downstream(fn, label):
    try:
        fn()
    except Exception as exc:
        if isinstance(exc, ValueError) and "recipient" in str(exc).lower():
            raise AssertionError(label + ": rejected by recipient guard") from exc
        print(f"[GREEN] {label}")
        return
    raise AssertionError(label)


def expect_bound(fn, label):
    try:
        fn()
    except ValueError as exc:
        if "recipient" not in str(exc).lower():
            raise AssertionError(
                f"{label}: wrong ValueError: {exc}"
            ) from exc
        print(f"[GREEN] {label}")
        return
    except Exception as exc:
        raise AssertionError(
            f"{label}: reached downstream path instead of recipient bound"
        ) from exc
    raise AssertionError(label)


def main():
    core = make_core()

    canonical = "N" + ("a" * 40)
    expect_downstream(
        lambda: core.send("ed25519", canonical, 1, 0),
        "canonical recipient reaches normal send path",
    )

    # SEC-182 supersedes the old loose 256-character service allowance with
    # the canonical Axven address width.  SEC-054 still owns the invariant
    # that oversized recipient text is rejected before downstream work.
    legacy_maximum = "N" + ("a" * 255)
    expect_bound(
        lambda: core.send("ed25519", legacy_maximum, 1, 0),
        "legacy maximum recipient alias rejected at canonical boundary",
    )

    expect_bound(
        lambda: core.send(
            "ed25519",
            "N" + ("a" * 256),
            1,
            0,
        ),
        "oversized recipient rejected",
    )

    expect_bound(
        lambda: core.send(
            "ed25519",
            "N" + ("a" * 1_000_000),
            1,
            0,
        ),
        "extreme recipient rejected",
    )

    print("SEC-054 send recipient bounds: 4/4 GREEN")


if __name__ == "__main__":
    main()
