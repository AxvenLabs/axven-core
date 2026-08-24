from core import AxvenCore


MAX_RECIPIENT_LENGTH = 256


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
        if isinstance(exc, ValueError) and str(exc) == "recipient address too long":
            raise AssertionError(label + ": rejected too early") from exc
        print(f"[GREEN] {label}")
        return
    raise AssertionError(label)


def expect_bound(fn, label):
    try:
        fn()
    except ValueError as exc:
        if str(exc) != "recipient address too long":
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

    maximum = "N" + ("a" * (MAX_RECIPIENT_LENGTH - 1))
    expect_downstream(
        lambda: core.send("ed25519", maximum, 1, 0),
        "maximum recipient length reaches normal send path",
    )

    expect_bound(
        lambda: core.send(
            "ed25519",
            "N" + ("a" * MAX_RECIPIENT_LENGTH),
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