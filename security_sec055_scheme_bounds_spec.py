from core import AxvenCore


MAX_SCHEME_LENGTH = 64


class DummyLock:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class DummyTip:
    height = 100


class DummyIdentity:
    def address_of(self, scheme):
        if len(str(scheme)) > MAX_SCHEME_LENGTH:
            raise AssertionError("scheme reached downstream wallet path")
        raise RuntimeError("normal downstream path")


class DummyChain:
    def __init__(self):
        self._state_lock = DummyLock()
        self.tip = DummyTip()

    def balance(self, address):
        raise AssertionError("unexpected chain balance call")

    def spendable(self, address):
        raise AssertionError("unexpected chain spendable call")

    def mine(self, address, mempool):
        raise AssertionError("unexpected chain mine call")


class DummyPending:
    def is_reserved(self, outpoint):
        return False


def make_core():
    core = object.__new__(AxvenCore)
    core.identity = DummyIdentity()
    core.chain = DummyChain()
    core.pending = DummyPending()
    core.mempool = object()
    return core


def expect_downstream(fn, label):
    try:
        fn()
    except RuntimeError as exc:
        if str(exc) != "normal downstream path":
            raise
        print(f"[GREEN] {label}")
        return
    except ValueError as exc:
        if str(exc) == "scheme too long":
            raise AssertionError(label + ": rejected too early") from exc
        print(f"[GREEN] {label}")
        return
    raise AssertionError(label)


def expect_bound(fn, label):
    try:
        fn()
    except ValueError as exc:
        if str(exc) != "scheme too long":
            raise AssertionError(
                f"{label}: wrong ValueError: {exc}"
            ) from exc
        print(f"[GREEN] {label}")
        return
    except Exception as exc:
        raise AssertionError(
            f"{label}: reached downstream path instead of scheme bound"
        ) from exc
    raise AssertionError(label)


def main():
    core = make_core()

    expect_downstream(
        lambda: core.balance("ed25519"),
        "canonical scheme reaches normal wallet path",
    )

    expect_downstream(
        lambda: core.balance("s" * MAX_SCHEME_LENGTH),
        "maximum scheme length reaches normal wallet path",
    )

    oversized = "s" * (MAX_SCHEME_LENGTH + 1)

    expect_bound(
        lambda: core.balance(oversized),
        "oversized balance scheme rejected",
    )

    expect_bound(
        lambda: core.wallet_status(oversized),
        "oversized wallet_status scheme rejected",
    )

    expect_bound(
        lambda: core.list_unspent(oversized),
        "oversized list_unspent scheme rejected",
    )

    expect_bound(
        lambda: core.mine(1, oversized),
        "oversized mine scheme rejected",
    )

    expect_bound(
        lambda: core.send(
            oversized,
            "N" + ("a" * 40),
            1,
            0,
        ),
        "oversized send input scheme rejected",
    )

    expect_bound(
        lambda: core.balance("s" * 1_000_000),
        "extreme scheme rejected",
    )

    print("SEC-055 scheme bounds: 8/8 GREEN")


if __name__ == "__main__":
    main()