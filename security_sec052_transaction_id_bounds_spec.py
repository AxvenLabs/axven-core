from core import AxvenCore


def green(label):
    print(f"[GREEN] {label}")


class FakeLock:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeChain:
    def __init__(self):
        self._state_lock = FakeLock()
        self.blocks = []


class FakeMempool:
    def __init__(self):
        self.txs = {}


def make_core():
    core = object.__new__(AxvenCore)
    core.chain = FakeChain()
    core.mempool = FakeMempool()
    return core


def expect_key_error(fn, label):
    try:
        fn()
    except KeyError:
        green(label)
        return
    raise AssertionError(label)


def expect_value_error(fn, label):
    try:
        fn()
    except ValueError:
        green(label)
        return
    raise AssertionError(label)


def main():
    core = make_core()

    canonical = "f" * 64

    expect_key_error(
        lambda: core.get_transaction(canonical),
        "canonical transaction id reaches normal lookup",
    )

    maximum = "a" * 64

    expect_key_error(
        lambda: core.get_transaction(maximum),
        "maximum transaction id length reaches normal lookup",
    )

    expect_value_error(
        lambda: core.get_transaction("a" * 65),
        "oversized transaction id rejected",
    )

    expect_value_error(
        lambda: core.get_transaction("a" * 4096),
        "extreme transaction id rejected",
    )

    print("SEC-052 transaction lookup ID bounds: 4/4 GREEN")


if __name__ == "__main__":
    main()
