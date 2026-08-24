from core import AxvenCore


class DummyTip:
    height = 100


class DummyStateLock:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class DummyChain:
    def __init__(self):
        self.tip = DummyTip()
        self._state_lock = DummyStateLock()
        self.blocks = []


def make_core():
    core = object.__new__(AxvenCore)
    core.chain = DummyChain()
    return core


def expect_key_error(fn, label):
    try:
        fn()
    except KeyError:
        print(f"[GREEN] {label}")
        return
    raise AssertionError(label)


def expect_value_error(fn, label):
    try:
        fn()
    except ValueError:
        print(f"[GREEN] {label}")
        return
    except KeyError as exc:
        raise AssertionError(
            f"{label}: reached normal block lookup instead of input rejection"
        ) from exc
    raise AssertionError(label)


def main():
    core = make_core()

    expect_key_error(
        lambda: core.get_block("100"),
        "canonical numeric block id reaches normal lookup",
    )

    expect_key_error(
        lambda: core.get_block("999999999999999999"),
        "bounded numeric block id reaches normal lookup",
    )

    expect_value_error(
        lambda: core.get_block("9" * 65),
        "oversized numeric block id rejected",
    )

    expect_value_error(
        lambda: core.get_block("9" * 4096),
        "extreme numeric block id rejected",
    )

    print("SEC-053 block ID bounds: 4/4 GREEN")


if __name__ == "__main__":
    main()
