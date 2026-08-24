from core import AxvenCore


MAX_BLOCK_STRING_ID_LENGTH = 64


class DummyLock:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class DummyChain:
    def __init__(self):
        self._state_lock = DummyLock()
        self.blocks = []
        self.index = {}


def make_core():
    core = object.__new__(AxvenCore)
    core.chain = DummyChain()
    return core


def expect_lookup(fn, label):
    try:
        fn()
    except KeyError:
        print(f"[GREEN] {label}")
        return
    except ValueError as exc:
        raise AssertionError(
            f"{label}: rejected before normal lookup: {exc}"
        ) from exc
    raise AssertionError(label)


def expect_bound(fn, label):
    try:
        fn()
    except ValueError as exc:
        if str(exc) != "block id too long":
            raise AssertionError(
                f"{label}: wrong ValueError: {exc}"
            ) from exc
        print(f"[GREEN] {label}")
        return
    except KeyError as exc:
        raise AssertionError(
            f"{label}: reached normal block lookup instead of input rejection"
        ) from exc
    raise AssertionError(label)


def main():
    core = make_core()

    expect_lookup(
        lambda: core.get_block("a" * MAX_BLOCK_STRING_ID_LENGTH),
        "canonical block hash length reaches normal lookup",
    )

    expect_lookup(
        lambda: core.get_block("z" * MAX_BLOCK_STRING_ID_LENGTH),
        "maximum non-numeric block string reaches normal lookup",
    )

    expect_bound(
        lambda: core.get_block("z" * (MAX_BLOCK_STRING_ID_LENGTH + 1)),
        "oversized non-numeric block string rejected",
    )

    expect_bound(
        lambda: core.get_block("z" * 1_000_000),
        "extreme non-numeric block string rejected",
    )

    print("SEC-056 block string ID bounds: 4/4 GREEN")


if __name__ == "__main__":
    main()