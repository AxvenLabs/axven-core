from core import AxvenCore
import p2p


class DummyChain:
    pass


class DummyMempool:
    pass


def expect_error(fn, label):
    try:
        fn()
    except (ValueError, TypeError):
        print(f"[GREEN] {label}")
        return

    raise AssertionError(label)


def main():
    core = object.__new__(AxvenCore)
    core.chain = DummyChain()
    core.mempool = DummyMempool()

    original = p2p.sync_to_peer
    calls = []

    def fake_sync_to_peer(address, session, limit=128, max_rounds=100):
        calls.append((address, limit))
        return 7

    p2p.sync_to_peer = fake_sync_to_peer

    try:
        # Canonical host must preserve existing behavior.
        result = core.sync_peer("127.0.0.1", 31337, 128)
        assert result == 7
        assert calls[-1] == (("127.0.0.1", 31337), 128)
        print("[GREEN] canonical sync_peer host preserved")

        # DNS-style host must remain valid.
        result = core.sync_peer("node.axven.org", 31337, 1)
        assert result == 7
        assert calls[-1] == (("node.axven.org", 31337), 1)
        print("[GREEN] DNS-style sync_peer host preserved")

        # Match _parse_peer normalization semantics.
        result = core.sync_peer("  node.axven.org  ", 31337, 1)
        assert result == 7
        assert calls[-1] == (("node.axven.org", 31337), 1)
        print("[GREEN] sync_peer host whitespace normalization preserved")

        maximum = "a" * 255
        result = core.sync_peer(maximum, 31337, 1)
        assert result == 7
        assert calls[-1] == ((maximum, 31337), 1)
        print("[GREEN] maximum sync_peer host length preserved")

        before = len(calls)
        expect_error(
            lambda: core.sync_peer("", 31337, 1),
            "empty sync_peer host rejected",
        )
        assert len(calls) == before

        before = len(calls)
        expect_error(
            lambda: core.sync_peer("   ", 31337, 1),
            "whitespace-only sync_peer host rejected",
        )
        assert len(calls) == before

        before = len(calls)
        expect_error(
            lambda: core.sync_peer("a" * 256, 31337, 1),
            "oversized sync_peer host rejected",
        )
        assert len(calls) == before

        print("SEC-050 sync_peer host bounds: 7/7 GREEN")

    finally:
        p2p.sync_to_peer = original


if __name__ == "__main__":
    main()
