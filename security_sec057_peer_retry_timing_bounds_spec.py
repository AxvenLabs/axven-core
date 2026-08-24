from core import AxvenCore


MAX_RETRY_SECONDS = 3600.0


def make_core():
    core = object.__new__(AxvenCore)
    core.outbound_peers = []
    core.peer_retry_delay_seconds = {}
    core.peer_next_retry_at = {}
    core.peer_retry_base_interval = {}
    core.peer_consecutive_failures = {}
    return core


def expect_value_error(fn, label):
    try:
        fn()
    except ValueError:
        print(f"[GREEN] {label}")
        return
    except Exception as exc:
        raise AssertionError(
            f"{label}: wrong exception {type(exc).__name__}: {exc}"
        ) from exc
    raise AssertionError(label)


def main():
    core = make_core()
    peer = ("127.0.0.1", 18444)

    # Normal finite values must preserve existing behavior.
    core.set_peer_retry_schedule(peer, 5.0, 5.0)
    if core.peer_retry_delay_seconds[peer] != 5.0:
        raise AssertionError("canonical retry delay changed")
    print("[GREEN] canonical retry schedule preserved")

    delay = core.peer_retry_delay(peer, base_interval=5.0, cap=60.0)
    if delay != 5.0:
        raise AssertionError("canonical retry calculation changed")
    print("[GREEN] canonical retry calculation preserved")

    expect_value_error(
        lambda: core.set_peer_retry_schedule(peer, float("nan"), 5.0),
        "NaN retry delay rejected",
    )

    expect_value_error(
        lambda: core.set_peer_retry_schedule(peer, float("inf"), 5.0),
        "infinite retry delay rejected",
    )

    expect_value_error(
        lambda: core.set_peer_retry_schedule(
            peer,
            MAX_RETRY_SECONDS + 1.0,
            5.0,
        ),
        "oversized retry delay rejected",
    )

    expect_value_error(
        lambda: core.set_peer_retry_schedule(peer, 5.0, float("nan")),
        "NaN retry base rejected",
    )

    expect_value_error(
        lambda: core.peer_retry_delay(
            peer,
            base_interval=float("inf"),
            cap=60.0,
        ),
        "infinite retry base rejected",
    )

    expect_value_error(
        lambda: core.peer_retry_delay(
            peer,
            base_interval=5.0,
            cap=float("inf"),
        ),
        "infinite retry cap rejected",
    )

    print("SEC-057 peer retry timing bounds: 8/8 GREEN")


if __name__ == "__main__":
    main()