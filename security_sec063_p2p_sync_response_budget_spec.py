#!/usr/bin/env python3
"""SEC-063 P2P get_blocks response frame-budget contract."""

import json
import threading

import p2p


TEST_BLOCK_PAYLOAD_BYTES = 6 * 1024 * 1024


def wire_size(message):
    return len(
        json.dumps(
            message,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )


class FakeBlock:
    def __init__(self, index):
        self.index = index
        self.payload = "x" * TEST_BLOCK_PAYLOAD_BYTES

    def hash(self):
        return f"{self.index:064x}"

    def to_dict(self):
        return {
            "height": self.index,
            "payload": self.payload,
        }


class FakeChain:
    def __init__(self, blocks):
        self.blocks = list(blocks)
        self._state_lock = threading.RLock()


class SinkSocket:
    def __init__(self):
        self.sent = None

    def sendall(self, data):
        self.sent = data


class DummySocket:
    def close(self):
        pass


class FakeSyncSession:
    def __init__(self, source_blocks):
        self.source_blocks = source_blocks
        self.received = 0

    def locator(self):
        if self.received == 0:
            return []
        return [self.source_blocks[self.received - 1].hash()]

    def handle(self, reply):
        count = len(reply["blocks"])
        self.received += count
        return {
            "type": "accepted",
            "kind": "blocks",
            "count": count,
        }


def main():
    checks = 0

    blocks = [FakeBlock(i) for i in range(3)]
    chain = FakeChain(blocks)
    session = p2p.PeerSession(chain)

    one_block_response = {
        "type": "blocks",
        "blocks": [blocks[0].to_dict()],
    }

    assert wire_size(one_block_response) <= p2p.MAX_MESSAGE_BYTES, (
        "test fixture invalid: one block must fit inside one P2P frame"
    )
    checks += 1
    print("[GREEN] one large block fits P2P frame")

    legacy_full_response = {
        "type": "blocks",
        "blocks": [block.to_dict() for block in blocks],
    }

    assert wire_size(legacy_full_response) > p2p.MAX_MESSAGE_BYTES, (
        "test fixture invalid: three-block batch must exceed P2P frame"
    )
    checks += 1
    print("[GREEN] three-block legacy batch exceeds P2P frame")

    reply = session.handle(
        {
            "type": "get_blocks",
            "locator": [],
            "limit": 3,
        }
    )

    assert reply["type"] == "blocks"
    assert 1 <= len(reply["blocks"]) <= 3
    assert reply["blocks"] == legacy_full_response["blocks"][:len(reply["blocks"])]
    checks += 1
    print("[GREEN] sync response preserves ordered forward progress")

    reply_bytes = wire_size(reply)

    assert reply_bytes <= p2p.MAX_MESSAGE_BYTES, (
        f"get_blocks response exceeds P2P frame budget: "
        f"{reply_bytes} > {p2p.MAX_MESSAGE_BYTES}"
    )
    checks += 1
    print(
        f"[GREEN] get_blocks response bounded at "
        f"{reply_bytes}/{p2p.MAX_MESSAGE_BYTES} bytes"
    )

    sink = SinkSocket()
    p2p.send_message(sink, reply)

    assert sink.sent is not None
    assert len(sink.sent) == reply_bytes + 4
    checks += 1
    print("[GREEN] bounded sync response is sendable by P2P framing")

    destination = FakeSyncSession(blocks)

    original_connect = p2p.connect
    original_request = p2p.request

    try:
        p2p.connect = lambda address: DummySocket()
        p2p.request = lambda sock, message: session.handle(message)

        total = p2p.sync_to_peer(
            ("fake-peer", 1),
            destination,
            limit=3,
            max_rounds=10,
        )
    finally:
        p2p.connect = original_connect
        p2p.request = original_request

    assert total == 3, (
        f"byte-truncated sync stopped early: {total}/3 blocks"
    )
    assert destination.received == 3
    checks += 1
    print("[GREEN] byte-truncated sync continues across multiple rounds")

    print(
        f"SEC-063 P2P sync response frame budget: "
        f"{checks}/6 GREEN"
    )


if __name__ == "__main__":
    main()