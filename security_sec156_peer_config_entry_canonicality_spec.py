#!/usr/bin/env python3
"""SEC-156 persisted peer-entry canonicality contract."""

import inspect
import json
import tempfile

import axven
from core import AxvenCore
from datadir import DataDir


def expect_value_error(fn,label,contains=None):
    try:
        fn()
    except ValueError as exc:
        if contains is not None:
            assert contains in str(exc),(label,str(exc))
        print("[GREEN]",label)
        return 1
    raise AssertionError(label)


def main():
    checks=0
    with tempfile.TemporaryDirectory() as td:
        data=DataDir(td)

        data.peer_file.write_text(
            json.dumps([{"host":"127.0.0.1","port":31337}]),
            encoding="utf-8",
        )
        assert data.load_peers()==[("127.0.0.1",31337)]
        checks+=1
        print("[GREEN] canonical persisted peer object preserved")

        data.peer_file.write_text(
            json.dumps([{"host":"127.0.0.1","port":31337,"extra":True}]),
            encoding="utf-8",
        )
        checks+=expect_value_error(
            data.load_peers,
            "unknown persisted peer object field rejected",
            "unknown peer entry field",
        )

        data.peer_file.write_text(
            json.dumps([{"host":"127.0.0.1"}]),
            encoding="utf-8",
        )
        checks+=expect_value_error(
            data.load_peers,
            "missing persisted peer field remains rejected",
            "peer entry requires host and port",
        )

        data.peer_file.write_text(
            json.dumps([["127.0.0.1",31337]]),
            encoding="utf-8",
        )
        assert data.load_peers()==[("127.0.0.1",31337)]
        checks+=1
        print("[GREEN] legacy persisted list peer remains compatible")

        data.peer_file.write_text(
            json.dumps(["node.axven.org:31338"]),
            encoding="utf-8",
        )
        assert data.load_peers()==[("node.axven.org",31338)]
        checks+=1
        print("[GREEN] legacy persisted text peer remains compatible")

        data.peer_file.write_text(
            json.dumps([{"host":"127.0.0.1","port":True}]),
            encoding="utf-8",
        )
        checks+=expect_value_error(
            data.load_peers,
            "boolean persisted peer port remains rejected",
            "peer port must be integer",
        )

        data.peer_file.write_text(
            json.dumps([{"host":7,"port":31337}]),
            encoding="utf-8",
        )
        checks+=expect_value_error(
            data.load_peers,
            "non-string persisted peer host remains rejected",
            "peer host must be string",
        )

        canonical=[("127.0.0.1",31337),("node.axven.org",31338)]
        data.save_peers(canonical)
        assert data.load_peers()==canonical
        raw=json.loads(data.peer_file.read_text(encoding="utf-8"))
        assert all(set(entry)=={"host","port"} for entry in raw)
        checks+=1
        print("[GREEN] peer writer emits exact canonical object schema")

    source=inspect.getsource(DataDir.load_peers)
    gate='set(peer) != {"host","port"}'
    assert gate in source
    assert source.index(gate) < source.index('peer=(peer["host"],peer["port"])')
    checks+=1
    print("[GREEN] exact object-field gate precedes peer normalization")

    assert AxvenCore._parse_peer(("127.0.0.1",31337))==("127.0.0.1",31337)
    checks+=1
    print("[GREEN] canonical runtime peer parser semantics unchanged")

    assert axven.CHAIN_ID=="axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT=="ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven._genesis().hash()=="a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3"
    checks+=1
    print("[GREEN] peer canonicality hardening leaves chain identity unchanged")

    assert checks==11,checks
    print("SEC-156 peer-config entry canonicality: 11/11 GREEN")


if __name__=="__main__":
    main()
