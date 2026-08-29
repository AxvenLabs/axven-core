#!/usr/bin/env python3
"""SEC-149: bound persisted peer JSON before parser allocation and reject duplicate keys."""
import inspect
import json
import tempfile
from pathlib import Path

import axven
import datadir
from core import AxvenCore
from datadir import DataDir


def expect_value_error(fn,label):
    try:
        fn()
    except ValueError:
        print("[GREEN]",label)
        return
    raise AssertionError(label)


def main():
    checks=0

    def green(label,condition):
        nonlocal checks
        assert condition,label
        checks += 1
        print("[GREEN]",label)

    green(
        "peer-config raw JSON budgets are pinned above canonical schema depth",
        datadir.MAX_PEER_CONFIG_JSON_NESTING_DEPTH == 16
        and datadir.MAX_PEER_CONFIG_JSON_STRUCTURAL_ITEMS == 1024,
    )

    canonical=json.dumps(
        [{"host":"127.0.0.1","port":31337}],
        sort_keys=True,
    ).encode("utf-8")
    datadir._preflight_peer_config_json(canonical)
    green("canonical peer JSON passes raw preflight",True)

    quoted=(
        b'[{"host":"node-[{\\\"x\\\":1}]-\\\\-example","port":31337}]'
    )
    datadir._preflight_peer_config_json(quoted)
    green("container-looking bytes inside peer strings consume no nesting budget",True)

    exact=(b"[" * datadir.MAX_PEER_CONFIG_JSON_NESTING_DEPTH
           + b"]" * datadir.MAX_PEER_CONFIG_JSON_NESTING_DEPTH)
    datadir._preflight_peer_config_json(exact)
    green("exact peer-config nesting boundary is accepted by preflight",True)

    over=(b"[" * (datadir.MAX_PEER_CONFIG_JSON_NESTING_DEPTH + 1)
          + b"]" * (datadir.MAX_PEER_CONFIG_JSON_NESTING_DEPTH + 1))
    expect_value_error(
        lambda: datadir._preflight_peer_config_json(over),
        "over-depth peer JSON rejected by raw preflight",
    )
    checks += 1

    shallow=(
        b"[" + b",".join(
            [b"[]"] * (datadir.MAX_PEER_CONFIG_JSON_STRUCTURAL_ITEMS + 1)
        ) + b"]"
    )
    green(
        "shallow structural-overflow fixture stays below peer-config byte cap",
        len(shallow) < datadir.MAX_PEER_CONFIG_BYTES,
    )
    expect_value_error(
        lambda: datadir._preflight_peer_config_json(shallow),
        "shallow peer JSON fan-out rejected by raw preflight",
    )
    checks += 1

    with tempfile.TemporaryDirectory() as td:
        data=DataDir(td)
        data.save_peers([
            ("127.0.0.1",31337),
            ("node.axven.org",31338),
        ])
        green(
            "canonical persisted peer round-trip preserved",
            data.load_peers()
            == [("127.0.0.1",31337),("node.axven.org",31338)],
        )

        maximum=[(f"node-{i}.axven.org",10000+i) for i in range(AxvenCore.MAX_CONFIGURED_PEERS)]
        data.save_peers(maximum)
        encoded=data.peer_file.read_bytes()
        datadir._preflight_peer_config_json(encoded)
        green(
            "maximum canonical peer set stays inside new structural budget",
            data.load_peers() == maximum,
        )

        data.peer_file.write_bytes(over)
        original_loads=json.loads
        calls=[]
        def spy_loads(*args,**kwargs):
            calls.append((args,kwargs))
            return original_loads(*args,**kwargs)
        json.loads=spy_loads
        try:
            expect_value_error(
                data.load_peers,
                "over-depth persisted peer JSON rejected",
            )
            checks += 1
            green(
                "over-depth persisted peer JSON is rejected before json.loads",
                calls == [],
            )
        finally:
            json.loads=original_loads

        data.peer_file.write_bytes(shallow)
        calls=[]
        json.loads=spy_loads
        try:
            expect_value_error(
                data.load_peers,
                "over-complex persisted peer JSON rejected",
            )
            checks += 1
            green(
                "over-complex persisted peer JSON is rejected before json.loads",
                calls == [],
            )
        finally:
            json.loads=original_loads

        duplicate=(
            '[{"host":"127.0.0.1","host":"localhost","port":31337}]'
        )
        data.peer_file.write_text(duplicate,encoding="utf-8")
        expect_value_error(
            data.load_peers,
            "duplicate persisted peer object key rejected",
        )
        checks += 1

        nested_duplicate=(
            '[[{"host":"127.0.0.1","port":31337,"port":31338}]]'
        )
        data.peer_file.write_text(nested_duplicate,encoding="utf-8")
        expect_value_error(
            data.load_peers,
            "duplicate keys are rejected recursively before peer semantics",
        )
        checks += 1

        data.peer_file.write_text('[{"host":"127.0.0.1",]',encoding="utf-8")
        expect_value_error(
            data.load_peers,
            "ordinary malformed peer JSON remains fail-closed",
        )
        checks += 1

        data.peer_file.write_bytes(b"[\xff]")
        expect_value_error(
            data.load_peers,
            "invalid UTF-8 peer config remains fail-closed",
        )
        checks += 1

        # Preserve legacy parser-compatible persisted list/text peer forms.
        data.peer_file.write_text(
            json.dumps([["127.0.0.1",31337],"node.axven.org:31338"]),
            encoding="utf-8",
        )
        green(
            "legacy valid persisted peer forms remain compatible",
            data.load_peers()
            == [("127.0.0.1",31337),("node.axven.org",31338)],
        )

    source=inspect.getsource(DataDir.load_peers)
    green(
        "production peer loader preflights before json.loads",
        source.index("_preflight_peer_config_json(encoded)")
        < source.index("raw=json.loads("),
    )
    green(
        "production peer loader uses recursive duplicate-key rejection",
        "object_pairs_hook=_reject_duplicate_peer_json_keys" in source,
    )
    preflight_src=inspect.getsource(datadir._preflight_peer_config_json)
    green(
        "peer JSON preflight is quote-aware and fan-out bounded",
        "in_string" in preflight_src
        and "MAX_PEER_CONFIG_JSON_NESTING_DEPTH" in preflight_src
        and "MAX_PEER_CONFIG_JSON_STRUCTURAL_ITEMS" in preflight_src,
    )
    green(
        "peer-config parser hardening leaves canonical chain identity unchanged",
        axven.CHAIN_ID == "axven-devnet-2"
        and axven.CONFIG_FINGERPRINT
        == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
        and axven.Blockchain().tip.hash()
        == "a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3",
    )

    print(f"SEC-149 peer-config JSON preparse: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
