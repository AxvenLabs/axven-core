"""ARCH-001 research-only programmable L1 primitives.

This module is intentionally NOT imported by Axven production consensus.
It provides deterministic data structures for architecture comparison only.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any


class ResearchTransitionError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def commitment(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


@dataclass(frozen=True)
class AxvenObject:
    object_id: str
    owner_or_authority: str
    object_type: str
    version: int
    data: dict[str, Any]
    authorization_policy: str

    def canonical(self) -> dict[str, Any]:
        if self.version < 0:
            raise ResearchTransitionError("negative object version")
        return {
            "authorization_policy": self.authorization_policy,
            "data": self.data,
            "object_id": self.object_id,
            "object_type": self.object_type,
            "owner_or_authority": self.owner_or_authority,
            "version": self.version,
        }


@dataclass(frozen=True)
class ResearchTransaction:
    sender: str
    sequence: int
    read_set: tuple[str, ...]
    write_set: tuple[str, ...]
    program_id: str
    arguments: dict[str, Any]
    resource_limit: int
    authorization_policy: str

    def canonical(self) -> dict[str, Any]:
        if self.sequence < 0:
            raise ResearchTransitionError("negative sequence")
        if self.resource_limit < 0:
            raise ResearchTransitionError("negative resource limit")
        if len(set(self.read_set)) != len(self.read_set):
            raise ResearchTransitionError("duplicate read object")
        if len(set(self.write_set)) != len(self.write_set):
            raise ResearchTransitionError("duplicate write object")
        return {
            "arguments": self.arguments,
            "authorization_policy": self.authorization_policy,
            "program_id": self.program_id,
            "read_set": list(self.read_set),
            "resource_limit": self.resource_limit,
            "sender": self.sender,
            "sequence": self.sequence,
            "write_set": list(self.write_set),
        }

    def txid(self) -> str:
        return commitment(self.canonical())


def access_conflicts(a: ResearchTransaction, b: ResearchTransaction) -> bool:
    a_reads, a_writes = set(a.read_set), set(a.write_set)
    b_reads, b_writes = set(b.read_set), set(b.write_set)
    return bool(
        a_writes & (b_reads | b_writes)
        or b_writes & (a_reads | a_writes)
    )


def state_commitment(objects: dict[str, AxvenObject]) -> str:
    canonical_state = {
        object_id: objects[object_id].canonical()
        for object_id in sorted(objects)
    }
    return commitment(canonical_state)
