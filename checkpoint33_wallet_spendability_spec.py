#!/usr/bin/env python3

import axven
import wallet
from core import AxvenCore
from rpc import RPCDispatcher

checks = []

def ok(name, cond):
    assert cond, name
    checks.append(name)

def make_identity():
    return wallet.WalletIdentity()

identity = make_identity()
core = AxvenCore(identity=identity)
rpc = RPCDispatcher(core)

scheme = axven.SCHEME_ED25519

# Empty wallet.
s0 = rpc.call("get_wallet_status", {"scheme": scheme})
ok("empty total", s0["total"] == 0)
ok("empty spendable", s0["spendable"] == 0)
ok("empty reserved", s0["reserved"] == 0)
ok("empty immature", s0["immature"] == 0)

# First coinbase exists in total balance but is immature.
core.mine(1, scheme)
s1 = rpc.call("get_wallet_status", {"scheme": scheme})
ok("coinbase total visible", s1["total"] == axven.INITIAL_REWARD)
ok("coinbase not spendable", s1["spendable"] == 0)
ok("coinbase not reserved", s1["reserved"] == 0)
ok("coinbase immature", s1["immature"] == axven.INITIAL_REWARD)

# Advance until block #1 reaches 100-block maturity.
core.mine(axven.COINBASE_MATURITY, scheme)
s2 = rpc.call("get_wallet_status", {"scheme": scheme})
ok("first reward matured", s2["spendable"] >= axven.INITIAL_REWARD)
ok("no reservation before send", s2["reserved"] == 0)
ok(
    "mature accounting invariant",
    s2["total"] == s2["spendable"] + s2["reserved"] + s2["immature"],
)

# Spend from the mature coinbase. Use our own address as recipient;
# the purpose here is spendability/reservation accounting.
sent = core.send(
    scheme,
    identity.address_n,
    100_000_000,
    1_000,
)
ok("transaction created", bool(sent["txid"]))

s3 = rpc.call("get_wallet_status", {"scheme": scheme})
ok("pending input reserved", s3["reserved"] >= axven.INITIAL_REWARD)
ok(
    "reserved removed from spendable",
    s3["spendable"] + s3["reserved"] + s3["immature"] == s3["total"],
)

# Confirmation releases the pending reservation.
core.mine(1, scheme)
s4 = rpc.call("get_wallet_status", {"scheme": scheme})
ok("reservation released after confirmation", s4["reserved"] == 0)
ok("confirmed funds spendable", s4["spendable"] > 0)
ok(
    "final accounting invariant",
    s4["total"] == s4["spendable"] + s4["reserved"] + s4["immature"],
)

# Existing get_balance RPC remains backward compatible.
legacy = rpc.call("get_balance", {"scheme": scheme})
ok("legacy get_balance unchanged", isinstance(legacy, int))
ok("legacy balance equals total", legacy == s4["total"])

# All-scheme form.
all_status = rpc.call("get_wallet_status")
ok("all schemes returned", set(all_status) == {
    axven.SCHEME_ED25519,
    axven.SCHEME_ML_DSA,
    axven.SCHEME_HYBRID,
})

print(f"Checkpoint 33 wallet spendability spec: {len(checks)}/{len(checks)} GREEN")
