#!/usr/bin/env python3
"""Run release validation sequentially; intended for the user's real machine."""
from __future__ import annotations
import json, subprocess, sys, time
from pathlib import Path

ROOT=Path(__file__).resolve().parent
SUITES=[
 ("pq_dependency_check.py","PQ dependency smoke"),
 ("pq_real_validation.py","PQ M/H end-to-end"),
 ("wallet_integration_spec_test.py","W-003 wallet integration"),
 ("release_packaging_test.py","Release packaging"),
 ("daemon_lifecycle_test.py","Daemon lifecycle"),
 ("wallet_persistence_cli_test.py","Wallet persistence/CLI"),
 ("core_rpc_test.py","Core/RPC"),
 ("p2p_tcp_lifecycle_test.py","P2P TCP lifecycle"),
 ("devnet_rehearsal.py","Two-node devnet rehearsal"),
 ("checkpoint42_peer_reconnect_spec.py","Persistent peer reconnect/recovery"),
 ("checkpoint43_peer_health_spec.py","Peer health tracking"),
 ("checkpoint44_peer_health_summary_spec.py","Peer health summary"),
 ("checkpoint45_peer_health_timestamps_spec.py","Peer health timestamps"),
 ("checkpoint46_peer_retry_backoff_spec.py","Peer retry backoff"),
 ("checkpoint46_peer_retry_scheduler_spec.py","Peer retry scheduler"),
 ("checkpoint47_peer_retry_observability_spec.py","Peer retry observability"),
 ("checkpoint47_peer_retry_daemon_spec.py","Peer retry observability daemon"),
 ("checkpoint48_peer_retry_recovery_spec.py","Peer retry recovery"),
 ("checkpoint49_peer_recovery_summary_spec.py","Peer recovery summary"),
 ("checkpoint50_peer_health_classification_spec.py","Peer health classification"),
 ("checkpoint51_peer_health_transitions_spec.py","Peer health transitions"),
 ("checkpoint51_peer_health_transitions_daemon_spec.py","Peer health transitions daemon"),
 ("checkpoint52_peer_health_history_spec.py","Peer health history"),
 ("checkpoint52_peer_health_history_daemon_spec.py","Peer health history daemon"),
 ("checkpoint53_peer_health_incidents_spec.py","Peer health incidents"),
 ("checkpoint53_peer_health_incidents_daemon_spec.py","Peer health incidents daemon"),
 ("checkpoint54_peer_health_incident_history_spec.py","Peer health incident history"),
 ("checkpoint54_peer_health_incident_history_daemon_spec.py","Peer health incident history daemon"),
 ("activation_record_encoding_test.py","Activation record UTF-8"),
 ("post_activation_audit.py","Post-activation audit"),
 ("p2p_spec_test.py","P2P spec"),
 ("consensus_rebuild_test.py","Consensus rebuild"),
 ("smt_incremental_test.py","Incremental SMT"),
 ("security_sec014_atomic_read_spec.py","SEC-014 atomic chain read"),
 ("security_sec014_production_readers_spec.py","SEC-014 production reader boundaries"),
 ("security_sec015_p2p_inbound_timeout_spec.py","SEC-015 P2P inbound timeout"),
 ("security_sec016_p2p_sync_bounds_spec.py","SEC-016 P2P sync bounds"),
 ("security_sec017_p2p_block_batch_bounds_spec.py","SEC-017 P2P block batch bounds"),
 ("security_sec018_p2p_tx_structural_bounds_spec.py","SEC-018 P2P tx structural bounds"),
 ("security_sec019_p2p_block_structure_spec.py","SEC-019 P2P block structure"),
 ("security_sec020_p2p_locator_elements_spec.py","SEC-020 P2P locator elements"),
 ("security_sec021_p2p_block_batch_elements_spec.py","SEC-021 P2P block-batch elements"),
 ("security_sec022_p2p_tx_elements_spec.py","SEC-022 P2P tx elements"),
 ("security_sec023_orphan_pool_bounds_spec.py","SEC-023 orphan pool bounds"),
 ("security_sec024_orphan_dedup_spec.py","SEC-024 orphan dedup"),
 ("security_sec025_mempool_bounds_spec.py","SEC-025 mempool bounds"),
 ("security_sec026_mempool_byte_bounds_spec.py","SEC-026 mempool byte bounds"),
 ("security_sec027_orphan_byte_bounds_spec.py","SEC-027 orphan byte bounds"),
 ("security_sec028_p2p_inbound_peer_bounds_spec.py","SEC-028 inbound peer bounds"),
 ("security_sec029_rpc_request_timeout_spec.py","SEC-029 RPC request timeout"),
 ("security_sec030_rpc_concurrency_bounds_spec.py","SEC-030 RPC concurrency bounds"),
 ("security_sec031_rpc_request_body_bounds_spec.py","SEC-031 RPC request body bounds"),
 ("security_sec032_rpc_params_structure_spec.py","SEC-032 RPC params structure"),
 ("security_sec033_rpc_method_structure_spec.py","SEC-033 RPC method structure"),
 ("security_sec034_rpc_content_type_spec.py","SEC-034 RPC content type"),
 ("security_sec035_rpc_request_envelope_spec.py","SEC-035 RPC request envelope"),
 ("security_sec036_rpc_method_bounds_spec.py","SEC-036 RPC method bounds"),
 ("security_sec037_rpc_param_key_bounds_spec.py","SEC-037 RPC param key bounds"),
 ("security_sec038_rpc_param_count_bounds_spec.py","SEC-038 RPC param count bounds"),
 ("security_sec039_rpc_duplicate_json_keys_spec.py","SEC-039 RPC duplicate JSON keys"),
 ("security_sec040_rpc_param_depth_bounds_spec.py","SEC-040 RPC param depth bounds"),
 ("security_sec041_rpc_param_complexity_bounds_spec.py","SEC-041 RPC param complexity bounds"),
 ("security_sec042_rpc_mine_count_bounds_spec.py","SEC-042 RPC mine count bounds"),
 ("security_sec043_rpc_send_value_bounds_spec.py","SEC-043 RPC send value bounds"),
 ("security_sec044_rpc_sync_batch_bounds_spec.py","SEC-044 RPC sync batch bounds"),
 ("security_sec045_rpc_query_limit_bounds_spec.py","SEC-045 RPC query limit bounds"),
 ("security_sec046_rpc_sync_peer_port_bounds_spec.py","SEC-046 RPC sync peer port bounds"),
 ("security_sec047_rpc_peer_port_bounds_spec.py","SEC-047 RPC peer port bounds"),
 ("security_sec048_rpc_start_p2p_port_bounds_spec.py","SEC-048 RPC start_p2p port bounds"),
 ("security_sec049_peer_host_bounds_spec.py","SEC-049 peer host bounds"),
 ("security_sec050_sync_peer_host_bounds_spec.py","SEC-050 sync_peer host bounds"),
 ("security_sec051_p2p_listener_host_bounds_spec.py","SEC-051 P2P listener host bounds"),
 ("security_sec052_transaction_id_bounds_spec.py","SEC-052 transaction lookup ID bounds"),
 ("security_sec053_block_id_bounds_spec.py","SEC-053 block ID bounds"),
 ("security_sec054_recipient_address_bounds_spec.py","SEC-054 send recipient bounds"),
]

def main():
    rows=[]; all_ok=True
    for script,name in SUITES:
        print(f"\n=== {name} ===",flush=True)
        t=time.perf_counter()
        p=subprocess.run([sys.executable,script],cwd=ROOT,text=True)
        sec=time.perf_counter()-t
        ok=p.returncode==0
        rows.append({"name":name,"script":script,"ok":ok,"seconds":round(sec,3)})
        all_ok &= ok
        if not ok:
            print(f"\nSTOP: {name} failed.",flush=True)
            break
    print("\n=== AXVEN VALIDATION SUMMARY ===")
    print(json.dumps({"ok":all_ok,"results":rows},indent=2))
    raise SystemExit(0 if all_ok else 1)

if __name__=="__main__":main()
