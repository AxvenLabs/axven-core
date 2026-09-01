use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const BOUNDARY_VERSION: &str = "rust-001";
const SMT_DEPTH: usize = 256;
type Hash32 = [u8; 32];
type NodeKey = [u8; 32];
type SmtEntry = (String, u64, String, bool, u64);

fn native_probe_impl(data: &[u8]) -> (usize, u64) {
    let mut acc = 0x9e37_79b9_7f4a_7c15_u64;
    for &byte in data {
        acc ^= u64::from(byte);
        acc = acc.rotate_left(7).wrapping_mul(0x1000_0000_01b3);
    }
    (data.len(), acc)
}

fn sha256_bytes(data: &[u8]) -> Hash32 {
    let digest = Sha256::digest(data);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn hash_pair(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let digest = hasher.finalize();
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn hex_digest(value: &Hash32) -> String {
    let mut output = String::with_capacity(64);
    for byte in value {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn shift_right_one(value: &NodeKey) -> NodeKey {
    let mut output = [0_u8; 32];
    let mut carry = 0_u8;
    for (index, byte) in value.iter().copied().enumerate() {
        output[index] = (byte >> 1) | carry;
        carry = (byte & 1) << 7;
    }
    output
}

fn shift_left_one(value: &NodeKey) -> NodeKey {
    let mut output = [0_u8; 32];
    let mut carry = 0_u8;
    for index in (0..32).rev() {
        let byte = value[index];
        output[index] = (byte << 1) | carry;
        carry = byte >> 7;
    }
    output
}

fn smt_defaults() -> Vec<Hash32> {
    let mut defaults = vec![[0_u8; 32]; SMT_DEPTH + 1];
    defaults[SMT_DEPTH] = [0_u8; 32];
    for depth in (0..SMT_DEPTH).rev() {
        defaults[depth] = hash_pair(&defaults[depth + 1], &defaults[depth + 1]);
    }
    defaults
}

fn smt_key(op: &str) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(b"axven-smt-key-v1|");
    hasher.update(op.as_bytes());
    let digest = hasher.finalize();
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn smt_value(op: &str, amount: u64, recipient: &str, coinbase: bool, height: u64) -> Hash32 {
    let material = format!(
        "axven-smt-leaf-v1|{op}|{amount}|{recipient}|{}|{height}",
        u8::from(coinbase)
    );
    sha256_bytes(material.as_bytes())
}

fn smt_root_mirror_impl(entries: &[SmtEntry]) -> Result<Hash32, &'static str> {
    let defaults = smt_defaults();
    if entries.is_empty() {
        return Ok(defaults[0]);
    }

    let mut seen = BTreeSet::new();
    let mut nodes: BTreeMap<NodeKey, Hash32> = BTreeMap::new();
    for (op, amount, recipient, coinbase, height) in entries {
        if !seen.insert(op.as_str()) {
            return Err("duplicate UTXO outpoint");
        }
        nodes.insert(
            smt_key(op),
            smt_value(op, *amount, recipient, *coinbase, *height),
        );
    }

    for depth in (1..=SMT_DEPTH).rev() {
        let touched: BTreeSet<NodeKey> = nodes.keys().map(shift_right_one).collect();
        let mut parents = BTreeMap::new();
        for parent in touched {
            let left_key = shift_left_one(&parent);
            let mut right_key = left_key;
            right_key[31] |= 1;
            let left = nodes.get(&left_key).unwrap_or(&defaults[depth]);
            let right = nodes.get(&right_key).unwrap_or(&defaults[depth]);
            let parent_hash = hash_pair(left, right);
            if parent_hash != defaults[depth - 1] {
                parents.insert(parent, parent_hash);
            }
        }
        nodes = parents;
    }

    Ok(nodes.get(&[0_u8; 32]).copied().unwrap_or(defaults[0]))
}

#[pyfunction]
fn boundary_version() -> &'static str {
    BOUNDARY_VERSION
}

#[pyfunction]
fn native_probe(data: &[u8]) -> (usize, u64) {
    native_probe_impl(data)
}

#[pyfunction]
fn smt_root_mirror(entries: Vec<SmtEntry>) -> PyResult<String> {
    smt_root_mirror_impl(&entries)
        .map(|root| hex_digest(&root))
        .map_err(PyValueError::new_err)
}

#[pymodule]
fn axven_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(boundary_version, m)?)?;
    m.add_function(wrap_pyfunction!(native_probe, m)?)?;
    m.add_function(wrap_pyfunction!(smt_root_mirror, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entries() -> Vec<SmtEntry> {
        vec![
            (
                "00aa:0".to_string(),
                50,
                "N1111111111111111111111111111111111111111".to_string(),
                true,
                1,
            ),
            (
                "00bb:1".to_string(),
                25,
                "M2222222222222222222222222222222222222222".to_string(),
                false,
                7,
            ),
        ]
    }

    #[test]
    fn probe_is_deterministic() {
        let input = b"axven-rust-001";
        assert_eq!(native_probe_impl(input), native_probe_impl(input));
    }

    #[test]
    fn probe_is_input_sensitive() {
        assert_ne!(native_probe_impl(b"a"), native_probe_impl(b"b"));
    }

    #[test]
    fn empty_probe_is_stable() {
        assert_eq!(native_probe_impl(b"").0, 0);
    }

    #[test]
    fn empty_smt_root_is_stable() {
        assert_eq!(
            smt_root_mirror_impl(&[]),
            smt_root_mirror_impl(&[])
        );
    }

    #[test]
    fn smt_mirror_is_order_independent() {
        let entries = sample_entries();
        let reversed = entries.iter().cloned().rev().collect::<Vec<_>>();
        assert_eq!(
            smt_root_mirror_impl(&entries).unwrap(),
            smt_root_mirror_impl(&reversed).unwrap()
        );
    }

    #[test]
    fn smt_mirror_rejects_duplicate_outpoints() {
        let mut entries = sample_entries();
        entries.push(entries[0].clone());
        assert_eq!(
            smt_root_mirror_impl(&entries),
            Err("duplicate UTXO outpoint")
        );
    }
}
