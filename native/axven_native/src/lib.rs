use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const BOUNDARY_VERSION: &str = "rust-001";
const SMT_DEPTH: usize = 256;
type Hash32 = [u8; 32];

#[derive(Clone, Debug)]
struct UtxoRecord {
    op: String,
    amount: u64,
    recipient: String,
    coinbase: bool,
    height: u64,
}

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzUtxoRecord {
    pub op: String,
    pub amount: u64,
    pub recipient: String,
    pub coinbase: bool,
    pub height: u64,
}

fn native_probe_impl(data: &[u8]) -> (usize, u64) {
    let mut acc = 0x9e37_79b9_7f4a_7c15_u64;
    for &byte in data {
        acc ^= u64::from(byte);
        acc = acc.rotate_left(7).wrapping_mul(0x1000_0000_01b3);
    }
    (data.len(), acc)
}

fn sha256_bytes(data: &[u8]) -> Hash32 {
    Sha256::digest(data).into()
}

fn sha256_pair(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn hex_lower(hash: &Hash32) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &byte in hash {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn shift_right_one(mut key: Hash32) -> Hash32 {
    let mut carry = 0u8;
    for byte in &mut key {
        let next_carry = *byte & 1;
        *byte = (*byte >> 1) | (carry << 7);
        carry = next_carry;
    }
    key
}

fn smt_defaults() -> [Hash32; SMT_DEPTH + 1] {
    let mut defaults = [[0u8; 32]; SMT_DEPTH + 1];
    defaults[SMT_DEPTH] = [0u8; 32];
    for depth in (0..SMT_DEPTH).rev() {
        defaults[depth] = sha256_pair(&defaults[depth + 1], &defaults[depth + 1]);
    }
    defaults
}

fn smt_key(op: &str) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(b"axven-smt-key-v1|");
    hasher.update(op.as_bytes());
    hasher.finalize().into()
}

fn smt_value(record: &UtxoRecord) -> Hash32 {
    let raw = format!(
        "axven-smt-leaf-v1|{}|{}|{}|{}|{}",
        record.op,
        record.amount,
        record.recipient,
        u8::from(record.coinbase),
        record.height
    );
    sha256_bytes(raw.as_bytes())
}

fn smt_root_mirror_impl(records: &[UtxoRecord]) -> Result<Hash32, &'static str> {
    let defaults = smt_defaults();
    if records.is_empty() {
        return Ok(defaults[0]);
    }

    let mut seen_outpoints = BTreeSet::new();
    let mut nodes: BTreeMap<Hash32, Hash32> = BTreeMap::new();
    for record in records {
        if !seen_outpoints.insert(record.op.as_str()) {
            return Err("duplicate UTXO outpoint");
        }
        let key = smt_key(&record.op);
        if nodes.insert(key, smt_value(record)).is_some() {
            return Err("SMT key collision");
        }
    }

    for depth in (1..=SMT_DEPTH).rev() {
        let default_child = defaults[depth];
        let default_parent = defaults[depth - 1];
        let mut grouped: BTreeMap<Hash32, [Option<Hash32>; 2]> = BTreeMap::new();

        for (key, hash) in nodes {
            let side = usize::from(key[31] & 1);
            let parent = shift_right_one(key);
            let children = grouped.entry(parent).or_insert([None, None]);
            children[side] = Some(hash);
        }

        let mut parents = BTreeMap::new();
        for (parent, children) in grouped {
            let left = children[0].unwrap_or(default_child);
            let right = children[1].unwrap_or(default_child);
            let hash = sha256_pair(&left, &right);
            if hash != default_parent {
                parents.insert(parent, hash);
            }
        }
        nodes = parents;
    }

    Ok(nodes.get(&[0u8; 32]).copied().unwrap_or(defaults[0]))
}

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_smt_root_mirror(records: &[FuzzUtxoRecord]) -> Result<[u8; 32], &'static str> {
    let internal = records
        .iter()
        .map(|record| UtxoRecord {
            op: record.op.clone(),
            amount: record.amount,
            recipient: record.recipient.clone(),
            coinbase: record.coinbase,
            height: record.height,
        })
        .collect::<Vec<_>>();
    smt_root_mirror_impl(&internal)
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
fn smt_root_mirror(records: Vec<(String, u64, String, bool, u64)>) -> PyResult<String> {
    let records = records
        .into_iter()
        .map(|(op, amount, recipient, coinbase, height)| UtxoRecord {
            op,
            amount,
            recipient,
            coinbase,
            height,
        })
        .collect::<Vec<_>>();
    smt_root_mirror_impl(&records)
        .map(|hash| hex_lower(&hash))
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

    fn record(
        op: String,
        amount: u64,
        recipient: String,
        coinbase: bool,
        height: u64,
    ) -> UtxoRecord {
        UtxoRecord {
            op,
            amount,
            recipient,
            coinbase,
            height,
        }
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
    fn empty_smt_root_matches_python_oracle() {
        let root = smt_root_mirror_impl(&[]).expect("empty mirror");
        assert_eq!(
            hex_lower(&root),
            "b178c245c947ea7e21ecede07728941a6ab1b706143c06873baff8ebd6de6308"
        );
    }

    #[test]
    fn one_leaf_smt_root_matches_python_oracle() {
        let records = vec![record(
            format!("{}:0", "00".repeat(32)),
            1,
            format!("N{}", "1".repeat(40)),
            false,
            1,
        )];
        let root = smt_root_mirror_impl(&records).expect("one-leaf mirror");
        assert_eq!(
            hex_lower(&root),
            "f9c17f4ac4ffe9b72aaebc1ed3a4c241f0316c29883a8adcbef610a92170e45d"
        );
    }

    #[test]
    fn two_leaf_smt_root_matches_python_oracle() {
        let records = vec![
            record(
                format!("{}:0", "00".repeat(32)),
                1,
                format!("N{}", "1".repeat(40)),
                false,
                1,
            ),
            record(
                format!("{}:1", "11".repeat(32)),
                5_000_000_000,
                format!("M{}", "2".repeat(40)),
                true,
                100,
            ),
        ];
        let root = smt_root_mirror_impl(&records).expect("two-leaf mirror");
        assert_eq!(
            hex_lower(&root),
            "72850532475df352c95089fc89890c848a04612ccc583b9111cd19c15be9d138"
        );
    }

    #[test]
    fn duplicate_outpoint_fails_closed() {
        let item = record(
            format!("{}:0", "22".repeat(32)),
            7,
            format!("N{}", "3".repeat(40)),
            false,
            2,
        );
        assert!(smt_root_mirror_impl(&[item.clone(), item]).is_err());
    }
}
