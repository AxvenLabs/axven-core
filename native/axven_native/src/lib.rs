use pyo3::prelude::*;

const BOUNDARY_VERSION: &str = "rust-001";

fn native_probe_impl(data: &[u8]) -> (usize, u64) {
    let mut acc = 0x9e37_79b9_7f4a_7c15_u64;
    for &byte in data {
        acc ^= u64::from(byte);
        acc = acc.rotate_left(7).wrapping_mul(0x1000_0000_01b3);
    }
    (data.len(), acc)
}

#[pyfunction]
fn boundary_version() -> &'static str {
    BOUNDARY_VERSION
}

#[pyfunction]
fn native_probe(data: &[u8]) -> (usize, u64) {
    native_probe_impl(data)
}

#[pymodule]
fn axven_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(boundary_version, m)?)?;
    m.add_function(wrap_pyfunction!(native_probe, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
