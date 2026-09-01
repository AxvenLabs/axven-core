#![no_main]

use axven_native::{FuzzUtxoRecord, fuzz_smt_root_mirror};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4096;
const MAX_RECORDS: usize = 32;
const MAX_TEXT_BYTES: usize = 96;

fn take_u8(data: &[u8], cursor: &mut usize) -> Option<u8> {
    let value = *data.get(*cursor)?;
    *cursor += 1;
    Some(value)
}

fn take_u64(data: &[u8], cursor: &mut usize) -> Option<u64> {
    let end = cursor.checked_add(8)?;
    let bytes: [u8; 8] = data.get(*cursor..end)?.try_into().ok()?;
    *cursor = end;
    Some(u64::from_le_bytes(bytes))
}

fn take_text(data: &[u8], cursor: &mut usize) -> Option<String> {
    let declared = usize::from(take_u8(data, cursor)?);
    let len = declared % (MAX_TEXT_BYTES + 1);
    let end = cursor.checked_add(len)?;
    let raw = data.get(*cursor..end)?;
    *cursor = end;
    Some(String::from_utf8_lossy(raw).into_owned())
}

fn decode_records(data: &[u8]) -> Vec<FuzzUtxoRecord> {
    let mut cursor = 0usize;
    let Some(count_byte) = take_u8(data, &mut cursor) else {
        return Vec::new();
    };
    let count = usize::from(count_byte) % (MAX_RECORDS + 1);
    let mut records = Vec::with_capacity(count);

    for _ in 0..count {
        let Some(op) = take_text(data, &mut cursor) else {
            break;
        };
        let Some(amount) = take_u64(data, &mut cursor) else {
            break;
        };
        let Some(recipient) = take_text(data, &mut cursor) else {
            break;
        };
        let Some(coinbase_byte) = take_u8(data, &mut cursor) else {
            break;
        };
        let Some(height) = take_u64(data, &mut cursor) else {
            break;
        };

        records.push(FuzzUtxoRecord {
            op,
            amount,
            recipient,
            coinbase: coinbase_byte & 1 == 1,
            height,
        });
    }

    records
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let records = decode_records(data);
    let baseline = fuzz_smt_root_mirror(&records);

    assert_eq!(baseline, fuzz_smt_root_mirror(&records));

    let mut reversed = records.clone();
    reversed.reverse();
    assert_eq!(baseline, fuzz_smt_root_mirror(&reversed));

    if !records.is_empty() {
        let mut rotated = records.clone();
        let shift = usize::from(data.last().copied().unwrap_or_default()) % rotated.len();
        rotated.rotate_left(shift);
        assert_eq!(baseline, fuzz_smt_root_mirror(&rotated));
    }
});
