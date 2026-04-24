use std::collections::BTreeMap;

use super::common::mask_to_bits;

pub(crate) fn fixture_memory_map(regions: &[(u64, Vec<u8>)]) -> BTreeMap<u64, u8> {
    let mut memory = BTreeMap::new();
    for (address, bytes) in regions {
        for (offset, byte) in bytes.iter().copied().enumerate() {
            memory.insert(address + offset as u64, byte);
        }
    }
    memory
}

pub(crate) fn value_to_le_bytes(value: u128, bits: u16) -> Vec<u8> {
    let byte_len = bits.div_ceil(8) as usize;
    (0..byte_len)
        .map(|index| ((value >> (index * 8)) & 0xff) as u8)
        .collect()
}

pub(crate) fn load_le_value(memory: &BTreeMap<u64, u8>, address: u64, bits: u16) -> u128 {
    let byte_len = bits.div_ceil(8) as usize;
    let mut value = 0u128;
    for index in 0..byte_len {
        let byte = memory
            .get(&(address + index as u64))
            .copied()
            .unwrap_or_default() as u128;
        value |= byte << (index * 8);
    }
    mask_to_bits(value, bits)
}

pub(crate) fn load_le_bytes(memory: &BTreeMap<u64, u8>, address: u64, bits: u16) -> Vec<u8> {
    let byte_len = bits.div_ceil(8) as usize;
    (0..byte_len)
        .map(|index| {
            memory
                .get(&(address + index as u64))
                .copied()
                .unwrap_or_default()
        })
        .collect()
}
