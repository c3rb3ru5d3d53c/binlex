// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::borrow::Cow;
use std::collections::HashSet;

const SPAMSUM_LENGTH: usize = 64;
const MIN_BLOCK_SIZE: usize = 3;
const ROLLING_WINDOW: usize = 7;
const COMMON_SEQUENCE_LEN: usize = 7;
const FNV_OFFSET: u32 = 0x2802_1967;
const FNV_PRIME: u32 = 0x0100_0193;
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Computes and compares ssdeep-style fuzzy hashes for byte buffers.
pub struct SSDeep<'ssdeep> {
    pub bytes: Cow<'ssdeep, [u8]>,
}

impl<'ssdeep> SSDeep<'ssdeep> {
    #[allow(dead_code)]
    pub fn new(bytes: &'ssdeep [u8]) -> Self {
        Self {
            bytes: Cow::Borrowed(bytes),
        }
    }

    #[allow(dead_code)]
    pub fn from_bytes(bytes: Vec<u8>) -> SSDeep<'static> {
        SSDeep {
            bytes: Cow::Owned(bytes),
        }
    }

    pub fn compare(&self, other: &Self) -> Option<f64> {
        let lhs = self.hexdigest()?;
        let rhs = other.hexdigest()?;
        Self::compare_hexdigests(&lhs, &rhs)
    }

    pub fn compare_hexdigest(&self, other: &str) -> Option<f64> {
        let lhs = self.hexdigest()?;
        Self::compare_hexdigests(&lhs, other)
    }

    pub fn compare_hexdigests(lhs: &str, rhs: &str) -> Option<f64> {
        let lhs = ParsedHash::parse(lhs)?;
        let rhs = ParsedHash::parse(rhs)?;

        let score = if lhs.block_size == rhs.block_size {
            score_strings(&lhs.hash, &rhs.hash, lhs.block_size).max(score_strings(
                &lhs.hash2,
                &rhs.hash2,
                lhs.block_size * 2,
            ))
        } else if lhs.block_size == rhs.block_size * 2 {
            score_strings(&lhs.hash2, &rhs.hash, lhs.block_size)
        } else if rhs.block_size == lhs.block_size * 2 {
            score_strings(&lhs.hash, &rhs.hash2, rhs.block_size)
        } else {
            return None;
        };

        Some(score as f64)
    }

    #[allow(dead_code)]
    pub fn hexdigest(&self) -> Option<String> {
        if self.bytes.is_empty() {
            return None;
        }

        let bytes = self.bytes.as_ref();
        let mut block_size = estimate_block_size(bytes.len());

        loop {
            let (hash, hash2) = compute_signature(bytes, block_size);
            if block_size > MIN_BLOCK_SIZE && hash.len() < SPAMSUM_LENGTH / 2 {
                block_size /= 2;
                continue;
            }
            return Some(format!("{}:{}:{}", block_size, hash, hash2));
        }
    }
}

#[derive(Clone)]
struct ParsedHash {
    block_size: usize,
    hash: String,
    hash2: String,
}

impl ParsedHash {
    fn parse(value: &str) -> Option<Self> {
        let mut parts = value.splitn(3, ':');
        let block_size = parts.next()?.parse::<usize>().ok()?;
        let hash = parts.next()?.to_string();
        let hash2 = parts.next()?.to_string();
        if block_size < MIN_BLOCK_SIZE || !is_valid_hash(&hash) || !is_valid_hash(&hash2) {
            return None;
        }
        Some(Self {
            block_size,
            hash,
            hash2,
        })
    }
}

fn is_valid_hash(hash: &str) -> bool {
    !hash.is_empty() && hash.bytes().all(|byte| BASE64.contains(&byte))
}

fn estimate_block_size(length: usize) -> usize {
    let mut block_size = MIN_BLOCK_SIZE;
    while block_size * SPAMSUM_LENGTH < length {
        block_size *= 2;
    }
    block_size
}

fn compute_signature(bytes: &[u8], block_size: usize) -> (String, String) {
    let mut rolling = RollingHash::default();
    let mut hash = TraditionalHash::default();
    let mut hash2 = TraditionalHash::default();
    let mut signature = String::new();
    let mut signature2 = String::new();

    for &byte in bytes {
        let roll = rolling.update(byte);
        hash.update(byte);
        hash2.update(byte);

        if roll % block_size as u32 == (block_size - 1) as u32 {
            push_char(&mut signature, hash.base64_char());
            hash.reset();
        }

        let double_block = block_size * 2;
        if roll % double_block as u32 == (double_block - 1) as u32 {
            push_char(&mut signature2, hash2.base64_char());
            hash2.reset();
        }
    }

    push_char(&mut signature, hash.base64_char());
    push_char(&mut signature2, hash2.base64_char());

    (signature, signature2)
}

fn push_char(output: &mut String, ch: char) {
    if output.len() < SPAMSUM_LENGTH {
        output.push(ch);
    }
}

#[derive(Default)]
struct TraditionalHash {
    value: u32,
}

impl TraditionalHash {
    fn update(&mut self, byte: u8) {
        if self.value == 0 {
            self.value = FNV_OFFSET;
        }
        self.value = self.value.wrapping_mul(FNV_PRIME) ^ byte as u32;
    }

    fn reset(&mut self) {
        self.value = FNV_OFFSET;
    }

    fn base64_char(&self) -> char {
        BASE64[(self.value & 63) as usize] as char
    }
}

struct RollingHash {
    x: u32,
    y: u32,
    z: u32,
    count: usize,
    window: [u8; ROLLING_WINDOW],
}

impl Default for RollingHash {
    fn default() -> Self {
        Self {
            x: 0,
            y: 0,
            z: 0,
            count: 0,
            window: [0; ROLLING_WINDOW],
        }
    }
}

impl RollingHash {
    fn update(&mut self, byte: u8) -> u32 {
        self.y = self.y.wrapping_sub(self.x);
        self.y = self
            .y
            .wrapping_add((ROLLING_WINDOW as u32).wrapping_mul(byte as u32));
        self.x = self.x.wrapping_add(byte as u32);
        self.x = self
            .x
            .wrapping_sub(self.window[self.count % ROLLING_WINDOW] as u32);
        self.window[self.count % ROLLING_WINDOW] = byte;
        self.count += 1;
        self.z = self.z.wrapping_shl(5) ^ byte as u32;
        self.x.wrapping_add(self.y).wrapping_add(self.z)
    }
}

fn score_strings(lhs: &str, rhs: &str, block_size: usize) -> u32 {
    if lhs == rhs {
        return 100;
    }

    let lhs = eliminate_long_sequences(lhs);
    let rhs = eliminate_long_sequences(rhs);

    if !has_common_sequence(&lhs, &rhs, COMMON_SEQUENCE_LEN) {
        return 0;
    }

    let distance = edit_distance(&lhs, &rhs) as u32;
    let total_len = (lhs.len() + rhs.len()) as u32;
    if total_len == 0 {
        return 0;
    }

    let scaled = (distance * SPAMSUM_LENGTH as u32) / total_len;
    let mut score = 100u32.saturating_sub((100 * scaled) / SPAMSUM_LENGTH as u32);
    let cap = ((block_size / MIN_BLOCK_SIZE) * lhs.len().min(rhs.len())) as u32;
    if score > cap {
        score = cap;
    }
    score
}

fn eliminate_long_sequences(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut previous = None;
    let mut run = 0usize;

    for ch in input.chars() {
        if Some(ch) == previous {
            run += 1;
            if run > 3 {
                continue;
            }
        } else {
            previous = Some(ch);
            run = 1;
        }
        result.push(ch);
    }

    result
}

fn has_common_sequence(lhs: &str, rhs: &str, width: usize) -> bool {
    if lhs.len() < width || rhs.len() < width {
        return lhs == rhs;
    }

    let mut windows = HashSet::new();
    for window in lhs.as_bytes().windows(width) {
        windows.insert(window);
    }
    rhs.as_bytes()
        .windows(width)
        .any(|window| windows.contains(window))
}

fn edit_distance(lhs: &str, rhs: &str) -> usize {
    let lhs = lhs.as_bytes();
    let rhs = rhs.as_bytes();
    let mut prev: Vec<usize> = (0..=rhs.len()).collect();
    let mut curr = vec![0usize; rhs.len() + 1];

    for (i, &left) in lhs.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &right) in rhs.iter().enumerate() {
            let substitution_cost = if left == right { 0 } else { 2 };
            curr[j + 1] = (prev[j + 1] + 1)
                .min(curr[j] + 1)
                .min(prev[j] + substitution_cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[rhs.len()]
}

#[cfg(test)]
mod tests {
    use super::SSDeep;

    #[test]
    fn hashes_hello_world_vector() {
        let digest = SSDeep::new(b"Hello, World!\n").hexdigest().expect("digest");
        assert_eq!(digest, "3:aaX8v:aV");
    }

    #[test]
    fn compares_ffuzzy_example_pair() {
        let lhs = "6:3ll7QzDkmJmMHkQoO/llSZEnEuLszmbMAWn:VqDk5QtLbW";
        let rhs = "6:3ll7QzDkmQjmMoDHglHOxPWT0lT0lT0lB:VqDk+n";
        let score = SSDeep::compare_hexdigests(lhs, rhs).expect("score");
        assert_eq!(score, 46.0);
    }

    #[test]
    fn compares_ffuzzy_normalization_example_pair() {
        let lhs = "12288:+ySwl5P+C5IxJ845HYV5sxOH/cccccccei:+Klhav84a5sxJ";
        let rhs = "12288:+yUwldx+C5IxJ845HYV5sxOH/cccccccex:+glvav84a5sxK";
        let score = SSDeep::compare_hexdigests(lhs, rhs).expect("score");
        assert_eq!(score, 88.0);
    }

    #[test]
    fn hashes_and_compares_ppdeep_examples() {
        let lhs = "The equivalence of mass and energy translates into the well-known E = mc²";
        let rhs = "The equivalence of mass and energy translates into the well-known E = MC2";

        let lhs_digest = SSDeep::new(lhs.as_bytes()).hexdigest().expect("lhs digest");
        let rhs_digest = SSDeep::new(rhs.as_bytes()).hexdigest().expect("rhs digest");

        assert_eq!(
            lhs_digest,
            "3:RC0qYX4LBFA0dxEq4z2LRK+oCKI9VnXn:RvqpLB60dx8ilK+owX"
        );
        assert_eq!(
            rhs_digest,
            "3:RC0qYX4LBFA0dxEq4z2LRK+oCKI99:RvqpLB60dx8ilK+oA"
        );
        assert_eq!(
            SSDeep::compare_hexdigests(&lhs_digest, &rhs_digest),
            Some(34.0)
        );
    }

    #[test]
    fn invalid_digest_returns_none() {
        assert_eq!(
            SSDeep::compare_hexdigests("not-a-digest", "3:abc:def"),
            None
        );
    }

    #[test]
    fn empty_input_returns_none() {
        assert_eq!(SSDeep::new(b"").hexdigest(), None);
    }
}
