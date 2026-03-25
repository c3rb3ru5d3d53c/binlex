use std::collections::BTreeSet;

pub fn dot(lhs: &[f32], rhs: &[f32]) -> f32 {
    if lhs.is_empty() || rhs.is_empty() || lhs.len() != rhs.len() {
        return 0.0;
    }
    lhs.iter().zip(rhs).map(|(left, right)| left * right).sum()
}

pub fn cosine(lhs: &[f32], rhs: &[f32]) -> f32 {
    if lhs.is_empty() || rhs.is_empty() || lhs.len() != rhs.len() {
        return 0.0;
    }
    let mut lhs_norm = 0.0f32;
    let mut rhs_norm = 0.0f32;
    for value in lhs {
        lhs_norm += value * value;
    }
    for value in rhs {
        rhs_norm += value * value;
    }
    if lhs_norm == 0.0 || rhs_norm == 0.0 {
        return 0.0;
    }
    dot(lhs, rhs) / (lhs_norm.sqrt() * rhs_norm.sqrt())
}

pub fn euclidean(lhs: &[f32], rhs: &[f32]) -> f32 {
    if lhs.is_empty() || rhs.is_empty() || lhs.len() != rhs.len() {
        return 0.0;
    }
    lhs.iter()
        .zip(rhs)
        .map(|(left, right)| {
            let delta = left - right;
            delta * delta
        })
        .sum::<f32>()
        .sqrt()
}

pub fn manhattan(lhs: &[f32], rhs: &[f32]) -> f32 {
    if lhs.is_empty() || rhs.is_empty() || lhs.len() != rhs.len() {
        return 0.0;
    }
    lhs.iter()
        .zip(rhs)
        .map(|(left, right)| (left - right).abs())
        .sum()
}

pub fn chebyshev(lhs: &[f32], rhs: &[f32]) -> f32 {
    if lhs.is_empty() || rhs.is_empty() || lhs.len() != rhs.len() {
        return 0.0;
    }
    lhs.iter()
        .zip(rhs)
        .map(|(left, right)| (left - right).abs())
        .fold(0.0f32, f32::max)
}

pub fn hamming<T: PartialEq>(lhs: &[T], rhs: &[T]) -> usize {
    if lhs.is_empty() || rhs.is_empty() || lhs.len() != rhs.len() {
        return 0;
    }
    lhs.iter()
        .zip(rhs)
        .filter(|(left, right)| left != right)
        .count()
}

pub fn jaccard_signature<T: PartialEq>(lhs: &[T], rhs: &[T]) -> f64 {
    if lhs.is_empty() || rhs.is_empty() || lhs.len() != rhs.len() {
        return 0.0;
    }
    let matches = lhs
        .iter()
        .zip(rhs)
        .filter(|(left, right)| left == right)
        .count();
    matches as f64 / lhs.len() as f64
}

pub fn jaccard_set<T: Ord>(lhs: &[T], rhs: &[T]) -> f64 {
    if lhs.is_empty() || rhs.is_empty() {
        return 0.0;
    }
    let lhs = lhs.iter().collect::<BTreeSet<_>>();
    let rhs = rhs.iter().collect::<BTreeSet<_>>();
    let intersection = lhs.intersection(&rhs).count();
    let union = lhs.union(&rhs).count();
    if union == 0 {
        return 0.0;
    }
    intersection as f64 / union as f64
}

pub fn dice<T: Ord>(lhs: &[T], rhs: &[T]) -> f64 {
    if lhs.is_empty() || rhs.is_empty() {
        return 0.0;
    }
    let lhs = lhs.iter().collect::<BTreeSet<_>>();
    let rhs = rhs.iter().collect::<BTreeSet<_>>();
    let intersection = lhs.intersection(&rhs).count();
    let denominator = lhs.len() + rhs.len();
    if denominator == 0 {
        return 0.0;
    }
    (2 * intersection) as f64 / denominator as f64
}

pub fn overlap_coefficient<T: Ord>(lhs: &[T], rhs: &[T]) -> f64 {
    if lhs.is_empty() || rhs.is_empty() {
        return 0.0;
    }
    let lhs = lhs.iter().collect::<BTreeSet<_>>();
    let rhs = rhs.iter().collect::<BTreeSet<_>>();
    let intersection = lhs.intersection(&rhs).count();
    let min_size = lhs.len().min(rhs.len());
    if min_size == 0 {
        return 0.0;
    }
    intersection as f64 / min_size as f64
}

pub fn pearson(lhs: &[f32], rhs: &[f32]) -> f64 {
    if lhs.is_empty() || rhs.is_empty() || lhs.len() != rhs.len() {
        return 0.0;
    }
    let len = lhs.len() as f64;
    let lhs_mean = lhs.iter().map(|value| *value as f64).sum::<f64>() / len;
    let rhs_mean = rhs.iter().map(|value| *value as f64).sum::<f64>() / len;
    let mut numerator = 0.0f64;
    let mut lhs_variance = 0.0f64;
    let mut rhs_variance = 0.0f64;
    for (left, right) in lhs.iter().zip(rhs) {
        let left_delta = *left as f64 - lhs_mean;
        let right_delta = *right as f64 - rhs_mean;
        numerator += left_delta * right_delta;
        lhs_variance += left_delta * left_delta;
        rhs_variance += right_delta * right_delta;
    }
    if lhs_variance == 0.0 || rhs_variance == 0.0 {
        return 0.0;
    }
    numerator / (lhs_variance.sqrt() * rhs_variance.sqrt())
}
