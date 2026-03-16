pub fn normalize_l2(values: &mut [f32]) {
    let norm = values.iter().map(|value| value * value).sum::<f32>().sqrt();
    if norm > 0.0 {
        for value in values.iter_mut() {
            *value /= norm;
        }
    }
}

pub fn mean(values: &[f32]) -> f32 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f32>() / values.len() as f32
    }
}

pub fn max_or_zero(values: &[f32]) -> f32 {
    values
        .iter()
        .copied()
        .fold(0.0f32, |current, value| current.max(value))
}

pub fn weighted_mean(values: &[f32], weights: &[f32]) -> f32 {
    if values.is_empty() || weights.is_empty() || values.len() != weights.len() {
        return 0.0;
    }
    let weight_sum = weights.iter().sum::<f32>();
    if weight_sum <= 0.0 {
        return mean(values);
    }
    values
        .iter()
        .zip(weights.iter())
        .map(|(value, weight)| value * weight)
        .sum::<f32>()
        / weight_sum
}

pub fn weighted_histogram(values: &[f32], weights: &[f32], buckets: usize, scale: f32) -> Vec<f32> {
    let mut histogram = vec![0.0f32; buckets];
    if values.is_empty() || weights.is_empty() || values.len() != weights.len() || buckets == 0 {
        return histogram;
    }

    let max_bucket = buckets - 1;
    for (value, weight) in values.iter().zip(weights.iter()) {
        let bucket = ((*value / scale).floor() as usize).min(max_bucket);
        histogram[bucket] += *weight;
    }

    let total = weights.iter().sum::<f32>();
    if total > 0.0 {
        for value in &mut histogram {
            *value /= total;
        }
    }
    histogram
}

pub fn downsample_vector(values: &[f32], dimensions: usize) -> Vec<f32> {
    if dimensions == 0 || values.is_empty() {
        return Vec::new();
    }
    if dimensions == values.len() {
        return values.to_vec();
    }

    let source_len = values.len() as f32;
    let target_len = dimensions as f32;
    let mut reduced = vec![0.0f32; dimensions];

    for (target_index, target_value) in reduced.iter_mut().enumerate() {
        let start = target_index as f32 * source_len / target_len;
        let end = (target_index as f32 + 1.0) * source_len / target_len;
        let first = start.floor() as usize;
        let last = end.ceil() as usize;
        let mut total = 0.0f32;
        let mut weight_sum = 0.0f32;

        for source_index in first..last.min(values.len()) {
            let source_start = source_index as f32;
            let source_end = source_start + 1.0;
            let overlap = (end.min(source_end) - start.max(source_start)).max(0.0);
            if overlap > 0.0 {
                total += values[source_index] * overlap;
                weight_sum += overlap;
            }
        }

        if weight_sum > 0.0 {
            *target_value = total / weight_sum;
        }
    }

    reduced
}
