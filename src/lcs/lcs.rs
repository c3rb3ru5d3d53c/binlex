use std::cmp::{max, Ordering};

pub struct FuzzyLCS<'a> {
    s1: &'a str,
    s2: &'a str,
}

impl<'a> FuzzyLCS<'a> {
    pub fn new(s1: &'a str, s2: &'a str) -> Self {
        FuzzyLCS { s1, s2 }
    }

    fn compute(&self) -> Vec<usize> {
        let a: Vec<char> = self.s1.chars().collect();
        let b: Vec<char> = self.s2.chars().collect();
        let na = a.len();
        let nb = b.len();
        let mut dp = vec![0; nb + 1];

        for i in 0..na {
            let mut prev = 0;
            for j in 0..nb {
                let temp = dp[j + 1];
                if a[i] == b[j] {
                    dp[j + 1] = prev + 1;
                } else {
                    dp[j + 1] = max(dp[j + 1], dp[j]);
                }
                prev = temp;
            }
        }

        dp
    }

    pub fn compare(
        &self,
        threshold: f64,
        max_results: usize,
        min_length: usize,
        wildcard_ratio: f64) -> Vec<(f64, &str)> {
        let a_len = self.s1.len();
        let b_len = self.s2.len();
        let dp = self.compute();

        let mut matches= Vec::new();

        for start in 0..b_len {
            for end in (start + 1)..=b_len {
                let lcs_length = dp[end];
                let substring = &self.s2[start..end];
                if substring.len() < min_length {
                    continue;
                }
                if FuzzyLCS::wildcard_ratio(substring) > wildcard_ratio {
                    continue;
                }
                let score = lcs_length as f64 / max(a_len, substring.len()) as f64;

                if score >= threshold {
                    matches.push((score, substring));
                }
            }
        }

        matches.sort_by(|a, b| {
            b.0.partial_cmp(&a.0).unwrap_or(Ordering::Equal)
                .then_with(|| b.1.len().cmp(&a.1.len()))
        });

        matches.truncate(max_results);

        matches
    }

    pub fn wildcard_ratio(s: &str) -> f64 {
        let total_chars = s.chars().count();
        if total_chars == 0 { return 0.0; }
        let count = s.chars().filter(|&c| c == '?').count();
        count as f64 / total_chars as f64
    }
}
