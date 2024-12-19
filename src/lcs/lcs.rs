use std::cmp::{max, Ordering};
use std::collections::HashMap;

pub struct FuzzyLCS<'a> {
    s1: &'a str,
    s2: &'a str,
}

impl<'a> FuzzyLCS<'a> {
    pub fn new(s1: &'a str, s2: &'a str) -> Self {
        FuzzyLCS { s1, s2 }
    }

    pub fn compare(
        &self,
        threshold: f64,
        max_results: usize,
        min_length: usize,
        wildcard_ratio: f64,
    ) -> Vec<(f64, String)> {
        let a: Vec<char> = self.s1.chars().collect();
        let b: Vec<char> = self.s2.chars().collect();
        let a_len = a.len();
        let b_len = b.len();

        let mut unique_matches: HashMap<String, f64> = HashMap::new();

        for start in 0..b_len {
            for end in (start + 1)..=b_len {
                let substring = &self.s2[start..end];

                if substring.len() < min_length {
                    continue;
                }

                if Self::wildcard_ratio(substring) > wildcard_ratio {
                    continue;
                }

                let substring_chars: Vec<char> = substring.chars().collect();
                let sub_len = substring_chars.len();

                let mut dp = vec![vec![0; sub_len + 1]; a_len + 1];

                for i in 1..=a_len {
                    for j in 1..=sub_len {
                        if a[i - 1] == substring_chars[j - 1] {
                            dp[i][j] = dp[i - 1][j - 1] + 1;
                        } else {
                            dp[i][j] = max(dp[i - 1][j], dp[i][j - 1]);
                        }
                    }
                }

                let lcs_length = dp[a_len][sub_len];
                let score = lcs_length as f64 / a_len.max(sub_len) as f64;

                if score >= threshold && lcs_length > 0 {
                    let mut lcs = String::new();
                    let (mut i, mut j) = (a_len, sub_len);

                    while i > 0 && j > 0 {
                        if a[i - 1] == substring_chars[j - 1] {
                            lcs.push(a[i - 1]);
                            i -= 1;
                            j -= 1;
                        } else if dp[i - 1][j] > dp[i][j - 1] {
                            i -= 1;
                        } else {
                            j -= 1;
                        }
                    }

                    lcs = lcs.chars().rev().collect::<String>();

                    if let Some(existing_score) = unique_matches.get(&lcs) {
                        if score > *existing_score {
                            unique_matches.insert(lcs, score);
                        }
                    } else {
                        unique_matches.insert(lcs, score);
                    }
                }
            }
        }

        let mut matches: Vec<(f64, String)> = unique_matches.into_iter()
            .map(|(lcs, score)| (score, lcs))
            .collect();

        matches.sort_by(|a, b| {
            b.0.partial_cmp(&a.0).unwrap_or(Ordering::Equal)
                .then_with(|| b.1.len().cmp(&a.1.len()))
        });

        matches.truncate(max_results);

        matches
    }

    pub fn wildcard_ratio(s: &str) -> f64 {
        let total_chars = s.chars().count();
        if total_chars == 0 {
            return 0.0;
        }
        let count = s.chars().filter(|&c| c == '?').count();
        count as f64 / total_chars as f64
    }
}
