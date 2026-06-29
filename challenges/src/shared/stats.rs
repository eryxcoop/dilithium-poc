//! Small numeric formatting helpers for classroom transcripts.

/// Returns the first `count` values rounded to two decimals.
pub fn rounded_prefix(values: &[f64], count: usize) -> Vec<f64> {
    values
        .iter()
        .take(count)
        .map(|value| (value * 100.0).round() / 100.0)
        .collect()
}
