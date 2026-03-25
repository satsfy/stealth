/// Configurable thresholds for privacy vulnerability detection.
///
/// Each field controls a specific heuristic boundary used by one or
/// more detectors.  The [`Default`] implementation matches the values
/// that were previously hard-coded in `detect.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorThresholds {
    /// Amount (in satoshis) at or below which a UTXO is considered dust.
    pub dust_sats: u64,
    /// Strict dust boundary (Bitcoin Core relay minimum).
    pub strict_dust_sats: u64,
    /// Minimum satoshi value to be considered a "normal" input
    /// (used in dust-spending detection).
    pub normal_input_min_sats: u64,
    /// Minimum number of inputs for a transaction to be flagged as a
    /// consolidation.
    pub consolidation_min_inputs: usize,
    /// Maximum number of outputs for a consolidation transaction.
    pub consolidation_max_outputs: usize,
    /// Number of confirmation blocks after which a UTXO is considered
    /// dormant.
    pub dormant_utxo_blocks: i64,
    /// Number of outputs required for a transaction to look like an
    /// exchange batch withdrawal.
    pub exchange_batch_min_outputs: usize,
    /// Minimum number of outputs in a transaction to even be
    /// considered for dust-attack analysis.
    pub dust_attack_min_outputs: usize,
    /// Minimum dust outputs in a single transaction required for a
    /// dust-attack finding.
    pub dust_attack_min_dust_outputs: usize,
    /// Upper satoshi bound for toxic-change detection.
    pub toxic_change_upper_sats: u64,
}

impl Default for DetectorThresholds {
    fn default() -> Self {
        Self {
            dust_sats: 1_000,
            strict_dust_sats: 546,
            normal_input_min_sats: 10_000,
            consolidation_min_inputs: 3,
            consolidation_max_outputs: 2,
            dormant_utxo_blocks: 100,
            exchange_batch_min_outputs: 5,
            dust_attack_min_outputs: 10,
            dust_attack_min_dust_outputs: 5,
            toxic_change_upper_sats: 10_000,
        }
    }
}
