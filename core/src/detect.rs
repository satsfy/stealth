use std::collections::{HashMap, HashSet};

use serde_json::json;

use crate::graph::TxGraph;
use crate::types::*;

impl TxGraph {
    /// Run all 12 vulnerability detectors and produce a [`Report`].
    ///
    /// Optionally pass sets of known-risky and known-exchange transaction IDs
    /// to enable taint analysis (detector 11) and exchange-origin detection
    /// (detector 10).
    pub fn detect_all(
        &mut self,
        known_risky_txids: Option<&HashSet<String>>,
        known_exchange_txids: Option<&HashSet<String>>,
    ) -> Report {
        let mut findings = Vec::new();
        let mut warnings = Vec::new();

        self.detect_address_reuse(&mut findings);
        self.detect_cioh(&mut findings);
        self.detect_dust(&mut findings);
        self.detect_dust_spending(&mut findings);
        self.detect_change_detection(&mut findings);
        self.detect_consolidation_origin(&mut findings);
        self.detect_script_type_mixing(&mut findings);
        self.detect_cluster_merge(&mut findings);
        self.detect_lookback_depth(&mut findings, &mut warnings);
        self.detect_exchange_origin(&mut findings, known_exchange_txids);
        self.detect_tainted_utxos(&mut findings, &mut warnings, known_risky_txids);
        self.detect_behavioral_fingerprint(&mut findings);

        let stats = Stats {
            transactions_analyzed: self.our_txids.len(),
            addresses_derived: self.addr_map.len(),
            utxos_current: self.utxos.len(),
        };

        Report::new(stats, findings, warnings)
    }

    // ── 1. Address Reuse ───────────────────────────────────────────────────

    fn detect_address_reuse(&mut self, findings: &mut Vec<Finding>) {
        for addr in self.our_addrs.clone() {
            let entries = match self.addr_txs.get(&addr) {
                Some(e) => e,
                None => continue,
            };
            let receive_txids: HashSet<&str> = entries
                .iter()
                .filter(|e| e.category == "receive")
                .filter_map(|e| {
                    if e.txid.is_empty() {
                        None
                    } else {
                        Some(e.txid.as_str())
                    }
                })
                .collect();

            if receive_txids.len() >= 2 {
                let meta = self.addr_map.get(&addr);
                let role = if meta.map_or(false, |m| m.internal) {
                    "change"
                } else {
                    "receive"
                };
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::AddressReuse,
                    severity: Severity::High,
                    description: format!(
                        "Address {} ({}) reused across {} transactions",
                        addr,
                        role,
                        receive_txids.len()
                    ),
                    details: Some(json!({
                        "address": addr,
                        "role": role,
                        "tx_count": receive_txids.len(),
                        "txids": receive_txids.iter().collect::<Vec<_>>(),
                    })),
                    correction: Some(
                        "Generate a fresh address for every payment received. \
                         Enable HD wallet derivation (BIP-32/44/84) so your wallet \
                         produces a new address automatically."
                            .into(),
                    ),
                });
            }
        }
    }

    // ── 2. Common Input Ownership Heuristic (CIOH) ─────────────────────────

    fn detect_cioh(&mut self, findings: &mut Vec<Finding>) {
        let txids: Vec<String> = self.our_txids.iter().cloned().collect();
        for txid in &txids {
            let tx = match self.fetch_tx(txid) {
                Some(t) => t,
                None => continue,
            };
            let vin_count = tx
                .get("vin")
                .and_then(|v| v.as_array())
                .map_or(0, |a| a.len());
            if vin_count < 2 {
                continue;
            }

            let input_addrs = self.get_input_addresses(txid);
            if input_addrs.len() < 2 {
                continue;
            }

            let our_inputs: Vec<_> = input_addrs
                .iter()
                .filter(|ia| self.is_ours(&ia.address))
                .collect();
            if our_inputs.len() < 2 {
                continue;
            }

            let total_inputs = input_addrs.len();
            let n_ours = our_inputs.len();
            let ownership_pct = (n_ours as f64 / total_inputs as f64 * 100.0).round() as u32;

            let severity = if n_ours == total_inputs {
                Severity::Critical
            } else {
                Severity::High
            };

            findings.push(Finding {
                vulnerability_type: VulnerabilityType::Cioh,
                severity,
                description: format!(
                    "TX {} merges {}/{} of your inputs ({}% ownership)",
                    txid, n_ours, total_inputs, ownership_pct
                ),
                details: Some(json!({
                    "txid": txid,
                    "total_inputs": total_inputs,
                    "our_inputs": n_ours,
                    "ownership_pct": ownership_pct,
                })),
                correction: Some(
                    "Use coin control to select only one UTXO per transaction. \
                     If consolidation is unavoidable, do it privately via a CoinJoin round."
                        .into(),
                ),
            });
        }
    }

    // ── 3. Dust UTXO Detection ─────────────────────────────────────────────

    fn detect_dust(&mut self, findings: &mut Vec<Finding>) {
        const DUST_SATS: u64 = 1000;
        const STRICT_DUST: u64 = 546;

        // Current UTXOs
        let utxos = self.utxos.clone();
        for utxo in &utxos {
            if !self.is_ours(&utxo.address) {
                continue;
            }
            let sats = (utxo.amount * 1e8).round() as u64;
            if sats <= DUST_SATS {
                let label = if sats <= STRICT_DUST {
                    "STRICT_DUST"
                } else {
                    "dust-class"
                };
                let severity = if sats <= STRICT_DUST {
                    Severity::High
                } else {
                    Severity::Medium
                };
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::Dust,
                    severity,
                    description: format!(
                        "Dust UTXO at {} ({} sats, {}, unspent)",
                        utxo.address, sats, label
                    ),
                    details: Some(json!({
                        "status": "unspent",
                        "address": utxo.address,
                        "sats": sats,
                        "label": label,
                        "txid": utxo.txid,
                        "vout": utxo.vout,
                    })),
                    correction: Some(
                        "Do not spend this dust output — doing so links your other inputs \
                         to this address via CIOH. Use your wallet's coin freeze feature to \
                         exclude it from future transactions."
                            .into(),
                    ),
                });
            }
        }

        // Historical dust (already spent)
        let txids: Vec<String> = self.our_txids.iter().cloned().collect();
        let current_keys: HashSet<(String, String)> = utxos
            .iter()
            .map(|u| (u.txid.clone(), u.address.clone()))
            .collect();
        let mut seen = HashSet::new();
        for txid in &txids {
            let outputs = self.get_output_addresses(txid);
            for out in &outputs {
                let sats = (out.value * 1e8).round() as u64;
                if sats <= DUST_SATS && self.is_ours(&out.address) {
                    let key = (txid.clone(), out.address.clone());
                    if !current_keys.contains(&key) && seen.insert(key) {
                        findings.push(Finding {
                            vulnerability_type: VulnerabilityType::Dust,
                            severity: Severity::Low,
                            description: format!(
                                "Historical dust output at {} ({} sats, already spent)",
                                out.address, sats
                            ),
                            details: Some(json!({
                                "status": "spent",
                                "address": out.address,
                                "sats": sats,
                                "txid": txid,
                            })),
                            correction: Some(
                                "This dust has already been spent. Going forward, reject \
                                 unsolicited dust by enabling automatic dust rejection."
                                    .into(),
                            ),
                        });
                    }
                }
            }
        }
    }

    // ── 4. Dust Spent with Normal Inputs ───────────────────────────────────

    fn detect_dust_spending(&mut self, findings: &mut Vec<Finding>) {
        const DUST_SATS: u64 = 1000;

        let txids: Vec<String> = self.our_txids.iter().cloned().collect();
        for txid in &txids {
            let input_addrs = self.get_input_addresses(txid);
            if input_addrs.len() < 2 {
                continue;
            }

            let mut dust_inputs = Vec::new();
            let mut normal_inputs = Vec::new();
            for ia in &input_addrs {
                if !self.is_ours(&ia.address) {
                    continue;
                }
                let sats = (ia.value * 1e8).round() as u64;
                if sats <= DUST_SATS {
                    dust_inputs.push(ia);
                } else if sats > 10_000 {
                    normal_inputs.push(ia);
                }
            }

            if !dust_inputs.is_empty() && !normal_inputs.is_empty() {
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::DustSpending,
                    severity: Severity::High,
                    description: format!(
                        "TX {} spends {} dust input(s) alongside {} normal input(s)",
                        txid,
                        dust_inputs.len(),
                        normal_inputs.len()
                    ),
                    details: Some(json!({
                        "txid": txid,
                        "dust_inputs": dust_inputs.iter().map(|d| {
                            json!({"address": d.address, "sats": (d.value * 1e8).round() as u64})
                        }).collect::<Vec<_>>(),
                        "normal_inputs": normal_inputs.iter().map(|n| {
                            json!({"address": n.address, "amount_btc": n.value})
                        }).collect::<Vec<_>>(),
                    })),
                    correction: Some(
                        "Freeze dust UTXOs in your wallet to prevent them from being \
                         automatically selected as inputs."
                            .into(),
                    ),
                });
            }
        }
    }

    // ── 5. Change Detection ────────────────────────────────────────────────

    fn detect_change_detection(&mut self, findings: &mut Vec<Finding>) {
        let txids: Vec<String> = self.our_txids.iter().cloned().collect();
        for txid in &txids {
            let outputs = self.get_output_addresses(txid);
            if outputs.len() < 2 {
                continue;
            }
            let input_addrs = self.get_input_addresses(txid);
            let our_in: Vec<_> = input_addrs
                .iter()
                .filter(|ia| self.is_ours(&ia.address))
                .collect();
            if our_in.is_empty() {
                continue;
            }

            let our_outs: Vec<_> = outputs
                .iter()
                .filter(|o| self.is_ours(&o.address))
                .collect();
            let ext_outs: Vec<_> = outputs
                .iter()
                .filter(|o| !self.is_ours(&o.address))
                .collect();
            if our_outs.is_empty() || ext_outs.is_empty() {
                continue;
            }

            let mut problems = Vec::new();
            for change in &our_outs {
                let ch_sats = (change.value * 1e8).round() as u64;
                let ch_round = ch_sats % 100_000 == 0 || ch_sats % 1_000_000 == 0;

                for payment in &ext_outs {
                    let pay_sats = (payment.value * 1e8).round() as u64;
                    let pay_round = pay_sats % 100_000 == 0 || pay_sats % 1_000_000 == 0;

                    if pay_round && !ch_round {
                        problems.push(format!(
                            "Round payment ({} sats) vs non-round change ({} sats)",
                            pay_sats, ch_sats
                        ));
                    }

                    let in_types: HashSet<String> = our_in
                        .iter()
                        .map(|ia| self.script_type(&ia.address))
                        .collect();
                    let ch_type = self.script_type(&change.address);
                    if in_types.contains(&ch_type) && change.script_type != payment.script_type {
                        problems.push(format!(
                            "Change script type ({}) matches input type — different from payment ({})",
                            change.script_type, payment.script_type
                        ));
                    }

                    if let Some(meta) = self.addr_map.get(&change.address) {
                        if meta.internal {
                            problems.push(
                                "Change uses an internal (BIP-44 /1/*) derivation path".into(),
                            );
                        }
                    }
                }
            }

            if !problems.is_empty() {
                problems.truncate(6);
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::ChangeDetection,
                    severity: Severity::Medium,
                    description: format!(
                        "TX {} has identifiable change output(s) ({} heuristic(s) matched)",
                        txid,
                        problems.len()
                    ),
                    details: Some(json!({
                        "txid": txid,
                        "reasons": problems,
                    })),
                    correction: Some(
                        "Use PayJoin (BIP-78) so the receiver also contributes an input. \
                         Avoid sending round amounts so the change amount is not the obvious leftover."
                            .into(),
                    ),
                });
            }
        }
    }

    // ── 6. Consolidation Origin ────────────────────────────────────────────

    fn detect_consolidation_origin(&mut self, findings: &mut Vec<Finding>) {
        const CONSOLIDATION_THRESHOLD: usize = 3;

        let utxos = self.utxos.clone();
        for utxo in &utxos {
            if !self.is_ours(&utxo.address) {
                continue;
            }
            let parent = match self.fetch_tx(&utxo.txid) {
                Some(t) => t,
                None => continue,
            };
            let n_in = parent
                .get("vin")
                .and_then(|v| v.as_array())
                .map_or(0, |a| a.len());
            let n_out = parent
                .get("vout")
                .and_then(|v| v.as_array())
                .map_or(0, |a| a.len());

            if n_in >= CONSOLIDATION_THRESHOLD && n_out <= 2 {
                let parent_inputs = self.get_input_addresses(&utxo.txid);
                let our_parent_in = parent_inputs
                    .iter()
                    .filter(|ia| self.is_ours(&ia.address))
                    .count();

                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::Consolidation,
                    severity: Severity::Medium,
                    description: format!(
                        "UTXO {}:{} ({:.8} BTC) born from a {}-input consolidation",
                        utxo.txid, utxo.vout, utxo.amount, n_in
                    ),
                    details: Some(json!({
                        "txid": utxo.txid,
                        "vout": utxo.vout,
                        "amount_btc": utxo.amount,
                        "consolidation_inputs": n_in,
                        "consolidation_outputs": n_out,
                        "our_inputs_in_consolidation": our_parent_in,
                    })),
                    correction: Some(
                        "Avoid consolidating many UTXOs into one in a single transaction. \
                         If fee savings require consolidation, do it through a CoinJoin."
                            .into(),
                    ),
                });
            }
        }
    }

    // ── 7. Script Type Mixing ──────────────────────────────────────────────

    fn detect_script_type_mixing(&mut self, findings: &mut Vec<Finding>) {
        let txids: Vec<String> = self.our_txids.iter().cloned().collect();
        for txid in &txids {
            let input_addrs = self.get_input_addresses(txid);
            if input_addrs.len() < 2 {
                continue;
            }
            let our_in: Vec<_> = input_addrs
                .iter()
                .filter(|ia| self.is_ours(&ia.address))
                .collect();
            if our_in.len() < 2 {
                continue;
            }

            let mut types: HashSet<String> = HashSet::new();
            for ia in &input_addrs {
                let t = self.script_type(&ia.address);
                if t != "unknown" {
                    types.insert(t);
                }
            }

            if types.len() >= 2 {
                let mut sorted: Vec<String> = types.into_iter().collect();
                sorted.sort();
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::ScriptTypeMixing,
                    severity: Severity::High,
                    description: format!("TX {} mixes input script types: {:?}", txid, sorted),
                    details: Some(json!({
                        "txid": txid,
                        "script_types": sorted,
                    })),
                    correction: Some(
                        "Migrate all funds to a single address type — preferably Taproot (P2TR). \
                         Never mix P2PKH, P2SH-P2WPKH, P2WPKH, and P2TR inputs in the same transaction."
                            .into(),
                    ),
                });
            }
        }
    }

    // ── 8. Cluster Merge ───────────────────────────────────────────────────

    fn detect_cluster_merge(&mut self, findings: &mut Vec<Finding>) {
        let txids: Vec<String> = self.our_txids.iter().cloned().collect();
        for txid in &txids {
            let input_addrs = self.get_input_addresses(txid);
            if input_addrs.len() < 2 {
                continue;
            }
            let our_in: Vec<_> = input_addrs
                .iter()
                .filter(|ia| self.is_ours(&ia.address))
                .collect();
            if our_in.len() < 2 {
                continue;
            }

            // Trace each input one hop back to find funding sources.
            let mut funding_sources: HashMap<String, HashSet<String>> = HashMap::new();
            for ia in &our_in {
                let parent_tx = match self.fetch_tx(&ia.funding_txid) {
                    Some(t) => t,
                    None => continue,
                };
                let mut gp_sources = HashSet::new();
                if let Some(vins) = parent_tx.get("vin").and_then(|v| v.as_array()) {
                    for p_vin in vins {
                        if p_vin.get("coinbase").is_some() {
                            gp_sources.insert("coinbase".into());
                        } else if let Some(ptxid) = p_vin.get("txid").and_then(|v| v.as_str()) {
                            gp_sources.insert(ptxid[..16.min(ptxid.len())].to_string());
                        }
                    }
                }
                let key = format!(
                    "{}:{}",
                    &ia.funding_txid[..16.min(ia.funding_txid.len())],
                    ia.funding_vout
                );
                funding_sources.insert(key, gp_sources);
            }

            let all_sources: Vec<&HashSet<String>> = funding_sources.values().collect();
            if all_sources.len() >= 2 {
                let mut merged = false;
                'outer: for i in 0..all_sources.len() {
                    for j in (i + 1)..all_sources.len() {
                        if all_sources[i].is_disjoint(all_sources[j]) {
                            merged = true;
                            break 'outer;
                        }
                    }
                }

                if merged {
                    findings.push(Finding {
                        vulnerability_type: VulnerabilityType::ClusterMerge,
                        severity: Severity::High,
                        description: format!(
                            "TX {} merges UTXOs from {} different funding chains",
                            txid,
                            funding_sources.len()
                        ),
                        details: Some(json!({
                            "txid": txid,
                            "funding_sources": funding_sources.iter()
                                .map(|(k, v)| (k.clone(), v.iter().cloned().collect::<Vec<_>>()))
                                .collect::<HashMap<_, _>>(),
                        })),
                        correction: Some(
                            "Use coin control to spend UTXOs from only one funding source \
                             per transaction. Keep UTXOs received from different counterparties \
                             in separate wallets."
                                .into(),
                        ),
                    });
                }
            }
        }
    }

    // ── 9. Lookback Depth / UTXO Age ───────────────────────────────────────

    fn detect_lookback_depth(&mut self, findings: &mut Vec<Finding>, warnings: &mut Vec<Finding>) {
        let our_utxos: Vec<_> = self
            .utxos
            .iter()
            .filter(|u| self.is_ours(&u.address))
            .cloned()
            .collect();
        if our_utxos.len() < 2 {
            return;
        }

        let mut aged: Vec<_> = our_utxos.iter().map(|u| (u, u.confirmations)).collect();
        aged.sort_by(|a, b| b.1.cmp(&a.1));

        let oldest = aged.first().unwrap();
        let newest = aged.last().unwrap();
        let spread = oldest.1 - newest.1;

        if spread < 10 {
            return;
        }

        findings.push(Finding {
            vulnerability_type: VulnerabilityType::UtxoAgeSpread,
            severity: Severity::Low,
            description: format!(
                "UTXO age spread of {} blocks between oldest and newest",
                spread
            ),
            details: Some(json!({
                "spread_blocks": spread,
                "oldest": {
                    "txid": oldest.0.txid,
                    "confirmations": oldest.1,
                    "amount_btc": oldest.0.amount,
                },
                "newest": {
                    "txid": newest.0.txid,
                    "confirmations": newest.1,
                    "amount_btc": newest.0.amount,
                },
            })),
            correction: Some(
                "Prefer spending older UTXOs first (FIFO coin selection) to normalize \
                 the age distribution of your UTXO set."
                    .into(),
            ),
        });

        const OLD_THRESHOLD: i64 = 100;
        let old_count = aged.iter().filter(|(_, c)| *c >= OLD_THRESHOLD).count();
        if old_count > 0 {
            warnings.push(Finding {
                vulnerability_type: VulnerabilityType::DormantUtxos,
                severity: Severity::Low,
                description: format!(
                    "{} UTXO(s) have ≥{} confirmations (dormant/hoarded coins pattern)",
                    old_count, OLD_THRESHOLD
                ),
                details: Some(json!({
                    "count": old_count,
                    "threshold_blocks": OLD_THRESHOLD,
                })),
                correction: None,
            });
        }
    }

    // ── 10. Exchange Origin ────────────────────────────────────────────────

    fn detect_exchange_origin(
        &mut self,
        findings: &mut Vec<Finding>,
        known_exchange_txids: Option<&HashSet<String>>,
    ) {
        const BATCH_THRESHOLD: usize = 5;

        let txids: Vec<String> = self.our_txids.iter().cloned().collect();
        for txid in &txids {
            let tx = match self.fetch_tx(txid) {
                Some(t) => t,
                None => continue,
            };
            let n_out = tx
                .get("vout")
                .and_then(|v| v.as_array())
                .map_or(0, |a| a.len());
            if n_out < BATCH_THRESHOLD {
                continue;
            }

            let input_addrs = self.get_input_addresses(txid);
            let our_inputs: Vec<_> = input_addrs
                .iter()
                .filter(|ia| self.is_ours(&ia.address))
                .collect();
            if !our_inputs.is_empty() {
                continue; // We're a sender, not a recipient.
            }

            let our_outputs: Vec<_> = self
                .get_output_addresses(txid)
                .into_iter()
                .filter(|o| self.is_ours(&o.address))
                .collect();
            if our_outputs.is_empty() {
                continue;
            }

            let mut signals = vec![format!("High output count: {}", n_out)];

            if let Some(vouts) = tx.get("vout").and_then(|v| v.as_array()) {
                let unique_addrs: HashSet<&str> = vouts
                    .iter()
                    .filter_map(|v| v.pointer("/scriptPubKey/address").and_then(|a| a.as_str()))
                    .collect();
                if unique_addrs.len() >= BATCH_THRESHOLD {
                    signals.push(format!("{} unique recipient addresses", unique_addrs.len()));
                }
            }

            if let Some(exchange_txids) = known_exchange_txids {
                if exchange_txids.contains(txid.as_str()) {
                    signals.push("TX matches known exchange wallet history".into());
                }
            }

            if signals.len() >= 2 {
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::ExchangeOrigin,
                    severity: Severity::Medium,
                    description: format!(
                        "TX {} looks like an exchange batch withdrawal ({} signal(s))",
                        txid,
                        signals.len()
                    ),
                    details: Some(json!({
                        "txid": txid,
                        "signals": signals,
                        "received_outputs": our_outputs.iter().map(|o| {
                            json!({"address": o.address, "amount_btc": o.value})
                        }).collect::<Vec<_>>(),
                    })),
                    correction: Some(
                        "Withdraw via Lightning Network to avoid the exchange-origin fingerprint. \
                         After withdrawal, pass the UTXO through a CoinJoin."
                            .into(),
                    ),
                });
            }
        }
    }

    // ── 11. Tainted UTXOs ──────────────────────────────────────────────────

    fn detect_tainted_utxos(
        &mut self,
        findings: &mut Vec<Finding>,
        warnings: &mut Vec<Finding>,
        known_risky_txids: Option<&HashSet<String>>,
    ) {
        let risky_txids = match known_risky_txids {
            Some(t) if !t.is_empty() => t,
            _ => return,
        };

        let txids: Vec<String> = self.our_txids.iter().cloned().collect();

        for txid in &txids {
            let input_addrs = self.get_input_addresses(txid);
            let our_in: Vec<_> = input_addrs
                .iter()
                .filter(|ia| self.is_ours(&ia.address))
                .collect();
            if our_in.is_empty() || input_addrs.len() < 2 {
                continue;
            }

            let tainted: Vec<_> = input_addrs
                .iter()
                .filter(|ia| risky_txids.contains(&ia.funding_txid))
                .collect();
            let clean: Vec<_> = input_addrs
                .iter()
                .filter(|ia| !risky_txids.contains(&ia.funding_txid))
                .collect();

            if !tainted.is_empty() && !clean.is_empty() {
                let taint_pct =
                    (tainted.len() as f64 / input_addrs.len() as f64 * 100.0).round() as u32;
                findings.push(Finding {
                    vulnerability_type: VulnerabilityType::TaintedUtxoMerge,
                    severity: Severity::High,
                    description: format!(
                        "TX {} merges {} tainted + {} clean inputs ({}% taint)",
                        txid,
                        tainted.len(),
                        clean.len(),
                        taint_pct
                    ),
                    details: Some(json!({
                        "txid": txid,
                        "tainted_inputs": tainted.iter().map(|t| {
                            json!({"address": t.address, "amount_btc": t.value, "source_txid": t.funding_txid})
                        }).collect::<Vec<_>>(),
                        "clean_inputs": clean.iter().map(|c| {
                            json!({"address": c.address, "amount_btc": c.value})
                        }).collect::<Vec<_>>(),
                        "taint_pct": taint_pct,
                    })),
                    correction: Some(
                        "Freeze tainted UTXOs to prevent them from being spent alongside \
                         clean funds. Never merge inputs from known risky sources."
                            .into(),
                    ),
                });
            }
        }

        // Direct taint: we received directly from a risky source.
        for txid in &txids {
            if risky_txids.contains(txid.as_str()) {
                let our_outs: Vec<_> = self
                    .get_output_addresses(txid)
                    .into_iter()
                    .filter(|o| self.is_ours(&o.address))
                    .collect();
                if !our_outs.is_empty() {
                    warnings.push(Finding {
                        vulnerability_type: VulnerabilityType::DirectTaint,
                        severity: Severity::High,
                        description: format!("TX {} is directly from a known risky source", txid),
                        details: Some(json!({
                            "txid": txid,
                            "received_outputs": our_outs.iter().map(|o| {
                                json!({"address": o.address, "amount_btc": o.value})
                            }).collect::<Vec<_>>(),
                        })),
                        correction: None,
                    });
                }
            }
        }
    }

    // ── 12. Behavioral Fingerprint ─────────────────────────────────────────

    fn detect_behavioral_fingerprint(&mut self, findings: &mut Vec<Finding>) {
        // Collect send transactions (where we have inputs).
        let txids: Vec<String> = self.our_txids.iter().cloned().collect();
        let mut send_txids = Vec::new();
        for txid in &txids {
            let input_addrs = self.get_input_addresses(txid);
            if input_addrs.iter().any(|ia| self.is_ours(&ia.address)) {
                send_txids.push(txid.clone());
            }
        }

        if send_txids.len() < 3 {
            return;
        }

        let mut output_counts = Vec::new();
        let mut input_script_types = Vec::new();
        let mut rbf_signals = Vec::new();
        let mut locktime_values = Vec::new();
        let mut fee_rates: Vec<f64> = Vec::new();
        let mut uses_round_amounts: usize = 0;
        let mut total_payments: usize = 0;

        for txid in &send_txids {
            let tx = match self.fetch_tx(txid) {
                Some(t) => t,
                None => continue,
            };

            let n_out = tx
                .get("vout")
                .and_then(|v| v.as_array())
                .map_or(0, |a| a.len());
            output_counts.push(n_out);

            locktime_values.push(tx.get("locktime").and_then(|v| v.as_u64()).unwrap_or(0));

            if let Some(vins) = tx.get("vin").and_then(|v| v.as_array()) {
                for vin in vins {
                    let seq = vin
                        .get("sequence")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0xffff_ffff);
                    rbf_signals.push(seq < 0xffff_fffe);
                }
            }

            let input_addrs = self.get_input_addresses(txid);
            for ia in &input_addrs {
                if self.is_ours(&ia.address) {
                    input_script_types.push(self.script_type(&ia.address));
                }
            }

            let outputs = self.get_output_addresses(txid);
            for out in &outputs {
                if !self.is_ours(&out.address) {
                    let sats = (out.value * 1e8).round() as u64;
                    total_payments += 1;
                    if sats > 0 && (sats % 100_000 == 0 || sats % 1_000_000 == 0) {
                        uses_round_amounts += 1;
                    }
                }
            }

            // Fee rate
            let vsize = tx.get("vsize").and_then(|v| v.as_u64()).unwrap_or(0);
            if vsize > 0 {
                let in_total: f64 = input_addrs.iter().map(|ia| ia.value).sum();
                let out_total: f64 = tx
                    .get("vout")
                    .and_then(|v| v.as_array())
                    .map_or(0.0, |arr| {
                        arr.iter()
                            .filter_map(|v| v.get("value").and_then(|val| val.as_f64()))
                            .sum()
                    });
                let fee_sats = ((in_total - out_total) * 1e8).round();
                if fee_sats > 0.0 {
                    fee_rates.push(fee_sats / vsize as f64);
                }
            }
        }

        let mut problems = Vec::new();

        // Round amount pattern
        if total_payments > 0 {
            let round_pct = uses_round_amounts as f64 / total_payments as f64 * 100.0;
            if round_pct > 60.0 {
                problems.push(format!(
                    "Round payment amounts: {:.0}% of payments are round numbers.",
                    round_pct
                ));
            }
        }

        // Uniform output count
        if output_counts.len() >= 3 && output_counts.iter().all(|&c| c == output_counts[0]) {
            problems.push(format!(
                "Uniform output count: all {} send TXs have exactly {} outputs.",
                output_counts.len(),
                output_counts[0]
            ));
        }

        // Script type consistency
        let input_types_set: HashSet<&String> = input_script_types.iter().collect();
        if input_types_set.len() > 1 {
            problems.push(format!(
                "Mixed input script types used across TXs: {:?}.",
                input_types_set
            ));
        }

        // RBF signaling
        if !rbf_signals.is_empty() {
            let rbf_pct = rbf_signals.iter().filter(|&&b| b).count() as f64
                / rbf_signals.len() as f64
                * 100.0;
            if rbf_pct == 100.0 {
                problems.push("RBF always enabled: 100% of inputs signal replace-by-fee.".into());
            } else if rbf_pct == 0.0 {
                problems.push("RBF never enabled: 0% of inputs signal replace-by-fee.".into());
            }
        }

        // Locktime pattern
        if locktime_values.len() >= 3 {
            let all_nonzero = locktime_values.iter().all(|&lt| lt > 0);
            let all_zero = locktime_values.iter().all(|&lt| lt == 0);
            if all_nonzero {
                problems.push(
                    "Anti-fee-sniping locktime always set — consistent with Bitcoin Core.".into(),
                );
            } else if all_zero {
                problems.push("Locktime always 0 — no anti-fee-sniping.".into());
            }
        }

        // Fee rate consistency
        if fee_rates.len() >= 3 {
            let avg: f64 = fee_rates.iter().sum::<f64>() / fee_rates.len() as f64;
            if avg > 0.0 {
                let variance: f64 = fee_rates.iter().map(|f| (f - avg).powi(2)).sum::<f64>()
                    / fee_rates.len() as f64;
                let stddev = variance.sqrt();
                let cv = stddev / avg;
                if cv < 0.15 {
                    problems.push(format!(
                        "Very consistent fee rate: avg {:.1} sat/vB ± {:.1} (CV={:.2}).",
                        avg, stddev, cv
                    ));
                }
            }
        }

        if problems.is_empty() {
            return;
        }

        findings.push(Finding {
            vulnerability_type: VulnerabilityType::BehavioralFingerprint,
            severity: Severity::Medium,
            description: format!(
                "Behavioral fingerprint detected across {} send transactions ({} pattern(s))",
                send_txids.len(),
                problems.len()
            ),
            details: Some(json!({
                "send_tx_count": send_txids.len(),
                "patterns": problems,
            })),
            correction: Some(
                "Switch to wallet software that applies anti-fingerprinting defaults. \
                 Avoid sending only round amounts — add small random satoshi offsets. \
                 Standardize on a single modern script type (Taproot)."
                    .into(),
            ),
        });
    }
}
