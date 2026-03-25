//! Canonical analysis pipeline.
//!
//! [`AnalysisEngine`] is the primary entry point for running a privacy
//! scan.  It accepts a [`BlockchainGateway`] for data access and routes
//! every scan request through the shared gateway abstraction, ensuring a
//! single execution path for HTTP, CLI, and library consumers.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::config::AnalysisConfig;
use crate::descriptor::normalize_descriptors;
use crate::error::AnalysisError;
use crate::gateway::{
    BlockchainGateway, DecodedTransaction, DescriptorType, Utxo, WalletHistory, WalletTxCategory,
    WalletTxEntry,
};
use crate::graph::TxGraph;
use crate::types::Report;

/// Adapter so that a `&dyn BlockchainGateway` can be passed where a
/// `&dyn DescriptorNormalizer` is expected (trait-object upcasting is
/// not available for blanket impls).
struct GatewayNormalizer<'a>(&'a dyn BlockchainGateway);

impl crate::descriptor::DescriptorNormalizer for GatewayNormalizer<'_> {
    fn normalize(&self, descriptor: &str) -> Result<String, AnalysisError> {
        self.0.normalize_descriptor(descriptor)
    }
}

// ── Input types ─────────────────────────────────────────────────────────────

/// What to scan.
#[derive(Debug, Clone)]
pub enum ScanTarget {
    Descriptor(String),
    Descriptors(Vec<String>),
    Utxos(Vec<UtxoInput>),
}

/// A raw UTXO to analyse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoInput {
    pub txid: String,
    pub vout: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_sats: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

// ── Engine settings ─────────────────────────────────────────────────────────

/// Top-level settings for [`AnalysisEngine`], combining detector config
/// with optional known-wallet hooks used by taint and exchange detectors.
#[derive(Debug, Clone)]
pub struct EngineSettings {
    pub config: AnalysisConfig,
    pub known_risky_txids: Option<HashSet<String>>,
    pub known_exchange_txids: Option<HashSet<String>>,
}

impl Default for EngineSettings {
    fn default() -> Self {
        Self {
            config: AnalysisConfig::default(),
            known_risky_txids: None,
            known_exchange_txids: None,
        }
    }
}

// ── Engine ──────────────────────────────────────────────────────────────────

/// Runs a privacy analysis through a [`BlockchainGateway`].
///
/// Construct one per request (or per CLI invocation) and call
/// [`analyze`](Self::analyze).
pub struct AnalysisEngine<'a> {
    gateway: &'a dyn BlockchainGateway,
    settings: EngineSettings,
}

impl std::fmt::Debug for AnalysisEngine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisEngine")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl<'a> AnalysisEngine<'a> {
    pub fn new(gateway: &'a dyn BlockchainGateway, settings: EngineSettings) -> Self {
        Self { gateway, settings }
    }

    /// Run a full privacy scan for the given target.
    pub fn analyze(&self, target: ScanTarget) -> Result<Report, AnalysisError> {
        match target {
            ScanTarget::Descriptor(d) => self.analyze_descriptors(vec![d]),
            ScanTarget::Descriptors(ds) => self.analyze_descriptors(ds),
            ScanTarget::Utxos(utxos) => self.analyze_utxos(utxos),
        }
    }

    // ── descriptor path ─────────────────────────────────────────────────

    fn analyze_descriptors(&self, raw_descriptors: Vec<String>) -> Result<Report, AnalysisError> {
        let normalizer = GatewayNormalizer(self.gateway);
        let resolved = normalize_descriptors(
            &raw_descriptors,
            self.settings.config.derivation_range_end,
            &normalizer,
        )?;
        let history = self.gateway.scan_descriptors(&resolved)?;
        let mut graph = TxGraph::from_wallet_history(history);
        Ok(graph.detect_all(
            self.settings.known_risky_txids.as_ref(),
            self.settings.known_exchange_txids.as_ref(),
        ))
    }

    // ── UTXO path ───────────────────────────────────────────────────────

    fn analyze_utxos(&self, utxos: Vec<UtxoInput>) -> Result<Report, AnalysisError> {
        let history = self.resolve_utxo_history(&utxos)?;
        let mut graph = TxGraph::from_wallet_history(history);
        Ok(graph.detect_all(
            self.settings.known_risky_txids.as_ref(),
            self.settings.known_exchange_txids.as_ref(),
        ))
    }

    /// Build a [`WalletHistory`] from raw UTXO inputs by fetching the
    /// referenced transactions (and their parents) through the gateway.
    fn resolve_utxo_history(&self, utxos: &[UtxoInput]) -> Result<WalletHistory, AnalysisError> {
        let mut wallet_txs = Vec::new();
        let mut utxo_entries = Vec::new();
        let mut transactions: HashMap<String, DecodedTransaction> = HashMap::new();
        let mut fetch_queue: Vec<String> = Vec::new();

        for utxo in utxos {
            // Fetch the UTXO's parent transaction.
            if !transactions.contains_key(&utxo.txid) {
                let tx = self.gateway.get_transaction(&utxo.txid)?;
                fetch_queue.extend(
                    tx.vin
                        .iter()
                        .filter(|i| !i.coinbase)
                        .map(|i| i.previous_txid.clone()),
                );
                transactions.insert(utxo.txid.clone(), tx);
            }

            let tx = &transactions[&utxo.txid];

            let address = utxo
                .address
                .clone()
                .or_else(|| {
                    tx.vout
                        .iter()
                        .find(|o| o.n == utxo.vout)
                        .map(|o| o.address.clone())
                })
                .unwrap_or_default();

            let value = utxo.value_sats.map(|s| s as f64 / 1e8).unwrap_or_else(|| {
                tx.vout
                    .iter()
                    .find(|o| o.n == utxo.vout)
                    .map(|o| o.value_btc)
                    .unwrap_or(0.0)
            });

            if !address.is_empty() {
                wallet_txs.push(WalletTxEntry {
                    txid: utxo.txid.clone(),
                    address: address.clone(),
                    category: WalletTxCategory::Receive,
                    amount_btc: value,
                    confirmations: 0,
                    blockheight: 0,
                });
            }

            utxo_entries.push(Utxo {
                txid: utxo.txid.clone(),
                vout: utxo.vout,
                address,
                amount_btc: value,
                confirmations: 0,
                script_type: DescriptorType::Unknown,
            });
        }

        // Fetch ancestor transactions for input resolution.
        while let Some(txid) = fetch_queue.pop() {
            if transactions.contains_key(&txid) {
                continue;
            }
            if let Ok(tx) = self.gateway.get_transaction(&txid) {
                fetch_queue.extend(
                    tx.vin
                        .iter()
                        .filter(|i| !i.coinbase)
                        .map(|i| i.previous_txid.clone()),
                );
                transactions.insert(txid, tx);
            }
        }

        Ok(WalletHistory {
            wallet_txs,
            utxos: utxo_entries,
            transactions,
        })
    }
}
