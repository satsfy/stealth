use std::collections::{HashMap, HashSet};

use corepc_client::client_sync::{v29::Client, Result as RpcResult};

use crate::types::{AddressInfo, InputInfo, OutputInfo, WalletTx};

/// Indexed view of all transactions touching a wallet's address set.
///
/// The graph lazily fetches and caches raw transactions from the RPC node
/// as detectors request input/output data for specific txids.
#[derive(Debug)]
pub struct TxGraph {
    /// Map of our addresses → metadata.
    pub addr_map: HashMap<String, AddressInfo>,
    /// All our addresses (quick lookup).
    pub our_addrs: HashSet<String>,
    /// Current UTXOs from `listunspent`.
    pub utxos: Vec<UtxoEntry>,
    /// Transaction IDs that touch our wallet.
    pub our_txids: HashSet<String>,
    /// Per-address transaction entries.
    pub addr_txs: HashMap<String, Vec<WalletTx>>,
    /// Per-txid set of our addresses involved.
    pub tx_addrs: HashMap<String, HashSet<String>>,

    /// Client reference for lazy tx fetches.
    client: Client,
    /// Cached decoded transactions (txid → JSON value).
    tx_cache: HashMap<String, serde_json::Value>,
    /// Cached input addresses per txid.
    input_cache: HashMap<String, Vec<InputInfo>>,
    /// Cached output addresses per txid.
    output_cache: HashMap<String, Vec<OutputInfo>>,
}

/// A UTXO entry from `listunspent`.
#[derive(Debug, Clone)]
pub struct UtxoEntry {
    pub txid: String,
    pub vout: u32,
    pub address: String,
    pub amount: f64,
    pub confirmations: i64,
}

impl TxGraph {
    /// Build a `TxGraph` by querying the RPC client for the wallet's
    /// full transaction history and current UTXO set.
    pub fn build(client: Client) -> RpcResult<Self> {
        // Get all transactions (listsinceblock includes change addresses)
        let list_txs = client.list_since_block()?;
        let wallet_txs: Vec<WalletTx> = list_txs
            .transactions
            .iter()
            .map(|item| WalletTx {
                txid: item.txid.clone(),
                address: item.address.clone().unwrap_or_default(),
                category: format!("{:?}", item.category).to_lowercase(),
                amount: item.amount,
                confirmations: item.confirmations,
            })
            .collect();

        // Get all UTXOs
        let list_unspent = client.list_unspent()?;
        let utxos: Vec<UtxoEntry> = list_unspent
            .0
            .iter()
            .map(|item| UtxoEntry {
                txid: item.txid.clone(),
                vout: item.vout as u32,
                address: item.address.clone(),
                amount: item.amount,
                confirmations: item.confirmations,
            })
            .collect();

        // Build indices
        let mut our_txids = HashSet::new();
        let mut addr_txs: HashMap<String, Vec<WalletTx>> = HashMap::new();
        let mut tx_addrs: HashMap<String, HashSet<String>> = HashMap::new();

        for wtx in &wallet_txs {
            if !wtx.txid.is_empty() {
                our_txids.insert(wtx.txid.clone());
            }
            if !wtx.address.is_empty() && !wtx.txid.is_empty() {
                addr_txs
                    .entry(wtx.address.clone())
                    .or_default()
                    .push(wtx.clone());
                tx_addrs
                    .entry(wtx.txid.clone())
                    .or_default()
                    .insert(wtx.address.clone());
            }
        }

        // Derive address map from UTXOs (basic — full descriptor resolution
        // would require importdescriptors support).
        let mut our_addrs = HashSet::new();
        let mut addr_map = HashMap::new();
        for utxo in &utxos {
            our_addrs.insert(utxo.address.clone());
            addr_map
                .entry(utxo.address.clone())
                .or_insert_with(|| AddressInfo {
                    script_type: script_type_from_address(&utxo.address),
                    internal: false,
                    index: 0,
                });
        }
        // Also include addresses seen in transaction history.
        // Only "receive" entries are our addresses; "send" entries have the
        // counterparty's destination address.
        for wtx in &wallet_txs {
            if !wtx.address.is_empty() && wtx.category != "send" {
                our_addrs.insert(wtx.address.clone());
                addr_map
                    .entry(wtx.address.clone())
                    .or_insert_with(|| AddressInfo {
                        script_type: script_type_from_address(&wtx.address),
                        internal: false,
                        index: 0,
                    });
            }
        }
        // list_since_block/list_transactions omit change addresses.
        // list_address_groupings includes ALL used addresses (including change).
        if let Ok(groupings) = client.list_address_groupings() {
            let json = serde_json::to_value(&groupings).unwrap_or_default();
            if let Some(groups) = json.as_array() {
                for group in groups {
                    if let Some(items) = group.as_array() {
                        for item in items {
                            let addr = item
                                .as_array()
                                .and_then(|a| a.first())
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            if !addr.is_empty() {
                                our_addrs.insert(addr.to_string());
                                addr_map
                                    .entry(addr.to_string())
                                    .or_insert_with(|| AddressInfo {
                                        script_type: script_type_from_address(addr),
                                        internal: false,
                                        index: 0,
                                    });
                            }
                        }
                    }
                }
            }
        }

        Ok(TxGraph {
            addr_map,
            our_addrs,
            utxos,
            our_txids,
            addr_txs,
            tx_addrs,
            client,
            tx_cache: HashMap::new(),
            input_cache: HashMap::new(),
            output_cache: HashMap::new(),
        })
    }

    /// Check whether an address belongs to our wallet.
    pub fn is_ours(&self, address: &str) -> bool {
        self.our_addrs.contains(address)
    }

    /// Get the script type for an address.
    pub fn script_type(&self, address: &str) -> String {
        self.addr_map
            .get(address)
            .map(|info| info.script_type.clone())
            .unwrap_or_else(|| script_type_from_address(address))
    }

    /// Fetch a decoded transaction as a JSON value (cached).
    pub fn fetch_tx(&mut self, txid: &str) -> Option<serde_json::Value> {
        if let Some(cached) = self.tx_cache.get(txid) {
            return Some(cached.clone());
        }
        let txid_parsed: bitcoin::Txid = txid.parse().ok()?;
        let raw = self.client.get_raw_transaction_verbose(txid_parsed).ok()?;
        let value = serde_json::to_value(&raw).ok()?;
        self.tx_cache.insert(txid.to_string(), value.clone());
        Some(value)
    }

    /// Get all input addresses for a transaction (cached).
    pub fn get_input_addresses(&mut self, txid: &str) -> Vec<InputInfo> {
        if let Some(cached) = self.input_cache.get(txid) {
            return cached.clone();
        }

        let tx = match self.fetch_tx(txid) {
            Some(tx) => tx,
            None => {
                self.input_cache.insert(txid.to_string(), vec![]);
                return vec![];
            }
        };

        let mut addrs = Vec::new();
        if let Some(inputs) = tx.get("vin").and_then(|v| v.as_array()) {
            for vin in inputs {
                if vin.get("coinbase").is_some() {
                    continue;
                }
                let parent_txid = match vin.get("txid").and_then(|v| v.as_str()) {
                    Some(t) => t.to_string(),
                    None => continue,
                };
                let vout = vin.get("vout").and_then(|v| v.as_u64()).unwrap_or(0);
                if let Some(parent) = self.fetch_tx(&parent_txid) {
                    if let Some(outputs) = parent.get("vout").and_then(|v| v.as_array()) {
                        if let Some(vout_data) = outputs.get(vout as usize) {
                            let addr = vout_data
                                .pointer("/scriptPubKey/address")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let value = vout_data
                                .get("value")
                                .and_then(|v| v.as_f64())
                                .unwrap_or(0.0);
                            addrs.push(InputInfo {
                                address: addr,
                                value,
                                funding_txid: parent_txid,
                                funding_vout: vout as u32,
                            });
                        }
                    }
                }
            }
        }

        self.input_cache.insert(txid.to_string(), addrs.clone());
        addrs
    }

    /// Get all output addresses for a transaction (cached).
    pub fn get_output_addresses(&mut self, txid: &str) -> Vec<OutputInfo> {
        if let Some(cached) = self.output_cache.get(txid) {
            return cached.clone();
        }

        let tx = match self.fetch_tx(txid) {
            Some(tx) => tx,
            None => {
                self.output_cache.insert(txid.to_string(), vec![]);
                return vec![];
            }
        };

        let mut addrs = Vec::new();
        if let Some(outputs) = tx.get("vout").and_then(|v| v.as_array()) {
            for vout in outputs {
                let addr = vout
                    .pointer("/scriptPubKey/address")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let value = vout.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let index = vout.get("n").and_then(|v| v.as_u64()).unwrap_or(0);
                let script_type = vout
                    .pointer("/scriptPubKey/type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                addrs.push(OutputInfo {
                    address: addr,
                    value,
                    index,
                    script_type,
                });
            }
        }

        self.output_cache.insert(txid.to_string(), addrs.clone());
        addrs
    }
}

/// Infer script type from address prefix.
pub fn script_type_from_address(address: &str) -> String {
    if address.starts_with("tb1q") || address.starts_with("bc1q") || address.starts_with("bcrt1q") {
        "p2wpkh".into()
    } else if address.starts_with("tb1p")
        || address.starts_with("bc1p")
        || address.starts_with("bcrt1p")
    {
        "p2tr".into()
    } else if address.starts_with('2') || address.starts_with('3') {
        "p2sh-p2wpkh".into()
    } else if address.starts_with('1') || address.starts_with('m') || address.starts_with('n') {
        "p2pkh".into()
    } else {
        "unknown".into()
    }
}
