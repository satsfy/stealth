use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Txid};

use crate::gateway::{DecodedTransaction, WalletHistory, WalletTxCategory};
use crate::types::{btc_to_sats, AddressInfo, InputInfo, OutputInfo, WalletTx};

/// Indexed view of all transactions touching a wallet's address set.
///
/// All caches are populated up-front from a [`WalletHistory`] so no live
/// RPC connection is needed at detection time.
#[derive(Debug)]
pub struct TxGraph {
    /// Map of our addresses → metadata.
    pub addr_map: HashMap<String, AddressInfo>,
    /// All our addresses (quick lookup).
    pub our_addrs: HashSet<String>,
    /// Current UTXOs from `listunspent`.
    pub utxos: Vec<UtxoEntry>,
    /// Transaction IDs that touch our wallet.
    pub our_txids: HashSet<Txid>,
    /// Per-address transaction entries.
    pub addr_txs: HashMap<String, Vec<WalletTx>>,
    /// Per-txid set of our addresses involved.
    pub tx_addrs: HashMap<Txid, HashSet<String>>,

    /// Decoded transactions keyed by txid.
    pub tx_cache: HashMap<Txid, DecodedTransaction>,
    /// Cached input addresses per txid.
    pub input_cache: HashMap<Txid, Vec<InputInfo>>,
    /// Cached output addresses per txid.
    pub output_cache: HashMap<Txid, Vec<OutputInfo>>,
}

/// A UTXO entry from `listunspent`.
#[derive(Debug, Clone)]
pub struct UtxoEntry {
    pub txid: Txid,
    pub vout: u32,
    pub address: String,
    pub amount_sats: u64,
    pub confirmations: u32,
}

impl TxGraph {
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

    /// Look up a decoded transaction by txid.
    pub fn fetch_tx(&self, txid: &Txid) -> Option<&DecodedTransaction> {
        self.tx_cache.get(txid)
    }

    /// Get all input addresses for a transaction.
    pub fn get_input_addresses(&self, txid: &Txid) -> Vec<InputInfo> {
        self.input_cache.get(txid).cloned().unwrap_or_default()
    }

    /// Get all output addresses for a transaction.
    pub fn get_output_addresses(&self, txid: &Txid) -> Vec<OutputInfo> {
        self.output_cache.get(txid).cloned().unwrap_or_default()
    }

    /// Build a [`TxGraph`] from a pre-fetched [`WalletHistory`] produced
    /// by a [`BlockchainGateway`](crate::gateway::BlockchainGateway).
    ///
    /// All transaction caches are populated up-front so no live RPC
    /// connection is needed.
    pub fn from_wallet_history(history: WalletHistory) -> Self {
        let mut our_addrs = HashSet::new();
        let mut addr_map = HashMap::new();
        let mut our_txids = HashSet::new();
        let mut addr_txs: HashMap<String, Vec<WalletTx>> = HashMap::new();
        let mut tx_addrs: HashMap<Txid, HashSet<String>> = HashMap::new();

        for entry in &history.wallet_txs {
            our_txids.insert(entry.txid);
            if entry.address.is_empty() {
                continue;
            }

            let wtx = WalletTx {
                txid: entry.txid,
                address: entry.address.clone(),
                category: entry.category,
                amount_sats: btc_to_sats(entry.amount_btc),
                confirmations: entry.confirmations,
            };

            if entry.category != WalletTxCategory::Send {
                our_addrs.insert(entry.address.clone());
                addr_map
                    .entry(entry.address.clone())
                    .or_insert_with(|| AddressInfo {
                        script_type: script_type_from_address(&entry.address),
                        internal: history.internal_addresses.contains(&entry.address),
                        index: 0,
                    });
            }

            addr_txs.entry(entry.address.clone()).or_default().push(wtx);
            tx_addrs
                .entry(entry.txid)
                .or_default()
                .insert(entry.address.clone());
        }

        let utxos: Vec<UtxoEntry> = history
            .utxos
            .iter()
            .map(|u| {
                our_addrs.insert(u.address.clone());
                addr_map
                    .entry(u.address.clone())
                    .or_insert_with(|| AddressInfo {
                        script_type: script_type_from_address(&u.address),
                        internal: history.internal_addresses.contains(&u.address),
                        index: 0,
                    });
                UtxoEntry {
                    txid: u.txid,
                    vout: u.vout,
                    address: u.address.clone(),
                    amount_sats: btc_to_sats(u.amount_btc),
                    confirmations: u.confirmations,
                }
            })
            .collect();

        // Pre-populate caches from decoded transactions.
        let mut tx_cache = HashMap::new();
        let mut input_cache: HashMap<Txid, Vec<InputInfo>> = HashMap::new();
        let mut output_cache: HashMap<Txid, Vec<OutputInfo>> = HashMap::new();

        for (txid, tx) in &history.transactions {
            tx_cache.insert(*txid, tx.clone());

            let inputs: Vec<InputInfo> = tx
                .vin
                .iter()
                .filter_map(|input| {
                    if input.coinbase {
                        return None;
                    }
                    let parent = history.transactions.get(&input.previous_txid)?;
                    let out = parent.vout.iter().find(|o| o.n == input.previous_vout)?;
                    Some(InputInfo {
                        address: out.address.clone(),
                        value_sats: btc_to_sats(out.value_btc),
                        funding_txid: input.previous_txid,
                        funding_vout: input.previous_vout,
                    })
                })
                .collect();
            input_cache.insert(*txid, inputs);

            let outputs: Vec<OutputInfo> = tx
                .vout
                .iter()
                .map(|out| OutputInfo {
                    address: out.address.clone(),
                    value_sats: btc_to_sats(out.value_btc),
                    index: out.n as u64,
                    script_type: if !out.address.is_empty() {
                        script_type_from_address(&out.address)
                    } else {
                        out.script_type.as_script_name().to_string()
                    },
                })
                .collect();
            output_cache.insert(*txid, outputs);
        }

        TxGraph {
            addr_map,
            our_addrs,
            utxos,
            our_txids,
            addr_txs,
            tx_addrs,
            tx_cache,
            input_cache,
            output_cache,
        }
    }
}

/// Determine script type by actually decoding the address and inspecting
/// the resulting script.
///
/// Unlike the old prefix-based heuristic this handles all cases correctly:
///
/// * `bc1q` / `tb1q` / `bcrt1q` with a 20-byte program → **p2wpkh**
/// * `bc1q` / `tb1q` / `bcrt1q` with a 32-byte program → **p2wsh**
/// * `bc1p` / `tb1p` / `bcrt1p` → **p2tr**
/// * Base58 `1`/`m`/`n` (version 0x00/0x6f) → **p2pkh**
/// * Base58 `3`/`2` (version 0x05/0xc4) → **p2sh** (we *cannot* know if it
///   wraps p2wpkh, p2wsh, or bare multisig without the redeem script)
pub fn script_type_from_address(address: &str) -> String {
    // `assume_checked` skips network validation, allowing the function to
    // work for mainnet, testnet, signet and regtest addresses uniformly.
    if let Ok(addr) =
        Address::from_str(address).map(|a: Address<NetworkUnchecked>| a.assume_checked())
    {
        let script = addr.script_pubkey();
        if script.is_p2pkh() {
            return "p2pkh".into();
        } else if script.is_p2sh() {
            // Without the redeemScript (only available at spend time)
            // we cannot distinguish p2sh-p2wpkh from p2sh-p2wsh or
            // bare p2sh multisig.  Report as generic "p2sh".
            return "p2sh".into();
        } else if script.is_p2wpkh() {
            return "p2wpkh".into();
        } else if script.is_p2wsh() {
            return "p2wsh".into();
        } else if script.is_p2tr() {
            return "p2tr".into();
        }
    }

    "unknown".into()
}
