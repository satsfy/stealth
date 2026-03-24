//! Integration tests for stealth-core.
//!
//! Each test spins up a fresh regtest Bitcoin Core via `corepc-node`,
//! reproduces one or more privacy vulnerabilities, then runs the
//! detector to verify it fires the expected finding(s).

use std::collections::{BTreeMap, HashSet};

use corepc_node::client::bitcoin::{Address, Amount};
use corepc_node::{AddressType, Input, Node, Output};
use stealth_core::{TxGraph, VulnerabilityType};

// ─── helpers ────────────────────────────────────────────────────────────────

fn node() -> Node {
    let exe = corepc_node::exe_path().expect("bitcoind not found");
    let mut conf = corepc_node::Conf::default();
    conf.args.push("-txindex");
    Node::with_conf(exe, &conf).expect("failed to start bitcoind")
}

fn mine(node: &Node, n: usize, addr: &Address) {
    node.client.generate_to_address(n, addr).unwrap();
}

fn has_finding(graph: &mut TxGraph, vtype: VulnerabilityType) -> bool {
    let report = graph.detect_all(None, None);
    report
        .findings
        .iter()
        .any(|f| f.vulnerability_type == vtype)
}

fn has_finding_with(
    graph: &mut TxGraph,
    vtype: VulnerabilityType,
    known_risky: Option<&HashSet<String>>,
    known_exchange: Option<&HashSet<String>>,
) -> bool {
    let report = graph.detect_all(known_risky, known_exchange);
    report
        .findings
        .iter()
        .any(|f| f.vulnerability_type == vtype)
}

// ─── 1. Address Reuse ───────────────────────────────────────────────────────

#[test]
fn detect_address_reuse() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client.send_to_address(&ba, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    // Reuse the same alice address twice
    let reused = alice.new_address().unwrap();
    bob.send_to_address(&reused, Amount::from_sat(1_000_000))
        .unwrap();
    bob.send_to_address(&reused, Amount::from_sat(2_000_000))
        .unwrap();
    mine(&node, 1, &da);

    let mut graph = TxGraph::build(alice).unwrap();
    assert!(has_finding(&mut graph, VulnerabilityType::AddressReuse));
}

// ─── 2. Common Input Ownership Heuristic (CIOH) ────────────────────────────

#[test]
fn detect_cioh() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice multiple small UTXOs (each to a different address)
    for _ in 0..5 {
        let a = alice.new_address().unwrap();
        bob.send_to_address(&a, Amount::from_sat(500_000)).unwrap();
    }
    mine(&node, 1, &da);

    // Alice consolidates them into one tx (multi-input -> CIOH)
    let utxos = alice.list_unspent().unwrap();
    let small: Vec<_> = utxos.0.iter().filter(|u| u.amount < 0.006).collect();
    assert!(small.len() >= 2, "need at least 2 small utxos");

    let inputs: Vec<Input> = small
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    let total_sats: u64 = small.iter().map(|u| (u.amount * 1e8).round() as u64).sum();
    let fee_sats: u64 = 10_000;
    let dest = bob.new_address().unwrap();
    let outputs = vec![Output::new(dest, Amount::from_sat(total_sats - fee_sats))];

    let raw = alice.create_raw_transaction(&inputs, &outputs).unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    assert!(signed.complete);
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let mut graph = TxGraph::build(alice).unwrap();
    assert!(has_finding(&mut graph, VulnerabilityType::Cioh));
}

// ─── 3. Dust UTXO Detection ────────────────────────────────────────────────

#[test]
fn detect_dust() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client.send_to_address(&ba, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    // Create 1000-sat dust output to alice via raw tx
    let dust_addr = alice.new_address().unwrap();
    let bob_utxos = bob.list_unspent().unwrap();
    let big = bob_utxos
        .0
        .iter()
        .max_by(|a, b| a.amount.partial_cmp(&b.amount).unwrap())
        .unwrap();

    let big_sats = (big.amount * 1e8).round() as u64;
    let dust_sats: u64 = 1_000;
    let fee_sats: u64 = 10_000;
    let change_sats = big_sats - dust_sats - fee_sats;

    let change_addr = bob.new_address().unwrap();
    let raw = bob
        .create_raw_transaction(
            &[Input {
                txid: big.txid.parse().unwrap(),
                vout: big.vout as u64,
                sequence: None,
            }],
            &[
                Output::new(dust_addr, Amount::from_sat(dust_sats)),
                Output::new(change_addr, Amount::from_sat(change_sats)),
            ],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = bob.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    bob.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let mut graph = TxGraph::build(alice).unwrap();
    assert!(has_finding(&mut graph, VulnerabilityType::Dust));
}

// ─── 4. Dust Spending with Normal Inputs ────────────────────────────────────

#[test]
fn detect_dust_spending() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice a normal UTXO
    let alice_normal = alice.new_address().unwrap();
    bob.send_to_address(&alice_normal, Amount::from_btc(0.5).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice a dust UTXO via raw tx
    let dust_addr = alice.new_address().unwrap();
    let bob_utxos = bob.list_unspent().unwrap();
    let big = bob_utxos
        .0
        .iter()
        .max_by(|a, b| a.amount.partial_cmp(&b.amount).unwrap())
        .unwrap();
    let big_sats = (big.amount * 1e8).round() as u64;
    let dust_sats: u64 = 1_000;
    let fee_sats: u64 = 10_000;

    let change_addr = bob.new_address().unwrap();
    let raw = bob
        .create_raw_transaction(
            &[Input {
                txid: big.txid.parse().unwrap(),
                vout: big.vout as u64,
                sequence: None,
            }],
            &[
                Output::new(dust_addr, Amount::from_sat(dust_sats)),
                Output::new(
                    change_addr,
                    Amount::from_sat(big_sats - dust_sats - fee_sats),
                ),
            ],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = bob.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    bob.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    // Now alice spends dust + normal together
    let utxos = alice.list_unspent().unwrap();
    let dust_u = utxos
        .0
        .iter()
        .find(|u| (u.amount * 1e8).round() as u64 <= 1000)
        .expect("dust utxo");
    let normal_u = utxos
        .0
        .iter()
        .find(|u| u.amount > 0.001)
        .expect("normal utxo");

    let total_sats = (dust_u.amount * 1e8).round() as u64 + (normal_u.amount * 1e8).round() as u64;
    let dest = bob.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &[
                Input {
                    txid: dust_u.txid.parse().unwrap(),
                    vout: dust_u.vout as u64,
                    sequence: None,
                },
                Input {
                    txid: normal_u.txid.parse().unwrap(),
                    vout: normal_u.vout as u64,
                    sequence: None,
                },
            ],
            &[Output::new(dest, Amount::from_sat(total_sats - 10_000))],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let mut graph = TxGraph::build(alice).unwrap();
    assert!(has_finding(&mut graph, VulnerabilityType::DustSpending));
}

// ─── 5. Change Detection ───────────────────────────────────────────────────

#[test]
fn detect_change_detection() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();

    // Fund alice with a clean 1 BTC UTXO
    let aa = alice.new_address().unwrap();
    node.client.send_to_address(&aa, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    // Alice sends a round 0.05 BTC to bob via send_to_address.
    // Bitcoin Core will automatically create a change output.
    let bob_addr = bob.new_address().unwrap();
    alice
        .send_to_address(&bob_addr, Amount::from_sat(5_000_000))
        .unwrap();
    mine(&node, 1, &da);

    let mut graph = TxGraph::build(alice).unwrap();
    assert!(has_finding(&mut graph, VulnerabilityType::ChangeDetection));
}

// ─── 6. Consolidation Origin ───────────────────────────────────────────────

#[test]
fn detect_consolidation() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice 4 small UTXOs
    for _ in 0..4 {
        let a = alice.new_address().unwrap();
        bob.send_to_address(&a, Amount::from_sat(300_000)).unwrap();
    }
    mine(&node, 1, &da);

    // Alice consolidates into one address (>=3 inputs, <=2 outputs)
    let utxos = alice.list_unspent().unwrap();
    let small: Vec<_> = utxos
        .0
        .iter()
        .filter(|u| u.amount > 0.002 && u.amount < 0.004)
        .collect();
    assert!(small.len() >= 3, "need at least 3 small utxos");

    let inputs: Vec<Input> = small
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    let total_sats: u64 = small.iter().map(|u| (u.amount * 1e8).round() as u64).sum();
    let consol_addr = alice.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &inputs,
            &[Output::new(
                consol_addr,
                Amount::from_sat(total_sats - 10_000),
            )],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let mut graph = TxGraph::build(alice).unwrap();
    assert!(has_finding(&mut graph, VulnerabilityType::Consolidation));
}

// ─── 7. Script Type Mixing ─────────────────────────────────────────────────

#[test]
fn detect_script_type_mixing() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Give alice one P2WPKH and one P2TR utxo
    let wpkh_addr = alice.new_address_with_type(AddressType::Bech32).unwrap();
    let tr_addr = alice.new_address_with_type(AddressType::Bech32m).unwrap();
    bob.send_to_address(&wpkh_addr, Amount::from_sat(500_000))
        .unwrap();
    bob.send_to_address(&tr_addr, Amount::from_sat(500_000))
        .unwrap();
    mine(&node, 1, &da);

    // Alice spends both types together
    let utxos = alice.list_unspent().unwrap();
    assert!(utxos.0.len() >= 2, "need at least 2 utxos");

    let inputs: Vec<Input> = utxos
        .0
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    let total_sats: u64 = utxos
        .0
        .iter()
        .map(|u| (u.amount * 1e8).round() as u64)
        .sum();
    let dest = bob.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &inputs,
            &[Output::new(dest, Amount::from_sat(total_sats - 10_000))],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let mut graph = TxGraph::build(alice).unwrap();
    assert!(has_finding(&mut graph, VulnerabilityType::ScriptTypeMixing));
}

// ─── 8. Cluster Merge ──────────────────────────────────────────────────────

#[test]
fn detect_cluster_merge() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    let carol = node.create_wallet("carol").unwrap();
    // Fund bob and carol
    let ba = bob.new_address().unwrap();
    let ca = carol.new_address().unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    node.client
        .send_to_address(&ca, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Bob sends to alice_addr_1, Carol sends to alice_addr_2
    let a1 = alice.new_address().unwrap();
    let a2 = alice.new_address().unwrap();
    bob.send_to_address(&a1, Amount::from_sat(400_000)).unwrap();
    carol
        .send_to_address(&a2, Amount::from_sat(400_000))
        .unwrap();
    mine(&node, 1, &da);

    // Alice spends both together -> cluster merge
    let utxos = alice.list_unspent().unwrap();
    assert!(utxos.0.len() >= 2, "need at least 2 utxos");

    let inputs: Vec<Input> = utxos
        .0
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    let total_sats: u64 = utxos
        .0
        .iter()
        .map(|u| (u.amount * 1e8).round() as u64)
        .sum();
    let dest = bob.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &inputs,
            &[Output::new(dest, Amount::from_sat(total_sats - 10_000))],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let mut graph = TxGraph::build(alice).unwrap();
    assert!(has_finding(&mut graph, VulnerabilityType::ClusterMerge));
}

// ─── 9. Lookback Depth / UTXO Age ──────────────────────────────────────────

#[test]
fn detect_utxo_age_spread() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();

    // Old UTXO
    let old_addr = alice.new_address().unwrap();
    node.client
        .send_to_address(&old_addr, Amount::from_sat(1_000_000))
        .unwrap();
    mine(&node, 20, &da);

    // New UTXO
    let new_addr = alice.new_address().unwrap();
    node.client
        .send_to_address(&new_addr, Amount::from_sat(1_000_000))
        .unwrap();
    mine(&node, 1, &da);

    let mut graph = TxGraph::build(alice).unwrap();
    assert!(has_finding(&mut graph, VulnerabilityType::UtxoAgeSpread));
}

// ─── 10. Exchange Origin ───────────────────────────────────────────────────

#[test]
fn detect_exchange_origin() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let exchange = node.create_wallet("exchange").unwrap();
    let bob = node.create_wallet("bob").unwrap();
    // Fund exchange
    let ea = exchange.new_address().unwrap();
    node.client
        .send_to_address(&ea, Amount::from_btc(5.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Exchange batch withdrawal to 8 addresses (alice gets some, bob gets some)
    let mut amounts: BTreeMap<Address, Amount> = BTreeMap::new();
    for i in 0..5u64 {
        let a = alice.new_address().unwrap();
        amounts.insert(a, Amount::from_sat(1_000_000 + i * 100_000));
    }
    for i in 0..3u64 {
        let b = bob.new_address().unwrap();
        amounts.insert(b, Amount::from_sat(1_000_000 + i * 200_000));
    }
    let send_result = exchange.send_many(amounts).unwrap();
    mine(&node, 1, &da);

    let exchange_txids: HashSet<String> = [send_result.0.clone()].into_iter().collect();
    let mut graph = TxGraph::build(alice).unwrap();
    assert!(has_finding_with(
        &mut graph,
        VulnerabilityType::ExchangeOrigin,
        None,
        Some(&exchange_txids)
    ));
}

// ─── 11. Tainted UTXOs ─────────────────────────────────────────────────────

#[test]
fn detect_tainted_utxo_merge() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let risky = node.create_wallet("risky").unwrap();
    let bob = node.create_wallet("bob").unwrap();

    // Fund
    let ra = risky.new_address().unwrap();
    let ba = bob.new_address().unwrap();
    node.client
        .send_to_address(&ra, Amount::from_btc(2.0).unwrap())
        .unwrap();
    node.client
        .send_to_address(&ba, Amount::from_btc(2.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Risky sends to alice
    let ta = alice.new_address().unwrap();
    let taint_result = risky
        .send_to_address(&ta, Amount::from_sat(1_000_000))
        .unwrap();
    let taint_txid = taint_result.0.clone();

    // Bob sends clean to alice
    let ca = alice.new_address().unwrap();
    bob.send_to_address(&ca, Amount::from_sat(1_000_000))
        .unwrap();
    mine(&node, 1, &da);

    // Alice spends both together (tainted + clean)
    let utxos = alice.list_unspent().unwrap();
    assert!(utxos.0.len() >= 2);

    let inputs: Vec<Input> = utxos
        .0
        .iter()
        .map(|u| Input {
            txid: u.txid.parse().unwrap(),
            vout: u.vout as u64,
            sequence: None,
        })
        .collect();
    let total_sats: u64 = utxos
        .0
        .iter()
        .map(|u| (u.amount * 1e8).round() as u64)
        .sum();
    let carol = node.create_wallet("carol").unwrap();
    let dest = carol.new_address().unwrap();
    let raw = alice
        .create_raw_transaction(
            &inputs,
            &[Output::new(dest, Amount::from_sat(total_sats - 10_000))],
        )
        .unwrap();
    let tx = raw.transaction().unwrap();
    let signed = alice.sign_raw_transaction_with_wallet(&tx).unwrap();
    let stx = signed.into_model().unwrap().tx;
    alice.send_raw_transaction(&stx).unwrap();
    mine(&node, 1, &da);

    let risky_txids: HashSet<String> = [taint_txid].into_iter().collect();
    let mut graph = TxGraph::build(alice).unwrap();
    assert!(has_finding_with(
        &mut graph,
        VulnerabilityType::TaintedUtxoMerge,
        Some(&risky_txids),
        None
    ));
}

// ─── 12. Behavioral Fingerprint ────────────────────────────────────────────

#[test]
fn detect_behavioral_fingerprint() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let carol = node.create_wallet("carol").unwrap();

    // Fund alice generously
    let aa = alice.new_address().unwrap();
    node.client
        .send_to_address(&aa, Amount::from_btc(5.0).unwrap())
        .unwrap();
    mine(&node, 1, &da);

    // Alice sends 5 round-amount payments (behavioral pattern)
    for i in 1u64..=5 {
        let dest = carol.new_address().unwrap();
        alice
            .send_to_address(&dest, Amount::from_sat(i * 1_000_000))
            .unwrap();
        mine(&node, 1, &da);
    }

    let mut graph = TxGraph::build(alice).unwrap();
    let report = graph.detect_all(None, None);
    assert!(report
        .findings
        .iter()
        .any(|f| f.vulnerability_type == VulnerabilityType::BehavioralFingerprint));
}

// ─── Full Report Smoke Test ─────────────────────────────────────────────────

#[test]
fn full_report_generates() {
    let node = node();
    let da = node.client.new_address().unwrap();
    mine(&node, 110, &da);

    let alice = node.create_wallet("alice").unwrap();
    let aa = alice.new_address().unwrap();
    node.client.send_to_address(&aa, Amount::ONE_BTC).unwrap();
    mine(&node, 1, &da);

    let mut graph = TxGraph::build(alice).unwrap();
    let report = graph.detect_all(None, None);

    assert_eq!(
        report.summary.findings + report.summary.warnings,
        report.findings.len() + report.warnings.len()
    );
    assert_eq!(report.stats.utxos_current, 1);
}
