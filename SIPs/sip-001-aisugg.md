https://claude.ai/chat/da7aa3bd-d647-4bc7-b472-9d12cf7f24f6

```
Title: SIP-001
Authors:
    - Renato Britto (satsfy) <0xsatsfy@gmail.com>
Status: Open
Type: Specification
Assigned: 2026-03-16
License: BSD-3-Clause
```

# SIP-001: Stealth - Bitcoin UTXO Privacy Audit Framework

## Introduction

### Abstract

This document specifies the architecture, roadmap, and integration strategy for **Stealth**, an open-source privacy audit framework for Bitcoin wallets. Stealth analyzes the transaction history and UTXO set derived from wallet descriptors, surfaces privacy vulnerabilities using on-chain heuristics, scores wallet hygiene, and provides actionable remediations. The goal is to evolve Stealth from a hackathon proof-of-concept into a production-grade tool that ships as a standalone application, an embeddable library, and a set of integrations for the broader Bitcoin wallet ecosystem.

### Motivation

Bitcoin's transparency is a double-edged sword. Every transaction is publicly auditable, which makes the protocol trustless but also makes financial privacy an active problem that users must solve. Chain analysis firms exploit well-documented heuristics (common input ownership, change detection, dust attacks, script-type fingerprinting) to cluster addresses into entities, often with devastating accuracy.

Today, the average Bitcoin user has no practical way to audit their own wallet's privacy posture. Sparrow Wallet provides coin control. Samourai offered mixing. But nobody offers a **diagnostic** tool that tells a user: "here is what a chain analyst can already infer about you, and here is what you should do about it."

Stealth fills this gap. It is not a wallet. It does not hold keys (unless optionally provided for hardened path exploration). It is a read-only privacy X-ray that runs against your own full node, making no external network connections, and produces a structured report of findings, warnings, and remediations.

### Problem Statement

1. **No defensive tooling exists for regular users.** Chain analysis is a billion-dollar industry. The tools on the other side of the table are either academic papers or forensics software (Chainalysis, Elliptic, Crystal). Users have nothing equivalent pointing inward.
2. **Wallet developers lack a privacy scoring library.** BDK, bitcoinjs-lib, and other wallet SDKs offer coin selection but no built-in privacy analysis. Wallet developers who want to warn users about risky spending patterns must build heuristic engines from scratch.
3. **Self-hosted node operators want privacy dashboards.** Umbrel and Start9 users already run full nodes. A one-click privacy audit app that connects to their local Bitcoin Core instance is a natural fit.
4. **Privacy hygiene is invisible.** Users cannot see the damage done by address reuse, dust merging, or consolidation transactions until it is too late. Stealth makes this damage visible.

### Prior Art and Differentiation

Several projects touch adjacent problem spaces. Stealth's positioning relative to each:

- **OXT Research / Samourai Wallet**: Published foundational heuristic research (the 4-part "Understanding Bitcoin Privacy" series). Samourai was seized by U.S. authorities in April 2024. OXT.me remains available but is a hosted block explorer, not a self-hosted audit tool.
- **BlockSci (Princeton)**: Academic blockchain analysis framework. Requires full chain parsing, written in C++ with Python bindings, and is oriented toward researchers, not end users.
- **Chainforensics**: A Docker-based UTXO forensics tool for Umbrel announced in late 2025. Forensics-oriented (offense), not defense-oriented. Stealth is the inverse: it tells you what forensics tools would find, so you can fix it.
- **btc-heuristics**: MIT-licensed heuristics library for UTXO wallet health scoring, aligned with Maelstrom Grant. Library-only scope; no UI, no integration story, no remediation engine.
- **Open Bitcoin Privacy Project**: Inactive since ~2018. Contributed CoinJoin Sudoku and wallet privacy ratings. Stealth carries the torch with modern heuristics and a production deployment model.

Stealth's differentiation: it is **defense-first**, **self-hosted**, **descriptor-native**, **integration-ready**, and **remediation-aware**.

## Design

### Architecture Overview

Stealth is restructured around a layered architecture that separates concerns cleanly:

```
+---------------------------------------------------------+
|                    User Interfaces                      |
|  Web UI | CLI | Sparrow Plugin | Wallet SDK callback   |
+---------------------------------------------------------+
|                     REST API                            |
|  /scan  /score  /remediate  /preflight  /export         |
+---------------------------------------------------------+
|                  Analysis Engine                        |
|  Descriptor Parser | UTXO Scanner | Heuristic Detectors|
|  Cluster Analyzer  | Privacy Scorer | Remediation Engine|
+---------------------------------------------------------+
|                  Node Adapter Layer                     |
|  Bitcoin Core RPC  |  Electrum Protocol  |  (future)    |
+---------------------------------------------------------+
|                  Bitcoin Full Node                      |
|  Bitcoin Core (required) | Floresta (future/research)   |
+---------------------------------------------------------+
```

### Core Rewrite: Python to Rust

The current `detect.py` proof-of-concept is rewritten in Rust as `stealth-core`, a library crate. Rationale:

- **BDK interoperability.** BDK is Rust-native. A Rust core can be consumed as a crate dependency inside BDK-based wallets with zero FFI overhead.
- **Performance.** Heuristic analysis over large UTXO sets involves significant iteration. Rust's zero-cost abstractions and memory safety make it the right tool.
- **Cross-platform FFI.** Rust compiles to C-compatible shared libraries, enabling bindings for Python (PyO3), Java/Kotlin (JNI), Swift, and WASM.
- **Ecosystem alignment.** rust-bitcoin, rust-miniscript, bdk_chain, and Floresta are all Rust. Stealth belongs in this family.

The Rust rewrite does NOT mean the Python version is abandoned. The Python implementation remains as a reference and is used to generate ground-truth test vectors for the Rust port.

### Specification

#### Inputs

The user may provide one or more of each:

- **Wallet descriptor** (e.g., `wpkh(xpub.../0/*)`, `tr(xpub...)`, multisig variants). This is the primary input. Stealth derives addresses from the descriptor using standard BIP32/BIP44/BIP49/BIP84/BIP86 derivation and scans the chain for matching transactions.
- **UTXO set** (explicit list of outpoints). For users who want to audit a specific set of coins without providing a descriptor.
- **PSBT** (for pre-flight analysis). Before broadcasting a transaction, Stealth can analyze the PSBT and warn about privacy leaks the transaction would create.
- **Private key** (optional). Only necessary for exploring UTXOs behind hardened derivation paths. Never stored, never transmitted. Used in-memory only.

#### Outputs

Stealth produces a structured report containing:

- **Findings**: Privacy vulnerabilities detected, each with a type, severity (LOW / MEDIUM / HIGH / CRITICAL), human-readable description, structured evidence (txids, addresses, amounts), and one or more suggested remediations.
- **Warnings**: Potential issues that may or may not represent real privacy leaks depending on context (e.g., dormant UTXOs, direct receipt from a flagged source).
- **Privacy Score**: A composite score from 0 (fully deanonymized) to 100 (no detectable privacy leaks), computed from weighted findings. The scoring model is documented and deterministic.
- **Cluster Map**: A graph of address clusters inferred from the wallet's transaction history, showing which UTXOs a chain analyst would likely group together and why.
- **Remediation Plan**: Actionable steps the user can take to improve their score, prioritized by impact and cost (in terms of transaction fees).

### Networking and Security Model

**Stealth makes exactly one class of network connection: to a Bitcoin full node over RPC or Electrum protocol.** No telemetry. No analytics. No external APIs. No DNS lookups beyond what the OS resolver does for the configured node address.

The security boundary is simple: if the node Stealth connects to can be trusted with on-chain queries, Stealth adds no additional attack surface. For maximum security, the node should be local (127.0.0.1) or accessed over Tor.

**Connection backends supported:**

1. **Bitcoin Core JSON-RPC** (primary, recommended). Requires `txindex=1` for full transaction lookups or `importdescriptor` for wallet-based scanning.
2. **Electrum Protocol** (for Electrum Server, Electrs, Fulcrum). Enables integration with existing Umbrel/Start9 setups that already run an Electrum server alongside Bitcoin Core.

**Future research: Floresta compatibility.** The SIP's original text stated that compact nodes like Floresta "cannot be used" because they only validate and cannot retrieve UTXO sets. This is partially outdated. Floresta now supports compact block filters (BIP158) and an integrated Electrum server. While Floresta does not maintain a full `txindex`, its Electrum interface could serve as a backend for Stealth in watch-only mode if the user provides their xpub to Floresta for indexing. This is tracked as a research item, not a launch requirement. Floresta is currently migrating its P2P protocol to BIP-0183 and is mainnet-limited during this transition.

### Vulnerability Taxonomy

Stealth detects the following classes of privacy vulnerabilities and warnings. Each detector is implemented as a standalone module with well-defined inputs and outputs, enabling community contribution of new detectors.

#### Findings (Privacy Vulnerabilities)

**ADDRESS_REUSE** - An address received funds in multiple transactions. This links the history and balances of all transactions involving that address and is the most basic privacy failure. Severity: HIGH.

**CIOH (Common Input Ownership Heuristic)** - Multiple inputs from different addresses were spent together in a single transaction, allowing an analyst to infer they are controlled by the same entity. Severity: HIGH.

**DUST** - A UTXO with a value below the dust threshold (546 sats for P2PKH, 294 sats for P2WPKH) was detected. Dust outputs are commonly used in dust attacks to link addresses when the dust is later spent. Severity: MEDIUM.

**DUST_SPENDING** - A dust-value input was spent alongside normal-value inputs in the same transaction. This actively confirms the link between the dust address and the user's other addresses. Severity: CRITICAL.

**CHANGE_DETECTION** - The change output of a transaction is trivially identifiable through round-number heuristics, script-type matching, or output ordering. This reveals the payment amount and direction of funds. Severity: MEDIUM.

**CONSOLIDATION** - A UTXO was created from a transaction with many inputs and few outputs (a consolidation pattern). This links all input addresses as belonging to the same entity. Severity: MEDIUM.

**SCRIPT_TYPE_MIXING** - A transaction spent inputs of different script families (e.g., P2PKH and P2WPKH together). This is a strong wallet fingerprint because most wallets use a single script type. Severity: HIGH.

**CLUSTER_MERGE** - Inputs from previously separate funding chains (distinct clusters) were merged in a single transaction. This retroactively links transaction histories that were previously independent. Severity: CRITICAL.

**UTXO_AGE_SPREAD** - UTXOs with significantly different ages were spent together. Large age spreads reveal dormancy patterns and look-back windows. Severity: LOW.

**EXCHANGE_ORIGIN** - A UTXO likely originated from an exchange batch withdrawal (identified by the characteristic many-output, few-input pattern with round amounts). Exchanges perform KYC, so this UTXO is linked to a real identity at the source. Severity: MEDIUM.

**TAINTED_UTXO_MERGE** - UTXOs with known taint (e.g., from a flagged source) were merged with clean UTXOs, propagating taint to the entire output set. Severity: CRITICAL.

**BEHAVIORAL_FINGERPRINT** - Consistent patterns in transaction construction (timing, fee rates, output counts, change position) create a wallet/user fingerprint distinguishable from the general population. Severity: LOW.

#### Warnings

**DORMANT_UTXOS** - UTXOs that have not been spent for an extended period. Not a vulnerability per se, but dormant coins become increasingly identifiable as time passes. Severity: INFO.

**DIRECT_TAINT** - A UTXO was received directly from a source flagged in known-entity databases (e.g., sanctioned addresses). This is a warning because the user may not control the sender's behavior. Severity: MEDIUM.

### Privacy Scoring Model

The privacy score is a weighted composite of individual finding severities and their count, normalized to a 0-100 scale. The formula is deterministic and reproducible:

```
score = max(0, 100 - sum(penalty(finding) for finding in findings))

penalty(finding) = base_penalty[finding.severity] * decay(count)

base_penalty = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3 }
decay(n) = 1.0 for n=1, 0.5 for n=2, 0.25 for n>=3 (diminishing returns)
```

The score is capped at 0 (floor). A score of 100 means no detectable findings. The model is intentionally simple and auditable. Future SIPs may propose more sophisticated scoring that incorporates cluster size, temporal analysis, and anon-set estimation.

### PSBT Pre-Flight Analysis

A key feature for wallet integrations: before a user broadcasts a transaction, Stealth can analyze the unsigned PSBT and report privacy implications:

- Would this transaction create a CIOH link between previously unlinked UTXOs?
- Is the change output trivially detectable?
- Does the transaction mix script types?
- Would spending this set of inputs merge clusters?
- Is the fee rate an outlier that fingerprints the wallet?

The pre-flight API accepts a PSBT (base64-encoded) and returns findings with severity, allowing the wallet to display warnings before the user confirms.

### Remediation Engine

Stealth does not just diagnose. It prescribes. Each finding type maps to one or more remediation strategies:

- **ADDRESS_REUSE**: Generate and use fresh addresses. For wallets supporting BIP352 (Silent Payments), recommend migration to a silent payment address to eliminate reuse permanently.
- **CIOH / CLUSTER_MERGE**: Recommend spending UTXOs from different clusters in separate transactions. Suggest CoinJoin or payjoin if supported by the user's wallet.
- **DUST / DUST_SPENDING**: Flag dust UTXOs and recommend marking them "do not spend" in coin control. If already spent, note the damage and suggest mixing the tainted output.
- **CHANGE_DETECTION**: Recommend wallets that randomize change position and use same-type change outputs. Suggest spending exact amounts when possible (no change).
- **SCRIPT_TYPE_MIXING**: Migrate all funds to a single script type (preferably P2TR for Taproot's uniformity benefits).
- **EXCHANGE_ORIGIN**: If privacy is critical, recommend breaking the link through a CoinJoin or time-delayed self-transfer through separate wallets.

Remediations are suggestions, not actions. Stealth never constructs, signs, or broadcasts transactions.

### Silent Payments Awareness (BIP352)

BIP352 (Silent Payments) was recently updated to v1.1.0 (March 2, 2026) and is being adopted by wallets including Bitcoin Core 28.0+, Cake Wallet, Silentium, and BlueWallet. Silent Payments fundamentally address the ADDRESS_REUSE problem by deriving unique on-chain addresses from a single static payment code.

Stealth will:

1. **Detect Silent Payment outputs.** Recognize P2TR outputs generated by the BIP352 protocol and exclude them from ADDRESS_REUSE false positives.
2. **Recommend Silent Payments** as a remediation for ADDRESS_REUSE findings when the user's wallet supports BIP352.
3. **Score Silent Payment adoption** positively in the privacy score, as it represents a structural improvement in privacy posture.

## Deployment

### Phase 1: Core Library and CLI (v0.1.0)

**Target: Q3 2026**

- Rust rewrite of all 12 finding detectors and 2 warning detectors from `detect.py`.
- `stealth-core` published as a Rust crate on crates.io.
- CLI binary (`stealth-cli`) that accepts a descriptor, connects to Bitcoin Core RPC, and outputs JSON or human-readable reports.
- Test vectors generated from the existing Python `reproduce.py` regtest scenarios.
- BSD-3-Clause license.

Deliverables:
- `stealth-core` crate (library)
- `stealth-cli` binary
- Regtest test harness
- CI/CD with cross-compilation (linux-amd64, linux-arm64, macos-amd64, macos-arm64)

### Phase 2: REST API and Web UI (v0.2.0)

**Target: Q4 2026**

- Lightweight HTTP API server (Axum or Actix-web) wrapping `stealth-core`.
- Endpoints: `/api/scan`, `/api/score`, `/api/preflight`, `/api/export`.
- React-based web UI (evolved from the existing frontend) that connects to the local API.
- Docker image published to Docker Hub and GitHub Container Registry.
- Docker Compose template for standalone deployment.

### Phase 3: Umbrel and Start9 App Store (v0.3.0)

**Target: Q1 2027**

- Umbrel app package (`umbrel-app.yml`, `docker-compose.yml`, `exports.sh`) following the Umbrel App Framework specification.
- Auto-configuration to connect to the user's existing Bitcoin Core node via Umbrel's `$APP_BITCOIN_*` environment variables.
- Optional Electrum backend for users running Electrs or Fulcrum alongside their node.
- Start9 service wrapper with StartOS manifest.
- Submission to both app stores.

This addresses the community request in [Issue #4](https://github.com/LORDBABUINO/stealth/issues/4).

### Phase 4: BDK Integration (v0.4.0)

**Target: Q2 2027**

- `stealth-bdk` crate that wraps `stealth-core` and provides a `PrivacyAnalyzer` trait compatible with `bdk_wallet::Wallet`.
- Given a `Wallet` instance, `PrivacyAnalyzer` can iterate the wallet's transaction history and UTXO set, run all detectors, and return a `PrivacyReport`.
- PSBT pre-flight analysis as a `TxBuilder` extension: `tx_builder.privacy_check()` returns warnings before `finish()`.
- Privacy-aware coin selection: a custom `CoinSelectionAlgorithm` implementation that penalizes selections that would create CIOH links, merge clusters, or mix script types.
- Published to crates.io. Any BDK-based wallet can add `stealth-bdk` as a dependency and get privacy analysis with minimal code.

This is the highest-leverage integration because BDK powers wallets including Bitkey, Peach Bitcoin, Envoy (Foundation), Bull Bitcoin, Padawan Wallet, and Lava.

### Phase 5: Sparrow Wallet Integration (v0.5.0)

**Target: Q3 2027**

Sparrow Wallet is Java-based (requires Java 25+) and does not expose a plugin API. Integration options:

1. **Upstream contribution.** Contribute a "Privacy Audit" tab to Sparrow's codebase that calls Stealth's REST API (running locally) or bundles a JNI-wrapped `stealth-core`. Sparrow's architecture (descriptor-native, UTXO-aware, coin-control-friendly) makes it a natural host. This requires coordination with Sparrow's maintainer (craigraw).

2. **Companion mode.** Stealth runs as a separate app alongside Sparrow and connects to the same Electrum server or Bitcoin Core node. The user exports a descriptor from Sparrow and imports it into Stealth. This works today with no upstream changes.

3. **PSBT interop.** Sparrow constructs PSBTs before signing. Stealth's pre-flight API can analyze a PSBT exported from Sparrow (via file or clipboard) and return warnings. This could be integrated into Sparrow's transaction review flow.

Approach (1) is the ideal end state. Approach (2) is the pragmatic starting point. Approach (3) is a quick win that provides value with minimal integration effort.

### Phase 6: Language Bindings and Mobile (v1.0.0)

**Target: Q4 2027**

- Python bindings via PyO3 (`stealth-py` on PyPI).
- Kotlin/Java bindings via JNI (`stealth-jvm` on Maven Central).
- Swift bindings via UniFFI for iOS wallet integration.
- WASM build for browser-based analysis (descriptor + UTXO set mode, no node connection required).

### Future Research Items

These are not committed to the roadmap but are tracked as research:

- **Floresta backend support.** Investigate using Floresta's Electrum server as a lightweight alternative to Bitcoin Core for Stealth's chain queries. This would enable privacy audits on resource-constrained devices (Raspberry Pi Zero, mobile phones) where a full Bitcoin Core + txindex is impractical.
- **Anon-set estimation.** Go beyond binary "found / not found" for each heuristic and estimate the actual anonymity set size for each UTXO (i.e., how many plausible ownership hypotheses exist).
- **Temporal analysis.** Detect timing-based fingerprints (e.g., transactions consistently broadcast at the same time of day, suggesting a timezone).
- **CoinJoin quality scoring.** For UTXOs that went through a CoinJoin, assess the quality of the mix (equal output amounts, number of participants, post-mix spending behavior).
- **Taproot script-path privacy.** Analyze how Taproot key-path vs. script-path spending reveals information about multisig or timelock conditions.
- **Watch-only mode with compact block filters (BIP158).** Enable descriptor scanning without `txindex` by using compact block filters to identify relevant blocks, then fetching only those blocks. This aligns with Floresta's architecture and enables lighter deployments.

## Technical Decisions and Tradeoffs

### Why Rust over Python for the core?

The Python `detect.py` is effective for prototyping but has three structural problems: (1) Python's GIL limits parallelism for scanning large UTXO sets, (2) Python cannot be embedded in mobile apps or compiled to WASM, and (3) BDK is Rust, and FFI bridges between Python and Rust add complexity and failure modes. The Rust rewrite eliminates all three.

### Why BSD-3-Clause?

BSD-3-Clause is the most permissive license that still requires attribution. It allows wallet vendors (including commercial ones) to integrate Stealth without copyleft concerns, maximizing adoption. This aligns with BDK's MIT/Apache-2.0 licensing and the broader Bitcoin development culture of permissive licensing.

### Why not use external APIs (mempool.space, blockchain.info)?

External APIs violate Stealth's core privacy guarantee. Querying a third-party API with your addresses reveals your wallet to that service. Every chain query Stealth makes goes exclusively to the user's own node.

### Why descriptor-native?

Descriptors are the modern standard for representing wallet spending conditions. BDK is descriptor-native. Bitcoin Core's wallet has moved to descriptors. Sparrow uses descriptors internally. By accepting descriptors as the primary input, Stealth integrates naturally with all of these and supports arbitrary spending policies (single-sig, multisig, Taproot, timelocked) without special-casing each script type.

### Why not build transaction construction / mixing directly into Stealth?

Stealth is a diagnostic tool, not a wallet. Adding transaction construction would dramatically increase the attack surface, require key management, and create regulatory ambiguity. The clean separation between "what's wrong" (Stealth) and "how to fix it" (the user's wallet of choice) is intentional and permanent.

## Governance and Contribution

### Open Source Development

- **Repository**: github.com/LORDBABUINO/stealth (or a dedicated org to be created)
- **License**: BSD-3-Clause
- **Language**: Rust (core), TypeScript/React (web UI), Python (legacy reference and test tooling)
- **CI/CD**: GitHub Actions with cross-platform builds, clippy, rustfmt, and test vectors
- **Release cadence**: Semantic versioning. Minor releases monthly during active development. Patch releases as needed.

### Funding

The project will pursue funding through:

- **OpenSats General Fund**: Stealth aligns with OpenSats' mission of supporting open-source Bitcoin privacy tools. Multiple similar projects (Floresta, BDK, Dana Wallet, BlindBit Suite, Citadel-Tech) have received grants.
- **Human Rights Foundation (HRF) Bitcoin Development Fund**: Privacy tools for Bitcoin self-custody are directly relevant to HRF's mission.
- **Maelstrom / Spiral / Brink**: Bitcoin developer grant programs that fund infrastructure and tooling.
- **Community donations**: Bitcoin and Lightning donations via a project-controlled address and BOLT12 offer.

### Review Process

- All code changes via pull request with at least one reviewer approval.
- Security-sensitive changes (node communication, key handling) require two reviewer approvals.
- Detector modules require test vectors derived from regtest scenarios before merge.
- The Python reference implementation serves as an oracle for Rust port correctness.

## Acknowledgements

- JorgeSantana (LORDBABUINO) - Original author and maintainer
- Herberson Miranda (hsmiranda) - Core contributor
- Breno Britto - Contributor
- QnA - Feedback and testing
- Seth (Seth for Privacy) - Privacy review and guidance
- OXT Research / Samourai Wallet - Foundational heuristic research that informs Stealth's detector taxonomy
- Bitcoin Development Kit contributors - For the descriptor and wallet primitives Stealth builds upon
- Floresta / Vinteum - For advancing lightweight node infrastructure that may power future Stealth deployments
- The participants of the hackathon where Stealth was born

## References

1. BIP32 - Hierarchical Deterministic Wallets
2. BIP44/49/84/86 - Derivation path standards
3. BIP352 - Silent Payments (v1.1.0, 2026-03-02)
4. BIP158 - Compact Block Filters for Light Clients
5. OXT Research, "Understanding Bitcoin Privacy with OXT" (Parts 1-4)
6. Ghesmati et al., "Studying Bitcoin Privacy Attacks and Their Impact" (IACR ePrint 2021/1088)
7. Bitcoin Development Kit - https://bitcoindevkit.org
8. Floresta - https://getfloresta.org
9. Umbrel App Framework - https://github.com/getumbrel/umbrel-apps
10. Sparrow Wallet - https://sparrowwallet.com
11. Chainalysis heuristic taxonomy (public documentation)
12. Meiklejohn et al., "A Fistful of Bitcoins: Characterizing Payments Among Men with No Names" (IMC 2013)

## Copyright

This document is licensed under the 3-clause BSD license.