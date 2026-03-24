use serde::{Deserialize, Serialize};
use stealth_core::{Report, Stats, Summary};
use thiserror::Error;

/// Canonical input accepted by the HTTP scan preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanTarget {
    Descriptor(String),
    Descriptors(Vec<String>),
    Utxos(Vec<UtxoInput>),
}

/// Minimal UTXO shape accepted by the HTTP scan preflight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoInput {
    pub txid: String,
    pub vout: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_sats: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

pub type ScanReport = Report;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ScanError {
    #[error("invalid scan input: {0}")]
    InvalidInput(String),
}

pub fn preflight_scan(target: ScanTarget) -> Result<ScanReport, ScanError> {
    let normalized = normalize_target(target)?;

    let stats = Stats {
        transactions_analyzed: 0,
        addresses_derived: normalized.descriptor_count,
        utxos_current: normalized.utxo_count,
    };
    let findings = Vec::new();
    let warnings = Vec::new();
    let summary = Summary {
        findings: findings.len(),
        warnings: warnings.len(),
        clean: findings.is_empty() && warnings.is_empty(),
    };

    Ok(Report {
        stats,
        findings,
        warnings,
        summary,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedScanInput {
    descriptor_count: usize,
    utxo_count: usize,
}

fn normalize_target(target: ScanTarget) -> Result<NormalizedScanInput, ScanError> {
    match target {
        ScanTarget::Descriptor(descriptor) => {
            validate_descriptor_shape(&descriptor)?;
            Ok(NormalizedScanInput {
                descriptor_count: 1,
                utxo_count: 0,
            })
        }
        ScanTarget::Descriptors(descriptors) => {
            if descriptors.is_empty() {
                return Err(ScanError::InvalidInput(
                    "descriptors cannot be empty".to_owned(),
                ));
            }
            for (index, descriptor) in descriptors.iter().enumerate() {
                if let Err(ScanError::InvalidInput(message)) = validate_descriptor_shape(descriptor)
                {
                    return Err(ScanError::InvalidInput(format!(
                        "descriptors[{index}] {message}",
                    )));
                }
            }
            Ok(NormalizedScanInput {
                descriptor_count: descriptors.len(),
                utxo_count: 0,
            })
        }
        ScanTarget::Utxos(utxos) => {
            if utxos.is_empty() {
                return Err(ScanError::InvalidInput("utxos cannot be empty".to_owned()));
            }
            if utxos.iter().any(|utxo| utxo.txid.trim().is_empty()) {
                return Err(ScanError::InvalidInput(
                    "utxos cannot contain empty txid values".to_owned(),
                ));
            }
            Ok(NormalizedScanInput {
                descriptor_count: 0,
                utxo_count: utxos.len(),
            })
        }
    }
}

fn validate_descriptor_shape(descriptor: &str) -> Result<(), ScanError> {
    let trimmed = descriptor.trim();
    if trimmed.is_empty() {
        return Err(ScanError::InvalidInput(
            "descriptor cannot be blank".to_owned(),
        ));
    }

    let (body, checksum) = split_descriptor_checksum(trimmed)?;
    if let Some(checksum) = checksum {
        validate_descriptor_checksum_shape(checksum)?;
    }

    if body.chars().any(char::is_whitespace) {
        return Err(ScanError::InvalidInput(
            "descriptor cannot contain whitespace".to_owned(),
        ));
    }
    if !is_supported_descriptor_prefix(body) {
        return Err(ScanError::InvalidInput(
            "descriptor has unsupported script form".to_owned(),
        ));
    }
    if !body.ends_with(')') {
        return Err(ScanError::InvalidInput(
            "descriptor must end with ')'".to_owned(),
        ));
    }
    if !has_balanced_parentheses(body) {
        return Err(ScanError::InvalidInput(
            "descriptor has unbalanced parentheses".to_owned(),
        ));
    }
    if body
        .split_once('(')
        .map(|(_, inner)| inner.trim_end_matches(')').trim().is_empty())
        .unwrap_or(true)
    {
        return Err(ScanError::InvalidInput(
            "descriptor payload cannot be empty".to_owned(),
        ));
    }

    Ok(())
}

fn split_descriptor_checksum(descriptor: &str) -> Result<(&str, Option<&str>), ScanError> {
    let mut parts = descriptor.split('#');
    let body = parts.next().expect("split always returns first element");
    let checksum = parts.next();
    if parts.next().is_some() {
        return Err(ScanError::InvalidInput(
            "descriptor contains multiple checksum separators ('#')".to_owned(),
        ));
    }
    Ok((body, checksum))
}

fn validate_descriptor_checksum_shape(checksum: &str) -> Result<(), ScanError> {
    if checksum.len() != 8 || !checksum.chars().all(|char| char.is_ascii_alphanumeric()) {
        return Err(ScanError::InvalidInput(
            "descriptor checksum must be 8 alphanumeric characters (shape only)".to_owned(),
        ));
    }
    Ok(())
}

fn is_supported_descriptor_prefix(descriptor_body: &str) -> bool {
    const SUPPORTED_PREFIXES: [&str; 6] = ["wpkh(", "tr(", "pkh(", "sh(wpkh(", "wsh(", "sh(wsh("];
    SUPPORTED_PREFIXES
        .iter()
        .any(|prefix| descriptor_body.starts_with(prefix))
}

fn has_balanced_parentheses(value: &str) -> bool {
    let mut depth = 0usize;
    for char in value.chars() {
        if char == '(' {
            depth += 1;
            continue;
        }
        if char == ')' {
            if depth == 0 {
                return false;
            }
            depth -= 1;
        }
    }
    depth == 0
}
