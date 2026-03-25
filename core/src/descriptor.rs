/// Descriptor normalization pipeline.
///
/// Strips checksums, deduces receive/change pairs (`/0/*` ↔ `/1/*`),
/// and deduplicates the resolved descriptors.

/// Normalize a set of raw descriptor strings for import.
///
/// For each descriptor the function:
///
/// 1. Strips any trailing `#checksum`.
/// 2. If the descriptor contains `/0/*` (receive) it derives the
///    matching `/1/*` (change) descriptor, and vice-versa.
/// 3. Deduplicates the resulting set.
///
/// Returns pairs of `(descriptor, is_internal)` ready for import.
pub fn normalize_descriptors(raw: &[String]) -> Vec<(String, bool)> {
    let mut result: Vec<(String, bool)> = Vec::new();

    for descriptor in raw {
        let without_checksum = descriptor
            .split('#')
            .next()
            .map(str::trim)
            .unwrap_or_default()
            .to_string();

        if without_checksum.is_empty() {
            continue;
        }

        let candidates = if without_checksum.contains("/0/*") {
            vec![
                (without_checksum.clone(), false),
                (without_checksum.replace("/0/*", "/1/*"), true),
            ]
        } else if without_checksum.contains("/1/*") {
            vec![
                (without_checksum.replace("/1/*", "/0/*"), false),
                (without_checksum.clone(), true),
            ]
        } else {
            vec![(without_checksum, false)]
        };

        for candidate in candidates {
            if !result.contains(&candidate) {
                result.push(candidate);
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_checksum_and_infers_change_pair() {
        let raw = vec![String::from(
            "wpkh([abcd/84h/1h/0h]tpub123/0/*)#somechecksum",
        )];
        let result = normalize_descriptors(&raw);

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, "wpkh([abcd/84h/1h/0h]tpub123/0/*)");
        assert!(!result[0].1); // external
        assert_eq!(result[1].0, "wpkh([abcd/84h/1h/0h]tpub123/1/*)");
        assert!(result[1].1); // internal
    }

    #[test]
    fn infers_receive_from_change_descriptor() {
        let raw = vec![String::from("wpkh([abcd]tpub123/1/*)")];
        let result = normalize_descriptors(&raw);

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, "wpkh([abcd]tpub123/0/*)");
        assert!(!result[0].1);
        assert_eq!(result[1].0, "wpkh([abcd]tpub123/1/*)");
        assert!(result[1].1);
    }

    #[test]
    fn plain_descriptor_passes_through() {
        let raw = vec![String::from("addr(bc1qexample)")];
        let result = normalize_descriptors(&raw);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "addr(bc1qexample)");
        assert!(!result[0].1);
    }

    #[test]
    fn deduplicates() {
        let raw = vec![
            String::from("wpkh(tpub123/0/*)"),
            String::from("wpkh(tpub123/0/*)"),
        ];
        let result = normalize_descriptors(&raw);

        // Should produce just 2 (receive + change), not 4.
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn skips_empty() {
        let raw = vec![String::from(""), String::from("  #checksum")];
        let result = normalize_descriptors(&raw);
        assert!(result.is_empty());
    }
}
