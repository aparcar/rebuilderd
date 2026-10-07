//! Verification of in-toto attestations served by a rebuilderd instance.
//!
//! An attestation carries one signature per signing key: the worker's, and the
//! daemon's countersignature, each potentially in both a classical and a
//! post-quantum algorithm. Verifying it means answering two separate
//! questions -- is the signature cryptographically valid, and is the key one we
//! actually trust -- so the report distinguishes them rather than collapsing
//! everything into a single boolean.

use crate::args::PinnedKeys;
use in_toto::crypto::{HashAlgorithm, HashValue, PublicKey, SignatureScheme};
use in_toto::models::{Metablock, MetadataWrapper};
use rebuilderd_common::api::Client;
use rebuilderd_common::api::v1::MetaRestApi;
use rebuilderd_common::errors::*;
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

/// A public key the daemon publishes, with a label for reporting.
pub struct KnownKey {
    pub pubkey: PublicKey,
    pub owner: &'static str,
}

/// The outcome for a single signature on an attestation.
pub struct SignatureReport {
    pub keyid: String,
    pub scheme: Option<SignatureScheme>,
    pub owner: Option<&'static str>,
    pub verified: bool,
}

impl SignatureReport {
    /// Whether this signature is post-quantum.
    pub fn is_post_quantum(&self) -> bool {
        #[cfg(feature = "pqc")]
        {
            matches!(
                self.scheme,
                Some(SignatureScheme::MlDsa44V1)
                    | Some(SignatureScheme::MlDsa65V1)
                    | Some(SignatureScheme::MlDsa87V1)
            )
        }
        #[cfg(not(feature = "pqc"))]
        {
            false
        }
    }

    /// Human readable algorithm, or the raw keyid-only case.
    pub fn scheme_name(&self) -> String {
        match &self.scheme {
            Some(scheme) => serde_json::to_value(scheme)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "unknown".to_string()),
            None => "unknown".to_string(),
        }
    }
}

/// Fetch every public key the daemon publishes.
///
/// A daemon built without post-quantum support serves no ML-DSA key, and one
/// built with it but with an older client is equally possible, so a missing
/// key is not an error here -- it just means those signatures cannot be
/// attributed.
pub async fn fetch_known_keys(client: &Client) -> Result<Vec<KnownKey>> {
    let mut keys = Vec::new();

    let response = client
        .get_public_keys()
        .await
        .context("Failed to fetch the daemon's public keys")?;
    for pem in response.current {
        for pubkey in parse_pubkeys(pem.as_bytes(), SignatureScheme::Ed25519)? {
            keys.push(KnownKey {
                pubkey,
                owner: "daemon",
            });
        }
    }

    #[cfg(feature = "pqc")]
    match client.get_pqc_public_keys().await {
        Ok(response) => {
            for pem in response.current {
                for pubkey in
                    parse_pubkeys(pem.as_bytes(), in_toto::crypto::SignatureScheme::MlDsa65V1)?
                {
                    keys.push(KnownKey {
                        pubkey,
                        owner: "daemon",
                    });
                }
            }
        }
        Err(err) => {
            debug!("Daemon publishes no post-quantum key: {:#}", err);
        }
    }

    Ok(keys)
}

fn parse_pubkeys(buf: &[u8], scheme: SignatureScheme) -> Result<Vec<PublicKey>> {
    let pems = pem::parse_many(buf).context("Failed to parse pem")?;
    pems.into_iter()
        .filter(|pem| pem.tag() == "PUBLIC KEY")
        .map(|pem| {
            PublicKey::from_spki(pem.contents(), scheme.clone())
                .context("Failed to parse public key")
        })
        .collect()
}

/// Load the public keys the caller pinned on the command line.
///
/// Keys are labelled `pinned` rather than `daemon`, because that is the whole
/// point: their authority comes from the caller having archived them, not from
/// the instance being checked vouching for itself.
pub fn load_pinned_keys(keys: &PinnedKeys) -> Result<Vec<KnownKey>> {
    let mut loaded = Vec::new();

    for path in &keys.key {
        let buf = std::fs::read(path).with_context(|| format!("Failed to read {:?}", path))?;
        for pubkey in parse_pubkeys(&buf, SignatureScheme::Ed25519)? {
            loaded.push(KnownKey {
                pubkey,
                owner: "pinned",
            });
        }
    }

    #[cfg(feature = "pqc")]
    for path in &keys.pqc_key {
        let buf = std::fs::read(path).with_context(|| format!("Failed to read {:?}", path))?;
        for pubkey in parse_pubkeys(&buf, SignatureScheme::MlDsa65V1)? {
            loaded.push(KnownKey {
                pubkey,
                owner: "pinned",
            });
        }
    }

    #[cfg(not(feature = "pqc"))]
    if !keys.pqc_key.is_empty() {
        bail!("This build has no post-quantum support, rebuild with --features pqc");
    }

    Ok(loaded)
}

/// What an attestation claims about a specific artifact.
pub struct ProductClaim {
    pub name: String,
    pub hashes: HashMap<HashAlgorithm, HashValue>,
}

/// Read the `products` of an attestation -- the artifacts it makes claims about.
pub fn products(attestation: &[u8]) -> Result<Vec<ProductClaim>> {
    let metablock =
        serde_json::from_slice::<Metablock>(attestation).context("Failed to parse attestation")?;

    let MetadataWrapper::Link(link) = metablock.metadata else {
        bail!("Attestation is a layout, not a link; it makes no artifact claims");
    };

    Ok(link
        .products
        .into_iter()
        .map(|(path, hashes)| ProductClaim {
            name: path.to_string(),
            hashes,
        })
        .collect())
}

/// Hash a file with the algorithms in-toto records.
pub fn hash_file(path: &Path) -> Result<HashMap<HashAlgorithm, HashValue>> {
    let file = File::open(path).with_context(|| format!("Failed to open {:?}", path))?;
    let (_size, hashes) =
        in_toto::crypto::calculate_hashes(file, &[HashAlgorithm::Sha256, HashAlgorithm::Sha512])
            .context("Failed to hash artifact")?;
    Ok(hashes)
}

/// Whether the file's digests match what the attestation claims.
///
/// Every algorithm the attestation records must be present and equal. A claim
/// listing an algorithm we did not compute is a mismatch, not something to
/// quietly skip -- otherwise an attestation could weaken the check by naming
/// only algorithms the verifier ignores.
pub fn hashes_match(
    claim: &HashMap<HashAlgorithm, HashValue>,
    actual: &HashMap<HashAlgorithm, HashValue>,
) -> bool {
    if claim.is_empty() {
        return false;
    }

    claim.iter().all(|(alg, expected)| {
        actual
            .get(alg)
            .map(|got| got.value() == expected.value())
            .unwrap_or(false)
    })
}

/// Check every signature on an attestation against the keys we know about.
pub fn verify(attestation: &[u8], known_keys: &[KnownKey]) -> Result<Vec<SignatureReport>> {
    let metablock =
        serde_json::from_slice::<Metablock>(attestation).context("Failed to parse attestation")?;

    // The signed message, reconstructed exactly as `Metablock::verify` does
    // internally.
    //
    // We check each signature against its own key rather than calling
    // `Metablock::verify` once per key. That method takes a threshold and a set
    // of authorized keys, so a per-key call warns about every *other* signature
    // as unauthorized -- which is quadratic and extremely noisy. It also
    // iterates a HashMap and stops once the threshold is met, so which
    // signatures it inspects, and therefore what it logs, varies between runs.
    let raw = metablock
        .metadata
        .to_bytes()
        .context("Failed to serialize attestation metadata")?;
    let message = String::from_utf8(raw)
        .context("Attestation metadata is not valid UTF-8")?
        .replace("\\n", "\n");

    let mut reports = Vec::new();
    for signature in &metablock.signatures {
        let keyid = signature.key_id().prefix();

        // Signatures are matched to keys by keyid; a key we do not have is
        // reported as such rather than silently ignored, because "we could not
        // check this" and "this is invalid" are very different statements.
        let known = known_keys
            .iter()
            .find(|known| known.pubkey.key_id() == signature.key_id());

        let Some(known) = known else {
            reports.push(SignatureReport {
                keyid,
                scheme: None,
                owner: None,
                verified: false,
            });
            continue;
        };

        let verified = known.pubkey.verify(message.as_bytes(), signature).is_ok();

        reports.push(SignatureReport {
            keyid,
            scheme: Some(known.pubkey.scheme().clone()),
            owner: Some(known.owner),
            verified,
        });
    }

    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use in_toto::crypto::{KeyType, PrivateKey};
    use in_toto::models::{LinkMetadataBuilder, MetadataWrapper};

    fn ed25519_key() -> PrivateKey {
        let der = PrivateKey::new(KeyType::Ed25519).unwrap();
        PrivateKey::from_pkcs8(&der, SignatureScheme::Ed25519).unwrap()
    }

    #[cfg(feature = "pqc")]
    fn mldsa_key() -> PrivateKey {
        let der = PrivateKey::new_mldsa(SignatureScheme::MlDsa65V1).unwrap();
        PrivateKey::from_pkcs8(&der, SignatureScheme::MlDsa65V1).unwrap()
    }

    fn metadata(name: &str) -> MetadataWrapper {
        MetadataWrapper::Link(
            LinkMetadataBuilder::new()
                .name(name.to_string())
                .build()
                .unwrap(),
        )
    }

    fn attestation(keys: &[&PrivateKey], name: &str) -> Vec<u8> {
        let block = Metablock::new(metadata(name), keys).unwrap();
        serde_json::to_vec(&block).unwrap()
    }

    fn known(key: &PrivateKey) -> KnownKey {
        KnownKey {
            pubkey: key.public().clone(),
            owner: "daemon",
        }
    }

    #[test]
    fn verifies_a_known_signature() {
        let key = ed25519_key();
        let reports = verify(&attestation(&[&key], "rebuild"), &[known(&key)]).unwrap();

        assert_eq!(reports.len(), 1);
        assert!(reports[0].verified);
        assert_eq!(reports[0].owner, Some("daemon"));
        assert!(!reports[0].is_post_quantum());
    }

    /// A signature we have no key for must not be reported as invalid -- "could
    /// not check" and "is forged" are different claims. This is the worker's
    /// situation today, since the daemon publishes no worker keys.
    #[test]
    fn reports_unknown_keys_separately() {
        let signer = ed25519_key();
        let unrelated = ed25519_key();

        let reports = verify(&attestation(&[&signer], "rebuild"), &[known(&unrelated)]).unwrap();

        assert_eq!(reports.len(), 1);
        assert!(!reports[0].verified);
        assert_eq!(reports[0].owner, None, "should not be attributed");
        assert_eq!(reports[0].scheme_name(), "unknown");
    }

    /// A signature over different metadata must fail, not pass unnoticed.
    #[test]
    fn rejects_a_tampered_attestation() {
        let key = ed25519_key();
        let mut block: Metablock =
            serde_json::from_slice(&attestation(&[&key], "rebuild")).unwrap();

        block.metadata = metadata("rebuild something else");
        let tampered = serde_json::to_vec(&block).unwrap();

        let reports = verify(&tampered, &[known(&key)]).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].owner, Some("daemon"), "key is still recognised");
        assert!(!reports[0].verified, "tampered metadata must not verify");
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn distinguishes_post_quantum_signatures() {
        let classical = ed25519_key();
        let pqc = mldsa_key();

        let reports = verify(
            &attestation(&[&classical, &pqc], "rebuild"),
            &[known(&classical), known(&pqc)],
        )
        .unwrap();

        assert_eq!(reports.len(), 2);
        assert!(reports.iter().all(|r| r.verified));

        assert_eq!(reports.iter().filter(|r| r.is_post_quantum()).count(), 1);
        assert_eq!(reports.iter().filter(|r| !r.is_post_quantum()).count(), 1);

        let pq = reports.iter().find(|r| r.is_post_quantum()).unwrap();
        assert_eq!(pq.scheme_name(), "ml-dsa-65/1");
    }

    /// Regression: results must not depend on iteration order.
    ///
    /// Verifying via `Metablock::verify` once per key made the output depend on
    /// HashMap ordering, so identical invocations logged differently from run
    /// to run. Each signature is now checked against its own key.
    #[test]
    fn is_deterministic_with_mixed_known_and_unknown_keys() {
        let known_a = ed25519_key();
        let unknown_a = ed25519_key();
        let unknown_b = ed25519_key();

        let attestation = attestation(&[&unknown_a, &known_a, &unknown_b], "rebuild");
        let keys = [known(&known_a)];

        let first = verify(&attestation, &keys).unwrap();
        assert_eq!(first.len(), 3);
        assert_eq!(first.iter().filter(|r| r.verified).count(), 1);
        assert_eq!(first.iter().filter(|r| r.owner.is_none()).count(), 2);

        // Same input, same output, every time.
        for _ in 0..16 {
            let again = verify(&attestation, &keys).unwrap();
            let a: Vec<_> = first.iter().map(|r| (&r.keyid, r.verified)).collect();
            let b: Vec<_> = again.iter().map(|r| (&r.keyid, r.verified)).collect();
            assert_eq!(a, b, "verification results varied between runs");
        }
    }

    #[test]
    fn hashes_match_requires_every_claimed_algorithm() {
        let sha256 = HashValue::new(vec![1, 2, 3]);
        let sha512 = HashValue::new(vec![4, 5, 6]);

        let claim: HashMap<_, _> = [
            (HashAlgorithm::Sha256, sha256.clone()),
            (HashAlgorithm::Sha512, sha512.clone()),
        ]
        .into_iter()
        .collect();

        let both: HashMap<_, _> = claim.clone();
        assert!(hashes_match(&claim, &both));

        // an algorithm we did not compute must not be silently skipped
        let only_256: HashMap<_, _> = [(HashAlgorithm::Sha256, sha256.clone())]
            .into_iter()
            .collect();
        assert!(!hashes_match(&claim, &only_256));

        // one matching algorithm is not enough if another disagrees
        let wrong_512: HashMap<_, _> = [
            (HashAlgorithm::Sha256, sha256),
            (HashAlgorithm::Sha512, HashValue::new(vec![9, 9, 9])),
        ]
        .into_iter()
        .collect();
        assert!(!hashes_match(&claim, &wrong_512));
    }

    /// An attestation claiming nothing must never validate a file.
    #[test]
    fn hashes_match_rejects_an_empty_claim() {
        let actual: HashMap<_, _> = [(HashAlgorithm::Sha256, HashValue::new(vec![1]))]
            .into_iter()
            .collect();
        assert!(!hashes_match(&HashMap::new(), &actual));
    }

    #[test]
    fn hash_file_agrees_with_the_recorded_digests() {
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"rebuilt artifact").unwrap();

        let hashes = hash_file(file.path()).unwrap();

        // sha256("rebuilt artifact"), computed with shasum(1), not by this code
        assert_eq!(
            data_encoding::HEXLOWER.encode(hashes[&HashAlgorithm::Sha256].value()),
            "1f1c5907df3a85c818a574b67bb1c2fa654604d09deba7f147396e6c0553ca5f"
        );
    }
}
