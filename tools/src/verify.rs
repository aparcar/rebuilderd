//! Verification of in-toto attestations served by a rebuilderd instance.
//!
//! An attestation carries one signature per signing key: the worker's, and the
//! daemon's countersignature, each potentially in both a classical and a
//! post-quantum algorithm. Verifying it means answering two separate
//! questions -- is the signature cryptographically valid, and is the key one we
//! actually trust -- so the report distinguishes them rather than collapsing
//! everything into a single boolean.

use in_toto::crypto::{PublicKey, SignatureScheme};
use in_toto::models::Metablock;
use rebuilderd_common::api::Client;
use rebuilderd_common::api::v1::MetaRestApi;
use rebuilderd_common::errors::*;

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

/// Check every signature on an attestation against the keys we know about.
pub fn verify(attestation: &[u8], known_keys: &[KnownKey]) -> Result<Vec<SignatureReport>> {
    let metablock =
        serde_json::from_slice::<Metablock>(attestation).context("Failed to parse attestation")?;

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

        // `verify` takes a threshold and a set of authorized keys, so checking
        // a single signature means asking for a threshold of one against a set
        // containing only that key.
        let verified = metablock.verify(1, [&known.pubkey]).is_ok();

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
}
