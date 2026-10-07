//! Post-quantum attestation signatures.
//!
//! The daemon holds an ML-DSA key alongside its Ed25519 one and appends a
//! second signature to the in-toto metablock it already counter-signs. Because
//! `signatures` is a list, an attestation ends up carrying both a classical and
//! a post-quantum signature: existing verifiers keep working off the Ed25519
//! entry, while a verifier that no longer trusts Ed25519 can rely on the
//! ML-DSA one. Either algorithm being broken leaves the other binding.
//!
//! This is deliberately not a separate detached signature or a separate
//! endpoint -- the signature lives inside the metablock, so it is served,
//! stored and transported by the existing attestation path unchanged.
//!
//! NOTE: the on-the-wire construction follows TAP 21, which is still a draft.
//! Treat the format as unsettled: do not publish this key as a long-term trust
//! anchor until it is final.

use in_toto::crypto::{PrivateKey, PublicKey, SignatureScheme};
use pem::Pem;
use rebuilderd_common::errors::*;
use rebuilderd_common::utils;
use std::path::Path;

const PEM_PUBLIC_KEY: &str = "PUBLIC KEY";
const PEM_PRIVATE_KEY: &str = "PRIVATE KEY";

/// The parameter set we sign with.
///
/// ML-DSA-65 is the middle option and the one OpenPGP picked as its
/// MUST-implement composite; -44 saves little and -87 costs a lot of bytes per
/// attestation for security nobody is asking for yet.
pub const SCHEME: SignatureScheme = SignatureScheme::MlDsa65V1;

/// Generate a new ML-DSA keypair, PEM encoded as (private, public).
pub fn keygen_pem() -> Result<(String, String)> {
    let privkey = PrivateKey::new_mldsa(SCHEME)?;
    let pubkey = {
        let privkey = PrivateKey::from_pkcs8(&privkey, SCHEME)?;
        pubkey_to_pem(privkey.public())?
    };
    Ok((privkey_to_pem(privkey), pubkey))
}

pub fn privkey_to_pem(privkey: Vec<u8>) -> String {
    pem::encode(&Pem::new(PEM_PRIVATE_KEY, privkey))
}

pub fn pubkey_to_pem(pubkey: &PublicKey) -> Result<String> {
    let pubkey = pubkey.as_spki()?;
    Ok(pem::encode(&Pem::new(PEM_PUBLIC_KEY, pubkey)))
}

pub fn pem_to_privkey(buf: &[u8]) -> Result<PrivateKey> {
    let pems = pem::parse_many(buf).context("Failed to parse pem file")?;
    pems.into_iter()
        .find(|pem| pem.tag() == PEM_PRIVATE_KEY)
        .context("No private key found in PEM file")
        .and_then(|pem| {
            PrivateKey::from_pkcs8(pem.contents(), SCHEME)
                .context("Failed to parse post-quantum private key")
        })
}

/// Load the ML-DSA signing key, generating one on first use.
///
/// Mirrors `attestation::load_or_create_privkey_pem` so operators get the same
/// behaviour for both keys.
pub fn load_or_create_privkey_pem(path: &Path) -> Result<PrivateKey> {
    let privkey = utils::load_or_create(path, || {
        info!("generating new post-quantum signing private key: {path:?}");
        let privkey = PrivateKey::new_mldsa(SCHEME)?;
        Ok(privkey_to_pem(privkey).into_bytes())
    })?;

    pem_to_privkey(&privkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_roundtrip() {
        let (privkey_pem, pubkey_pem) = keygen_pem().unwrap();

        let privkey = pem_to_privkey(privkey_pem.as_bytes()).unwrap();
        assert_eq!(pubkey_to_pem(privkey.public()).unwrap(), pubkey_pem);
    }

    #[test]
    fn test_sign_verify() {
        let (privkey_pem, _) = keygen_pem().unwrap();
        let privkey = pem_to_privkey(privkey_pem.as_bytes()).unwrap();

        let sig = privkey.sign(b"attestation bytes").unwrap();
        privkey
            .public()
            .verify(b"attestation bytes", &sig)
            .expect("our own signature verifies");
    }

    #[test]
    fn test_rejects_tampered_payload() {
        let (privkey_pem, _) = keygen_pem().unwrap();
        let privkey = pem_to_privkey(privkey_pem.as_bytes()).unwrap();

        let sig = privkey.sign(b"attestation bytes").unwrap();
        assert!(privkey.public().verify(b"tampered bytes", &sig).is_err());
    }

    #[test]
    fn test_uses_post_quantum_scheme() {
        let (privkey_pem, _) = keygen_pem().unwrap();
        let privkey = pem_to_privkey(privkey_pem.as_bytes()).unwrap();
        assert_eq!(privkey.public().scheme(), &SignatureScheme::MlDsa65V1);
    }
}
