use data_encoding::BASE64;
use in_toto::{
    crypto::{KeyType, PrivateKey, PublicKey, SignatureScheme},
    models::{Metablock, MetadataWrapper},
};
use pem::Pem;
use rebuilderd_common::errors::*;
use rebuilderd_common::utils;
use rebuilderd_common::utils::{is_zstd_compressed, zstd_compress, zstd_decompress};
use std::borrow::Cow;
use std::path::Path;

const PEM_PUBLIC_KEY: &str = "PUBLIC KEY";
const PEM_PRIVATE_KEY: &str = "PRIVATE KEY";

pub struct Secret(Vec<u8>);

fn keygen() -> Result<(Secret, PublicKey)> {
    let privkey = PrivateKey::new(KeyType::Ed25519)?;

    let pubkey = {
        let privkey = PrivateKey::from_pkcs8(&privkey, SignatureScheme::Ed25519)?;
        privkey.public().to_owned()
    };

    Ok((Secret(privkey), pubkey))
}

pub fn keygen_pem() -> Result<(String, String)> {
    let (privkey, pubkey) = keygen()?;

    let privkey = privkey_to_pem(privkey);
    let pubkey = pubkey_to_pem(&pubkey)?;

    Ok((privkey, pubkey))
}

pub fn privkey_to_pem(privkey: Secret) -> String {
    pem::encode(&Pem::new(PEM_PRIVATE_KEY, privkey.0))
}

pub fn pubkey_to_pem(pubkey: &PublicKey) -> Result<String> {
    let pubkey = pubkey.as_spki()?;
    let pem = pem::encode(&Pem::new(PEM_PUBLIC_KEY, pubkey));
    Ok(pem)
}

pub fn pem_to_privkeys(buf: &[u8]) -> Result<impl Iterator<Item = Result<PrivateKey>>> {
    let pems = pem::parse_many(buf).context("Failed to parse pem file")?;
    let iter = pems
        .into_iter()
        .filter(|pem| pem.tag() == PEM_PRIVATE_KEY)
        .map(|pem| {
            PrivateKey::from_pkcs8(pem.contents(), SignatureScheme::Ed25519)
                .context("Failed to parse private key")
        });
    Ok(iter)
}

pub fn pem_to_pubkeys(buf: &[u8]) -> Result<impl Iterator<Item = Result<PublicKey>>> {
    let pems = pem::parse_many(buf).context("Failed to parse pem file")?;
    let iter = pems
        .into_iter()
        .filter(|pem| pem.tag() == PEM_PUBLIC_KEY)
        .map(|pem| {
            PublicKey::from_spki(pem.contents(), SignatureScheme::Ed25519)
                .context("Failed to parse public key")
        });
    Ok(iter)
}

pub fn load_or_create_privkey_pem(path: &Path) -> Result<PrivateKey> {
    let privkey = utils::load_or_create(path, || {
        info!("generating new signing private key: {path:?}");
        let privkey = PrivateKey::new(KeyType::Ed25519)?;
        let pem = privkey_to_pem(Secret(privkey));
        Ok(pem.into_bytes())
    })?;

    pem_to_privkeys(&privkey)?
        .next()
        .context("No private key found in PEM file")?
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub metablock: Metablock,
}

impl Attestation {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let metablock = serde_json::from_slice::<Metablock>(bytes)?;
        Ok(Self { metablock })
    }

    pub fn has_signature(&self, pubkey: &PublicKey) -> bool {
        self.metablock
            .signatures
            .iter()
            .any(|sig| sig.key_id() == pubkey.key_id())
    }

    pub fn sign(&mut self, privkey: &PrivateKey) -> Result<()> {
        debug!("creating signature on attestation");
        let new = Metablock::new(self.metablock.metadata.clone(), &[privkey])?;
        self.metablock.signatures.extend(new.signatures);
        Ok(())
    }

    /// Check whether `pubkey` has a valid signature on this attestation.
    ///
    /// Unlike `verify`, this inspects only the signature belonging to `pubkey`.
    /// `Metablock::verify` takes a threshold and a *set* of authorized keys, so
    /// asking it about one key makes it log every other signature as
    /// unauthorized.
    pub fn check_signature(&self, pubkey: &PublicKey) -> Result<SignatureCheck> {
        let Some(signature) = self
            .metablock
            .signatures
            .iter()
            .find(|sig| sig.key_id() == pubkey.key_id())
        else {
            return Ok(SignatureCheck::Missing);
        };

        // The signed message, as `Metablock` constructs it.
        let raw = self.metablock.metadata.to_bytes()?;
        let message = String::from_utf8(raw)
            .context("Attestation metadata is not valid UTF-8")?
            .replace("\\n", "\n");

        if pubkey.verify(message.as_bytes(), signature).is_ok() {
            Ok(SignatureCheck::Valid)
        } else {
            Ok(SignatureCheck::Invalid)
        }
    }

    pub fn verify<'a, I>(&self, threshold: u32, authorized_keys: I) -> Result<MetadataWrapper>
    where
        I: IntoIterator<Item = &'a PublicKey>,
    {
        let metadata = self.metablock.verify(threshold, authorized_keys)?;
        Ok(metadata)
    }

    pub fn serialize(&self) -> Result<String> {
        serde_json::to_string(&self.metablock).context("Failed to serialize attestation")
    }

    pub async fn to_compressed_bytes(&self) -> Result<Vec<u8>> {
        let json = self.serialize()?;
        let compressed = zstd_compress(json.as_bytes()).await?;
        Ok(compressed)
    }
}

/// Whether a given key has signed an attestation, and whether that signature
/// holds.
///
/// "No signature from this key" and "a signature that does not verify" are very
/// different situations -- the first is a worker that predates signing, the
/// second is a forgery or a bug -- so they are not collapsed into a bool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureCheck {
    /// The attestation carries no signature from this key.
    Missing,
    /// A signature from this key is present but does not verify.
    Invalid,
    /// A signature from this key is present and verifies.
    Valid,
}

/// Reconstruct a worker's in-toto public key from the form it registers with.
///
/// A worker's identity is `BASE64(raw ed25519 public key)`, and it signs with a
/// key loaded through `PrivateKey::from_pkcs8`, which attaches the
/// python-securesystemslib compatible `keyid_hash_algorithms`. The keyid is a
/// hash over those fields, so they have to be reproduced here exactly or the
/// reconstructed key gets a different keyid and matches nothing.
pub fn worker_pubkey(key: &str) -> Result<PublicKey> {
    let bytes = BASE64
        .decode(key.as_bytes())
        .context("Worker key is not valid base64")?;

    PublicKey::from_ed25519_with_keyid_hash_algorithms(
        bytes,
        Some(vec!["sha256".to_string(), "sha512".to_string()]),
    )
    .context("Failed to parse worker key as ed25519")
}

/// Check a possibly zstd-compressed attestation for a valid signature by `pubkey`.
pub async fn check_compressed_attestation_signature(
    bytes: &[u8],
    pubkey: &PublicKey,
) -> Result<SignatureCheck> {
    let decompressed = if is_zstd_compressed(bytes) {
        Cow::Owned(zstd_decompress(bytes).await.map_err(Error::from)?)
    } else {
        Cow::Borrowed(bytes)
    };

    let attestation = Attestation::parse(&decompressed)?;
    attestation.check_signature(pubkey)
}

/// Makes sure the attestation is signed by our private key
/// Returns true if a signature was created, returns false if attestation was already signed by us
pub async fn compressed_attestation_sign_if_necessary(
    bytes: Vec<u8>,
    privkey: &PrivateKey,
) -> Result<(Vec<u8>, bool)> {
    let decompressed = if is_zstd_compressed(&bytes) {
        let decompressed = zstd_decompress(&bytes).await.map_err(Error::from)?;
        Cow::Owned(decompressed)
    } else {
        Cow::Borrowed(&bytes)
    };

    let mut attestation = Attestation::parse(&decompressed)?;
    if attestation.has_signature(privkey.public()) {
        Ok((bytes, false))
    } else {
        attestation.sign(privkey)?;

        let compressed = attestation.to_compressed_bytes().await?;
        Ok((compressed, true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::HEXLOWER;
    use in_toto::{
        crypto::{HashAlgorithm, HashValue, KeyType, Signature, SignatureScheme},
        models::{LinkMetadata, MetadataWrapper, VirtualTargetPath},
    };
    use serde_json::Value;

    // temporary until https://github.com/in-toto/in-toto-rs/pull/111 lands
    fn hashvalue_from_hex(hex: &str) -> Result<HashValue> {
        let bytes = HEXLOWER.decode(hex.as_bytes())?;
        Ok(HashValue::new(bytes))
    }

    // temporary until https://github.com/in-toto/in-toto-rs/pull/111 lands
    fn signature(keyid: &str, value: &str) -> Signature {
        let value = Value::Object(
            [
                ("keyid".to_string(), Value::String(keyid.to_string())),
                ("sig".to_string(), Value::String(value.to_string())),
            ]
            .into_iter()
            .collect(),
        );
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn test_parse() {
        let json = r#"{"signatures":[{"keyid":"c25d24c04760b6982de77736776edc6600d5f8e1e84d0bba2a7299959ce7d47f","sig":"8cd70318ea1b34c91bf7303e9c8811df43d1b4746aa9adf1d503ebb0241e0fbff9be28f36dac0318825782bf05dbbcea7171eb0ca9a89be3b02666f0f3c84301"}],"signed":{"_type":"link","name":"rebuild spytrap-adb_0.3.5-1_amd64.deb","materials":{"rust-spytrap-adb_0.3.5-1_amd64.buildinfo":{"sha512":"d130dbdbd51480f5cb79c1e6ce09fa61a69766e56725543b9c19bee8248306b2c3c2a2c66b250992bf20b2f5af7cf03bf401255104714bc9d654126fb41bc59f","sha256":"9df2f9a721f5016874c5f78ae88d3df77f9e49ea6070f935bfeeb438cd73a158"}},"products":{"spytrap-adb_0.3.5-1_amd64.deb":{"sha256":"58a7d451d5d59fda6284a05418b99e34fab32d07e63d0b164404eaaed1317edd","sha512":"f38806536701138cb1b2059565e5f73ec07288f9a3013ba986e33d510432e183e7bfe94af31bb8d480b85c84f4c145ed5c28c5949d618a4e94b2c7aecb309642"}},"environment":null,"byproducts":{},"command":[]}}"#;
        let metablock = Attestation::parse(json.as_bytes()).unwrap();
        assert_eq!(metablock, Attestation {
            metablock: Metablock {
                signatures: vec![signature(
                    "c25d24c04760b6982de77736776edc6600d5f8e1e84d0bba2a7299959ce7d47f",
                    "8cd70318ea1b34c91bf7303e9c8811df43d1b4746aa9adf1d503ebb0241e0fbff9be28f36dac0318825782bf05dbbcea7171eb0ca9a89be3b02666f0f3c84301",
                )],
                metadata: MetadataWrapper::Link(LinkMetadata {
                    name: "rebuild spytrap-adb_0.3.5-1_amd64.deb".to_string(),
                    materials: [
                        (VirtualTargetPath::new("rust-spytrap-adb_0.3.5-1_amd64.buildinfo".to_string()).unwrap(), [
                            (HashAlgorithm::Sha512, hashvalue_from_hex("d130dbdbd51480f5cb79c1e6ce09fa61a69766e56725543b9c19bee8248306b2c3c2a2c66b250992bf20b2f5af7cf03bf401255104714bc9d654126fb41bc59f").unwrap()),
                            (HashAlgorithm::Sha256, hashvalue_from_hex("9df2f9a721f5016874c5f78ae88d3df77f9e49ea6070f935bfeeb438cd73a158").unwrap()),
                        ].into_iter().collect()),
                    ].into_iter().collect(),
                    products: [
                        (VirtualTargetPath::new("spytrap-adb_0.3.5-1_amd64.deb".to_string()).unwrap(), [
                            (HashAlgorithm::Sha256, hashvalue_from_hex("58a7d451d5d59fda6284a05418b99e34fab32d07e63d0b164404eaaed1317edd").unwrap()),
                            (HashAlgorithm::Sha512, hashvalue_from_hex("f38806536701138cb1b2059565e5f73ec07288f9a3013ba986e33d510432e183e7bfe94af31bb8d480b85c84f4c145ed5c28c5949d618a4e94b2c7aecb309642").unwrap()),
                        ].into_iter().collect()),
                    ].into_iter().collect(),
                    env: None,
                    byproducts: Default::default(),
                    command: vec![].into(),
                })
            }
        });
    }

    #[test]
    fn test_append_signature() {
        // generate keypair
        let privkey = PrivateKey::new(KeyType::Ed25519).unwrap();
        let privkey = PrivateKey::from_pkcs8(&privkey, SignatureScheme::Ed25519).unwrap();
        let pubkey = privkey.public();

        // take a metablock
        let json = r#"{"signatures":[{"keyid":"c25d24c04760b6982de77736776edc6600d5f8e1e84d0bba2a7299959ce7d47f","sig":"8cd70318ea1b34c91bf7303e9c8811df43d1b4746aa9adf1d503ebb0241e0fbff9be28f36dac0318825782bf05dbbcea7171eb0ca9a89be3b02666f0f3c84301"}],"signed":{"_type":"link","name":"rebuild spytrap-adb_0.3.5-1_amd64.deb","materials":{"rust-spytrap-adb_0.3.5-1_amd64.buildinfo":{"sha512":"d130dbdbd51480f5cb79c1e6ce09fa61a69766e56725543b9c19bee8248306b2c3c2a2c66b250992bf20b2f5af7cf03bf401255104714bc9d654126fb41bc59f","sha256":"9df2f9a721f5016874c5f78ae88d3df77f9e49ea6070f935bfeeb438cd73a158"}},"products":{"spytrap-adb_0.3.5-1_amd64.deb":{"sha256":"58a7d451d5d59fda6284a05418b99e34fab32d07e63d0b164404eaaed1317edd","sha512":"f38806536701138cb1b2059565e5f73ec07288f9a3013ba986e33d510432e183e7bfe94af31bb8d480b85c84f4c145ed5c28c5949d618a4e94b2c7aecb309642"}},"environment":null,"byproducts":{},"command":[]}}"#;
        let mut attestation = Attestation::parse(json.as_bytes()).unwrap();

        // ensure it's not valid yet
        attestation.verify(1, [pubkey]).unwrap_err();
        assert!(!attestation.has_signature(pubkey));

        // append a signature with our key
        attestation.sign(&privkey).unwrap();

        // ensure it's valid now
        attestation.verify(1, [pubkey]).unwrap();
        assert!(attestation.has_signature(pubkey));
    }

    #[test]
    fn test_load_privkey() {
        let mut iter = pem_to_privkeys(
            b"-----BEGIN PRIVATE KEY-----
            MFECAQEwBQYDK2VwBCIEINOWEV/DNN+AsZ+pLoixusXNmgS5x0TNXvkLQUnKz92k
            gSEAB5ySaw+WE9Ut06fYlPf2V4+5gbFHA5HZJK7n2WWAGvA=
            -----END PRIVATE KEY-----
            ",
        )
        .unwrap();
        let privkey = iter.next().unwrap().unwrap();
        let pubkey = pubkey_to_pem(privkey.public()).unwrap();
        assert_eq!(
            pubkey,
            "-----BEGIN PUBLIC KEY-----\r\n\
        MCwwBwYDK2VwBQADIQAHnJJrD5YT1S3Tp9iU9/ZXj7mBsUcDkdkkrufZZYAa8A==\r\n\
        -----END PUBLIC KEY-----\r\n\
        "
        );
    }

    fn worker_key() -> (PrivateKey, String) {
        // Exactly what worker/src/auth.rs does.
        let der = PrivateKey::new(KeyType::Ed25519).unwrap();
        let privkey = PrivateKey::from_pkcs8(&der, SignatureScheme::Ed25519).unwrap();
        let registered = BASE64.encode(privkey.public().as_bytes());
        (privkey, registered)
    }

    fn attestation_signed_by(privkey: &PrivateKey) -> Attestation {
        let metadata = MetadataWrapper::Link(LinkMetadata {
            name: "rebuild example_1.0_all.deb".to_string(),
            materials: Default::default(),
            products: Default::default(),
            env: None,
            byproducts: Default::default(),
            command: vec![].into(),
        });
        Attestation {
            metablock: Metablock::new(metadata, &[privkey]).unwrap(),
        }
    }

    /// The keyid is a hash over keytype, scheme, keyval *and*
    /// keyid_hash_algorithms. The worker signs with a key loaded through
    /// `from_pkcs8`, which sets the python-sslib compatible value, so
    /// reconstructing without it yields a different keyid that silently matches
    /// no signature at all.
    #[test]
    fn test_worker_pubkey_keyid_matches_the_signing_key() {
        let (privkey, registered) = worker_key();

        assert_eq!(
            worker_pubkey(&registered).unwrap().key_id(),
            privkey.public().key_id(),
            "reconstructed worker key has a different keyid than the signing key"
        );
    }

    #[test]
    fn test_check_signature_valid() {
        let (privkey, registered) = worker_key();
        let attestation = attestation_signed_by(&privkey);

        assert_eq!(
            attestation
                .check_signature(&worker_pubkey(&registered).unwrap())
                .unwrap(),
            SignatureCheck::Valid
        );
    }

    /// A key that never signed is "missing", not "invalid" -- the daemon treats
    /// those differently.
    #[test]
    fn test_check_signature_missing() {
        let (privkey, _) = worker_key();
        let (_, other_registered) = worker_key();
        let attestation = attestation_signed_by(&privkey);

        assert_eq!(
            attestation
                .check_signature(&worker_pubkey(&other_registered).unwrap())
                .unwrap(),
            SignatureCheck::Missing
        );
    }

    /// A signature over different metadata must be reported as invalid rather
    /// than quietly passing.
    #[test]
    fn test_check_signature_invalid() {
        let (privkey, registered) = worker_key();
        let mut attestation = attestation_signed_by(&privkey);

        attestation.metablock.metadata = MetadataWrapper::Link(LinkMetadata {
            name: "rebuild something_else.deb".to_string(),
            materials: Default::default(),
            products: Default::default(),
            env: None,
            byproducts: Default::default(),
            command: vec![].into(),
        });

        assert_eq!(
            attestation
                .check_signature(&worker_pubkey(&registered).unwrap())
                .unwrap(),
            SignatureCheck::Invalid
        );
    }

    #[test]
    fn test_worker_pubkey_rejects_garbage() {
        assert!(worker_pubkey("not a key").is_err());
        assert!(worker_pubkey(&BASE64.encode(b"too short")).is_err());
    }
}
