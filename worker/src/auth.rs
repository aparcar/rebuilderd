use data_encoding::BASE64;
use in_toto::crypto::{KeyType, PrivateKey, SignatureScheme};
use rebuilderd_common::api::Client;
use rebuilderd_common::config::ConfigFile;
use rebuilderd_common::errors::*;
use rebuilderd_common::utils;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

/// Parameter set for the worker's post-quantum key. Must match the daemon's
/// so that both signatures on a link use the same scheme.
#[cfg(feature = "pqc")]
const PQC_SCHEME: SignatureScheme = SignatureScheme::MlDsa65V1;

pub struct Profile {
    pub pubkey: String,
    pub privkey: PrivateKey,
    /// Post-quantum key used to co-sign links, alongside `privkey`.
    #[cfg(feature = "pqc")]
    pub pqc_privkey: PrivateKey,
}

impl Profile {
    pub fn new_client(
        &self,
        config: ConfigFile,
        endpoint: String,
        signup_secret: Option<String>,
        auth_cookie: Option<String>,
    ) -> Result<Client> {
        let mut client = Client::new(config, Some(endpoint))?;
        client.worker_key(self.pubkey.clone());
        if let Some(signup_secret) = signup_secret {
            client.signup_secret(signup_secret);
        } else if let Some(auth_cookie) = auth_cookie {
            client.auth_cookie(auth_cookie);
        }
        Ok(client)
    }
}

#[inline]
pub fn load() -> Result<Profile> {
    match fs::remove_file("rebuilder.key") {
        Ok(_) => info!("Deleted old v1 worker key"),
        Err(err) if err.kind() == ErrorKind::NotFound => (),
        Err(err) => warn!("Failed to delete old v1 worker key: {:#}", err),
    }

    load_key("rebuilder.v2.key")
}

/// The worker's post-quantum signing key.
///
/// Kept in the same raw PKCS#8 form as `rebuilder.v2.key` rather than the
/// daemon's PEM convention, so the two worker keys are handled alike.
#[cfg(feature = "pqc")]
fn load_pqc_key<P: AsRef<Path>>(path: P) -> Result<PrivateKey> {
    let privkey = utils::load_or_create(path.as_ref(), || {
        info!("generating new post-quantum worker key");
        PrivateKey::new_mldsa(PQC_SCHEME).map_err(Error::from)
    })?;

    PrivateKey::from_pkcs8(&privkey, PQC_SCHEME).map_err(Error::from)
}

fn load_key<P: AsRef<Path>>(path: P) -> Result<Profile> {
    let privkey = utils::load_or_create(path.as_ref(), || {
        PrivateKey::new(KeyType::Ed25519).map_err(Error::from)
    })?;

    let privkey = PrivateKey::from_pkcs8(&privkey, SignatureScheme::Ed25519)?;
    let pubkey = BASE64.encode(privkey.public().as_bytes());

    #[cfg(feature = "pqc")]
    let pqc_privkey = load_pqc_key("rebuilder.pqc.key")?;

    Ok(Profile {
        pubkey,
        privkey,
        #[cfg(feature = "pqc")]
        pqc_privkey,
    })
}
