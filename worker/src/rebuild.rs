use crate::config;
use crate::diffoscope::diffoscope;
use crate::download::download;
use crate::heartbeat::HeartBeat;
use crate::log;
use crate::proc;
use in_toto::crypto::PrivateKey;
use in_toto::runlib::in_toto_run;
use rebuilderd_common::api::v1::{ArtifactStatus, QueuedJobArtifact, RebuildArtifactReport};
use rebuilderd_common::errors::Context as _;
use rebuilderd_common::errors::*;
use rebuilderd_common::utils::zstd_compress;
use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::time;

pub struct Context<'a> {
    pub artifacts: Vec<QueuedJobArtifact>,
    pub input_url: Option<String>,
    pub backend: config::Backend,
    pub build: config::Build,
    pub diffoscope: config::Diffoscope,
    pub privkey: &'a PrivateKey,
    /// Post-quantum key co-signing the link, alongside `privkey`.
    #[cfg(feature = "pqc")]
    pub pqc_privkey: &'a PrivateKey,
}

/// Append a post-quantum signature to a link the worker has already signed.
///
/// `in_toto_run` signs with a single key, so the second signature is added
/// afterwards. in-toto's `signatures` is a list, so the link carries both and a
/// break of either algorithm leaves the other binding.
#[cfg(feature = "pqc")]
fn append_pqc_signature(link: &mut in_toto::models::Metablock, privkey: &PrivateKey) -> Result<()> {
    let pqc = in_toto::models::Metablock::new(link.metadata.clone(), &[privkey])?;
    link.signatures.extend(pqc.signatures);
    Ok(())
}

fn path_to_string(path: &Path) -> Result<String> {
    let s = path
        .to_str()
        .with_context(|| anyhow!("Path contains invalid characters: {:?}", path))?;
    Ok(s.to_string())
}

pub async fn compare_files(a: &Path, b: &Path) -> Result<bool> {
    let mut buf1 = [0u8; 4096];
    let mut buf2 = [0u8; 4096];

    info!("Comparing {:?} with {:?}", a, b);
    let mut f1 = File::open(a)
        .await
        .with_context(|| anyhow!("Failed to open {:?}", a))?;
    let mut f2 = File::open(b)
        .await
        .with_context(|| anyhow!("Failed to open {:?}", b))?;

    let mut pos = 0;
    loop {
        // read up to 4k bytes from the first file
        let n = f1.read_buf(&mut &mut buf1[..]).await?;

        // check if the first file is end-of-file
        if n == 0 {
            debug!("First file is at end-of-file");

            // check if other file is eof too
            let n = f2.read_buf(&mut &mut buf2[..]).await?;
            if n > 0 {
                info!("Files are not identical, {:?} is longer", b);
                return Ok(false);
            } else {
                return Ok(true);
            }
        }

        // check the same chunk in the other file
        match f2.read_exact(&mut buf2[..n]).await {
            Ok(n) => n,
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
                info!("Files are not identical, {:?} is shorter", b);
                return Ok(false);
            }
            err => err?,
        };

        if buf1[..n] != buf2[..n] {
            // get the exact position
            // this can't panic because we've already checked the slices are not equal
            let pos = pos
                + buf1[..n]
                    .iter()
                    .zip(buf2[..n].iter())
                    .position(|(a, b)| a != b)
                    .unwrap();
            info!("Files {:?} and {:?} differ at position {}", a, b, pos);

            return Ok(false);
        }

        // advance the number of bytes that are equal
        pos += n;
    }
}

pub async fn rebuild_with_heartbeat(
    ctx: &Context<'_>,
    log: &mut log::Buffer,
    hb: &dyn HeartBeat,
) -> Result<Vec<RebuildArtifactReport>> {
    let mut rebuild = Box::pin(rebuild(ctx, log));
    loop {
        tokio::select! {
            res = &mut rebuild => {
                return res;
            },
            _ = time::sleep(hb.interval()) => hb.ping().await?,
        }
    }
}

pub async fn rebuild(
    ctx: &Context<'_>,
    log: &mut log::Buffer,
) -> Result<Vec<RebuildArtifactReport>> {
    // setup
    let tmp = tempfile::Builder::new().prefix("rebuilderd").tempdir()?;

    let inputs_dir = tmp.path().join("inputs");
    fs::create_dir(&inputs_dir).context("Failed to create inputs/ temp dir")?;

    let out_dir = tmp.path().join("out");
    fs::create_dir(&out_dir).context("Failed to create out/ temp dir")?;

    // download
    let mut artifacts = Vec::new();
    for artifact in &ctx.artifacts {
        let artifact_filename = download(&artifact.url, &inputs_dir)
            .await
            .with_context(|| {
                anyhow!(
                    "Failed to download original package from {:?}",
                    artifact.url
                )
            })?;
        let artifact_path = inputs_dir.join(&artifact_filename);
        artifacts.push((artifact.clone(), artifact_filename, artifact_path));
    }

    let input_filename = if let Some(input_url) = &ctx.input_url {
        download(input_url, &inputs_dir)
            .await
            .with_context(|| anyhow!("Failed to download build input from {:?}", input_url))?
    } else {
        artifacts
            .first()
            .context("Failed to use first artifact as build input")?
            .1
            .to_owned()
    };
    let input_path = inputs_dir.join(&input_filename);

    // rebuild
    verify(ctx, log, &out_dir, &input_path).await?;

    // process results
    let mut results = Vec::new();
    for (artifact, artifact_filename, artifact_path) in artifacts {
        let output_path = out_dir.join(&artifact_filename);

        let result = if !output_path.exists() {
            info!(
                "No output artifact found, marking as BAD: {:?}",
                output_path
            );

            RebuildArtifactReport {
                name: artifact.name,
                diffoscope: None,
                attestation: None,
                status: ArtifactStatus::Bad,
            }
        } else if compare_files(&artifact_path, &output_path).await? {
            info!(
                "Output artifacts is identical, marking as GOOD: {:?}",
                output_path
            );

            let mut res = RebuildArtifactReport {
                name: artifact.name,
                diffoscope: None,
                attestation: None,
                status: ArtifactStatus::Good,
            };

            info!("Generating signed link");
            match in_toto_run(
                &format!("rebuild {}", artifact_filename.to_str().unwrap()),
                None,
                &[input_path
                    .to_str()
                    .ok_or_else(|| anyhow!("Input path contains invalid characters"))?],
                &[output_path
                    .to_str()
                    .ok_or_else(|| anyhow!("Output path contains invalid characters"))?],
                &[],
                Some(ctx.privkey),
                Some(&["sha512", "sha256"]),
                Some(&[
                    &format!("{}/", inputs_dir.to_str().unwrap()),
                    &format!("{}/", out_dir.to_str().unwrap()),
                ]),
            ) {
                Ok(signed_link) => {
                    info!("Signed link generated");

                    // in_toto_run signs with a single key, so the post-quantum
                    // signature is appended here. in-toto's `signatures` is a
                    // list, so the link ends up carrying both -- a break of
                    // either algorithm leaves the other binding.
                    #[cfg(feature = "pqc")]
                    let signed_link = {
                        let mut signed_link = signed_link;
                        append_pqc_signature(&mut signed_link, ctx.pqc_privkey)
                            .context("Failed to create post-quantum link signature")?;
                        info!("Post-quantum link signature generated");
                        signed_link
                    };

                    let attestation = serde_json::to_string(&signed_link)
                        .context("Failed to serialize attestation")?;

                    let encoded_attestation = zstd_compress(attestation.as_bytes())
                        .await
                        .map_err(Error::from)?;

                    res.attestation = Some(encoded_attestation);
                }
                Err(err) => warn!("Failed to generate in-toto attestation: {:#?}", err),
            }

            res
        } else {
            info!("Output artifact differs, marking as BAD: {:?}", output_path);

            let mut res = RebuildArtifactReport {
                name: artifact.name,
                diffoscope: None,
                attestation: None,
                status: ArtifactStatus::Bad,
            };

            // generate diffoscope diff if enabled
            if ctx.diffoscope.enabled {
                let diff = diffoscope(&artifact_path, &output_path, &ctx.diffoscope)
                    .await
                    .context("Failed to run diffoscope")?;

                let encoded_diffoscope =
                    zstd_compress(diff.as_bytes()).await.map_err(Error::from)?;

                res.diffoscope = Some(encoded_diffoscope);
            }

            res
        };

        results.push(result);
    }

    Ok(results)
}

async fn verify(
    ctx: &Context<'_>,
    log: &mut log::Buffer,
    out_dir: &Path,
    input_path: &Path,
) -> Result<()> {
    let bin = &ctx.backend.path;
    let timeout = ctx.build.timeout.unwrap_or(3600 * 24); // 24h

    let mut envs = HashMap::new();
    envs.insert("REBUILDERD_OUTDIR".into(), path_to_string(out_dir)?);

    let opts = proc::Options {
        timeout: Duration::from_secs(timeout),
        kill_at_size_limit: false,
        passthrough: !ctx.build.silent,
        envs,
    };

    proc::run(bin.as_ref(), &[input_path], opts, log).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn compare_files_equal() {
        let equal = compare_files(Path::new("src/main.rs"), Path::new("src/main.rs"))
            .await
            .unwrap();
        assert!(equal);
    }

    #[tokio::test]
    async fn compare_files_not_equal1() {
        let equal = compare_files(Path::new("src/main.rs"), Path::new("Cargo.toml"))
            .await
            .unwrap();
        assert!(!equal);
    }

    #[tokio::test]
    async fn compare_files_not_equal2() {
        let equal = compare_files(Path::new("Cargo.toml"), Path::new("src/main.rs"))
            .await
            .unwrap();
        assert!(!equal);
    }

    #[tokio::test]
    async fn compare_large_files_equal() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a"), [0u8; 4096 * 100]).unwrap();
        fs::write(dir.path().join("b"), [0u8; 4096 * 100]).unwrap();
        let equal = compare_files(&dir.path().join("a"), &dir.path().join("b"))
            .await
            .unwrap();
        assert!(equal);
    }

    #[tokio::test]
    async fn compare_large_files_not_equal() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a"), [0u8; 4096 * 100]).unwrap();
        fs::write(dir.path().join("b"), [1u8; 4096 * 100]).unwrap();
        let equal = compare_files(&dir.path().join("a"), &dir.path().join("b"))
            .await
            .unwrap();
        assert!(!equal);
    }
}

#[cfg(all(test, feature = "pqc"))]
mod pqc_tests {
    use super::*;
    use in_toto::crypto::{KeyType, SignatureScheme};
    use in_toto::models::{LinkMetadataBuilder, Metablock, MetadataWrapper};

    const PQC_SCHEME: SignatureScheme = SignatureScheme::MlDsa65V1;

    fn ed25519_key() -> PrivateKey {
        let der = PrivateKey::new(KeyType::Ed25519).unwrap();
        PrivateKey::from_pkcs8(&der, SignatureScheme::Ed25519).unwrap()
    }

    fn mldsa_key() -> PrivateKey {
        let der = PrivateKey::new_mldsa(PQC_SCHEME).unwrap();
        PrivateKey::from_pkcs8(&der, PQC_SCHEME).unwrap()
    }

    fn link(privkey: &PrivateKey) -> Metablock {
        let metadata = MetadataWrapper::Link(
            LinkMetadataBuilder::new()
                .name("rebuild example_1.0_all.deb".to_string())
                .build()
                .unwrap(),
        );
        Metablock::new(metadata, &[privkey]).unwrap()
    }

    /// The worker's link must end up carrying a classical *and* a post-quantum
    /// signature, each verifying on its own.
    #[test]
    fn appends_a_second_signature() {
        let classical = ed25519_key();
        let pqc = mldsa_key();

        let mut link = link(&classical);
        assert_eq!(link.signatures.len(), 1);

        append_pqc_signature(&mut link, &pqc).unwrap();
        assert_eq!(link.signatures.len(), 2);

        link.verify(1, [classical.public()])
            .expect("ed25519 signature still verifies alone");
        link.verify(1, [pqc.public()])
            .expect("ml-dsa signature verifies alone");
        link.verify(2, [classical.public(), pqc.public()])
            .expect("both verify together");
    }

    /// Appending must not disturb the signature that was already there.
    #[test]
    fn does_not_invalidate_the_existing_signature() {
        let classical = ed25519_key();
        let mut link = link(&classical);
        let before = link.signatures[0].clone();

        append_pqc_signature(&mut link, &mldsa_key()).unwrap();

        assert_eq!(link.signatures[0], before);
    }

    #[test]
    fn survives_a_json_roundtrip() {
        let classical = ed25519_key();
        let pqc = mldsa_key();

        let mut link = link(&classical);
        append_pqc_signature(&mut link, &pqc).unwrap();

        let json = serde_json::to_string(&link).unwrap();
        let parsed: Metablock = serde_json::from_str(&json).unwrap();

        parsed
            .verify(2, [classical.public(), pqc.public()])
            .expect("both signatures survive serialisation");
    }
}
