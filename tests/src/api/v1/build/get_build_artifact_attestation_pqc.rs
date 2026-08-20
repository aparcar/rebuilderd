//! The daemon's post-quantum countersignature.
//!
//! The signature lives inside the in-toto metablock alongside the Ed25519 one,
//! so these tests assert on what `GET .../attestation` actually serves rather
//! than on a separate endpoint.

use crate::actions::*;
use crate::fixtures::server::IsolatedServer;
use crate::fixtures::*;
use rebuilderd::attestation::Attestation;
use rebuilderd::pqc;
use rebuilderd_common::api::v1::{BuildRestApi, MetaRestApi, PackageRestApi};
use rstest::rstest;

/// Fetch the ids of the single artifact in a freshly rebuilt package.
async fn single_artifact(client: &rebuilderd_common::api::Client) -> (i32, i32) {
    let package = client
        .get_binary_packages(None, None, None)
        .await
        .map(|p| p.records)
        .unwrap()
        .pop()
        .unwrap();

    (package.build_id.unwrap(), package.artifact_id.unwrap())
}

async fn pqc_public_key(client: &rebuilderd_common::api::Client) -> in_toto::crypto::PublicKey {
    let response = client.get_pqc_public_keys().await.unwrap();
    let pem = response
        .current
        .first()
        .expect("a pqc public key is served");

    let pem = pem::parse(pem.as_bytes()).unwrap();
    in_toto::crypto::PublicKey::from_spki(pem.contents(), pqc::SCHEME).unwrap()
}

#[rstest]
#[tokio::test]
pub async fn attestation_carries_a_post_quantum_signature(mut isolated_server: IsolatedServer) {
    let client = &isolated_server.client;

    register_worker(client).await;
    import_single_package(client).await;
    report_good_rebuild_with_signed_attestation(client).await;

    let (build_id, artifact_id) = single_artifact(client).await;
    let attestation = client
        .get_build_artifact_attestation(build_id, artifact_id)
        .await
        .unwrap();
    let attestation = Attestation::parse(&attestation).unwrap();

    let pqc_key = pqc_public_key(client).await;
    assert!(
        attestation.has_signature(&pqc_key),
        "served attestation has no post-quantum signature"
    );
    attestation
        .verify(1, [&pqc_key])
        .expect("post-quantum signature verifies");

    isolated_server.shutdown().await;
}

/// The point of the exercise: the worker's Ed25519 signature and the daemon's
/// ML-DSA one coexist, so a break of either algorithm leaves the other binding.
#[rstest]
#[tokio::test]
pub async fn classical_and_post_quantum_signatures_coexist(mut isolated_server: IsolatedServer) {
    let client = &isolated_server.client;

    register_worker(client).await;
    import_single_package(client).await;
    report_good_rebuild_with_signed_attestation(client).await;

    let (build_id, artifact_id) = single_artifact(client).await;
    let attestation = client
        .get_build_artifact_attestation(build_id, artifact_id)
        .await
        .unwrap();
    let attestation = Attestation::parse(&attestation).unwrap();

    // worker's signature + daemon's ed25519 + daemon's ml-dsa
    assert!(
        attestation.metablock.signatures.len() >= 3,
        "expected at least three signatures, got {}",
        attestation.metablock.signatures.len()
    );

    let mut classical = Vec::new();
    for pem in client.get_public_keys().await.unwrap().current {
        for key in rebuilderd::attestation::pem_to_pubkeys(pem.as_bytes()).unwrap() {
            classical.push(key.unwrap());
        }
    }
    let pqc_key = pqc_public_key(client).await;

    // each half stands on its own...
    attestation
        .verify(1, &classical)
        .expect("ed25519 signature verifies alone");
    attestation
        .verify(1, [&pqc_key])
        .expect("ml-dsa signature verifies alone");

    // ...and the keyids are distinct, i.e. these really are two signatures.
    assert!(
        classical.iter().all(|k| k.key_id() != pqc_key.key_id()),
        "classical and post-quantum keyids collide"
    );

    isolated_server.shutdown().await;
}

/// Re-requesting must not append a second copy of the same signature.
#[rstest]
#[tokio::test]
pub async fn countersigning_is_idempotent(mut isolated_server: IsolatedServer) {
    let client = &isolated_server.client;

    register_worker(client).await;
    import_single_package(client).await;
    report_good_rebuild_with_signed_attestation(client).await;

    let (build_id, artifact_id) = single_artifact(client).await;

    let first = client
        .get_build_artifact_attestation(build_id, artifact_id)
        .await
        .unwrap();
    let second = client
        .get_build_artifact_attestation(build_id, artifact_id)
        .await
        .unwrap();

    assert_eq!(first, second, "second request changed the attestation");

    isolated_server.shutdown().await;
}
