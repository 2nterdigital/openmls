use openmls_traits::random::OpenMlsRand;
#[cfg(feature = "virtual-clients-draft")]
use openmls_traits::types::CryptoError;

#[cfg(feature = "virtual-clients-draft")]
use super::test_sender_ratchet::FailingCrypto;
#[cfg(feature = "virtual-clients-draft")]
use crate::tree::dual_use_ratchet::GenerationLaneContext;
use crate::{
    binary_tree::{array_representation::TreeSize, LeafNodeIndex},
    schedule::EncryptionSecret,
    tree::{secret_tree::*, sender_ratchet::SenderRatchetConfiguration},
};
use std::collections::HashMap;

#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn invalid_generation_lane_does_not_initialize_secret_tree() {
    let provider = &Provider::default();
    let encryption_secret = EncryptionSecret::random(ciphersuite, provider.rand());
    let mut secret_tree =
        SecretTree::new(encryption_secret, TreeSize::new(2), LeafNodeIndex::new(0));
    let before = secret_tree.clone();
    let invalid_lane = GenerationLaneContext::new(TreeSize::new(2), LeafNodeIndex::new(2));

    let err = secret_tree
        .secret_for_application_encryption_in_generation_lane(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(0),
            invalid_lane,
            &SenderRatchetConfiguration::default(),
        )
        .expect_err("invalid lane must be rejected before sender-ratchet initialization");

    assert_eq!(err, SecretTreeError::GenerationLaneInvalidResidue);
    assert_eq!(secret_tree, before);
}

#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn generation_lane_initialization_failure_leaves_secret_tree_unchanged() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let crypto = FailingCrypto::failing_on_expand(3);
    let encryption_secret = EncryptionSecret::random(ciphersuite, provider.rand());
    let mut secret_tree =
        SecretTree::new(encryption_secret, TreeSize::new(4), LeafNodeIndex::new(0));
    let before = secret_tree.clone();
    let lane = GenerationLaneContext::new(TreeSize::new(4), LeafNodeIndex::new(0));

    let error = secret_tree
        .secret_for_application_encryption_in_generation_lane(
            ciphersuite,
            &crypto,
            LeafNodeIndex::new(0),
            lane,
            configuration,
        )
        .expect_err("the second tree derivation must fail deterministically");

    assert_eq!(
        error,
        SecretTreeError::CryptoError(CryptoError::CryptoLibraryError)
    );
    assert_eq!(secret_tree, before);
}

// This tests the boundaries of the generations from a SecretTree
#[openmls_test::openmls_test]
fn test_boundaries() {
    let provider = &Provider::default();

    let configuration = &SenderRatchetConfiguration::default();
    let encryption_secret = EncryptionSecret::random(ciphersuite, provider.rand());
    let mut secret_tree = SecretTree::new(
        encryption_secret,
        TreeSize::from_leaf_count(3u32),
        LeafNodeIndex::new(2u32),
    );
    assert_eq!(secret_tree.own_index(), LeafNodeIndex::new(2u32));
    let secret_type = SecretType::ApplicationSecret;
    assert!(secret_tree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(0u32),
            secret_type,
            0,
            configuration
        )
        .is_ok());
    assert!(secret_tree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(1u32),
            secret_type,
            0,
            configuration
        )
        .is_ok());
    assert!(secret_tree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(0u32),
            secret_type,
            1,
            configuration
        )
        .is_ok());
    assert!(secret_tree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(0u32),
            secret_type,
            1_000,
            configuration,
        )
        .is_ok());
    assert_eq!(
        secret_tree.secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(1u32),
            secret_type,
            // We're at generation 1, so 1001 is still ok.
            1002,
            configuration,
        ),
        Err(SecretTreeError::TooDistantInTheFuture)
    );
    assert!(secret_tree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(0u32),
            secret_type,
            996,
            configuration,
        )
        .is_ok());
    assert_eq!(
        secret_tree.secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(0u32),
            secret_type,
            995,
            configuration,
        ),
        Err(SecretTreeError::TooDistantInThePast)
    );
    assert_eq!(
        secret_tree.secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(4u32),
            secret_type,
            0,
            configuration,
        ),
        Err(SecretTreeError::IndexOutOfBounds)
    );
    let encryption_secret = EncryptionSecret::random(ciphersuite, provider.rand());
    let mut largetree = SecretTree::new(
        encryption_secret,
        TreeSize::from_leaf_count(100_000u32),
        LeafNodeIndex::new(2u32),
    );
    assert!(largetree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(0u32),
            secret_type,
            0,
            configuration
        )
        .is_ok());
    largetree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(99_999u32),
            secret_type,
            0,
            configuration,
        )
        .unwrap();
    assert!(largetree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(99_999u32),
            secret_type,
            1_000,
            configuration,
        )
        .is_ok());
    assert_eq!(
        largetree.secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(200_000u32),
            secret_type,
            0,
            configuration,
        ),
        Err(SecretTreeError::IndexOutOfBounds)
    );
}

// This tests if the generation gets incremented correctly and that the returned
// values are unique.
#[openmls_test::openmls_test]
fn increment_generation() {
    let provider = &Provider::default();

    const SIZE: usize = 100;
    const MAX_GENERATIONS: usize = 10;

    let mut unique_values: HashMap<Vec<u8>, bool> = HashMap::new();
    let encryption_secret = EncryptionSecret::random(ciphersuite, provider.rand());
    let mut secret_tree = SecretTree::new(
        encryption_secret,
        TreeSize::from_leaf_count(SIZE as u32),
        LeafNodeIndex::new(0u32),
    );
    for i in 0..SIZE {
        assert_eq!(
            secret_tree.generation(LeafNodeIndex::new(i as u32), SecretType::HandshakeSecret),
            0
        );
        assert_eq!(
            secret_tree.generation(LeafNodeIndex::new(i as u32), SecretType::ApplicationSecret),
            0
        );
    }
    for i in 0..MAX_GENERATIONS {
        // We are index 0, so we can't get a decryption secret for that leaf.
        for j in 1..SIZE {
            let next_gen =
                secret_tree.generation(LeafNodeIndex::new(j as u32), SecretType::HandshakeSecret);
            let (handshake_key, handshake_nonce) = secret_tree
                .secret_for_decryption(
                    ciphersuite,
                    provider.crypto(),
                    LeafNodeIndex::new(j as u32),
                    SecretType::HandshakeSecret,
                    i as u32,
                    &SenderRatchetConfiguration::default(),
                )
                .expect("Index out of bounds.");
            assert_eq!(next_gen, i as u32);
            assert!(unique_values
                .insert(handshake_key.as_slice().to_vec(), true)
                .is_none());
            assert!(unique_values
                .insert(handshake_nonce.as_slice().to_vec(), true)
                .is_none());
            let next_gen =
                secret_tree.generation(LeafNodeIndex::new(j as u32), SecretType::ApplicationSecret);
            let (application_key, application_nonce) = secret_tree
                .secret_for_decryption(
                    ciphersuite,
                    provider.crypto(),
                    LeafNodeIndex::new(j as u32),
                    SecretType::ApplicationSecret,
                    i as u32,
                    &SenderRatchetConfiguration::default(),
                )
                .expect("Index out of bounds.");
            assert_eq!(next_gen, i as u32);
            assert!(unique_values
                .insert(application_key.as_slice().to_vec(), true)
                .is_none());
            assert!(unique_values
                .insert(application_nonce.as_slice().to_vec(), true)
                .is_none());
        }
    }
}

#[openmls_test::openmls_test]
fn secret_tree() {
    let provider = &Provider::default();

    let leaf_index = 0u32;
    let generation = 0;
    let n_leaves = 10u32;
    let configuration = &SenderRatchetConfiguration::default();
    let mut secret_tree = SecretTree::new(
        EncryptionSecret::from_slice(
            &provider
                .rand()
                .random_vec(ciphersuite.hash_length())
                .expect("An unexpected error occurred.")[..],
        ),
        TreeSize::new(n_leaves),
        LeafNodeIndex::new(1u32),
    );
    let (application_secret_key, application_secret_nonce) = secret_tree
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            LeafNodeIndex::new(leaf_index),
            SecretType::ApplicationSecret,
            generation,
            configuration,
        )
        .expect("Error getting decryption secret");
    println!(
        "application_secret_key: {:x?}",
        application_secret_key.as_slice()
    );
    println!(
        "application_secret_nonce: {:x?}",
        application_secret_nonce.as_slice()
    );
}
