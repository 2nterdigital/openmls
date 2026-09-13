#[cfg(feature = "virtual-clients-draft")]
use crate::binary_tree::{array_representation::TreeSize, LeafNodeIndex};
#[cfg(feature = "virtual-clients-draft")]
use crate::tree::dual_use_ratchet::{DualUseRatchet, GenerationLaneContext};
use crate::{
    ciphersuite::Secret,
    test_utils::*,
    tree::{secret_tree::SecretTreeError, sender_ratchet::*},
};

#[cfg(feature = "virtual-clients-draft")]
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{
        AeadType, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig, HpkeKeyPair,
        KemOutput, SignatureScheme,
    },
};
#[cfg(feature = "virtual-clients-draft")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "virtual-clients-draft")]
use tls_codec::SecretVLBytes;

#[cfg(feature = "virtual-clients-draft")]
pub(super) struct FailingCrypto {
    inner: openmls_rust_crypto::RustCrypto,
    fail_at_expand: usize,
    expand_calls: AtomicUsize,
}

#[cfg(feature = "virtual-clients-draft")]
impl FailingCrypto {
    pub(super) fn failing_on_expand(fail_at_expand: usize) -> Self {
        Self {
            inner: openmls_rust_crypto::RustCrypto::default(),
            fail_at_expand,
            expand_calls: AtomicUsize::new(0),
        }
    }
}

#[cfg(feature = "virtual-clients-draft")]
impl OpenMlsCrypto for FailingCrypto {
    fn supports(&self, _ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedCiphersuite)
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        Vec::new()
    }

    fn hkdf_extract(
        &self,
        _hash_type: HashType,
        _salt: &[u8],
        _ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        Err(CryptoError::CryptoLibraryError)
    }

    fn hmac(
        &self,
        _hash_type: HashType,
        _key: &[u8],
        _message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        Err(CryptoError::CryptoLibraryError)
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        let call = self.expand_calls.fetch_add(1, Ordering::Relaxed) + 1;
        if call == self.fail_at_expand {
            return Err(CryptoError::CryptoLibraryError);
        }
        self.inner.hkdf_expand(hash_type, prk, info, okm_len)
    }

    fn hash(&self, _hash_type: HashType, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::CryptoLibraryError)
    }

    fn aead_encrypt(
        &self,
        _alg: AeadType,
        _key: &[u8],
        _data: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::CryptoLibraryError)
    }

    fn aead_decrypt(
        &self,
        _alg: AeadType,
        _key: &[u8],
        _ct_tag: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::CryptoLibraryError)
    }

    fn signature_key_gen(&self, _alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        Err(CryptoError::CryptoLibraryError)
    }

    fn verify_signature(
        &self,
        _alg: SignatureScheme,
        _data: &[u8],
        _pk: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::CryptoLibraryError)
    }

    fn sign(
        &self,
        _alg: SignatureScheme,
        _data: &[u8],
        _key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::CryptoLibraryError)
    }

    fn hpke_seal(
        &self,
        _config: HpkeConfig,
        _pk_r: &[u8],
        _info: &[u8],
        _aad: &[u8],
        _ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        Err(CryptoError::CryptoLibraryError)
    }

    fn hpke_open(
        &self,
        _config: HpkeConfig,
        _input: &HpkeCiphertext,
        _sk_r: &[u8],
        _info: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::CryptoLibraryError)
    }

    fn hpke_setup_sender_and_export(
        &self,
        _config: HpkeConfig,
        _pk_r: &[u8],
        _info: &[u8],
        _exporter_context: &[u8],
        _exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        Err(CryptoError::CryptoLibraryError)
    }

    fn hpke_setup_receiver_and_export(
        &self,
        _config: HpkeConfig,
        _enc: &[u8],
        _sk_r: &[u8],
        _info: &[u8],
        _exporter_context: &[u8],
        _exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        Err(CryptoError::CryptoLibraryError)
    }

    fn derive_hpke_keypair(
        &self,
        _config: HpkeConfig,
        _ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        Err(CryptoError::CryptoLibraryError)
    }

    #[cfg(feature = "targeted-messages-draft")]
    fn hpke_open_psk(
        &self,
        _config: HpkeConfig,
        _input: &HpkeCiphertext,
        _sk_r: &[u8],
        _info: &[u8],
        _aad: &[u8],
        _psk: &[u8],
        _psk_id: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::CryptoLibraryError)
    }

    #[cfg(feature = "targeted-messages-draft")]
    fn hpke_seal_psk_resolved_aad<F, E>(
        &self,
        _config: HpkeConfig,
        _pk_r: &[u8],
        _info: &[u8],
        _ptxt: &[u8],
        _psk: &[u8],
        _psk_id: &[u8],
        _aad_builder: F,
    ) -> Result<HpkeCiphertext, openmls_traits::crypto::HpkeSealPskResolvedAadError<E>>
    where
        Self: Sized,
        F: FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    {
        unimplemented!("unused by the ratchet atomicity test")
    }

    fn ff1_aes128_encrypt(&self, _key: &[u8; 16], _plaintext: u32) -> Result<u32, CryptoError> {
        Err(CryptoError::CryptoLibraryError)
    }

    fn ff1_aes128_decrypt(&self, _key: &[u8; 16], _ciphertext: u32) -> Result<u32, CryptoError> {
        Err(CryptoError::CryptoLibraryError)
    }
}

// Test the maximum forward ratcheting
#[openmls_test::openmls_test]
fn test_max_forward_distance() {
    let provider = &Provider::default();

    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet1 = DecryptionRatchet::new(secret.clone());
    let mut ratchet2 = DecryptionRatchet::new(secret);

    // We expect this to still work
    let _secret = ratchet1
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            configuration.maximum_forward_distance(),
            configuration,
        )
        .expect("Expected decryption secret.");

    // We expect this to return an error
    let err = ratchet2
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            configuration.maximum_forward_distance() + 1,
            configuration,
        )
        .expect_err("Expected error.");

    assert_eq!(err, SecretTreeError::TooDistantInTheFuture);

    // Test if there's an overflow in the maximum forward distance check.
    ratchet1.ratchet_secret_mut().set_generation(u32::MAX - 5);
    ratchet1
        .secret_for_decryption(ciphersuite, provider.crypto(), u32::MAX - 1, configuration)
        .expect("Error ratcheting to very high generation");
}

// Test out-of-order generations
#[openmls_test::openmls_test]
fn test_out_of_order_generations() {
    let provider = &Provider::default();

    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet1 = DecryptionRatchet::new(secret);

    // Ratchet forward twice the size of the window
    for i in 0..configuration.out_of_order_tolerance() * 2 {
        let _secret = ratchet1
            .secret_for_decryption(ciphersuite, provider.crypto(), i, configuration)
            .expect("Expected decryption secret.");
    }

    // Check that secrets from before the window are not accessible anymore
    let err = ratchet1
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            configuration.out_of_order_tolerance() - 1,
            configuration,
        )
        .expect_err("Expected error.");

    assert_eq!(err, SecretTreeError::TooDistantInThePast);

    // All secrets within the window should have been deleted because of FS.
    for i in configuration.out_of_order_tolerance()..configuration.out_of_order_tolerance() * 2 {
        assert_eq!(
            ratchet1
                .secret_for_decryption(ciphersuite, provider.crypto(), i, configuration)
                .expect_err("Expected decryption secret."),
            SecretTreeError::SecretReuseError
        );
    }
}

// Test forward secrecy
#[openmls_test::openmls_test]
fn test_forward_secrecy() {
    let provider = &Provider::default();

    // Encryption Ratchets are forward-secret by default, since they don't store
    // any keys. Thus, we can only test FS on Decryption Ratchets.
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DecryptionRatchet::new(secret);

    // Let's ratchet once and see if the ratchet keeps any keys around.
    let _ratchet_secrets = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), 0, configuration)
        .expect("Error ratcheting forward.");

    // The generation should have increased.
    assert_eq!(ratchet.generation(), 1);

    // And we should get an error for generation 0.
    let err = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), 0, configuration)
        .expect_err("No error when trying to retrieve key outside of tolerance window.");
    assert_eq!(err, SecretTreeError::SecretReuseError);

    // Let's ratchet forward a few times, making the ratchet keep the secrets round for out-of-order decryption.
    let _ratchet_secrets = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), 10, configuration)
        .expect("Error ratcheting forward.");

    // First, let's make sure that the window works.
    let err = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), 5, configuration)
        .expect_err("No error when trying to retrieve key outside of tolerance window.");
    assert_eq!(err, SecretTreeError::TooDistantInThePast);

    // Now let's get a few keys. The first time we're trying to get the key of a given generation, it should work. The second time, we should get a SecretReuseError.
    for generation in 10 - configuration.out_of_order_tolerance() + 1..10 {
        let keys = ratchet.secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            generation,
            configuration,
        );
        assert!(keys.is_ok());

        let err = ratchet
            .secret_for_decryption(ciphersuite, provider.crypto(), generation, configuration)
            .expect_err("No error when trying to retrieve deleted key.");
        assert_eq!(err, SecretTreeError::SecretReuseError);
    }
}

// Test if a sender ratchet overflow is caught
#[test]
fn sender_ratchet_generation_overflow() {
    let provider = OpenMlsRustCrypto::default();
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = RatchetSecret::initial_ratchet_secret(secret);
    ratchet.set_generation(u32::MAX - 1);
    let _ = ratchet
        .ratchet_forward(provider.crypto(), ciphersuite)
        .expect("error ratcheting forward");
    let err = ratchet
        .ratchet_forward(provider.crypto(), ciphersuite)
        .expect_err("no error exceeding generation u32::MAX");
    assert_eq!(err, SecretTreeError::RatchetTooLong)
}

// === DualUseRatchet ===
//
// The tests below cover the dual-use-only methods
// (`secret_for_encryption`, `delete_secret_for_generation`) and the
// encrypt-then-decrypt-own state machine that's unique to `DualUseRatchet`.

// Encrypting caches the secret in the past-secrets window, then `confirm`
// (i.e. `delete_secret_for_generation`) drops it, and a later attempt to
// decrypt that generation fails as `SecretReuseError`.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_encrypt_confirm_drops_secret() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);

    let (generation, _) = ratchet
        .secret_for_encryption(ciphersuite, provider.crypto())
        .expect("Expected encryption secret.");
    assert_eq!(generation, 0);
    assert_eq!(ratchet.generation(), 1);

    // Confirm the message, dropping the cached encryption secret.
    ratchet.delete_secret_for_generation(generation);

    // Decrypting at the same generation now fails since the entry was removed.
    let err = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), generation, configuration)
        .expect_err("Confirmed secret should be unavailable.");
    assert_eq!(err, SecretTreeError::SecretReuseError);
}

// Without confirming, the local sender can decrypt their own message (the
// cached secret in the past-secrets window is removed when used). A second
// decryption attempt at the same generation then fails.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_encrypt_then_decrypt_own() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);

    let (generation, _) = ratchet
        .secret_for_encryption(ciphersuite, provider.crypto())
        .expect("Expected encryption secret.");

    // First decryption succeeds — the secret was cached when we encrypted.
    let _decrypted = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), generation, configuration)
        .expect("Expected to decrypt own message.");

    // Second decryption at the same generation fails.
    let err = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), generation, configuration)
        .expect_err("Reusing the same generation should fail.");
    assert_eq!(err, SecretTreeError::SecretReuseError);
}

// `delete_secret_for_generation` is a no-op when the requested generation
// hasn't been emitted yet (>= the ratchet head) and is idempotent for past
// generations whose cached secret was already removed.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_delete_secret_edge_cases() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);

    // Deleting at the current head (generation == head, window_index == -1) is
    // a no-op.
    ratchet.delete_secret_for_generation(ratchet.generation());
    assert_eq!(ratchet.generation(), 0);

    // Deleting a future generation is also a no-op.
    ratchet.delete_secret_for_generation(42);
    assert_eq!(ratchet.generation(), 0);

    // Now emit a couple of secrets so we have entries in the past-secrets
    // window.
    let (gen0, _) = ratchet
        .secret_for_encryption(ciphersuite, provider.crypto())
        .expect("Expected encryption secret.");
    let (_gen1, _) = ratchet
        .secret_for_encryption(ciphersuite, provider.crypto())
        .expect("Expected encryption secret.");

    // Deleting an already-cached past generation drops it; a second delete at
    // the same generation is harmless.
    ratchet.delete_secret_for_generation(gen0);
    ratchet.delete_secret_for_generation(gen0);

    // Decrypting that generation now fails.
    let err = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), gen0, configuration)
        .expect_err("Deleted secret should be unavailable.");
    assert_eq!(err, SecretTreeError::SecretReuseError);
}

// Encrypting more than `out_of_order_tolerance` messages without confirming or
// decrypting must not lock the local sender out of decrypting their oldest
// in-flight message: the past-bound check that's correct for a pure
// `DecryptionRatchet` (where anything that old has been pruned away) does not
// apply to a `DualUseRatchet`, because encryption keeps the secret.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_decrypts_past_out_of_order_tolerance() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);

    // Send more messages than `out_of_order_tolerance` so that the cache is
    // larger than the tolerance window.
    let send_count = configuration.out_of_order_tolerance() + 2;
    let mut first_generation = None;
    for _ in 0..send_count {
        let (generation, _) = ratchet
            .secret_for_encryption(ciphersuite, provider.crypto())
            .expect("Expected encryption secret.");
        first_generation.get_or_insert(generation);
    }
    let first_generation = first_generation.unwrap();
    assert!(ratchet.generation() - first_generation > configuration.out_of_order_tolerance());

    // The oldest cached secret is `out_of_order_tolerance + 1` generations
    // behind the head, but its secret is still cached, so decryption must
    // succeed.
    let _decrypted = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            first_generation,
            configuration,
        )
        .expect("Old encryption secret should still be retrievable for own decryption.");
}

// Confirming later messages must not advance the receive-side retention
// window or evict an older unconfirmed encryption secret. The older secret may
// still be needed to decrypt an own message from another virtual client.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_confirming_later_messages_keeps_old_unconfirmed_secret() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);

    let (first_generation, _) = ratchet
        .secret_for_encryption(ciphersuite, provider.crypto())
        .expect("Expected encryption secret.");

    for _ in 0..configuration.out_of_order_tolerance() + 2 {
        let (generation, _) = ratchet
            .secret_for_encryption(ciphersuite, provider.crypto())
            .expect("Expected encryption secret.");
        ratchet.delete_secret_for_generation(generation);
    }

    assert!(ratchet.generation() - first_generation > configuration.out_of_order_tolerance());

    let _decrypted = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            first_generation,
            configuration,
        )
        .expect("Old unconfirmed secret should still be retrievable for own decryption.");
}

// Successful decryption is what advances the receive-side window. Secrets
// derived only to cover skipped receive generations are pruned once they fall
// outside that window.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_decryption_moves_receive_window() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);

    let target_generation = configuration.out_of_order_tolerance() * 2;
    let _decrypted = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            target_generation,
            configuration,
        )
        .expect("Expected decryption secret.");

    let too_old_generation = target_generation - configuration.out_of_order_tolerance();
    let err = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            too_old_generation,
            configuration,
        )
        .expect_err("Expected the receive window to reject old generations.");
    assert_eq!(err, SecretTreeError::TooDistantInThePast);

    let retained_generation = target_generation - configuration.out_of_order_tolerance() + 1;
    let _decrypted = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            retained_generation,
            configuration,
        )
        .expect("Expected retained out-of-order secret.");
}

// Local sends must not occupy slots in the receive-side retention window. Only
// decrypting a message advances that window. In this scenario the first
// decryption leaves a full receive window, then we send and confirm enough
// messages to span the whole tolerance. A later decryption should prune only as
// far as that one received message requires, not by the locally sent
// generations.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_local_sends_do_not_advance_receive_window() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);

    let first_received_generation = configuration.out_of_order_tolerance();
    let _decrypted = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            first_received_generation,
            configuration,
        )
        .expect("Expected first decryption secret.");

    for _ in 0..configuration.out_of_order_tolerance() {
        let (generation, _) = ratchet
            .secret_for_encryption(ciphersuite, provider.crypto())
            .expect("Expected encryption secret.");
        ratchet.delete_secret_for_generation(generation);
    }

    let later_received_generation = ratchet.generation();
    let _decrypted = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            later_received_generation,
            configuration,
        )
        .expect("Expected later decryption secret.");

    let pruned_by_later_decryption =
        first_received_generation.saturating_sub(configuration.out_of_order_tolerance()) + 1;
    let err = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            pruned_by_later_decryption,
            configuration,
        )
        .expect_err("One old generation should be pruned by the later decryption.");
    assert_eq!(err, SecretTreeError::TooDistantInThePast);

    let retained_across_local_sends = pruned_by_later_decryption + 1;
    let _decrypted = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            retained_across_local_sends,
            configuration,
        )
        .expect("Local sends should not prune the receive window.");
}

// A lane send must derive the first generation belonging to the emulation
// leaf, retain skipped generations for a sibling's ciphertext, and return
// only the selected generation as the outgoing encryption secret.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_generation_lane_retains_skipped_generations() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);
    let lane = GenerationLaneContext::new(TreeSize::new(2), LeafNodeIndex::new(1));

    let (generation, _) = ratchet
        .secret_for_encryption_in_generation_lane(
            ciphersuite,
            provider.crypto(),
            lane,
            configuration,
        )
        .expect("Expected the leaf-1 lane to select generation 1.");

    assert_eq!(generation, 1);
    assert_eq!(ratchet.generation(), 2);

    // Generation 0 was skipped, but remains available to decrypt a sibling's
    // message. The selected generation is also available until confirmation.
    ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), 0, configuration)
        .expect("Skipped generation must be retained for decryption.");
    ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), 1, configuration)
        .expect("Selected generation must remain available until confirmation.");
}

// A lane's stride must fit both sender-ratchet windows. This validation must
// happen before any ratcheting so a rejected send leaves the head unchanged.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_generation_lane_rejects_stride_larger_than_sender_windows() {
    let provider = &Provider::default();
    let configuration = SenderRatchetConfiguration::new(1, 10);
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);
    // Three requested leaves round up to a four-leaf TreeSize, so the lane
    // stride is three (N_e - 1), not two.
    let lane = GenerationLaneContext::new(TreeSize::from_leaf_count(3), LeafNodeIndex::new(0));

    let err = ratchet
        .secret_for_encryption_in_generation_lane(
            ciphersuite,
            provider.crypto(),
            lane,
            &configuration,
        )
        .expect_err("A stride of three must exceed the configured tolerance of one.");

    assert_eq!(err, SecretTreeError::GenerationLaneTooWide);
    assert_eq!(ratchet.generation(), 0);
}

#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_generation_lane_rejects_stride_larger_than_forward_distance() {
    let provider = &Provider::default();
    let configuration = SenderRatchetConfiguration::new(10, 2);
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);
    let lane = GenerationLaneContext::new(TreeSize::from_leaf_count(3), LeafNodeIndex::new(0));

    let err = ratchet
        .secret_for_encryption_in_generation_lane(
            ciphersuite,
            provider.crypto(),
            lane,
            &configuration,
        )
        .expect_err("A stride of three must exceed the maximum forward distance of two.");

    assert_eq!(err, SecretTreeError::GenerationLaneTooWide);
    assert_eq!(ratchet.generation(), 0);
}

// A malformed binding must never be used to derive a modulo or to select a
// generation. Both the residue and emulation group size are validated at the
// generation-lane boundary.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_generation_lane_rejects_invalid_residue() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);
    let lane = GenerationLaneContext::new(TreeSize::from_leaf_count(1), LeafNodeIndex::new(2));

    let err = ratchet
        .secret_for_encryption_in_generation_lane(
            ciphersuite,
            provider.crypto(),
            lane,
            configuration,
        )
        .expect_err("A residue equal to the lane size must be rejected.");

    assert_eq!(err, SecretTreeError::GenerationLaneInvalidResidue);
    assert_eq!(ratchet.generation(), 0);
}

#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_generation_lane_rejects_max_target_before_mutation() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);
    ratchet.set_generation_for_test(u32::MAX - 1);
    let lane = GenerationLaneContext::new(TreeSize::new(2), LeafNodeIndex::new(1));

    let err = ratchet
        .secret_for_encryption_in_generation_lane(
            ciphersuite,
            provider.crypto(),
            lane,
            configuration,
        )
        .expect_err("A lane target at u32::MAX must be rejected before ratcheting.");

    assert_eq!(err, SecretTreeError::RatchetTooLong);
    assert_eq!(ratchet.generation(), u32::MAX - 1);
}

// Lane sends may retain skipped generations, but only the configured receive
// window of those skipped entries is kept. Awaiting-confirmation entries for
// actual sends remain available regardless of this pruning.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_generation_lane_prunes_only_skipped_generations() {
    let provider = &Provider::default();
    let configuration = SenderRatchetConfiguration::new(1, 10);
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);
    let lane = GenerationLaneContext::new(TreeSize::from_leaf_count(1), LeafNodeIndex::new(0));

    let first = ratchet
        .secret_for_encryption_in_generation_lane(
            ciphersuite,
            provider.crypto(),
            lane,
            &configuration,
        )
        .expect("Expected first lane generation.");
    let second = ratchet
        .secret_for_encryption_in_generation_lane(
            ciphersuite,
            provider.crypto(),
            lane,
            &configuration,
        )
        .expect("Expected second lane generation.");
    let third = ratchet
        .secret_for_encryption_in_generation_lane(
            ciphersuite,
            provider.crypto(),
            lane,
            &configuration,
        )
        .expect("Expected third lane generation.");
    assert_eq!((first.0, second.0, third.0), (0, 2, 4));

    // Generation 1 was the oldest skipped entry and is pruned once the
    // tolerance-1 window keeps generation 3.
    assert_eq!(
        ratchet
            .secret_for_decryption(ciphersuite, provider.crypto(), 1, &configuration)
            .expect_err("Old skipped generation must be pruned"),
        SecretTreeError::TooDistantInThePast
    );
    ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), 3, &configuration)
        .expect("Newest skipped generation must remain available.");

    // All actual lane sends remain awaiting confirmation and are not removed
    // by skipped-entry pruning.
    for generation in [first.0, second.0, third.0] {
        ratchet
            .secret_for_decryption(ciphersuite, provider.crypto(), generation, &configuration)
            .expect("Actual lane generation must remain until confirmation.");
    }
}

// Every residue in a four-leaf emulation group selects its own first
// generation, even when each ratchet starts from the same head. A tree with
// three active leaves still has four lanes: the unused fourth lane is part of
// the capacity and must not collapse the stride to three.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_generation_lane_maps_width_four_residues_and_capacity() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let width_four = TreeSize::new(4);

    assert_eq!(width_four.leaf_count(), 4);
    for residue in 0..4 {
        let mut ratchet = DualUseRatchet::new(secret.clone());
        let lane = GenerationLaneContext::new(width_four, LeafNodeIndex::new(residue));
        let (generation, _) = ratchet
            .secret_for_encryption_in_generation_lane(
                ciphersuite,
                provider.crypto(),
                lane,
                configuration,
            )
            .expect("every width-four residue must select a generation");

        assert_eq!(generation, residue);
        assert_eq!(ratchet.generation(), residue + 1);
    }

    // `from_leaf_count(3)` rounds the requested three active leaves up to the
    // four-leaf tree needed for lane assignment. Exercise only the three
    // active residues; the fourth lane remains blank while capacity is four.
    // This is intentionally a TreeSize/ratchet state check rather than a full
    // MLS integration fixture with an empty emulation leaf.
    let capacity_four = TreeSize::from_leaf_count(3);
    assert_eq!(capacity_four.leaf_count(), 4);
    let mut ratchet = DualUseRatchet::new(secret);
    let active_generations = (0..3)
        .map(|residue| {
            let lane = GenerationLaneContext::new(capacity_four, LeafNodeIndex::new(residue));
            ratchet
                .secret_for_encryption_in_generation_lane(
                    ciphersuite,
                    provider.crypto(),
                    lane,
                    configuration,
                )
                .expect("active width-four residue must send")
                .0
        })
        .collect::<Vec<_>>();
    assert_eq!(active_generations, vec![0, 1, 2]);
    assert_eq!(ratchet.generation(), 3);
}

// Serde must preserve all three pieces of a lane ratchet's state: the head,
// skipped generations that are Available, and emitted generations that remain
// AwaitingConfirmation. After restoring, the next send must continue in the
// same lane rather than restarting from the serialized head.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_generation_lane_serde_preserves_state_and_continues_lane() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let lane = GenerationLaneContext::new(TreeSize::new(2), LeafNodeIndex::new(1));
    let mut ratchet = DualUseRatchet::new(secret);

    // Lane 1 skips generation 0 and emits generation 1, leaving both entries
    // in distinct retained states and advancing the head to generation 2.
    let (generation, _) = ratchet
        .secret_for_encryption_in_generation_lane(
            ciphersuite,
            provider.crypto(),
            lane,
            configuration,
        )
        .expect("initial lane send");
    assert_eq!(generation, 1);
    assert_eq!(ratchet.generation(), 2);

    let serialized = serde_json::to_vec(&ratchet).expect("serialize dual-use ratchet");
    let mut restored: DualUseRatchet =
        serde_json::from_slice(&serialized).expect("deserialize dual-use ratchet");
    assert_eq!(restored.generation(), 2);

    // Available skipped material survives the round-trip and is one-shot.
    restored
        .secret_for_decryption(ciphersuite, provider.crypto(), 0, configuration)
        .expect("restored skipped generation must decrypt");
    assert_eq!(
        restored
            .secret_for_decryption(ciphersuite, provider.crypto(), 0, configuration)
            .expect_err("consumed skipped generation must reject replay"),
        SecretTreeError::SecretReuseError
    );

    // The emitted material is still AwaitingConfirmation and explicit
    // confirmation removes it before any own echo can be accepted.
    restored.delete_secret_for_generation(1);
    assert_eq!(
        restored
            .secret_for_decryption(ciphersuite, provider.crypto(), 1, configuration)
            .expect_err("confirmed lane generation must reject own echo"),
        SecretTreeError::SecretReuseError
    );

    // The restored head remains in lane 1: generation 2 is skipped and the
    // next actual send is generation 3.
    let (next_generation, _) = restored
        .secret_for_encryption_in_generation_lane(
            ciphersuite,
            provider.crypto(),
            lane,
            configuration,
        )
        .expect("restored ratchet must continue lane assignment");
    assert_eq!(next_generation, 3);
    restored
        .secret_for_decryption(ciphersuite, provider.crypto(), 2, configuration)
        .expect("restored skipped generation must remain available");
    restored
        .secret_for_decryption(ciphersuite, provider.crypto(), 3, configuration)
        .expect("restored awaiting-confirmation generation must remain available");
}

// A failed derivation after one skipped generation must leave both the head
// and retained-secret map unchanged so a caller can retry the lane send.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_generation_lane_mid_derivation_failure_preserves_state() {
    let configuration = &SenderRatchetConfiguration::default();
    let crypto = FailingCrypto::failing_on_expand(4);
    let secret = Secret::from_slice(&[0x42; 32]);
    let mut ratchet = DualUseRatchet::new(secret);
    let before = ratchet.clone();
    let lane = GenerationLaneContext::new(TreeSize::new(4), LeafNodeIndex::new(3));

    let error = ratchet
        .secret_for_encryption_in_generation_lane(ciphersuite, &crypto, lane, configuration)
        .expect_err("the second skipped generation must fail deterministically");

    assert_eq!(
        error,
        SecretTreeError::CryptoError(CryptoError::CryptoLibraryError)
    );
    assert_eq!(ratchet, before);
}
