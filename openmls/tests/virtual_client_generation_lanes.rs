#![cfg(feature = "virtual-clients-draft")]

use openmls::{
    components::vc_derivation_info::{EpochId, VC_COMPONENT_ID},
    extensions::{
        AppDataDictionary, AppDataDictionaryExtension, Extension, ExtensionType, Extensions,
    },
    framing::errors::{MessageDecryptionError, SecretTreeError},
    group::{
        MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, StagedWelcome,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    },
    key_packages::KeyPackage,
    prelude::{
        test_utils::new_credential, Capabilities, LeafNode, ProcessMessageError,
        ProcessedMessageContent, ValidationError,
    },
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;
use openmls_traits::OpenMlsProvider;
use tls_codec::Serialize as _;

/// Capabilities shared by the emulation and higher-level VC groups.
fn vc_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(vec![ExtensionType::AppDataDictionary])
        .build()
}

/// Leaf extensions advertising the VC component required by the draft.
fn vc_leaf_extensions() -> Extensions<LeafNode> {
    let supported_components: Vec<u16> = vec![VC_COMPONENT_ID];
    let app_components_body = supported_components
        .tls_serialize_detached()
        .expect("serialize AppComponents body");
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(1, app_components_body);
    let ext = Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary));
    Extensions::from_vec(vec![ext]).expect("build leaf-node Extensions")
}

/// Safe AAD context required to carry the derivation-epoch marker.
fn safe_aad_group_context_extensions() -> Extensions<openmls::group::GroupContext> {
    use openmls::component::{ComponentType, ComponentsList};

    let body = ComponentsList::new(Vec::new())
        .tls_serialize_detached()
        .expect("serialize ComponentsList body");
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(ComponentType::SafeAad.into(), body);
    let ext = Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary));
    Extensions::single(ext).expect("one app_data_dictionary extension is valid")
}

fn emulation_group_config(
    ciphersuite: openmls_traits::types::Ciphersuite,
    emulation_group: bool,
) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(vc_capabilities())
        .with_leaf_node_extensions(vc_leaf_extensions())
        .expect("attach leaf-node extensions")
        .with_group_context_extensions(safe_aad_group_context_extensions())
        .emulation_group(emulation_group)
        .build()
}

fn vc_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build()
}

fn make_emulator_group<P: OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    provider: &P,
    label: &[u8],
    emulation_group: bool,
) -> (MlsGroup, SignatureKeyPair) {
    let (credential, signer) = new_credential(provider, label, ciphersuite.signature_algorithm());
    let group = MlsGroup::new(
        provider,
        &signer,
        &emulation_group_config(ciphersuite, emulation_group),
        credential,
    )
    .expect("create emulator group");
    (group, signer)
}

fn newest_epoch<P: OpenMlsProvider>(group: &MlsGroup, provider: &P) -> EpochId {
    group
        .newest_vc_derivation_epoch(provider.storage())
        .expect("read newest derivation epoch")
        .expect("an emulation group has a derivation epoch")
}

fn vc_key_package<P: OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    provider: &P,
    label: &[u8],
) -> (KeyPackage, SignatureKeyPair) {
    let (credential, signer) = new_credential(provider, label, ciphersuite.signature_algorithm());
    let key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build(ciphersuite, provider, &signer, credential)
        .expect("build emulator KeyPackage")
        .key_package()
        .to_owned();
    (key_package, signer)
}

/// Add an emulator member and merge the Add Commit on the existing client.
fn add_emulator_client<P: OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    emulator_a: &mut MlsGroup,
    provider_a: &P,
    signer_a: &SignatureKeyPair,
    joiner_provider: &P,
    joiner_label: &[u8],
) -> (openmls::prelude::MlsMessageOut, MlsGroup, SignatureKeyPair) {
    let (key_package, signer) = vc_key_package(ciphersuite, joiner_provider, joiner_label);
    let (commit, welcome, _) = emulator_a
        .add_members(provider_a, signer_a, &[key_package])
        .expect("emulator_a add joiner");
    emulator_a
        .merge_pending_commit(provider_a)
        .expect("emulator_a merge add");
    let group = StagedWelcome::new_from_welcome(
        joiner_provider,
        &vc_join_config(),
        welcome.into_welcome().expect("emulator welcome"),
        Some(emulator_a.export_ratchet_tree().into()),
    )
    .map(|staged| staged.emulation_group(true))
    .and_then(|staged| staged.into_group(joiner_provider))
    .expect("joiner joins emulation group");
    (commit, group, signer)
}

fn shared_vc_identity<P: OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    provider_a: &P,
    provider_b: &P,
) -> (SignatureKeyPair, openmls::credentials::CredentialWithKey) {
    use openmls::credentials::{BasicCredential, CredentialWithKey};

    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("vc signer");
    signer
        .store(provider_a.storage())
        .expect("store vc signer on A");
    signer
        .store(provider_b.storage())
        .expect("store vc signer on B");
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"Alice (VC)".to_vec()).into(),
        signature_key: signer.public().into(),
    };
    (signer, credential)
}

fn send_vc_commit<P: OpenMlsProvider>(
    sender_group: &mut MlsGroup,
    emulator_group: &MlsGroup,
    provider: &P,
    signer: &SignatureKeyPair,
) -> openmls::prelude::MlsMessageOut {
    let bundle = sender_group
        .commit_builder()
        .vc_emulation(
            provider.crypto(),
            provider.storage(),
            emulator_group.group_id(),
        )
        .expect("vc emulation")
        .load_psks(provider.storage())
        .expect("load psks")
        .build(provider.rand(), provider.crypto(), signer, |_| true)
        .expect("build VC commit")
        .stage_commit(provider)
        .expect("stage VC commit");
    sender_group
        .merge_pending_commit(provider)
        .expect("merge VC commit");
    bundle.into_commit()
}

fn process_and_merge_commit<P: OpenMlsProvider>(
    receiver: &mut MlsGroup,
    provider: &P,
    commit: openmls::prelude::MlsMessageOut,
) {
    let processed = receiver
        .process_message(provider, commit.into_protocol_message().unwrap())
        .expect("process commit");
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        panic!("expected staged commit")
    };
    receiver
        .merge_staged_commit(provider, *staged)
        .expect("merge staged commit");
}

struct SiblingWelcomeGroups {
    emulator_a: MlsGroup,
    emulator_a_signer: SignatureKeyPair,
    emulator_b: MlsGroup,
    alice_a_main: MlsGroup,
    alice_b_main: MlsGroup,
    bob_main: MlsGroup,
    vc_signer: SignatureKeyPair,
}

/// Build two active siblings from one virtual-client KeyPackage Welcome.
fn setup_sibling_welcome_groups<P: OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    alice_a_provider: &P,
    alice_b_provider: &P,
    bob_provider: &P,
) -> SiblingWelcomeGroups {
    use openmls::components::vc_derivation_info::{
        assemble_vc_key_package_upload, process_vc_key_package_upload,
    };

    let (vc_signer, vc_credential) =
        shared_vc_identity(ciphersuite, alice_a_provider, alice_b_provider);
    let (mut emulator_a, emulator_a_signer) =
        make_emulator_group(ciphersuite, alice_a_provider, b"AliceEmulatorA", true);
    let (_, emulator_b, _) = add_emulator_client(
        ciphersuite,
        &mut emulator_a,
        alice_a_provider,
        &emulator_a_signer,
        alice_b_provider,
        b"AliceEmulatorB",
    );

    let mut batch = KeyPackage::builder()
        .leaf_node_capabilities(vc_capabilities())
        .leaf_node_extensions(vc_leaf_extensions())
        .build_vc_batch(
            ciphersuite,
            alice_a_provider,
            &vc_signer,
            vc_credential.clone(),
            emulator_a.group_id(),
            1,
        )
        .expect("build VC KeyPackage batch");
    let generation = batch.generation;
    let epoch_id = batch.epoch_id.clone();
    let (vc_key_package_bundle, key_package_info) = batch.key_packages.remove(0);
    let upload = assemble_vc_key_package_upload(
        alice_a_provider.storage(),
        epoch_id,
        generation,
        vec![key_package_info],
    )
    .expect("assemble VC KeyPackage upload");
    process_vc_key_package_upload(alice_b_provider, &upload).expect("process VC upload");

    let (bob_credential, bob_signer) =
        new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());
    let bob_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();
    let mut bob_main = MlsGroup::new(bob_provider, &bob_signer, &bob_config, bob_credential)
        .expect("create Bob group");
    let (_, welcome, _) = bob_main
        .add_members(
            bob_provider,
            &bob_signer,
            &[vc_key_package_bundle.key_package().clone()],
        )
        .expect("Bob adds virtual client");
    bob_main
        .merge_pending_commit(bob_provider)
        .expect("Bob merges add");
    let ratchet_tree = bob_main.export_ratchet_tree();
    let welcome = welcome.into_welcome().expect("welcome present");

    let join = |provider: &P, label: &str| {
        openmls::group::ProcessedWelcome::new_from_welcome(
            provider,
            &vc_join_config(),
            welcome.clone(),
        )
        .unwrap_or_else(|error| panic!("{label} processes Welcome: {error:?}"))
        .into_staged_welcome(provider, Some(ratchet_tree.clone().into()))
        .unwrap_or_else(|error| panic!("{label} stages Welcome: {error:?}"))
        .into_group(provider)
        .unwrap_or_else(|error| panic!("{label} joins group: {error:?}"))
    };
    let alice_a_main = join(alice_a_provider, "alice_a");
    let alice_b_main = join(alice_b_provider, "alice_b");
    assert_eq!(emulator_a.own_leaf_index().u32(), 0);
    assert_eq!(emulator_b.own_leaf_index().u32(), 1);
    assert_eq!(alice_a_main.own_leaf_index(), alice_b_main.own_leaf_index());
    assert_eq!(
        alice_a_main.epoch_authenticator(),
        alice_b_main.epoch_authenticator()
    );

    SiblingWelcomeGroups {
        emulator_a,
        emulator_a_signer,
        emulator_b,
        alice_a_main,
        alice_b_main,
        bob_main,
        vc_signer,
    }
}

fn expect_application(processed: openmls::prelude::ProcessedMessage, expected: &[u8]) {
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => {
            assert_eq!(message.into_bytes().as_slice(), expected);
        }
        ProcessedMessageContent::OwnPrivateMessage => {
            panic!("sibling message was taken for an own echo")
        }
        other => panic!("expected application message, got {other:?}"),
    }
}

#[openmls_test]
fn vc_generation_lanes_siblings_from_one_welcome_decrypt_each_other() {
    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();
    let bob_provider = Provider::default();
    let SiblingWelcomeGroups {
        mut alice_a_main,
        mut alice_b_main,
        mut bob_main,
        vc_signer,
        ..
    } = setup_sibling_welcome_groups(
        ciphersuite,
        &alice_a_provider,
        &alice_b_provider,
        &bob_provider,
    );

    let message_a = alice_a_main
        .create_unconfirmed_message(&alice_a_provider, &vc_signer, b"from alice_a")
        .expect("alice_a creates application message");
    let message_b = alice_b_main
        .create_unconfirmed_message(&alice_b_provider, &vc_signer, b"from alice_b")
        .expect("alice_b creates application message");
    assert_eq!(message_a.generation, 0);
    assert_eq!(message_b.generation, 1);
    let generation_id_a = message_a
        .generation_id
        .clone()
        .expect("alice_a message carries a generation id");
    let generation_id_b = message_b
        .generation_id
        .clone()
        .expect("alice_b message carries a generation id");
    assert_ne!(
        generation_id_a, generation_id_b,
        "sibling application sends must use distinct generation ids"
    );

    let protocol_message_a = message_a.message.into_protocol_message().unwrap();
    let protocol_message_b = message_b.message.into_protocol_message().unwrap();
    expect_application(
        bob_main
            .process_message(&bob_provider, protocol_message_a.clone())
            .expect("Bob processes alice_a's message"),
        b"from alice_a",
    );
    expect_application(
        alice_b_main
            .process_message(&alice_b_provider, protocol_message_a)
            .expect("alice_b processes alice_a's message"),
        b"from alice_a",
    );
    expect_application(
        bob_main
            .process_message(&bob_provider, protocol_message_b.clone())
            .expect("Bob processes alice_b's message"),
        b"from alice_b",
    );
    expect_application(
        alice_a_main
            .process_message(&alice_a_provider, protocol_message_b)
            .expect("alice_a processes alice_b's message"),
        b"from alice_b",
    );
}

/// Persisted sender-ratchet state must survive a process restart. With two
/// emulator leaves, the first sibling sends at generation 0 and the second at
/// generation 1; after loading both higher-level groups from storage, their
/// next sends must continue at generations 2 and 3 and remain decryptable.
#[openmls_test]
fn vc_generation_lanes_resume_after_group_reload() {
    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();
    let bob_provider = Provider::default();
    let SiblingWelcomeGroups {
        mut alice_a_main,
        mut alice_b_main,
        mut bob_main,
        vc_signer,
        ..
    } = setup_sibling_welcome_groups(
        ciphersuite,
        &alice_a_provider,
        &alice_b_provider,
        &bob_provider,
    );

    // Each create call advances and persists its own sender-ratchet state.
    let initial_a = alice_a_main
        .create_unconfirmed_message(&alice_a_provider, &vc_signer, b"initial from alice_a")
        .expect("alice_a creates initial application message");
    let initial_b = alice_b_main
        .create_unconfirmed_message(&alice_b_provider, &vc_signer, b"initial from alice_b")
        .expect("alice_b creates initial application message");
    assert_eq!(initial_a.generation, 0);
    assert_eq!(initial_b.generation, 1);

    // Reload through the public storage path rather than reconstructing a
    // ratchet. The old handles are dropped so all subsequent sends come from
    // the persisted groups.
    let alice_a_group_id = alice_a_main.group_id().clone();
    let alice_b_group_id = alice_b_main.group_id().clone();
    let mut alice_a_reloaded = MlsGroup::load(alice_a_provider.storage(), &alice_a_group_id)
        .expect("load alice_a group")
        .expect("alice_a group is persisted");
    let mut alice_b_reloaded = MlsGroup::load(alice_b_provider.storage(), &alice_b_group_id)
        .expect("load alice_b group")
        .expect("alice_b group is persisted");
    drop(alice_a_main);
    drop(alice_b_main);

    let message_a2 = alice_a_reloaded
        .create_unconfirmed_message(&alice_a_provider, &vc_signer, b"reloaded from alice_a")
        .expect("alice_a creates generation-2 application message after reload");
    let message_b3 = alice_b_reloaded
        .create_unconfirmed_message(&alice_b_provider, &vc_signer, b"reloaded from alice_b")
        .expect("alice_b creates generation-3 application message after reload");
    assert_eq!(
        [message_a2.generation, message_b3.generation],
        [2, 3],
        "reloaded sender ratchets must continue their two-leaf generation lanes"
    );

    let message_a2 = message_a2.message.into_protocol_message().unwrap();
    let message_b3 = message_b3.message.into_protocol_message().unwrap();
    expect_application(
        bob_main
            .process_message(&bob_provider, message_a2.clone())
            .expect("Bob decrypts alice_a's post-reload application message"),
        b"reloaded from alice_a",
    );
    expect_application(
        alice_b_reloaded
            .process_message(&alice_b_provider, message_a2)
            .expect("alice_b decrypts alice_a's post-reload application message"),
        b"reloaded from alice_a",
    );
    expect_application(
        bob_main
            .process_message(&bob_provider, message_b3.clone())
            .expect("Bob decrypts alice_b's post-reload application message"),
        b"reloaded from alice_b",
    );
    expect_application(
        alice_a_reloaded
            .process_message(&alice_a_provider, message_b3)
            .expect("alice_a decrypts alice_b's post-reload application message"),
        b"reloaded from alice_b",
    );
}

#[openmls_test]
fn vc_generation_lanes_reverse_delivery_keeps_generation_zero_decryptable() {
    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();
    let bob_provider = Provider::default();
    let SiblingWelcomeGroups {
        mut alice_a_main,
        mut alice_b_main,
        mut bob_main,
        vc_signer,
        ..
    } = setup_sibling_welcome_groups(
        ciphersuite,
        &alice_a_provider,
        &alice_b_provider,
        &bob_provider,
    );

    let message_a = alice_a_main
        .create_unconfirmed_message(&alice_a_provider, &vc_signer, b"from alice_a")
        .expect("alice_a creates generation-0 application message");
    let message_b = alice_b_main
        .create_unconfirmed_message(&alice_b_provider, &vc_signer, b"from alice_b")
        .expect("alice_b creates generation-1 application message");
    assert_eq!(message_a.generation, 0);
    assert_eq!(message_b.generation, 1);
    let protocol_message_a = message_a.message.into_protocol_message().unwrap();
    let protocol_message_b = message_b.message.into_protocol_message().unwrap();

    expect_application(
        bob_main
            .process_message(&bob_provider, protocol_message_b.clone())
            .expect("Bob processes generation-1 message first"),
        b"from alice_b",
    );
    expect_application(
        alice_a_main
            .process_message(&alice_a_provider, protocol_message_b)
            .expect("alice_a processes generation-1 message first"),
        b"from alice_b",
    );
    expect_application(
        bob_main
            .process_message(&bob_provider, protocol_message_a.clone())
            .expect("Bob processes delayed generation-0 message"),
        b"from alice_a",
    );
    expect_application(
        alice_b_main
            .process_message(&alice_b_provider, protocol_message_a)
            .expect("alice_b processes delayed generation-0 message"),
        b"from alice_a",
    );
}

#[openmls_test]
fn vc_generation_lanes_follow_sequential_membership_tree_capacity() {
    let alice_a_provider = Provider::default();
    let alice_b_provider = Provider::default();
    let bob_provider = Provider::default();
    let charly_provider = Provider::default();
    let SiblingWelcomeGroups {
        mut emulator_a,
        emulator_a_signer,
        mut emulator_b,
        mut alice_a_main,
        mut alice_b_main,
        mut bob_main,
        vc_signer,
    } = setup_sibling_welcome_groups(
        ciphersuite,
        &alice_a_provider,
        &alice_b_provider,
        &bob_provider,
    );

    let old_epoch_id = newest_epoch(&emulator_a, &alice_a_provider);
    let (membership_commit, _, _) = add_emulator_client(
        ciphersuite,
        &mut emulator_a,
        &alice_a_provider,
        &emulator_a_signer,
        &charly_provider,
        b"AliceEmulatorC",
    );
    process_and_merge_commit(&mut emulator_b, &alice_b_provider, membership_commit);
    let new_epoch_id = newest_epoch(&emulator_a, &alice_a_provider);
    assert_ne!(new_epoch_id, old_epoch_id);
    assert_eq!(
        new_epoch_id,
        newest_epoch(&emulator_b, &alice_b_provider),
        "both active emulator siblings must register the membership epoch"
    );

    // The VC Commit is built, merged and delivered sequentially before any
    // application message is created.
    let rebind_commit = send_vc_commit(
        &mut alice_a_main,
        &emulator_a,
        &alice_a_provider,
        &vc_signer,
    );
    process_and_merge_commit(&mut alice_b_main, &alice_b_provider, rebind_commit.clone());
    process_and_merge_commit(&mut bob_main, &bob_provider, rebind_commit);
    assert_eq!(alice_a_main.epoch(), alice_b_main.epoch());
    assert_eq!(alice_a_main.epoch(), bob_main.epoch());

    let message_a0 = alice_a_main
        .create_unconfirmed_message(&alice_a_provider, &vc_signer, b"alice_a generation 0")
        .expect("alice_a creates generation-0 application message");
    let message_b1 = alice_b_main
        .create_unconfirmed_message(&alice_b_provider, &vc_signer, b"alice_b generation 1")
        .expect("alice_b creates generation-1 application message");
    let message_a4 = alice_a_main
        .create_unconfirmed_message(&alice_a_provider, &vc_signer, b"alice_a generation 4")
        .expect("alice_a creates generation-4 application message");
    let message_b5 = alice_b_main
        .create_unconfirmed_message(&alice_b_provider, &vc_signer, b"alice_b generation 5")
        .expect("alice_b creates generation-5 application message");
    assert_eq!(
        [
            message_a0.generation,
            message_b1.generation,
            message_a4.generation,
            message_b5.generation,
        ],
        [0, 1, 4, 5],
        "application lanes must stride over the blank fourth leaf slot"
    );

    let messages = [
        (
            message_a0.message.into_protocol_message().unwrap(),
            b"alice_a generation 0".as_slice(),
            true,
        ),
        (
            message_b1.message.into_protocol_message().unwrap(),
            b"alice_b generation 1".as_slice(),
            false,
        ),
        (
            message_a4.message.into_protocol_message().unwrap(),
            b"alice_a generation 4".as_slice(),
            true,
        ),
        (
            message_b5.message.into_protocol_message().unwrap(),
            b"alice_b generation 5".as_slice(),
            false,
        ),
    ];
    for (message, expected, from_alice_a) in messages {
        expect_application(
            bob_main
                .process_message(&bob_provider, message.clone())
                .expect("Bob decrypts the sibling application message"),
            expected,
        );
        if from_alice_a {
            expect_application(
                alice_b_main
                    .process_message(&alice_b_provider, message)
                    .expect("alice_b decrypts alice_a's application message"),
                expected,
            );
        } else {
            expect_application(
                alice_a_main
                    .process_message(&alice_a_provider, message)
                    .expect("alice_a decrypts alice_b's application message"),
                expected,
            );
        }
    }
}

#[openmls_test]
fn vc_generation_lanes_own_confirm_and_replay_are_rejected() {
    let alice_provider = &Provider::default();
    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice_signer,
        &MlsGroupCreateConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .ciphersuite(ciphersuite)
            .use_ratchet_tree_extension(true)
            .capabilities(vc_capabilities())
            .with_leaf_node_extensions(vc_leaf_extensions())
            .expect("attach leaf-node extensions")
            .build(),
        alice_credential,
    )
    .expect("create Alice group");
    let (emulator_group, _) =
        make_emulator_group(ciphersuite, alice_provider, b"AliceEmulator", true);
    let _ = send_vc_commit(
        &mut alice_group,
        &emulator_group,
        alice_provider,
        &alice_signer,
    );

    let first = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, b"first")
        .expect("create first message");
    let first_ciphertext = first.message;
    let processed = alice_group
        .process_message(
            alice_provider,
            first_ciphertext.clone().into_protocol_message().unwrap(),
        )
        .expect("process own first echo");
    assert!(matches!(
        processed.into_content(),
        ProcessedMessageContent::ApplicationMessage(_)
    ));

    let err = alice_group
        .process_message(
            alice_provider,
            first_ciphertext.into_protocol_message().unwrap(),
        )
        .expect_err("a consumed generation must reject replay");
    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
            MessageDecryptionError::SecretTreeError(SecretTreeError::SecretReuseError),
        ))
    ));

    let second = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, b"second")
        .expect("create second message");
    let second_generation = second.generation;
    let second_protocol_message = second.message.into_protocol_message().unwrap();
    alice_group
        .confirm_application_message(alice_provider.storage(), second.epoch, second_generation)
        .expect("confirm second message");
    for attempt in ["own echo", "replay"] {
        let err = alice_group
            .process_message(alice_provider, second_protocol_message.clone())
            .expect_err("a confirmed generation must reject its echo");
        assert!(
            matches!(
                err,
                ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                    MessageDecryptionError::SecretTreeError(SecretTreeError::SecretReuseError),
                ))
            ),
            "expected a secret reuse error for {attempt}, got {err:?}"
        );
    }
}
