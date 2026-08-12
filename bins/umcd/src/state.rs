//! Runtime state (core.md §8): the daemon's shared mutable runtime context,
//! built once at startup and shared (behind an `Arc`) with the control
//! socket and carrier tasks.
use crate::application_data::ApplicationDataPlane;
use crate::bundle_service::BundleService;
use crate::config::NodeConfig;
use crate::control_authorization::restore_control_tokens;
use crate::discovery_service::DiscoveryService;
use crate::event_log::DaemonEvents;
use crate::relay_service::RelayService;
use crate::routing_service::RoutingService;
use crate::runtime_adapters::{OsClock, OsEntropy, TokioAdaptor};
use crate::session_bus::SessionBus;
use crate::session_manager::SessionControl;
use crate::session_manager::SessionManager;
#[cfg(not(test))]
use blake2::{Blake2s256, Digest};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc::SyncSender, Arc, Mutex};
use tokio::sync::mpsc;
use umc_carrier::Listener;
use umc_control::auth::TokenRegistry;
use umc_control::events::EventBus;
use umc_control::proto::umc::api::v1 as api;
use umc_core::app::AppRegistry;
use umc_core::app_io::{AppRx, AppTx};
use umc_core::block::Blocklist;
use umc_core::mesh::MeshConfig;
use umc_core::node::{Node, NodeConfig as NodeRuntimeConfig, NodeIdentity};
use umc_core::rate_limiter::RateLimiter;
use umc_core::revocation::{
    RevocationError, RevocationFreshness, RevocationStore, TofuError, TofuStore,
};
use umc_core::trust::{TrustLevel, TrustState, TrustStore};
use umc_core::well_known::WELL_KNOWN_APP;
use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
use umc_discovery::invitation::InvitationStore;
use umc_discovery::limit::EnumerationGuard;
use umc_handshake::identity::IdentityBinding;
use umc_metrics::Registry;
use umc_storage::keychain::KeychainError;
#[cfg(not(test))]
use umc_storage::keychain::{OsKeychain, SecretStore};
use umc_storage::keystore::{KeyClass, Keystore, KeystoreError};
use umc_storage::objects::ObjectStore;
use umc_storage::quota::QuotaAccount;
use umc_storage::sqlite::SqliteStore;
use umc_storage::store::{Namespace, Store};
use umc_types::runtime::{Clock, EntropySource, Instant};

/// Keystore file name inside the keystore directory (core.md §19).
pub(crate) const KEYSTORE_FILE: &str = "keystore.ks";
/// Record name for the node identity: one 64-byte record
/// `[identity_seed || static_seed]` under [`KeyClass::IdentitySigning`].
pub(crate) const NODE_IDENTITY_RECORD: &[u8] = b"node-identity";
/// Record name for the primary identity's signed binding (task F2): 56
/// bytes `[sequence || not_before || not_after || capabilities_hash]`. The
/// binding is stored separately from the 64-byte key record so
/// [`load_or_create_identity`]'s format stays stable; the sequence is
/// persisted so rotations stay monotonic across restarts (handshake.md
/// §33).
pub(crate) const BINDING_RECORD: &[u8] = b"node-identity/binding";
/// Record name for the secondary-identity index (task F2): a JSON
/// `SecondaryIndex` under [`KeyClass::IdentitySigning`].
pub(crate) const SECONDARY_INDEX_RECORD: &[u8] = b"secondary-identities";
/// Secondary identity record layout: 120 bytes
/// `[identity_seed || static_seed || sequence || not_before || not_after
/// || capabilities_hash]` under [`KeyClass::IdentitySigning`], named
/// `secondary-<n>`.
const SECONDARY_RECORD_LEN: usize = 64 + 8 + 8 + 8 + 32;
/// Binding record layout: `[sequence || not_before || not_after ||
/// capabilities_hash]`.
const BINDING_RECORD_LEN: usize = 8 + 8 + 8 + 32;

/// Local policy window for qualifying revocation-state claims. This is not a
/// guarantee that disconnected peers have seen every revocation; it bounds
/// how long persisted evidence is reported as fresh.
pub const DEFAULT_REVOCATION_FRESHNESS_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

/// Serializes `UMC_KEYSTORE_PASSWORD` mutations across test modules that
/// open keystores under a known password. Production code never touches it.
#[cfg(test)]
pub(crate) static KEYSTORE_PASSWORD_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// One secondary identity (task F2): a keystore-backed identity keypair
/// plus static handshake keypair with its own binding, kept out of the
/// primary node identity path. Created via `IdentityService.CreateIdentity`
/// or `ImportIdentity`; deletable; never the primary.
#[derive(Debug)]
pub struct SecondaryIdentity {
    pub identity: NodeIdentity,
    /// Keystore record name (`secondary-<n>`); also the control-surface
    /// identity handle.
    pub record_name: String,
    /// Proto `IdentityKind` as stored on create.
    pub kind: i32,
    pub label: String,
    pub binding: IdentityBinding,
    pub created_at_ms: u64,
}

/// Persistent index of secondary identities (task F2): enough metadata to
/// restore the registry at boot; the key material rides in per-identity
/// keystore records.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct SecondaryIndex {
    next_id: u64,
    entries: Vec<SecondaryIndexEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SecondaryIndexEntry {
    record_name: String,
    kind: i32,
    label: String,
    created_at_ms: u64,
}

/// The ticket-key derivation (handshake.md §35): HKDF-Extract of the
/// keystore identity seed. Re-run after identity-key rotation — a full
/// identity change must re-seal future tickets under the new identity.
pub(crate) fn ticket_key_for(identity: &NodeIdentity) -> [u8; 32] {
    umc_crypto::hkdf::extract(&[0u8; 32], &identity.identity.to_seed())
}

/// Retry-token key derived separately from the ticket key so a token cannot
/// be confused with a resumption ticket (handshake.md §21).
pub(crate) fn retry_key_for(identity: &NodeIdentity) -> [u8; 32] {
    let ticket_key = ticket_key_for(identity);
    umc_crypto::label::expand_label(&ticket_key, b"retry key", b"", 32)
        .expect("fixed retry key length")
        .try_into()
        .expect("fixed retry key length")
}

/// Loads the full identity registry from the keystore (task F2): the
/// primary node identity, its signed binding (persisted rotation state),
/// and every secondary identity. A fresh keystore generates and persists
/// all three.
///
/// # Errors
/// Returns a message when the keystore cannot be opened, a record is
/// malformed, or the password is wrong. Secondary restore failures are
/// logged and skipped (never fatal), mirroring the other restore paths.
pub(crate) fn load_identity_registry(
    config: &NodeConfig,
) -> Result<(NodeIdentity, IdentityBinding, Vec<SecondaryIdentity>), String> {
    let path = config.resolved_keystore_dir().join(KEYSTORE_FILE);
    let ks = Keystore::open(path, &keystore_password()).map_err(|e| format!("keystore: {e:?}"))?;
    let identity = match ks.load(KeyClass::IdentitySigning, NODE_IDENTITY_RECORD) {
        Ok(seeds) if seeds.len() == 64 => identity_from_seeds(&seeds),
        Ok(_) => return Err("keystore: malformed node-identity record (expected 64 bytes)".into()),
        Err(KeystoreError::UnsupportedClass) => {
            let identity = NodeIdentity::generate(&OsEntropy);
            let mut seeds = Vec::with_capacity(64);
            seeds.extend_from_slice(&identity.identity.to_seed());
            seeds.extend_from_slice(&identity.static_handshake.to_seed());
            ks.store(KeyClass::IdentitySigning, NODE_IDENTITY_RECORD, &seeds)
                .map_err(|e| format!("keystore store: {e:?}"))?;
            identity
        }
        Err(e) => return Err(format!("keystore load: {e:?}")),
    };
    let binding = match ks.load(KeyClass::IdentitySigning, BINDING_RECORD) {
        Ok(bytes) => binding_from_record(&identity, &bytes)
            .ok_or_else(|| "keystore: malformed binding record".to_string())?,
        Err(KeystoreError::UnsupportedClass) => {
            let binding = default_binding(&identity);
            persist_binding(&ks, &identity, &binding)?;
            binding
        }
        Err(e) => return Err(format!("keystore binding load: {e:?}")),
    };
    let secondaries = load_secondary_index(&ks)
        .map_err(|e| log::warn!("[identity] secondary index restore failed: {e}; ignoring"))
        .unwrap_or_default()
        .entries
        .into_iter()
        .filter_map(|entry| {
            match ks.load(KeyClass::IdentitySigning, entry.record_name.as_bytes()) {
                Ok(bytes) if bytes.len() == SECONDARY_RECORD_LEN => {
                    let identity = identity_from_seeds(&bytes[..64]);
                    let Some(binding) = binding_from_record(&identity, &bytes[64..]) else {
                        log::warn!(
                            "[identity] secondary {} has a malformed binding; skipping",
                            entry.record_name
                        );
                        return None;
                    };
                    Some(SecondaryIdentity {
                        identity,
                        record_name: entry.record_name,
                        kind: entry.kind,
                        label: entry.label,
                        binding,
                        created_at_ms: entry.created_at_ms,
                    })
                }
                Ok(_) => {
                    log::warn!(
                        "[identity] secondary {} record is malformed; skipping",
                        entry.record_name
                    );
                    None
                }
                Err(e) => {
                    log::warn!(
                        "[identity] secondary {} record load failed: {e:?}; skipping",
                        entry.record_name
                    );
                    None
                }
            }
        })
        .collect();
    Ok((identity, binding, secondaries))
}

/// The primary node identity from the keystore, or a fresh persisted one
/// (core.md §19/§63 — persistent endpoint identity). Thin wrapper over
/// [`load_identity_registry`] kept for `init_node`.
///
/// # Errors
/// See [`load_identity_registry`].
pub(crate) fn load_or_create_identity(config: &NodeConfig) -> Result<NodeIdentity, String> {
    load_identity_registry(config).map(|(identity, _, _)| identity)
}

/// The default binding for a fresh identity: sequence 0, valid from epoch
/// through the maximum not-after, all-zero capabilities hash (the v1
/// capability set is not yet computed — handshake.md §33).
fn default_binding(identity: &NodeIdentity) -> IdentityBinding {
    IdentityBinding::sign(
        &identity.identity,
        &identity.static_handshake.public(),
        0,
        u64::MAX,
        0,
        [0u8; 32],
    )
}

/// Rebuilds a signed binding from its persisted parameters. Ed25519
/// signatures are deterministic, so re-signing the same fields reproduces
/// the binding exactly.
fn binding_from_record(identity: &NodeIdentity, bytes: &[u8]) -> Option<IdentityBinding> {
    if bytes.len() != BINDING_RECORD_LEN {
        return None;
    }
    let sequence = u64::from_be_bytes(bytes[..8].try_into().ok()?);
    let not_before = u64::from_be_bytes(bytes[8..16].try_into().ok()?);
    let not_after = u64::from_be_bytes(bytes[16..24].try_into().ok()?);
    let mut capabilities_hash = [0u8; 32];
    capabilities_hash.copy_from_slice(&bytes[24..56]);
    Some(IdentityBinding::sign(
        &identity.identity,
        &identity.static_handshake.public(),
        not_before,
        not_after,
        sequence,
        capabilities_hash,
    ))
}

fn binding_bytes(binding: &IdentityBinding) -> Vec<u8> {
    let mut out = Vec::with_capacity(BINDING_RECORD_LEN);
    out.extend_from_slice(&binding.sequence.to_be_bytes());
    out.extend_from_slice(&binding.not_before.to_be_bytes());
    out.extend_from_slice(&binding.not_after.to_be_bytes());
    out.extend_from_slice(&binding.capabilities_hash);
    out
}

fn persist_binding(
    ks: &Keystore,
    identity: &NodeIdentity,
    binding: &IdentityBinding,
) -> Result<(), String> {
    let mut seeds = Vec::with_capacity(64);
    seeds.extend_from_slice(&identity.identity.to_seed());
    seeds.extend_from_slice(&identity.static_handshake.to_seed());
    // Delete + store: the keystore is append-only, so a second store under
    // the same name would be shadowed by the first record.
    // Order matters for crash consistency: write the BINDING first. A crash
    // between the two rewrites then leaves a new binding sequence with the
    // OLD static key — `binding_from_record` re-signs over the current
    // static, so the sequence would silently regress and peers would reject
    // the rotated binding (is_newer_than). Writing the binding first makes
    // the crash state recover to the old key with the new sequence, which
    // re-signs deterministically over the CURRENT static on load.
    ks.delete(KeyClass::IdentitySigning, BINDING_RECORD)
        .map_err(|e| format!("keystore delete: {e:?}"))?;
    ks.store(
        KeyClass::IdentitySigning,
        BINDING_RECORD,
        &binding_bytes(binding),
    )
    .map_err(|e| format!("keystore store: {e:?}"))?;
    ks.delete(KeyClass::IdentitySigning, NODE_IDENTITY_RECORD)
        .map_err(|e| format!("keystore delete: {e:?}"))?;
    ks.store(KeyClass::IdentitySigning, NODE_IDENTITY_RECORD, &seeds)
        .map_err(|e| format!("keystore store: {e:?}"))?;
    Ok(())
}

fn secondary_record_bytes(identity: &NodeIdentity, binding: &IdentityBinding) -> Vec<u8> {
    let mut out = Vec::with_capacity(SECONDARY_RECORD_LEN);
    out.extend_from_slice(&identity.identity.to_seed());
    out.extend_from_slice(&identity.static_handshake.to_seed());
    out.extend_from_slice(&binding_bytes(binding));
    out
}

fn persist_secondary(ks: &Keystore, secondary: &SecondaryIdentity) -> Result<(), String> {
    ks.delete(KeyClass::IdentitySigning, secondary.record_name.as_bytes())
        .map_err(|e| format!("keystore delete: {e:?}"))?;
    ks.store(
        KeyClass::IdentitySigning,
        secondary.record_name.as_bytes(),
        &secondary_record_bytes(&secondary.identity, &secondary.binding),
    )
    .map_err(|e| format!("keystore store: {e:?}"))
}

fn load_secondary_index(ks: &Keystore) -> Result<SecondaryIndex, String> {
    match ks.load(KeyClass::IdentitySigning, SECONDARY_INDEX_RECORD) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("index parse: {e}")),
        Err(KeystoreError::UnsupportedClass) => Ok(SecondaryIndex::default()),
        Err(e) => Err(format!("index load: {e:?}")),
    }
}

fn persist_secondary_index(ks: &Keystore, index: &SecondaryIndex) -> Result<(), String> {
    let bytes = serde_json::to_vec(index).map_err(|e| e.to_string())?;
    ks.delete(KeyClass::IdentitySigning, SECONDARY_INDEX_RECORD)
        .map_err(|e| format!("keystore delete: {e:?}"))?;
    ks.store(KeyClass::IdentitySigning, SECONDARY_INDEX_RECORD, &bytes)
        .map_err(|e| format!("keystore store: {e:?}"))
}

/// Password for the node keystore (core.md §63). Read from the
/// `UMC_KEYSTORE_PASSWORD` environment variable; when unset, the
/// development default of an empty password is used (documented in
/// storage.md §10; never prompted).
#[must_use]
/// Wall-clock epoch milliseconds as an `Instant`. Bundle timestamps are
/// persisted and compared across restarts, so they MUST be epoch-relative,
/// not process-relative (the monotonic node clock re-baselines per boot).
pub(crate) fn wall_now() -> Instant {
    use std::time::{SystemTime, UNIX_EPOCH};
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0);
    Instant(millis)
}

/// File kept outside the backup payload so a validated restore can advance a
/// generation that an older snapshot cannot roll back.
pub(crate) const RESTORE_ANCHOR_FILE: &str = ".restore-anchor";
const RESTORE_ANCHOR_KEY: &[u8] = b"runtime/restore-anchor";
#[cfg(not(test))]
const PLATFORM_RESTORE_ANCHOR_PREFIX: &str = "restore-anchor-v1/";

/// Reads the external restore generation. A missing or malformed anchor is
/// treated as generation zero and logged; startup still fails closed when the
/// persisted database anchor disagrees with the external value.
pub(crate) fn read_restore_anchor(data_dir: &std::path::Path) -> u64 {
    let path = data_dir.join(RESTORE_ANCHOR_FILE);
    match std::fs::read_to_string(&path) {
        Ok(value) => match value.trim().parse::<u64>() {
            Ok(generation) => generation,
            Err(error) => {
                log::warn!(
                    "[restore] ignoring malformed anchor {}: {error}",
                    path.display()
                );
                0
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => {
            log::warn!("[restore] cannot read anchor {}: {error}", path.display());
            0
        }
    }
}

/// Stable, non-sensitive keychain reference for one node data directory. The
/// path itself never enters the OS credential store account name.
#[cfg(not(test))]
fn platform_restore_anchor_reference(data_dir: &std::path::Path) -> String {
    let mut hasher = Blake2s256::new();
    hasher.update(b"UMC-RESTORE-ANCHOR-v1\0");
    hasher.update(data_dir.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let mut reference = String::with_capacity(PLATFORM_RESTORE_ANCHOR_PREFIX.len() + 64);
    reference.push_str(PLATFORM_RESTORE_ANCHOR_PREFIX);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(reference, "{byte:02x}");
    }
    reference
}

/// Reads the external OS-keychain generation. The native keychain is an
/// independent store from the backup payload; missing or unavailable native
/// backends are reported to the caller so the file anchor can remain the
/// bounded fallback.
#[cfg(test)]
#[allow(clippy::unnecessary_wraps)]
fn read_platform_restore_anchor(_data_dir: &std::path::Path) -> Result<Option<u64>, KeychainError> {
    Ok(None)
}

#[cfg(not(test))]
fn read_platform_restore_anchor(data_dir: &std::path::Path) -> Result<Option<u64>, KeychainError> {
    let keychain = OsKeychain;
    match keychain.get_secret(&platform_restore_anchor_reference(data_dir)) {
        Ok(bytes) if bytes.len() == 8 => Ok(Some(u64::from_be_bytes(
            bytes.as_slice().try_into().expect("eight-byte anchor"),
        ))),
        Ok(_) => Err(KeychainError::Unavailable),
        Err(KeychainError::Missing) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[allow(clippy::unnecessary_wraps)]
fn write_platform_restore_anchor(
    _data_dir: &std::path::Path,
    _generation: u64,
) -> Result<(), KeychainError> {
    Ok(())
}

#[cfg(not(test))]
fn write_platform_restore_anchor(
    data_dir: &std::path::Path,
    generation: u64,
) -> Result<(), KeychainError> {
    #[cfg(test)]
    {
        let _ = (data_dir, generation);
        return Ok(());
    }
    #[cfg(not(test))]
    {
        let keychain = OsKeychain;
        keychain.set_secret(
            &platform_restore_anchor_reference(data_dir),
            &generation.to_be_bytes(),
        )
    }
}

/// Advances and atomically persists the external restore generation.
///
/// # Errors
/// Returns a message when the anchor cannot be written or renamed into place.
pub(crate) fn advance_restore_anchor(data_dir: &std::path::Path) -> Result<u64, String> {
    let file_generation = read_restore_anchor(data_dir);
    let platform_generation = match read_platform_restore_anchor(data_dir) {
        Ok(value) => value.unwrap_or(0),
        Err(error) => {
            log::warn!("[restore] platform anchor unavailable while advancing: {error:?}");
            0
        }
    };
    let generation = file_generation.max(platform_generation).saturating_add(1);
    let path = data_dir.join(RESTORE_ANCHOR_FILE);
    let temporary = data_dir.join(format!("{RESTORE_ANCHOR_FILE}.tmp"));
    std::fs::write(&temporary, format!("{generation}\n"))
        .map_err(|error| format!("write restore anchor {}: {error}", temporary.display()))?;
    std::fs::rename(&temporary, &path)
        .map_err(|error| format!("install restore anchor {}: {error}", path.display()))?;
    if let Err(error) = write_platform_restore_anchor(data_dir, generation) {
        log::warn!("[restore] platform anchor update unavailable: {error:?}");
    }
    Ok(generation)
}

/// Compares the database's last-seen restore generation with the external
/// anchor and persists the highest value. A mismatch is a warning rather than
/// an automatic refusal: operators may intentionally restore an older,
/// validated snapshot, but trust/revocation claims must then be treated as
/// potentially stale (identity-trust.md §21.3, storage.md §21.3).
fn reconcile_restore_anchor(
    store: &dyn Store,
    data_dir: &std::path::Path,
) -> Result<Option<String>, String> {
    let file_external = read_restore_anchor(data_dir);
    let platform_external = match read_platform_restore_anchor(data_dir) {
        Ok(value) => value,
        Err(error) => {
            log::warn!("[restore] platform anchor unavailable at startup: {error:?}");
            None
        }
    };
    let external = file_external.max(platform_external.unwrap_or(0));
    let persisted = store
        .get(Namespace::Trust, RESTORE_ANCHOR_KEY)
        .map_err(|error| format!("restore anchor read: {error:?}"))?
        .map(|bytes| {
            if bytes.len() != 8 {
                return Err("malformed persisted restore anchor".to_string());
            }
            Ok(u64::from_be_bytes(bytes.as_slice().try_into().map_err(
                |_| "malformed persisted restore anchor".to_string(),
            )?))
        })
        .transpose()?;
    let effective = persisted.unwrap_or(external).max(external);
    let warning = match persisted {
        Some(value) if value != external => Some(format!(
            "trust/revocation state may be stale: restore anchor differs (database={value}, external={external})"
        )),
        None if external != 0 => Some(format!(
            "trust/revocation state may be stale: database has no restore anchor (external={external})"
        )),
        _ => None,
    };
    if persisted != Some(effective) {
        store
            .put(
                Namespace::Trust,
                RESTORE_ANCHOR_KEY,
                &effective.to_be_bytes(),
            )
            .map_err(|error| format!("restore anchor write: {error:?}"))?;
    }
    if effective > 0 && platform_external != Some(effective) {
        if let Err(error) = write_platform_restore_anchor(data_dir, effective) {
            log::warn!("[restore] platform anchor reconciliation unavailable: {error:?}");
        }
    }
    Ok(warning)
}

pub(crate) fn keystore_password() -> Vec<u8> {
    let Ok(pw) = std::env::var("UMC_KEYSTORE_PASSWORD") else {
        // Dev default: the keystore then protects identity with file
        // permissions only (storage.md §10.1 requires a strong secret
        // before production use).
        log::warn!("[keystore] warning: UMC_KEYSTORE_PASSWORD unset — using the dev default (no password protection)");
        return Vec::new();
    };
    pw.into_bytes()
}

fn identity_from_seeds(seeds: &[u8]) -> NodeIdentity {
    let identity_seed: [u8; 32] = seeds[..32].try_into().expect("32-byte identity seed");
    let static_seed: [u8; 32] = seeds[32..].try_into().expect("32-byte static seed");
    NodeIdentity {
        identity: IdentityKeyPair::from_seed(identity_seed),
        static_handshake: StaticHandshakeKeyPair::from_seed(static_seed),
    }
}

/// Bounded single-use session-ticket cache (handshake.md §35): the clear
/// ticket nonce is the ticket id, so a resume presenting an already-seen
/// nonce is a replay and is refused. FIFO eviction keeps the cache bounded.
#[derive(Debug, Default)]
pub struct TicketReplayCache {
    seen: HashSet<[u8; 16]>,
    order: VecDeque<[u8; 16]>,
}

impl TicketReplayCache {
    /// Maximum ticket ids retained.
    pub const CAP: usize = 1_024;

    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Records `nonce` as consumed. Returns `true` when the nonce is fresh
    /// (the resume may proceed) and `false` when it was seen before (a
    /// replay — refuse the resume).
    #[must_use]
    pub fn insert(&mut self, nonce: [u8; 16]) -> bool {
        if !self.seen.insert(nonce) {
            return false;
        }
        self.order.push_back(nonce);
        if self.order.len() > Self::CAP {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        true
    }

}

/// Bounded single-use identity-deletion confirmation cache. Confirmation
/// tokens are process-local and one-time; FIFO eviction keeps replay state
/// bounded without persisting sensitive authorization artifacts.
#[derive(Debug, Default)]
pub struct DeletionPlanReplayCache {
    seen: HashSet<[u8; 16]>,
    order: VecDeque<[u8; 16]>,
}

impl DeletionPlanReplayCache {
    /// Maximum confirmation nonces retained.
    pub const CAP: usize = 1_024;

    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Records `nonce`; returns `false` when already consumed.
    #[must_use]
    pub fn insert(&mut self, nonce: [u8; 16]) -> bool {
        if !self.seen.insert(nonce) {
            return false;
        }
        self.order.push_back(nonce);
        if self.order.len() > Self::CAP {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        true
    }

    #[must_use]
    pub fn seen(&self, nonce: [u8; 16]) -> bool {
        self.seen.contains(&nonce)
    }
}

/// Application registration metadata retained for the lifetime of the
/// runtime. Resumable registrations keep this record when their control
/// connection closes so a later registration with the same authenticated
/// principal and instance id can reclaim the application handle.
#[derive(Debug, Clone)]
pub struct ApplicationRegistration {
    pub application_name: String,
    pub application_instance_id: Vec<u8>,
    pub requested_endpoint_ids: Vec<Vec<u8>>,
    pub requested_protocol_ids: Vec<String>,
    pub requested_capabilities: Vec<i32>,
    pub resumable: bool,
    pub effective_grants: Vec<api::CapabilityGrant>,
    pub resume_token: Vec<u8>,
}

/// The daemon's shared runtime context.
pub struct RuntimeState {
    pub config: NodeConfig,
    /// Monotonic startup timestamp.
    pub started_at: Instant,
    /// Warning captured when the persisted trust/revocation anchor differs
    /// from the external restore-generation anchor.
    pub restore_warning: Option<String>,
    /// Startup warning when persisted revocation evidence is older than the
    /// local freshness window or cannot be read.
    pub revocation_warning: Option<String>,
    /// Random identifier for this daemon process instance. It changes on
    /// every startup and scopes control-plane handles and resume cursors.
    pub server_instance_id: [u8; 16],
    /// Secret used to authenticate event resume cursors. It is intentionally
    /// process-local, so a daemon restart invalidates outstanding cursors.
    pub event_cursor_key: [u8; 32],
    /// Secret used to authenticate identity-deletion confirmation tokens.
    /// Process-local scope makes tokens invalid after restart.
    pub deletion_plan_key: [u8; 32],
    /// Resolved control socket path.
    pub control_socket: PathBuf,
    /// Node database (namespaces: config, trust, records).
    pub store: Arc<SqliteStore>,
    /// Default trust level for unseen endpoints. Consumed by
    /// [`Self::trust_store`]; `PeerService.SetTrustState` changes it per
    /// endpoint (identity-trust.md §13).
    pub trust_default_level: TrustLevel,
    /// Endpoint blocklist (core.md §44, security-operations.md §16.2):
    /// `PeerService.BlockPeer`/`UnblockPeer` wire it, and the accept loop
    /// refuses sessions from blocked endpoints
    /// ([`Self::refuse_if_blocked`]).
    pub blocklist: Blocklist,
    /// Per-peer rate limiter for live control requests
    /// (resource-limits.md §47).
    pub rate_limiter: RateLimiter,
    /// Per-control-principal enumeration budget (discovery.md §18): list and
    /// query surfaces consume bounded work without revealing whether a
    /// hidden candidate exists after the budget is exhausted.
    pub enumeration_guard: EnumerationGuard,
    /// Node identity. Loaded from the keystore (core.md §19/§63), so the
    /// endpoint id survives restarts; a fresh identity is generated and
    /// persisted on first boot.
    pub node_identity: NodeIdentity,
    /// The primary identity's current signed binding (handshake.md §33,
    /// task F2): persisted sequence + validity window, re-signed on
    /// `RotateHandshakeKey`/`RotateIdentityKey`. Sequence is monotonic
    /// across restarts because the binding record lives in the keystore.
    pub primary_binding: IdentityBinding,
    /// Secondary identities (task F2): keystore-backed, created via
    /// `CreateIdentity`/`ImportIdentity`, deletable. Never the primary.
    pub secondaries: Vec<SecondaryIdentity>,
    /// Session-ticket key (handshake.md §35): HKDF-Extract of the keystore
    /// identity seed (the keystore-derived identity seed hash, SANCTIONED).
    /// Stable across restarts because the keystore identity is persistent;
    /// secret because the seed never leaves the daemon. Tickets sealed with
    /// it are opaque to peers — the ticket only carries its nonce in the
    /// clear (v1 wire format).
    pub ticket_key: [u8; 32],
    /// Stateless Retry token/integrity key, rotated with the node identity.
    pub retry_key: [u8; 32],
    /// Bounded single-use ticket cache: a ticket nonce seen before refuses
    /// the resume (handshake.md §35), so one ticket grants at most one
    /// session under the victim's endpoint id.
    pub ticket_replay_cache: std::sync::Mutex<TicketReplayCache>,
    /// Bounded single-use identity-deletion confirmation nonces.
    pub deletion_plan_replay: std::sync::Mutex<DeletionPlanReplayCache>,
    /// Operating mode profile (local mesh vs endpoint).
    pub mesh: MeshConfig,
    /// The runtime node: registered carriers, sessions (core.md §8).
    pub node: Node,
    /// `CarrierService` instance records and lifecycle revisions. Concrete
    /// carrier wiring is registered at startup; control-created records keep
    /// their options here until per-instance factories are available.
    pub carrier_instances:
        std::collections::HashMap<Vec<u8>, crate::control_carriers::CarrierInstanceRecord>,
    /// Whether carrier control records have been initialized for this runtime.
    /// This distinguishes an empty registry from a deliberately deleted last
    /// instance when type-only legacy operations are still in use.
    pub carrier_registry_initialized: bool,
    /// Bound carrier listeners; held here so the sockets stay alive.
    pub listeners: Vec<Box<dyn Listener + Send + Sync>>,
    /// Runtime listeners owned by control-created carrier instances. The
    /// accept task holds a clone of each `Arc`, while this map gives
    /// `StopCarrier` an idempotent close path for the underlying resource.
    pub carrier_listeners: HashMap<Vec<u8>, Arc<dyn Listener + Send + Sync>>,
    /// Live session registry (core.md §9.5); populated by the accept loops.
    pub sessions: Arc<SessionManager>,
    /// Session transport objects addressable by live application handles.
    pub session_controls: HashMap<u64, Arc<SessionControl>>,
    /// Outbound carrier links created through `CarrierService.Dial`. Keeping
    /// ownership here makes link handles independent from session handles and
    /// lets lifecycle operations close/drain them deterministically.
    pub carrier_links: HashMap<Vec<u8>, CarrierLinkRecord>,
    /// Weak self-reference so runtime handlers (e.g. CarrierService.Listen)
    /// can spawn state-bound tasks without deadlocking the held lock.
    pub self_arc: std::sync::Weak<std::sync::Mutex<RuntimeState>>,
    /// Session bus: cross-session delivery within one daemon (relay
    /// forwarding, future bundle delivery).
    pub bus: Arc<Mutex<SessionBus>>,
    /// Discovery service: candidate table + `PEER_HINT` builder.
    pub discovery: DiscoveryService,
    /// Invitation store (discovery.md §14): issued invitations and their
    /// validation keys, backing `PeerService.CreateInvitation`,
    /// `ImportInvitation`, and `RevokeInvitation`.
    pub invitations: InvitationStore,
    /// Relay service: circuit registry, admission, forwarding.
    pub relay: RelayService,
    /// Bounded endpoint handoffs created by relay-delivered Initial packets.
    /// The key is the authenticated adjacent session plus its peer-scoped
    /// wire circuit id; values feed the one destination-side `RelayLink`.
    pub relay_endpoint_handoffs: HashMap<(u64, u64), SyncSender<Vec<u8>>>,
    /// Bundle service: object-store-backed bundle admission and expiry.
    pub bundle: BundleService,
    /// Routing service: request admission, reverse paths, route cache.
    #[allow(dead_code)] // route-request handling lands in Phase 12
    pub routing: RoutingService,
    /// Bounded daemon event log; services push transitions into it.
    pub events: Arc<Mutex<DaemonEvents>>,
    /// Live event subscriptions for control-plane clients.
    pub event_bus: Arc<Mutex<EventBus>>,
    /// Bounded idempotency replay state shared across control connections and
    /// restored from encrypted API-namespace records on daemon restart.
    pub idempotency: crate::control_transport::IdempotencyCache,
    /// Bearer-token registry and grants for local control clients.
    pub token_registry: TokenRegistry,
    pub token_grants: HashMap<u64, Vec<api::CapabilityGrant>>,
    /// Bounded metrics registry (core.md §42): the daemon's counters,
    /// surfaced through `DiagnosticsService.GetMetricsSnapshot`.
    pub metrics: Arc<Registry>,
    /// Registered applications (core.md §9.6); the echo application is
    /// installed at startup so `org.umc.app/1` streams dispatch end to end.
    #[allow(dead_code)] // app registration over the control API lands in Phase 10
    pub apps: AppRegistry,
    /// Per-application inbound stream channels: session tasks forward
    /// received stream data into the application's channel.
    pub app_channels: Arc<Mutex<HashMap<Vec<u8>, AppTx>>>,
    /// Protocol ids owned by each control-plane application handle. The v1
    /// handle is the first requested protocol id, so this side table keeps
    /// multi-protocol registrations removable as one application.
    pub application_protocols: HashMap<Vec<u8>, Vec<Vec<u8>>>,
    /// Authorization principal that owns each control-plane application
    /// handle. Principal zero is the same-user OS-peer fallback.
    pub application_principals: HashMap<Vec<u8>, u64>,
    /// Control connection that owns each application handle. Empty IDs are
    /// used by in-process protocol tests, not live socket registrations.
    pub application_connections: HashMap<Vec<u8>, Vec<u8>>,
    /// Registration metadata needed to return effective grants and reclaim a
    /// resumable application after its control connection is replaced.
    pub application_registrations: HashMap<Vec<u8>, ApplicationRegistration>,
    /// Listener handles opened by applications. Listener handles are the
    /// application handle in the current v1 surface, but tracking their
    /// lifecycle separately lets `CloseListener` stop admission without
    /// unregistering the application itself.
    pub application_listeners: HashSet<Vec<u8>>,
    /// Bounded application-owned stream/datagram queues and pending accepts.
    pub application_data: ApplicationDataPlane,
    /// Per-application echo receivers: the application's outbound channel,
    /// drained by the session writers and sent back on the same stream.
    pub app_echo_rx: Arc<Mutex<HashMap<Vec<u8>, AppRx>>>,
    /// Development-only control API bearer credential (control-api.md
    /// §11.3). `None` in production: same-user Unix peer auth remains the
    /// local fallback, while presented bearer requests use grant checks.
    pub development_token: Option<Vec<u8>>,
    /// Set when a graceful shutdown was requested.
    pub shutdown_requested: Arc<AtomicBool>,
    /// Released once shutdown completes; the main task waits on it.
    pub shutdown_channel: mpsc::Sender<()>,
}

/// One daemon-owned raw outbound carrier link.
pub struct CarrierLinkRecord {
    pub carrier_handle: Vec<u8>,
    pub carrier_type: String,
    pub link: Arc<umc_carrier::BoxLink>,
}

impl std::fmt::Debug for RuntimeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeState")
            .field("started_at", &self.started_at)
            .field("control_socket", &self.control_socket)
            .field("restore_warning", &self.restore_warning.is_some())
            .field("revocation_warning", &self.revocation_warning.is_some())
            .field("listeners", &self.listeners.len())
            .finish_non_exhaustive()
    }
}

impl RuntimeState {
    /// Builds the runtime state: data dir + keystore dir, node database,
    /// identity (persisted in the keystore), security primitives, and the
    /// shutdown channel.
    ///
    /// # Errors
    ///
    /// Returns an error when the data or keystore directory cannot be
    /// created, the node database cannot be opened, or the keystore cannot
    /// be opened with the configured password
    /// ([`UMC_KEYSTORE_PASSWORD`](keystore_password)).
    #[allow(clippy::too_many_lines)] // startup composes all bounded daemon subsystems
    pub fn new(config: NodeConfig, shutdown_channel: mpsc::Sender<()>) -> Result<Self, String> {
        let resource_profile = config.resource_profile();
        let data_dir = config.resolved_data_dir();
        std::fs::create_dir_all(&data_dir).map_err(|e| format!("data dir: {e}"))?;
        std::fs::create_dir_all(config.resolved_keystore_dir())
            .map_err(|e| format!("keystore dir: {e}"))?;
        let store = Arc::new(
            SqliteStore::open(&data_dir.join("node.db")).map_err(|e| format!("store: {e:?}"))?,
        );
        let restore_warning = reconcile_restore_anchor(store.as_ref(), &data_dir)?;

        let (node_identity, primary_binding, secondaries) = load_identity_registry(&config)?;
        let node_endpoint_id = node_identity.endpoint_id();
        let node_identity_key = node_identity.identity.clone();
        // The runtime node and the state share the same key material.
        let state_identity = NodeIdentity {
            identity: node_identity.identity.clone(),
            static_handshake: node_identity.static_handshake.clone(),
        };
        // Session-ticket key (handshake.md §35): the keystore identity
        // seed hash — persistent across restarts and bound to the node's
        // identity (see the field docs).
        let ticket_key = ticket_key_for(&state_identity);
        let retry_key = retry_key_for(&state_identity);
        let dcid = node_identity.endpoint_id()[..8].to_vec();
        let realm_marker = config.realm_marker();
        let private_realm = config.is_private_network();
        let mut node = Node::new(
            NodeRuntimeConfig {
                identity: node_identity,
                dcid,
            },
            Arc::new(TokioAdaptor),
            Arc::new(TokioAdaptor),
        );
        node.set_realm(realm_marker, private_realm);
        let mesh = if config.mesh {
            MeshConfig::local_mesh()
        } else {
            MeshConfig::endpoint()
        };

        let event_bus = Arc::new(Mutex::new(EventBus::new()));
        let events = Arc::new(Mutex::new(DaemonEvents::new(200)));
        events
            .lock()
            .expect("event log")
            .attach_event_bus(event_bus.clone());
        let development_token = config
            .development_token
            .as_deref()
            .map(|token| token.as_bytes().to_vec());
        let bundle_objects = ObjectStore::open(data_dir.join("objects"))
            .map_err(|e| format!("bundle object store: {e:?}"))?;
        let bundle_quota =
            QuotaAccount::new(resource_profile, 0, resource_profile.bundle_storage_bytes());

        let mut apps = AppRegistry::new();
        apps.register(
            WELL_KNOWN_APP.to_vec(),
            crate::app_layer::ECHO_APP_NAME.to_string(),
        )
        .map_err(|e| format!("echo app registration: {e:?}"))?;

        let started_at = OsClock.now();
        let revocation_warning = match RevocationStore::new(store.as_ref())
            .freshness(started_at.0, DEFAULT_REVOCATION_FRESHNESS_MS)
        {
            Ok(RevocationFreshness::Stale {
                latest_recorded_at_ms,
            }) => Some(format!(
                "revocation state may be stale: newest local record is from {latest_recorded_at_ms}"
            )),
            Ok(RevocationFreshness::Fresh { .. } | RevocationFreshness::Unknown) => None,
            Err(error) => Some(format!("revocation state freshness unavailable: {error:?}")),
        };
        // Services bound to the node database restore persisted state at
        // startup: routes as candidates (storage.md §15.2), candidates as
        // operational hints (§16.4), bundle metadata (§6.3). Restore
        // failures are logged, never fatal.
        let mut discovery = DiscoveryService::new_with_realm(
            umc_discovery::table::DEFAULT_TABLE_CAP,
            realm_marker,
        );
        discovery.attach_store(store.clone());
        discovery.restore_candidates(store.as_ref(), started_at);
        discovery.record_advertised_endpoints(
            &node_identity_key,
            &node_endpoint_id,
            &config.advertised_endpoints,
            started_at,
        );
        let bootstrap_provider = crate::static_peers::BootstrapPeerProvider::new(
            &config.bootstrap_peers,
            started_at,
        );
        if !bootstrap_provider.is_empty() {
            discovery.register_provider(Box::new(bootstrap_provider));
            let startup_reports = discovery.start_providers();
            if startup_reports
                .iter()
                .any(|report| report.state != umc_discovery::manager::ProviderState::Running)
            {
                log::warn!("[discovery] bootstrap provider did not start cleanly");
            }
            let refresh = discovery.refresh_providers(started_at);
            log::debug!(
                "[discovery] bootstrap provider admitted {} candidate(s)",
                refresh.admitted_candidates
            );
        }
        let static_provider =
            crate::static_peers::StaticPeerProvider::new(&config.static_peers, started_at);
        if !static_provider.is_empty() {
            discovery.register_provider(Box::new(static_provider));
            let startup_reports = discovery.start_providers();
            if startup_reports
                .iter()
                .any(|report| report.state != umc_discovery::manager::ProviderState::Running)
            {
                log::warn!("[discovery] static provider did not start cleanly");
            }
            let refresh = discovery.refresh_providers(started_at);
            log::debug!(
                "[discovery] static provider admitted {} candidate(s)",
                refresh.admitted_candidates
            );
        }
        let mut routing = RoutingService::new();
        routing.attach_store(store.clone());
        routing.restore(store.as_ref(), started_at);
        let mut bundle = BundleService::new(bundle_objects, bundle_quota, events.clone());
        bundle.attach_store(store.clone());
        // Expiry comparison uses the node clock: the daemon's bundle
        // admission path (`CreateBundle`) stamps `created_at`/`expires_at`
        // from `node.clock`, so restore must compare against the same
        // clock family or every persisted bundle would look expired.
        let bundle_now = wall_now();
        match bundle.restore(store.as_ref(), bundle_now) {
            Ok(count) => log::info!("[bundle] restored {count} bundle(s) from metadata"),
            Err(e) => log::error!("[bundle] metadata restore failed: {e}"),
        }
        // The event log persists under the api namespace (core.md §15
        // audit logging): prior history is restored into the ring so the
        // control surface still sees it after a restart.
        {
            let mut events_guard = events.lock().expect("event log");
            events_guard.attach_store(store.clone());
            events_guard.restore_persisted(store.as_ref());
            if let Some(detail) = &restore_warning {
                log::warn!("[restore] {detail}");
                events_guard.push(crate::event_log::DaemonEvent {
                    kind: "restore_stale_state".into(),
                    at_ms: started_at.0,
                    detail: detail.clone(),
                });
            }
            if let Some(detail) = &revocation_warning {
                log::warn!("[trust] {detail}");
                events_guard.push(crate::event_log::DaemonEvent {
                    kind: "revocation_state_stale".into(),
                    at_ms: started_at.0,
                    detail: detail.clone(),
                });
            }
        }

        let mut server_instance_id = [0u8; 16];
        OsEntropy.fill(&mut server_instance_id);
        let mut event_cursor_key = [0u8; 32];
        OsEntropy.fill(&mut event_cursor_key);
        let mut deletion_plan_key = [0u8; 32];
        OsEntropy.fill(&mut deletion_plan_key);
        let (token_registry, token_grants) = restore_control_tokens(store.as_ref());
        let idempotency = crate::control_transport::IdempotencyCache::restore(
            store.as_ref(),
            &ticket_key,
            wall_now().0,
        );

        Ok(Self {
            control_socket: config.resolved_socket(),
            started_at,
            restore_warning,
            revocation_warning,
            server_instance_id,
            event_cursor_key,
            deletion_plan_key,
            config,
            store,
            trust_default_level: TrustLevel::Unknown,
            blocklist: Blocklist::new(60),
            rate_limiter: RateLimiter::new(1_024),
            enumeration_guard: EnumerationGuard::new(1_024),
            node_identity: state_identity,
            primary_binding,
            secondaries,
            ticket_key,
            retry_key,
            ticket_replay_cache: std::sync::Mutex::new(TicketReplayCache::new()),
            deletion_plan_replay: std::sync::Mutex::new(DeletionPlanReplayCache::new()),
            mesh,
            node,
            carrier_instances: HashMap::new(),
            carrier_registry_initialized: false,
            listeners: Vec::new(),
            carrier_listeners: HashMap::new(),
            sessions: Arc::new(SessionManager::new()),
            session_controls: HashMap::new(),
            carrier_links: HashMap::new(),
            self_arc: std::sync::Weak::new(),
            bus: Arc::new(Mutex::new(SessionBus::new())),
            discovery,
            invitations: InvitationStore::new(),
            relay: RelayService::new(events.clone()),
            relay_endpoint_handoffs: HashMap::new(),
            bundle,
            routing,
            events,
            event_bus,
            idempotency,
            token_registry,
            token_grants,
            metrics: Arc::new(Registry::new()),
            apps,
            app_channels: Arc::new(Mutex::new(HashMap::new())),
            application_protocols: HashMap::new(),
            application_principals: HashMap::new(),
            application_connections: HashMap::new(),
            application_registrations: HashMap::new(),
            application_listeners: HashSet::new(),
            application_data: ApplicationDataPlane::new(),
            app_echo_rx: Arc::new(Mutex::new(HashMap::new())),
            development_token,
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            shutdown_channel,
        })
    }

    /// Trust store over the shared node database: per-endpoint persisted
    /// levels, backing `PeerService.SetTrustState`.
    #[must_use]
    pub fn trust_store(&self) -> TrustStore<'_> {
        TrustStore::new(self.store.as_ref(), self.trust_default_level)
    }

    /// Returns the current local revocation-freshness classification.
    ///
    /// # Errors
    ///
    /// Returns an error when the trust namespace cannot be scanned or a
    /// revocation record is corrupt.
    pub fn revocation_freshness(&self, now_ms: u64) -> Result<RevocationFreshness, String> {
        RevocationStore::new(self.store.as_ref())
            .freshness(now_ms, DEFAULT_REVOCATION_FRESHNESS_MS)
            .map_err(|error| format!("revocation freshness: {error:?}"))
    }

    /// Produces the operator-facing qualification for trust/revocation
    /// claims. An unknown local record set is intentionally qualified rather
    /// than presented as proof that no revocation exists.
    #[must_use]
    pub fn revocation_claim_warning(&self, now_ms: u64) -> Option<String> {
        if let Some(detail) = &self.restore_warning {
            return Some(detail.clone());
        }
        match self.revocation_freshness(now_ms) {
            Ok(RevocationFreshness::Fresh { .. }) => None,
            Ok(RevocationFreshness::Unknown) => {
                Some("revocation state freshness unknown: no locally recorded update".into())
            }
            Ok(RevocationFreshness::Stale {
                latest_recorded_at_ms,
            }) => Some(format!(
                "revocation state may be stale: newest local record is from {latest_recorded_at_ms}"
            )),
            Err(error) => Some(error),
        }
    }

    /// Checks a verified handshake binding against revocation and TOFU state
    /// before the session is registered.
    ///
    /// # Errors
    /// Returns `IDENTITY_REVOKED` for an active revocation, or
    /// `TOFU_BINDING_MISMATCH` when the identity presents an unapproved
    /// binding change.
    pub fn validate_peer_binding(
        &self,
        binding: &IdentityBinding,
        now_ms: u64,
    ) -> Result<(), String> {
        match RevocationStore::new(self.store.as_ref()).check(binding, now_ms) {
            Ok(()) => {}
            Err(RevocationError::Revoked { .. }) => {
                return Err(format!("IDENTITY_REVOKED: {:?}", binding.endpoint_id));
            }
            Err(error) => return Err(format!("revocation check failed: {error:?}")),
        }
        match TofuStore::new(self.store.as_ref()).observe(binding, now_ms) {
            Ok(()) => Ok(()),
            Err(TofuError::BindingChanged { .. }) => {
                Err(format!("TOFU_BINDING_MISMATCH: {:?}", binding.endpoint_id))
            }
            Err(error) => Err(format!("TOFU check failed: {error:?}")),
        }
    }

    /// Refuses the endpoint while the blocklist holds an active block
    /// (security-operations.md §16.2). The accept loop consults this before
    /// registering any session, so `PeerService.BlockPeer` stops future
    /// sessions from the endpoint.
    ///
    /// # Errors
    /// Returns a message when `peer_endpoint_id` is blocked at `now`.
    pub fn refuse_if_blocked(&self, peer_endpoint_id: &[u8], now: Instant) -> Result<(), String> {
        match self.blocklist.is_blocked(peer_endpoint_id, now) {
            Some(expires_at) => Err(format!("peer blocked until {expires_at:?}")),
            None => Ok(()),
        }
    }

    /// Refuses new authenticated sessions for restricted, blocked, or revoked
    /// trust states while retaining the local relationship record.
    ///
    /// # Errors
    /// Returns a protocol-facing reason suitable for the handshake close
    /// event. Revocation deliberately uses the wire close reason name from
    /// handshake.md §46.
    pub fn refuse_if_trust_disallowed(&self, peer_endpoint_id: &[u8]) -> Result<(), String> {
        let state = self
            .trust_store()
            .effective_trust_state(peer_endpoint_id)
            .map_err(|error| format!("trust state unavailable: {error:?}"))?;
        if state.allows_new_session() {
            return Ok(());
        }
        let reason = match state {
            TrustState::Restricted => "TRUST_RESTRICTED",
            TrustState::Blocked => "TRUST_BLOCKED",
            TrustState::Revoked => "IDENTITY_REVOKED",
            TrustState::Unknown
            | TrustState::Observed
            | TrustState::Introduced
            | TrustState::Trusted => unreachable!("allowed trust state filtered above"),
        };
        Err(format!("{reason}: peer trust state {state:?}"))
    }

    /// Resolve an identity handle (the keystore record name) to the primary
    /// or a secondary (task F2). The primary's handle is the node-identity
    /// record name; secondaries use their own record names.
    #[must_use]
    pub fn identity_by_handle(&self, handle: &[u8]) -> Option<IdentityRef<'_>> {
        if handle == NODE_IDENTITY_RECORD {
            return Some(IdentityRef::Primary);
        }
        let record_name = String::from_utf8(handle.to_vec()).ok()?;
        self.secondaries
            .iter()
            .find(|entry| entry.record_name == record_name)
            .map(IdentityRef::Secondary)
    }

    /// Resolve an endpoint id to the primary or a secondary identity
    /// (task F2).
    #[must_use]
    pub fn identity_by_endpoint(&self, endpoint_id: &[u8]) -> Option<IdentityRef<'_>> {
        if self.node_identity.endpoint_id().as_slice() == endpoint_id {
            return Some(IdentityRef::Primary);
        }
        self.secondaries
            .iter()
            .find(|entry| entry.identity.endpoint_id().as_slice() == endpoint_id)
            .map(IdentityRef::Secondary)
    }

    /// `IdentityService.RotateHandshakeKey` (task F2, handshake.md §33):
    /// generate a fresh static handshake key, re-sign the identity binding
    /// at sequence + 1, persist both to the keystore, and switch the node
    /// to the new static key for future handshakes. The identity key (and
    /// therefore the endpoint id) is unchanged. Applies to the primary or
    /// to a secondary selected by handle.
    ///
    /// `lifetime_ms` bounds the binding's validity window; 0 means the
    /// binding never expires.
    ///
    /// # Errors
    /// Returns a message when the handle is unknown or the keystore write
    /// fails.
    pub fn rotate_handshake_key(
        &mut self,
        handle: &[u8],
        lifetime_ms: u64,
    ) -> Result<IdentityBinding, String> {
        let now = wall_now().0;
        // Resolve the target and copy the old binding/identity key before
        // any mutation so the borrow ends.
        let (is_primary, index) = self.resolve_target(handle)?;
        let old_sequence = if is_primary {
            self.primary_binding.sequence
        } else {
            self.secondaries[index].binding.sequence
        };
        let identity_key = if is_primary {
            self.node_identity.identity.clone()
        } else {
            self.secondaries[index].identity.identity.clone()
        };
        let new_static = StaticHandshakeKeyPair::generate();
        let binding = IdentityBinding::sign(
            &identity_key,
            &new_static.public(),
            now,
            if lifetime_ms == 0 {
                u64::MAX
            } else {
                now.saturating_add(lifetime_ms)
            },
            old_sequence.saturating_add(1),
            [0u8; 32],
        );
        let path = self.config.resolved_keystore_dir().join(KEYSTORE_FILE);
        let ks =
            Keystore::open(path, &keystore_password()).map_err(|e| format!("keystore: {e:?}"))?;
        if is_primary {
            let updated = NodeIdentity {
                identity: identity_key,
                static_handshake: new_static,
            };
            // Persist first: a keystore failure must leave the in-memory
            // node untouched.
            persist_binding(&ks, &updated, &binding)?;
            self.node_identity = updated;
            self.node.config.identity = NodeIdentity {
                identity: self.node_identity.identity.clone(),
                static_handshake: self.node_identity.static_handshake.clone(),
            };
            self.primary_binding = binding.clone();
        } else {
            let updated = SecondaryIdentity {
                identity: NodeIdentity {
                    identity: identity_key,
                    static_handshake: new_static,
                },
                record_name: self.secondaries[index].record_name.clone(),
                kind: self.secondaries[index].kind,
                label: self.secondaries[index].label.clone(),
                binding: binding.clone(),
                created_at_ms: self.secondaries[index].created_at_ms,
            };
            persist_secondary(&ks, &updated)?;
            self.secondaries[index] = updated;
        }
        Ok(binding)
    }

    /// `IdentityService.RotateIdentityKey` (task F2): generate a fresh
    /// identity keypair AND static handshake keypair, re-sign the binding
    /// at sequence + 1, and persist. For the primary this is a full
    /// identity change — the endpoint id changes, the node's dcid and
    /// session-ticket key follow, and existing session tickets stop being
    /// redeemable (documented).
    ///
    /// # Errors
    /// Returns a message when the handle is unknown or the keystore write
    /// fails.
    pub fn rotate_identity_key(&mut self, handle: &[u8]) -> Result<IdentityBinding, String> {
        let now = wall_now().0;
        let (is_primary, index) = self.resolve_target(handle)?;
        let old_sequence = if is_primary {
            self.primary_binding.sequence
        } else {
            self.secondaries[index].binding.sequence
        };
        let identity = NodeIdentity::generate(&OsEntropy);
        let binding = IdentityBinding::sign(
            &identity.identity,
            &identity.static_handshake.public(),
            now,
            u64::MAX,
            old_sequence.saturating_add(1),
            [0u8; 32],
        );
        let path = self.config.resolved_keystore_dir().join(KEYSTORE_FILE);
        let ks =
            Keystore::open(path, &keystore_password()).map_err(|e| format!("keystore: {e:?}"))?;
        if is_primary {
            persist_binding(&ks, &identity, &binding)?;
            self.node_identity = identity;
            self.node.config.identity = NodeIdentity {
                identity: self.node_identity.identity.clone(),
                static_handshake: self.node_identity.static_handshake.clone(),
            };
            self.node.config.dcid = self.node_identity.endpoint_id()[..8].to_vec();
            self.ticket_key = ticket_key_for(&self.node_identity);
            self.retry_key = retry_key_for(&self.node_identity);
            self.primary_binding = binding.clone();
        } else {
            let updated = SecondaryIdentity {
                identity: NodeIdentity {
                    identity: identity.identity,
                    static_handshake: identity.static_handshake,
                },
                record_name: self.secondaries[index].record_name.clone(),
                kind: self.secondaries[index].kind,
                label: self.secondaries[index].label.clone(),
                binding: binding.clone(),
                created_at_ms: self.secondaries[index].created_at_ms,
            };
            persist_secondary(&ks, &updated)?;
            self.secondaries[index] = updated;
        }
        Ok(binding)
    }

    /// `IdentityService.CreateIdentity` (task F2): generate a fresh
    /// secondary identity, store it in the keystore under a new record,
    /// and register it. The primary node identity is never touched.
    ///
    /// # Errors
    /// Returns a message when the keystore write fails.
    pub fn create_secondary_identity(
        &mut self,
        kind: i32,
        label: &str,
        lifetime_ms: u64,
    ) -> Result<SecondaryIdentity, String> {
        let now = wall_now().0;
        let identity = NodeIdentity::generate(&OsEntropy);
        let binding = IdentityBinding::sign(
            &identity.identity,
            &identity.static_handshake.public(),
            now,
            if lifetime_ms == 0 {
                u64::MAX
            } else {
                now.saturating_add(lifetime_ms)
            },
            0,
            [0u8; 32],
        );
        let path = self.config.resolved_keystore_dir().join(KEYSTORE_FILE);
        let ks =
            Keystore::open(path, &keystore_password()).map_err(|e| format!("keystore: {e:?}"))?;
        let mut index = load_secondary_index(&ks)?;
        let secondary = SecondaryIdentity {
            identity,
            record_name: format!("secondary-{}", index.next_id),
            kind,
            label: label.to_string(),
            binding,
            created_at_ms: now,
        };
        persist_secondary(&ks, &secondary)?;
        index.next_id = index.next_id.saturating_add(1);
        index.entries.push(SecondaryIndexEntry {
            record_name: secondary.record_name.clone(),
            kind,
            label: label.to_string(),
            created_at_ms: now,
        });
        persist_secondary_index(&ks, &index)?;
        let clone = secondary.clone_identity();
        self.secondaries.push(secondary);
        Ok(clone)
    }

    /// `IdentityService.DeleteIdentity` (task F2): remove a secondary
    /// identity from the registry and the keystore. The primary cannot be
    /// deleted (the caller rejects the primary handle).
    ///
    /// # Errors
    /// Returns a message when the handle is unknown or the keystore write
    /// fails.
    pub fn delete_secondary_identity(&mut self, handle: &[u8]) -> Result<(), String> {
        let record_name = String::from_utf8(handle.to_vec())
            .map_err(|_| "identity: invalid handle".to_string())?;
        let Some(index) = self
            .secondaries
            .iter()
            .position(|entry| entry.record_name == record_name)
        else {
            return Err("identity: unknown handle".into());
        };
        let path = self.config.resolved_keystore_dir().join(KEYSTORE_FILE);
        let ks =
            Keystore::open(path, &keystore_password()).map_err(|e| format!("keystore: {e:?}"))?;
        ks.delete(KeyClass::IdentitySigning, handle)
            .map_err(|e| format!("keystore delete: {e:?}"))?;
        let mut idx = load_secondary_index(&ks)?;
        idx.entries.retain(|entry| entry.record_name != record_name);
        persist_secondary_index(&ks, &idx)?;
        self.secondaries.remove(index);
        Ok(())
    }

    /// `IdentityService.ImportIdentity` (task F2): import raw
    /// `[identity_seed || static_seed]` material as a NEW secondary
    /// identity. The primary is never replaced by an import. When
    /// `validate_only` is set the seeds are validated and the would-be
    /// identity reported without touching the keystore or registry.
    ///
    /// # Errors
    /// Returns a message when the seeds are malformed or the keystore
    /// write fails.
    pub fn import_secondary_identity(
        &mut self,
        seeds: &[u8],
        label: &str,
        validate_only: bool,
    ) -> Result<SecondaryIdentity, String> {
        let identity_seed: [u8; 32] = seeds
            .get(..32)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| "identity: import requires 64 bytes of seeds".to_string())?;
        let static_seed: [u8; 32] = seeds
            .get(32..64)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| "identity: import requires 64 bytes of seeds".to_string())?;
        let identity = NodeIdentity {
            identity: IdentityKeyPair::from_seed(identity_seed),
            static_handshake: StaticHandshakeKeyPair::from_seed(static_seed),
        };
        let now = wall_now().0;
        let binding = IdentityBinding::sign(
            &identity.identity,
            &identity.static_handshake.public(),
            now,
            u64::MAX,
            0,
            [0u8; 32],
        );
        let path = self.config.resolved_keystore_dir().join(KEYSTORE_FILE);
        let ks =
            Keystore::open(path, &keystore_password()).map_err(|e| format!("keystore: {e:?}"))?;
        let mut index = load_secondary_index(&ks)?;
        let secondary = SecondaryIdentity {
            identity,
            record_name: format!("secondary-{}", index.next_id),
            kind: 0,
            label: label.to_string(),
            binding,
            created_at_ms: now,
        };
        if validate_only {
            // Validate-only: report the identity the seeds would create
            // without touching the keystore or registry.
            return Ok(secondary);
        }
        persist_secondary(&ks, &secondary)?;
        index.next_id = index.next_id.saturating_add(1);
        index.entries.push(SecondaryIndexEntry {
            record_name: secondary.record_name.clone(),
            kind: secondary.kind,
            label: label.to_string(),
            created_at_ms: now,
        });
        persist_secondary_index(&ks, &index)?;
        let clone = secondary.clone_identity();
        self.secondaries.push(secondary);
        Ok(clone)
    }

    /// Resolve an identity handle to `(is_primary, secondary_index)`.
    ///
    /// # Errors
    /// Returns a message for unknown or non-UTF-8 handles.
    fn resolve_target(&self, handle: &[u8]) -> Result<(bool, usize), String> {
        if handle == NODE_IDENTITY_RECORD {
            return Ok((true, 0));
        }
        let record_name = String::from_utf8(handle.to_vec())
            .map_err(|_| "identity: invalid handle".to_string())?;
        self.secondaries
            .iter()
            .position(|entry| entry.record_name == record_name)
            .map(|index| (false, index))
            .ok_or_else(|| "identity: unknown handle".into())
    }
}

/// A resolved identity reference (task F2): the primary or a secondary.
#[derive(Debug, Clone, Copy)]
pub enum IdentityRef<'a> {
    Primary,
    Secondary(&'a SecondaryIdentity),
}

impl SecondaryIdentity {
    /// A deep copy: `NodeIdentity` is not `Clone`, so the registry keeps
    /// its own copy while the caller takes one.
    fn clone_identity(&self) -> Self {
        SecondaryIdentity {
            identity: NodeIdentity {
                identity: self.identity.identity.clone(),
                static_handshake: self.identity.static_handshake.clone(),
            },
            record_name: self.record_name.clone(),
            kind: self.kind,
            label: self.label.clone(),
            binding: self.binding.clone(),
            created_at_ms: self.created_at_ms,
        }
    }
}

/// Daemon metric names (core.md §42). Names are flat and unlabeled — the
/// callers bake per-service distinctions into the name
/// (`control_requests_nodeadmin`, never `control_requests{service=NodeAdmin}`)
/// — and every series name lives here so all update sites share one
/// spelling. The registry caps distinct series at 1,024; daemon wiring uses
/// a fixed set well below that.
pub mod metric_names {
    /// Live sessions (gauge): set to the session registry count at each
    /// registration.
    pub const SESSIONS_ACTIVE: &str = "sessions_active";
    /// Sessions established since daemon start (counter).
    pub const SESSIONS_TOTAL: &str = "sessions_total";
    /// Inbound handshakes refused (counter).
    pub const HANDSHAKE_FAILURES: &str = "handshake_failures";
    /// IK-mode resumed sessions established (counter).
    pub const RESUMPTION_SESSIONS: &str = "resumption_sessions";
    /// Whether current trust claims require a revocation-freshness warning
    /// (gauge: 1 when unknown/stale/unreadable, otherwise 0).
    pub const REVOCATION_STATE_STALE: &str = "revocation_state_stale";
    /// Inbound protected packets fed to the session layer (counter).
    pub const PACKETS_RECEIVED: &str = "packets_received";
    /// Lost packets re-sent under fresh numbers (counter).
    pub const RETRANSMISSIONS: &str = "retransmissions";
    /// Persistent-congestion path degradations recorded (counter).
    pub const PATH_DEGRADED_EVENTS: &str = "path_degraded_events";
    /// Relay circuits admitted (counter; wire and control paths).
    pub const RELAY_CIRCUITS_OPENED: &str = "relay_circuits_opened";
    /// Relay circuits closed (counter; wire and control paths).
    pub const RELAY_CIRCUITS_CLOSED: &str = "relay_circuits_closed";
    /// Bundles admitted into the store (counter; wire and control paths).
    pub const BUNDLES_ADMITTED: &str = "bundles_admitted";
    /// Bundles expired and evicted by the delivery sweep (counter).
    pub const BUNDLES_EXPIRED: &str = "bundles_expired";
    /// Inbound route requests, admitted or refused (counter).
    pub const ROUTE_REQUESTS_RECEIVED: &str = "route_requests_received";
    /// Control API requests dispatched, per service (counters).
    pub const CONTROL_REQUESTS_NODEADMIN: &str = "control_requests_nodeadmin";
    /// `PeerService` and its `DiscoveryService` alias.
    pub const CONTROL_REQUESTS_PEERSERVICE: &str = "control_requests_peerservice";
    pub const CONTROL_REQUESTS_BUNDLE: &str = "control_requests_bundle";
    pub const CONTROL_REQUESTS_RELAY: &str = "control_requests_relay";
    /// `SessionService`.
    pub const CONTROL_REQUESTS_SESSION: &str = "control_requests_session";
    /// `RouteService`.
    pub const CONTROL_REQUESTS_ROUTE: &str = "control_requests_route";
    pub const CONTROL_REQUESTS_CONFIG: &str = "control_requests_config";
    pub const CONTROL_REQUESTS_DIAGNOSTICS: &str = "control_requests_diagnostics";
    /// `IdentityService` (task F2).
    pub const CONTROL_REQUESTS_IDENTITY: &str = "control_requests_identity";
    /// `CarrierService` (task F2).
    pub const CONTROL_REQUESTS_CARRIER: &str = "control_requests_carrier";
    /// `ApplicationService` (task F4).
    pub const CONTROL_REQUESTS_APP: &str = "control_requests_app";
    pub const CONTROL_REQUESTS_OTHER: &str = "control_requests_other";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use std::sync::atomic::{AtomicU64, Ordering};
    use umc_storage::quota::Profile;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fresh_config() -> NodeConfig {
        let dir = std::env::temp_dir().join(format!(
            "umcd-state-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        NodeConfig {
            data_dir: dir,
            ..NodeConfig::default()
        }
    }

    /// Runs `f` with `UMC_KEYSTORE_PASSWORD` set; env mutation is
    /// serialized so parallel tests cannot observe each other's password
    /// (shared with the server.rs keystore tests via
    /// `KEYSTORE_PASSWORD_TEST_LOCK`).
    fn with_password(password: &str, f: impl FnOnce()) {
        let _guard = KEYSTORE_PASSWORD_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::env::set_var("UMC_KEYSTORE_PASSWORD", password);
        f();
        std::env::remove_var("UMC_KEYSTORE_PASSWORD");
    }

    fn build(config: NodeConfig) -> RuntimeState {
        let (tx, _rx) = mpsc::channel(1);
        RuntimeState::new(config, tx).expect("runtime state")
    }

    #[test]
    fn restricted_and_revoked_trust_states_refuse_new_sessions() {
        with_password("state-trust-test", || {
            let state = build(fresh_config());
            let endpoint = [7u8; 32];
            state
                .trust_store()
                .set_state(&endpoint, TrustState::Restricted, 1)
                .expect("persist restricted state");
            let error = state
                .refuse_if_trust_disallowed(&endpoint)
                .expect_err("restricted peer must be refused");
            assert!(error.contains("TRUST_RESTRICTED"), "{error}");
            state
                .trust_store()
                .set_state(&endpoint, TrustState::Revoked, 2)
                .expect("persist revoked state");
            let error = state
                .refuse_if_trust_disallowed(&endpoint)
                .expect_err("revoked peer must be refused");
            assert!(error.contains("IDENTITY_REVOKED"), "{error}");
        });
    }

    #[test]
    fn runtime_uses_configured_resource_profile_for_bundle_quota() {
        with_password("state-profile-test", || {
            let mut config = fresh_config();
            config.profile = "constrained".into();
            let state = build(config);
            assert_eq!(state.bundle.manager.quota().profile, Profile::Constrained);
            assert_eq!(state.bundle.manager.quota().hard_limit, 0);
        });
    }

    #[test]
    fn binding_validation_enforces_tofu_and_revocation() {
        with_password("state-binding-test", || {
            let state = build(fresh_config());
            assert_eq!(
                umc_core::trust::TrustGraph::new(state.store.as_ref())
                    .effective_state(&[1u8; 32], "public", 1)
                    .expect("empty introduction graph"),
                TrustState::Unknown
            );
            let identity = IdentityKeyPair::generate();
            let first_static = StaticHandshakeKeyPair::generate();
            let first =
                IdentityBinding::sign(&identity, &first_static.public(), 0, u64::MAX, 0, [0; 32]);
            state
                .validate_peer_binding(&first, 10)
                .expect("first binding");
            let changed_static = StaticHandshakeKeyPair::generate();
            let changed =
                IdentityBinding::sign(&identity, &changed_static.public(), 0, u64::MAX, 1, [0; 32]);
            let error = state
                .validate_peer_binding(&changed, 11)
                .expect_err("TOFU mismatch");
            assert!(error.contains("TOFU_BINDING_MISMATCH"), "{error}");
            umc_core::revocation::RevocationStore::new(state.store.as_ref())
                .revoke(&first.endpoint_id, 0, 100, b"operator", 12)
                .expect("revoke");
            let error = state
                .validate_peer_binding(&first, 13)
                .expect_err("revocation");
            assert!(error.contains("IDENTITY_REVOKED"), "{error}");
        });
    }

    #[test]
    fn identity_is_persistent_across_restarts() {
        with_password("test-password", || {
            let config = fresh_config();
            let first = build(config.clone());
            let endpoint_id = first.node_identity.endpoint_id();
            drop(first);
            let second = build(config);
            assert_eq!(endpoint_id, second.node_identity.endpoint_id());
        });
    }

    #[test]
    fn rotate_handshake_key_changes_static_key_and_round_trips() {
        with_password("test-password", || {
            let config = fresh_config();
            let mut first = build(config.clone());
            let old_static = first.node_identity.static_handshake.public();
            let old_sequence = first.primary_binding.sequence;
            let binding = first
                .rotate_handshake_key(crate::state::NODE_IDENTITY_RECORD, 0)
                .expect("rotation");
            assert_eq!(binding.sequence, old_sequence + 1, "sequence increments");
            assert_ne!(
                first.node_identity.static_handshake.public(),
                old_static,
                "the node switches to the new static key"
            );
            assert_eq!(
                first.node.config.identity.static_handshake.public(),
                first.node_identity.static_handshake.public(),
                "the runtime node follows"
            );
            assert_eq!(
                first.node_identity.endpoint_id(),
                first.primary_binding.endpoint_id,
                "the identity key is unchanged"
            );
            drop(first);

            // Keystore round-trip: a fresh daemon over the same data dir
            // restores the rotated static key AND the binding sequence.
            let second = build(config);
            assert_ne!(
                second.node_identity.static_handshake.public(),
                old_static,
                "the rotated static key survives restart"
            );
            assert_eq!(
                second.primary_binding.static_handshake_public_key,
                second.node_identity.static_handshake.public(),
                "the restored binding matches the restored static key"
            );
            assert_eq!(second.primary_binding.sequence, old_sequence + 1);
        });
    }

    #[test]
    fn rotate_identity_key_changes_endpoint_and_round_trips() {
        with_password("test-password", || {
            let config = fresh_config();
            let mut first = build(config.clone());
            let old_endpoint = first.node_identity.endpoint_id();
            first
                .rotate_identity_key(crate::state::NODE_IDENTITY_RECORD)
                .expect("rotation");
            let new_endpoint = first.node_identity.endpoint_id();
            assert_ne!(new_endpoint, old_endpoint, "a full identity change");
            assert_eq!(
                first.node.config.dcid,
                new_endpoint[..8],
                "the node dcid follows the new endpoint"
            );
            assert_eq!(
                first.node.config.identity.endpoint_id(),
                new_endpoint,
                "the runtime node follows"
            );
            drop(first);

            let second = build(config);
            assert_eq!(second.node_identity.endpoint_id(), new_endpoint);
            assert_eq!(second.primary_binding.sequence, 1);
        });
    }

    #[test]
    fn secondaries_create_delete_and_restore() {
        with_password("test-password", || {
            let config = fresh_config();
            let mut first = build(config.clone());
            let secondary = first
                .create_secondary_identity(
                    umc_control::proto::umc::api::v1::IdentityKind::UserEndpoint as i32,
                    "alice",
                    0,
                )
                .expect("create");
            assert_eq!(first.secondaries.len(), 1);
            assert_eq!(first.secondaries[0].record_name, "secondary-0");
            assert_eq!(first.secondaries[0].label, "alice");
            assert_eq!(
                first.secondaries[0].binding.endpoint_id,
                secondary.identity.endpoint_id()
            );
            assert!(
                first
                    .identity_by_handle(secondary.record_name.as_bytes())
                    .is_some(),
                "the secondary resolves by handle"
            );
            drop(first);

            // Restore: the index + record round-trip through the keystore.
            let mut second = build(config.clone());
            assert_eq!(second.secondaries.len(), 1);
            assert_eq!(second.secondaries[0].record_name, "secondary-0");
            assert_eq!(
                second.secondaries[0].identity.endpoint_id(),
                secondary.identity.endpoint_id()
            );
            assert_eq!(second.secondaries[0].binding.sequence, 0);

            // Delete removes it from the registry and the keystore; the
            // next create reuses the slot without collision.
            second
                .delete_secondary_identity(secondary.record_name.as_bytes())
                .expect("delete");
            assert!(second.secondaries.is_empty());
            drop(second);

            let mut third = build(config);
            assert!(third.secondaries.is_empty(), "deleted stays deleted");
            let fresh = third
                .create_secondary_identity(0, "bob", 0)
                .expect("create after delete");
            assert_eq!(fresh.record_name, "secondary-1", "next_id advances");
        });
    }

    #[test]
    fn import_creates_a_secondary_and_never_touches_the_primary() {
        with_password("test-password", || {
            let config = fresh_config();
            let mut state = build(config.clone());
            let primary_endpoint = state.node_identity.endpoint_id();
            let source = NodeIdentity::generate(&OsEntropy);
            let mut seeds = Vec::with_capacity(64);
            seeds.extend_from_slice(&source.identity.to_seed());
            seeds.extend_from_slice(&source.static_handshake.to_seed());
            let imported = state
                .import_secondary_identity(&seeds, "imported", false)
                .expect("import");
            assert_eq!(imported.identity.endpoint_id(), source.endpoint_id());
            assert_eq!(state.node_identity.endpoint_id(), primary_endpoint);
            assert_eq!(state.secondaries.len(), 1);
            drop(state);

            let reopened = build(config);
            assert_eq!(reopened.node_identity.endpoint_id(), primary_endpoint);
            assert_eq!(
                reopened.secondaries[0].identity.endpoint_id(),
                source.endpoint_id()
            );

            // validate_only reports without storing.
            let mut only = reopened;
            let validated = only
                .import_secondary_identity(&seeds, "validate", true)
                .expect("validate");
            assert_eq!(validated.identity.endpoint_id(), source.endpoint_id());
            assert_eq!(only.secondaries.len(), 1, "validate-only stores nothing");
        });
    }

    #[test]
    fn import_rejects_malformed_seeds() {
        with_password("test-password", || {
            let mut state = build(fresh_config());
            assert!(state
                .import_secondary_identity(&[1u8; 32], "short", false)
                .is_err());
            assert!(state
                .import_secondary_identity(&[1u8; 63], "short", false)
                .is_err());
        });
    }

    #[test]
    fn fresh_dir_generates_a_new_identity_and_persists_it() {
        with_password("test-password", || {
            let a = fresh_config();
            let b = fresh_config();
            let sa = build(a.clone());
            let id_a = sa.node_identity.endpoint_id();
            drop(sa);
            // The same dir reloads the persisted identity...
            let sa2 = build(a);
            assert_eq!(id_a, sa2.node_identity.endpoint_id());
            // ...while a fresh dir derives a different one.
            let sb = build(b);
            assert_ne!(id_a, sb.node_identity.endpoint_id());
        });
    }

    #[test]
    fn replay_cache_is_single_use() {
        let mut cache = TicketReplayCache::new();
        let nonce = [7u8; 16];
        assert!(cache.insert(nonce), "the first use of a nonce is fresh");
        assert!(
            !cache.insert(nonce),
            "a second use of the same nonce is a replay"
        );
        assert!(cache.insert([8u8; 16]), "a different nonce is fresh");
    }

    #[test]
    fn replay_cache_evicts_fifo_at_cap() {
        let mut cache = TicketReplayCache::new();
        let mut oldest = None;
        for i in 0..=TicketReplayCache::CAP {
            let mut nonce = [0u8; 16];
            nonce[..2].copy_from_slice(&u16::try_from(i).expect("cap fits u16").to_be_bytes());
            if i == 0 {
                oldest = Some(nonce);
            }
            assert!(cache.insert(nonce), "fresh nonce {i} must be admitted");
        }
        assert!(
            cache.insert(oldest.expect("first nonce")),
            "the oldest entry must be evicted once the cap is exceeded"
        );
    }

    #[test]
    fn wall_now_is_epoch_relative_and_monotonic() {
        let a = wall_now().0;
        assert!(a > 1_700_000_000_000, "wall now must be epoch ms, got {a}");
        let b = wall_now().0;
        assert!(b >= a);
    }

    #[test]
    fn restore_anchor_advances_monotonically() {
        let dir = std::env::temp_dir().join(format!(
            "umcd-restore-anchor-{}-{}",
            std::process::id(),
            wall_now().0
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("anchor dir");
        assert_eq!(read_restore_anchor(&dir), 0);
        assert_eq!(advance_restore_anchor(&dir).expect("first anchor"), 1);
        assert_eq!(advance_restore_anchor(&dir).expect("second anchor"), 2);
        assert_eq!(read_restore_anchor(&dir), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn events_survive_restart() {
        with_password("test-password", || {
            let config = fresh_config();
            let first = build(config.clone());
            first
                .events
                .lock()
                .unwrap()
                .push(crate::event_log::DaemonEvent {
                    kind: "session_active".into(),
                    at_ms: 42,
                    detail: "restart check".into(),
                });
            drop(first);
            // A fresh daemon over the same data dir restores the event from
            // the api namespace (core.md §15 audit logging).
            let second = build(config);
            let recent = second.events.lock().unwrap().recent(10);
            assert_eq!(recent.len(), 1);
            assert_eq!(recent[0].kind, "session_active");
            assert_eq!(recent[0].at_ms, 42);
        });
    }

    #[test]
    fn startup_warns_when_external_restore_anchor_is_newer() {
        with_password("test-password", || {
            let config = fresh_config();
            let first = build(config.clone());
            let data_dir = config.resolved_data_dir();
            drop(first);
            advance_restore_anchor(&data_dir).expect("advance external anchor");
            let second = build(config);
            assert!(second.restore_warning.is_some());
            assert!(second
                .events
                .lock()
                .unwrap()
                .recent(10)
                .iter()
                .any(|event| event.kind == "restore_stale_state"));
        });
    }
}
