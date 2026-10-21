#![deny(unsafe_op_in_unsafe_fn)]

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm as ArgonAlgorithm, Argon2, Params as ArgonParams, Version as ArgonVersion};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use scrypt::{Params as ScryptParams, scrypt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{Emitter, Manager, State};
use totp_rs::{Algorithm as OtpAlgorithm, Secret, TOTP};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(windows)]
mod screen_capture;

const FORMAT_MAGIC: &[u8; 8] = b"OAUTHV01";
const FORMAT_VERSION: u32 = 1;
const DEFAULT_MEMORY_KIB: u32 = 65_536;
const DEFAULT_ITERATIONS: u32 = 3;
const DEFAULT_LANES: u32 = 1;
const MAX_VAULT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_IMPORT_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;
const MAX_KDF_MEMORY_KIB: u32 = 262_144;
const MAX_KDF_ITERATIONS: u32 = 10;
pub const WEBVIEW2_CLIENT_GUID: &str = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OtpAlgorithmKind {
    Sha1,
    Sha256,
    Sha512,
}
impl OtpAlgorithmKind {
    fn to_totp(&self) -> OtpAlgorithm {
        match self {
            Self::Sha1 => OtpAlgorithm::SHA1,
            Self::Sha256 => OtpAlgorithm::SHA256,
            Self::Sha512 => OtpAlgorithm::SHA512,
        }
    }
    fn as_label(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct TotpRecord {
    #[zeroize(skip)]
    pub id: String,
    #[zeroize(skip)]
    pub name: String,
    #[serde(default)]
    #[zeroize(skip)]
    pub subtitle: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default = "default_algorithm")]
    #[zeroize(skip)]
    pub algorithm: OtpAlgorithmKind,
    #[serde(default = "default_digits")]
    #[zeroize(skip)]
    pub digits: u32,
    #[serde(default = "default_period")]
    #[zeroize(skip)]
    pub period: u32,
    #[zeroize(skip)]
    pub added_at: u64,
    #[serde(default)]
    #[zeroize(skip)]
    pub recovery_set_id: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCode {
    #[zeroize(skip)]
    pub id: String,
    pub value: String,
    #[zeroize(skip)]
    pub used: bool,
    #[zeroize(skip)]
    pub added_at: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RecoverySet {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub subtitle: String,
    #[serde(default)]
    pub codes: Vec<RecoveryCode>,
    pub added_at: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Appearance {
    System,
    Light,
    Dark,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Preferences {
    #[serde(default = "default_true")]
    pub ask_after_copy: bool,
    #[serde(default = "default_true")]
    pub clear_clipboard: bool,
    #[serde(default = "default_appearance")]
    pub appearance: Appearance,
    #[serde(default)]
    pub camera_device_id: Option<String>,
    #[serde(default)]
    pub totp_order: Vec<String>,
    #[serde(default)]
    pub recovery_order: Vec<String>,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            ask_after_copy: true,
            clear_clipboard: true,
            appearance: Appearance::System,
            camera_device_id: None,
            totp_order: Vec::new(),
            recovery_order: Vec::new(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct VaultData {
    pub version: u32,
    #[serde(default)]
    pub totp_entries: Vec<TotpRecord>,
    #[serde(default)]
    pub recovery_sets: Vec<RecoverySet>,
    #[serde(default)]
    pub preferences: Preferences,
}
#[derive(Debug, Deserialize)]
pub struct TotpInput {
    pub name: String,
    #[serde(default)]
    pub subtitle: String,
    pub secret: String,
    #[serde(default = "default_algorithm")]
    pub algorithm: OtpAlgorithmKind,
    #[serde(default = "default_digits")]
    pub digits: u32,
    #[serde(default = "default_period")]
    pub period: u32,
    #[serde(default)]
    pub recovery_set_id: Option<String>,
}
#[derive(Debug, Deserialize)]
pub struct RecoverySetInput {
    pub name: String,
    #[serde(default)]
    pub subtitle: String,
    pub codes: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TotpRecordSummary {
    pub id: String,
    pub name: String,
    pub subtitle: String,
    pub algorithm: OtpAlgorithmKind,
    pub digits: u32,
    pub period: u32,
    pub added_at: u64,
    pub recovery_set_id: Option<String>,
}
fn totp_summary(record: &TotpRecord) -> TotpRecordSummary {
    TotpRecordSummary {
        id: record.id.clone(),
        name: record.name.clone(),
        subtitle: record.subtitle.clone(),
        algorithm: record.algorithm.clone(),
        digits: record.digits,
        period: record.period,
        added_at: record.added_at,
        recovery_set_id: record.recovery_set_id.clone(),
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultSummary {
    pub version: u32,
    pub totp_entries: Vec<TotpRecordSummary>,
    pub recovery_sets: Vec<RecoverySetSummary>,
    pub preferences: Preferences,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoverySetSummary {
    pub id: String,
    pub name: String,
    pub subtitle: String,
    pub available_count: usize,
    pub used_count: usize,
    pub added_at: u64,
}
fn vault_summary(vault: &VaultData) -> VaultSummary {
    VaultSummary {
        version: vault.version,
        totp_entries: vault.totp_entries.iter().map(totp_summary).collect(),
        recovery_sets: vault
            .recovery_sets
            .iter()
            .map(|set| RecoverySetSummary {
                id: set.id.clone(),
                name: set.name.clone(),
                subtitle: set.subtitle.clone(),
                available_count: set.codes.iter().filter(|code| !code.used).count(),
                used_count: set.codes.iter().filter(|code| code.used).count(),
                added_at: set.added_at,
            })
            .collect(),
        preferences: vault.preferences.clone(),
    }
}
#[derive(Debug, Serialize)]
pub struct TotpDisplay {
    pub id: String,
    pub name: String,
    pub subtitle: String,
    pub code: String,
    pub remaining_seconds: u32,
    pub period: u32,
    pub has_recovery_set: bool,
}
#[derive(Clone, Debug, Serialize, Zeroize)]
pub struct ImportCandidate {
    #[zeroize(skip)]
    pub name: String,
    #[zeroize(skip)]
    pub subtitle: String,
    pub secret: String,
    #[zeroize(skip)]
    pub algorithm: OtpAlgorithmKind,
    #[zeroize(skip)]
    pub digits: u32,
    #[zeroize(skip)]
    pub period: u32,
}
#[derive(Debug, Serialize, Deserialize)]
struct VaultHeader {
    version: u32,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}
#[derive(Clone)]
enum RestoreRecord {
    Totp(TotpRecord),
    Recovery(RecoverySet),
}
struct PendingConflict {
    id: String,
    existing_id: String,
    imported_id: String,
    record: RestoreRecord,
}
struct PendingRestore {
    baseline: VaultData,
    imported: VaultData,
    conflicts: Vec<PendingConflict>,
}
#[derive(Serialize)]
struct RestoreConflictView {
    id: String,
    kind: &'static str,
    current_name: String,
    current_subtitle: String,
    imported_name: String,
    imported_subtitle: String,
    current_detail: String,
    imported_detail: String,
}
#[derive(Deserialize)]
struct RestoreChoice {
    id: String,
    choice: String,
}
struct Session {
    path: PathBuf,
    password: Zeroizing<Vec<u8>>,
    vault: VaultData,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.password.zeroize();
        for record in &mut self.vault.totp_entries {
            record.zeroize();
        }
        for set in &mut self.vault.recovery_sets {
            for code in &mut set.codes {
                code.zeroize();
            }
        }
    }
}
#[derive(Default)]
pub struct AppState {
    session: Mutex<Option<Session>>,
    activity: Mutex<Option<InstantTracker>>,
    focus_lost_at: Mutex<Option<std::time::Instant>>,
    pending_restore: Mutex<Option<PendingRestore>>,
}
#[derive(Clone, Copy)]
struct InstantTracker(std::time::Instant);
impl InstantTracker {
    fn expired(&self, now: std::time::Instant) -> bool {
        now.duration_since(self.0) >= std::time::Duration::from_secs(300)
    }
}
fn default_true() -> bool {
    true
}
fn default_digits() -> u32 {
    6
}
fn default_period() -> u32 {
    30
}
fn default_algorithm() -> OtpAlgorithmKind {
    OtpAlgorithmKind::Sha1
}
fn default_appearance() -> Appearance {
    Appearance::System
}
fn unix_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "System clock is before the Unix epoch".into())
}
fn random_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| format!("Could not create a secure random identifier: {error}"))?;
    Ok(hex::encode(bytes))
}
fn validate_password(password: &str) -> Result<(), String> {
    let count = password.chars().count();
    if count < 12 {
        return Err("Use at least 12 characters for the master password.".into());
    }
    if password.chars().any(char::is_whitespace) {
        return Err("The master password cannot contain whitespace.".into());
    }
    if count > 1024 {
        return Err("The master password is too long.".into());
    }
    Ok(())
}

fn derive_key(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
) -> Result<Zeroizing<[u8; 32]>, String> {
    if salt.len() != 16 {
        return Err("The vault salt is invalid.".into());
    }
    if !(8_192..=MAX_KDF_MEMORY_KIB).contains(&memory_kib)
        || !(1..=MAX_KDF_ITERATIONS).contains(&iterations)
        || !(1..=8).contains(&lanes)
    {
        return Err("The vault uses unsafe or unsupported password-hashing settings.".into());
    }
    let params = ArgonParams::new(memory_kib, iterations, lanes, Some(32))
        .map_err(|_| "The vault password settings are invalid".to_string())?;
    let argon = Argon2::new(ArgonAlgorithm::Argon2id, ArgonVersion::V0x13, params);
    let mut output = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, output.as_mut())
        .map_err(|_| "Could not derive a vault key".to_string())?;
    Ok(output)
}
fn encrypt_vault(data: &VaultData, password: &[u8]) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut salt)
        .map_err(|error| format!("Could not create a vault salt: {error}"))?;
    getrandom::getrandom(&mut nonce)
        .map_err(|error| format!("Could not create a vault nonce: {error}"))?;
    let key = derive_key(
        password,
        &salt,
        DEFAULT_MEMORY_KIB,
        DEFAULT_ITERATIONS,
        DEFAULT_LANES,
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| "Could not initialize vault encryption".to_string())?;
    let plaintext = Zeroizing::new(
        serde_json::to_vec(data).map_err(|_| "Could not encode vault data".to_string())?,
    );
    let header_aad = format!("offline-authenticator:{FORMAT_VERSION}");
    let encrypted = Zeroizing::new(
        cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: header_aad.as_bytes(),
                },
            )
            .map_err(|_| "Could not encrypt the vault".to_string())?,
    );
    let header = VaultHeader {
        version: FORMAT_VERSION,
        memory_kib: DEFAULT_MEMORY_KIB,
        iterations: DEFAULT_ITERATIONS,
        lanes: DEFAULT_LANES,
        salt: BASE64.encode(salt),
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(encrypted.as_slice()),
    };
    let body =
        serde_json::to_vec(&header).map_err(|_| "Could not encode encrypted vault".to_string())?;
    let mut out = Vec::with_capacity(FORMAT_MAGIC.len() + 4 + body.len());
    out.extend_from_slice(FORMAT_MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&body);
    salt.zeroize();
    nonce.zeroize();
    Ok(out)
}
fn decrypt_vault(bytes: &[u8], password: &[u8]) -> Result<VaultData, String> {
    if bytes.len() < 12 || bytes.len() as u64 > MAX_VAULT_BYTES {
        return Err("The vault file is empty, too large, or incomplete.".into());
    }
    if &bytes[..8] != FORMAT_MAGIC {
        return Err("This is not a supported encrypted authenticator vault.".into());
    }
    let outer_version = u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| "The vault header is incomplete")?,
    );
    if outer_version != FORMAT_VERSION {
        return Err("This vault version is not supported.".into());
    }
    let header: VaultHeader = serde_json::from_slice(&bytes[12..])
        .map_err(|_| "The encrypted vault header is damaged or unsupported".to_string())?;
    if header.version != FORMAT_VERSION {
        return Err("This vault version is not supported.".into());
    }
    let salt = Zeroizing::new(
        BASE64
            .decode(&header.salt)
            .map_err(|_| "The encrypted vault salt is invalid".to_string())?,
    );
    let nonce = Zeroizing::new(
        BASE64
            .decode(&header.nonce)
            .map_err(|_| "The encrypted vault nonce is invalid".to_string())?,
    );
    if nonce.len() != 24 {
        return Err("The encrypted vault nonce is invalid.".into());
    }
    let ciphertext = Zeroizing::new(
        BASE64
            .decode(&header.ciphertext)
            .map_err(|_| "The encrypted vault data is invalid".to_string())?,
    );
    if ciphertext.len() > MAX_VAULT_BYTES as usize {
        return Err("The encrypted vault data is too large.".into());
    }
    let key = derive_key(
        password,
        &salt,
        header.memory_kib,
        header.iterations,
        header.lanes,
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| "Could not initialize vault encryption".to_string())?;
    let aad = format!("offline-authenticator:{}", header.version);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext.as_slice(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| {
                "The password is incorrect, or this vault has been changed.".to_string()
            })?,
    );
    let data: VaultData = serde_json::from_slice(&plaintext)
        .map_err(|_| "The decrypted vault data is not valid.".to_string())?;
    validate_vault(&data)?;
    Ok(data)
}
fn validate_vault(vault: &VaultData) -> Result<(), String> {
    if vault.version > 1 {
        return Err("This vault was made by a newer version of the app.".into());
    }
    if vault.totp_entries.len() > MAX_ENTRIES || vault.recovery_sets.len() > MAX_ENTRIES {
        return Err("This vault contains too many records.".into());
    }
    let mut totp_ids = std::collections::HashSet::new();
    for record in &vault.totp_entries {
        validate_totp_fields(&record.name, &record.secret, record.digits, record.period)?;
        if record.subtitle.chars().count() > 300 || record.name.chars().count() > 120 {
            return Err("Authenticator labels are too long.".into());
        }
        if record.name.trim().is_empty() {
            return Err("Authenticator names cannot be empty.".into());
        }
        if !totp_ids.insert(&record.id) {
            return Err("This vault contains duplicate authenticator identifiers.".into());
        }
    }
    let mut set_ids = std::collections::HashSet::new();
    for set in &vault.recovery_sets {
        if set.name.trim().is_empty()
            || set.name.chars().count() > 120
            || set.subtitle.chars().count() > 300
        {
            return Err("Recovery-code set labels are invalid or too long.".into());
        }
        if set.codes.is_empty() || set.codes.len() > MAX_ENTRIES {
            return Err("A recovery-code set must contain between 1 and 10,000 codes.".into());
        }
        if !set_ids.insert(&set.id) {
            return Err("This vault contains duplicate recovery-code identifiers.".into());
        }
        let mut code_ids = std::collections::HashSet::new();
        let mut code_values = std::collections::HashSet::new();
        for code in &set.codes {
            if code.value.trim().is_empty()
                || code.value.len() > 512
                || code.value.chars().any(char::is_control)
            {
                return Err("This vault contains an invalid recovery code.".into());
            }
            if !code_ids.insert(&code.id) || !code_values.insert(&code.value) {
                return Err("This vault contains duplicate recovery codes.".into());
            }
        }
    }
    Ok(())
}
fn validate_totp_fields(name: &str, secret: &str, digits: u32, period: u32) -> Result<(), String> {
    if name.trim().is_empty() || name.chars().count() > 120 {
        return Err("Enter a name between 1 and 120 characters.".into());
    }
    if !(6..=8).contains(&digits) {
        return Err("Authenticator codes must use 6, 7, or 8 digits.".into());
    }
    if !(1..=300).contains(&period) {
        return Err("The code period must be between 1 and 300 seconds.".into());
    }
    let cleaned = secret.trim().replace([' ', '-'], "").to_ascii_uppercase();
    let decoded = Secret::Encoded(cleaned)
        .to_bytes()
        .map_err(|_| "The shared key is not valid Base32.".to_string())?;
    if decoded.len() < 10 || decoded.len() > 128 {
        return Err("The shared key must be between 10 and 128 bytes.".into());
    }
    Ok(())
}
fn totp_for_record(entry: &TotpRecord) -> Result<TOTP, String> {
    validate_totp_fields(&entry.name, &entry.secret, entry.digits, entry.period)?;
    let secret = Secret::Encoded(
        entry
            .secret
            .trim()
            .replace([' ', '-'], "")
            .to_ascii_uppercase(),
    )
    .to_bytes()
    .map_err(|_| "The shared key is not valid Base32".to_string())?;
    Ok(TOTP::new_unchecked(
        entry.algorithm.to_totp(),
        entry.digits as usize,
        0,
        entry.period as u64,
        secret,
        None,
        entry.name.clone(),
    ))
}
fn replace_vault_file(temp: &Path, destination: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };
        let source: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
        let target: Vec<u16> = destination
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let result = unsafe {
            MoveFileExW(
                source.as_ptr(),
                target.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if result == 0 {
            return Err(format!(
                "Cannot replace the current vault: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        fs::rename(temp, destination)
            .map_err(|error| format!("Cannot replace the current vault: {error}"))
    }
}
fn atomic_write_replace(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    let parent = path.parent().ok_or("The destination folder is not valid")?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("Cannot create the destination folder: {error}"))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("Cannot create a safe temporary {label}: {error}"))?;
    temp.write_all(bytes)
        .map_err(|error| format!("Cannot write the encrypted {label}: {error}"))?;
    temp.as_file()
        .sync_all()
        .map_err(|error| format!("Cannot flush the encrypted {label}: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = temp
            .as_file()
            .metadata()
            .map_err(|error| format!("Cannot inspect encrypted file permissions: {error}"))?
            .permissions();
        permissions.set_mode(0o600);
        temp.as_file()
            .set_permissions(permissions)
            .map_err(|error| format!("Cannot secure encrypted file permissions: {error}"))?;
    }
    let (file, temp_path) = temp
        .keep()
        .map_err(|error| format!("Cannot stage encrypted {label}: {}", error.error))?;
    drop(file);
    if let Err(error) = replace_vault_file(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}
fn atomic_save(path: &Path, data: &VaultData, password: &[u8]) -> Result<(), String> {
    let bytes = encrypt_vault(data, password)?;
    atomic_write_replace(path, &bytes, "vault")
}
fn initialized_vault() -> VaultData {
    VaultData {
        version: FORMAT_VERSION,
        ..VaultData::default()
    }
}
fn get_session<'a>(
    state: &'a State<'_, AppState>,
) -> Result<std::sync::MutexGuard<'a, Option<Session>>, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "Vault state is unavailable".to_string())?;
    if guard.is_none() {
        return Err("The vault is locked.".into());
    }
    let now = std::time::Instant::now();
    let tracker = state
        .activity
        .lock()
        .map_err(|_| "Vault activity state is unavailable")?;
    let idle_expired = tracker.is_some_and(|item| item.expired(now));
    drop(tracker);
    let focus_expired = state
        .focus_lost_at
        .lock()
        .map_err(|_| "Vault focus state is unavailable")?
        .is_some_and(|lost_at| lost_at.elapsed() >= std::time::Duration::from_secs(300));
    if idle_expired || focus_expired {
        *guard = None;
        drop(guard);
        if let Ok(mut activity) = state.activity.lock() {
            *activity = None;
        }
        if let Ok(mut focus) = state.focus_lost_at.lock() {
            *focus = None;
        }
        if let Ok(mut pending) = state.pending_restore.lock() {
            *pending = None;
        }
        return Err("The vault was locked after five minutes away or without activity. Unlock it to continue.".into());
    }
    Ok(guard)
}
#[tauri::command(rename = "touch_vault_activity")]
fn touch_vault_activity(state: State<'_, AppState>) -> Result<(), String> {
    let _session = get_session(&state)?;
    let mut activity = state
        .activity
        .lock()
        .map_err(|_| "Vault activity state is unavailable")?;
    *activity = Some(InstantTracker(std::time::Instant::now()));
    Ok(())
}
fn save_session(session: &Session) -> Result<(), String> {
    atomic_save(&session.path, &session.vault, session.password.as_slice())
}
fn unlock_path(
    path: PathBuf,
    password: String,
) -> Result<(PathBuf, VaultData, Zeroizing<Vec<u8>>), String> {
    let mut password_bytes = Zeroizing::new(password.into_bytes());
    let metadata =
        fs::metadata(&path).map_err(|error| format!("Cannot open the selected vault: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_VAULT_BYTES {
        return Err("The selected vault file is not valid or exceeds the size limit.".into());
    }
    let file =
        File::open(&path).map_err(|error| format!("Cannot read the selected vault: {error}"))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(MAX_VAULT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Cannot read the selected vault: {error}"))?;
    let vault = decrypt_vault(&bytes, &password_bytes)?;
    Ok((path, vault, std::mem::take(&mut password_bytes)))
}

#[tauri::command(rename = "vault_exists")]
fn vault_exists(path: String) -> Result<bool, String> {
    Ok(PathBuf::from(path).is_file())
}
#[tauri::command(rename = "setup_vault")]
fn setup_vault(path: String, password: String) -> Result<(), String> {
    validate_password(&password)?;
    atomic_write_new(
        Path::new(&path),
        &encrypt_vault(&initialized_vault(), password.as_bytes())?,
    )
}
#[tauri::command(rename = "resolve_vault_path")]
fn resolve_vault_path(path: String, portable: bool) -> Result<String, String> {
    if portable {
        let exe = std::env::current_exe()
            .map_err(|error| format!("Cannot locate the app folder: {error}"))?;
        return validate_writable_folder(exe.parent().ok_or("Cannot locate the app folder")?);
    }
    let requested = PathBuf::from(path);
    validate_writable_folder(requested.parent().ok_or("Choose a folder for the vault")?)
}
fn validate_writable_folder(folder: &Path) -> Result<String, String> {
    fs::create_dir_all(folder)
        .map_err(|error| format!("Cannot create the vault folder: {error}"))?;
    let probe = folder.join(format!(".authenticator-write-test-{}.tmp", random_id()?));
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .map_err(|error| format!("This vault folder is not writable: {error}"))?;
    drop(result);
    fs::remove_file(&probe).map_err(|error| format!("Cannot verify the vault folder: {error}"))?;
    Ok(folder.join("vault.authvault").display().to_string())
}
#[tauri::command(rename = "unlock_vault")]
fn unlock_vault(
    path: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<VaultSummary, String> {
    let (path, vault, password) = unlock_path(PathBuf::from(path), password)?;
    *state
        .session
        .lock()
        .map_err(|_| "Vault state is unavailable".to_string())? = Some(Session {
        path,
        password,
        vault: vault.clone(),
    });
    *state
        .activity
        .lock()
        .map_err(|_| "Vault activity state is unavailable".to_string())? =
        Some(InstantTracker(std::time::Instant::now()));
    *state
        .focus_lost_at
        .lock()
        .map_err(|_| "Vault focus state is unavailable".to_string())? = None;
    Ok(vault_summary(&vault))
}
#[tauri::command(rename = "lock_vault")]
fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    *state
        .session
        .lock()
        .map_err(|_| "Vault state is unavailable".to_string())? = None;
    *state
        .activity
        .lock()
        .map_err(|_| "Vault activity state is unavailable".to_string())? = None;
    *state
        .focus_lost_at
        .lock()
        .map_err(|_| "Vault focus state is unavailable".to_string())? = None;
    *state
        .pending_restore
        .lock()
        .map_err(|_| "Vault restore state is unavailable".to_string())? = None;
    Ok(())
}
#[tauri::command(rename = "get_vault_path")]
fn get_vault_path(state: State<'_, AppState>) -> Result<String, String> {
    Ok(get_session(&state)?
        .as_ref()
        .ok_or("The vault is locked")?
        .path
        .display()
        .to_string())
}
#[tauri::command(rename = "get_recovery_set")]
fn get_recovery_set(set_id: String, state: State<'_, AppState>) -> Result<RecoverySet, String> {
    get_session(&state)?
        .as_ref()
        .ok_or("The vault is locked")?
        .vault
        .recovery_sets
        .iter()
        .find(|set| set.id == set_id)
        .cloned()
        .ok_or_else(|| "Recovery-code set not found".to_string())
}
#[tauri::command(rename = "get_vault_summary")]
fn get_vault_summary(state: State<'_, AppState>) -> Result<VaultSummary, String> {
    Ok(vault_summary(
        &get_session(&state)?
            .as_ref()
            .ok_or("The vault is locked")?
            .vault,
    ))
}
#[tauri::command(rename = "get_totp_codes")]
fn get_totp_codes(state: State<'_, AppState>) -> Result<Vec<TotpDisplay>, String> {
    let guard = get_session(&state)?;
    let session = guard.as_ref().ok_or("The vault is locked")?;
    session
        .vault
        .totp_entries
        .iter()
        .map(|entry| {
            let totp = totp_for_record(entry)?;
            let now = unix_seconds()?;
            let code = totp.generate(now);
            let remaining_seconds = (entry.period as u64 - now % entry.period as u64) as u32;
            Ok(TotpDisplay {
                id: entry.id.clone(),
                name: entry.name.clone(),
                subtitle: entry.subtitle.clone(),
                code,
                remaining_seconds,
                period: entry.period,
                has_recovery_set: entry
                    .recovery_set_id
                    .as_ref()
                    .is_some_and(|id| session.vault.recovery_sets.iter().any(|set| &set.id == id)),
            })
        })
        .collect()
}
#[tauri::command(rename = "add_totp")]
fn add_totp(input: TotpInput, state: State<'_, AppState>) -> Result<TotpRecordSummary, String> {
    validate_totp_fields(&input.name, &input.secret, input.digits, input.period)?;
    let record = TotpRecord {
        id: random_id()?,
        name: input.name.trim().to_owned(),
        subtitle: input.subtitle.trim().to_owned(),
        secret: input
            .secret
            .trim()
            .replace([' ', '-'], "")
            .to_ascii_uppercase(),
        algorithm: input.algorithm,
        digits: input.digits,
        period: input.period,
        added_at: unix_seconds()?,
        recovery_set_id: input.recovery_set_id,
    };
    totp_for_record(&record)?;
    let mut guard = get_session(&state)?;
    let session = guard.as_mut().ok_or("The vault is locked")?;
    if session.vault.totp_entries.len() >= MAX_ENTRIES {
        return Err("This vault already contains too many authenticators.".into());
    }
    session.vault.totp_entries.push(record.clone());
    if let Err(error) = save_session(session) {
        session.vault.totp_entries.pop();
        return Err(error);
    }
    Ok(totp_summary(&record))
}
#[tauri::command(rename = "update_totp")]
fn update_totp(mut record: TotpRecord, state: State<'_, AppState>) -> Result<(), String> {
    if record.subtitle.chars().count() > 300 {
        return Err("The account label is too long.".into());
    }
    let mut guard = get_session(&state)?;
    let session = guard.as_mut().ok_or("The vault is locked")?;
    let index = session
        .vault
        .totp_entries
        .iter()
        .position(|item| item.id == record.id)
        .ok_or("Authenticator not found")?;
    if record.secret.trim().is_empty() {
        record.secret = session.vault.totp_entries[index].secret.clone();
    }
    record.name = record.name.trim().to_owned();
    record.subtitle = record.subtitle.trim().to_owned();
    validate_totp_fields(&record.name, &record.secret, record.digits, record.period)?;
    let old = std::mem::replace(&mut session.vault.totp_entries[index], record);
    if let Err(error) = save_session(session) {
        session.vault.totp_entries[index] = old;
        return Err(error);
    }
    Ok(())
}
#[tauri::command(rename = "delete_totp")]
fn delete_totp(id: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = get_session(&state)?;
    let session = guard.as_mut().ok_or("The vault is locked")?;
    let index = session
        .vault
        .totp_entries
        .iter()
        .position(|entry| entry.id == id)
        .ok_or("Authenticator not found")?;
    let old = session.vault.totp_entries.remove(index);
    let previous_order = session.vault.preferences.totp_order.clone();
    session
        .vault
        .preferences
        .totp_order
        .retain(|record_id| record_id != &id);
    if let Err(error) = save_session(session) {
        session.vault.totp_entries.insert(index, old);
        session.vault.preferences.totp_order = previous_order;
        return Err(error);
    }
    Ok(())
}
#[tauri::command(rename = "reorder_totp")]
fn reorder_totp(ids: Vec<String>, state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = get_session(&state)?;
    let session = guard.as_mut().ok_or("The vault is locked")?;
    if ids.len() != session.vault.totp_entries.len()
        || ids.iter().collect::<std::collections::HashSet<_>>().len() != ids.len()
        || ids.iter().any(|id| {
            !session
                .vault
                .totp_entries
                .iter()
                .any(|entry| &entry.id == id)
        })
    {
        return Err("Authenticator order is invalid.".into());
    }
    let previous = std::mem::replace(&mut session.vault.preferences.totp_order, ids);
    if let Err(error) = save_session(session) {
        session.vault.preferences.totp_order = previous;
        return Err(error);
    }
    Ok(())
}

fn atomic_write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("The vault folder is not valid")?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("Cannot create the vault folder: {error}"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("Cannot create the vault file: {error}"))?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("Cannot safely write the vault: {error}"));
    }
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn check_label(name: &str, subtitle: &str) -> Result<(), String> {
    if name.trim().is_empty() || name.chars().count() > 120 {
        return Err("Enter a name between 1 and 120 characters.".into());
    }
    if subtitle.chars().count() > 300 {
        return Err("The account label is too long.".into());
    }
    Ok(())
}
fn check_recovery_codes(codes: &[RecoveryCode]) -> Result<(), String> {
    if codes.is_empty() || codes.len() > MAX_ENTRIES {
        return Err("A backup-code set must contain between 1 and 10,000 codes.".into());
    }
    let mut ids = std::collections::HashSet::new();
    let mut values = std::collections::HashSet::new();
    for code in codes {
        if code.value.trim().is_empty()
            || code.value.len() > 512
            || code.value.chars().any(char::is_control)
        {
            return Err(
                "A recovery code is empty, too long, or contains invalid characters.".into(),
            );
        }
        if !ids.insert(&code.id) || !values.insert(&code.value) {
            return Err("Recovery codes in a set must be unique.".into());
        }
    }
    Ok(())
}
fn update_vault<T>(
    state: &State<'_, AppState>,
    update: impl FnOnce(&mut VaultData) -> Result<T, String>,
) -> Result<T, String> {
    let mut guard = get_session(state)?;
    let session = guard.as_mut().ok_or("The vault is locked")?;
    let previous = session.vault.clone();
    let result = update(&mut session.vault)?;
    if let Err(error) = save_session(session) {
        session.vault = previous;
        return Err(error);
    }
    Ok(result)
}

#[tauri::command(rename = "get_default_vault_path")]
fn get_default_vault_path(app: tauri::AppHandle, portable: bool) -> Result<String, String> {
    if portable {
        let exe = std::env::current_exe()
            .map_err(|error| format!("Cannot locate the app folder: {error}"))?;
        let folder = exe.parent().ok_or("Cannot locate the app folder")?;
        let writable = OpenOptions::new()
            .create(true)
            .append(true)
            .open(folder.join(".authenticator-portable-check"));
        if let Ok(file) = writable {
            drop(file);
            let _ = fs::remove_file(folder.join(".authenticator-portable-check"));
        }
        return Ok(folder.join("vault.authvault").display().to_string());
    }
    let folder = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Cannot locate the app data folder: {error}"))?;
    Ok(folder.join("vault.authvault").display().to_string())
}

#[tauri::command(rename = "add_recovery_set")]
fn add_recovery_set(
    input: RecoverySetInput,
    state: State<'_, AppState>,
) -> Result<RecoverySetSummary, String> {
    check_label(&input.name, &input.subtitle)?;
    let mut seen = std::collections::HashSet::new();
    let mut codes = Vec::with_capacity(input.codes.len());
    for value in input.codes {
        let value = value.trim().to_owned();
        if !seen.insert(value.clone()) {
            return Err("Recovery codes in a set must be unique.".into());
        }
        codes.push(RecoveryCode {
            id: random_id()?,
            value,
            used: false,
            added_at: unix_seconds()?,
        });
    }
    check_recovery_codes(&codes)?;
    let set = RecoverySet {
        id: random_id()?,
        name: input.name.trim().to_owned(),
        subtitle: input.subtitle.trim().to_owned(),
        codes,
        added_at: unix_seconds()?,
    };
    update_vault(&state, |vault| {
        if vault.recovery_sets.len() >= MAX_ENTRIES {
            return Err("This vault already contains too many backup-code sets.".into());
        }
        vault.recovery_sets.push(set.clone());
        Ok(RecoverySetSummary {
            id: set.id.clone(),
            name: set.name.clone(),
            subtitle: set.subtitle.clone(),
            available_count: set.codes.len(),
            used_count: 0,
            added_at: set.added_at,
        })
    })
}
#[tauri::command(rename = "update_recovery_set")]
fn update_recovery_set(set: RecoverySet, state: State<'_, AppState>) -> Result<(), String> {
    check_label(&set.name, &set.subtitle)?;
    check_recovery_codes(&set.codes)?;
    update_vault(&state, |vault| {
        let index = vault
            .recovery_sets
            .iter()
            .position(|item| item.id == set.id)
            .ok_or("Backup-code set not found")?;
        vault.recovery_sets[index] = RecoverySet {
            name: set.name.trim().to_owned(),
            subtitle: set.subtitle.trim().to_owned(),
            ..set
        };
        Ok(())
    })
}
#[tauri::command(rename = "set_recovery_code_used")]
fn set_recovery_code_used(
    set_id: String,
    code_id: String,
    used: bool,
    state: State<'_, AppState>,
) -> Result<(), String> {
    update_vault(&state, |vault| {
        let set = vault
            .recovery_sets
            .iter_mut()
            .find(|item| item.id == set_id)
            .ok_or("Backup-code set not found")?;
        let code = set
            .codes
            .iter_mut()
            .find(|item| item.id == code_id)
            .ok_or("Recovery code not found")?;
        code.used = used;
        Ok(())
    })
}
#[tauri::command(rename = "delete_recovery_set")]
fn delete_recovery_set(id: String, state: State<'_, AppState>) -> Result<(), String> {
    update_vault(&state, |vault| {
        let index = vault
            .recovery_sets
            .iter()
            .position(|set| set.id == id)
            .ok_or("Backup-code set not found")?;
        vault.recovery_sets.remove(index);
        vault.preferences.recovery_order.retain(|item| item != &id);
        for entry in &mut vault.totp_entries {
            if entry.recovery_set_id.as_deref() == Some(&id) {
                entry.recovery_set_id = None;
            }
        }
        Ok(())
    })
}
#[tauri::command(rename = "reorder_recovery_sets")]
fn reorder_recovery_sets(ids: Vec<String>, state: State<'_, AppState>) -> Result<(), String> {
    update_vault(&state, |vault| {
        if ids.len() != vault.recovery_sets.len()
            || ids.iter().collect::<std::collections::HashSet<_>>().len() != ids.len()
            || ids
                .iter()
                .any(|id| !vault.recovery_sets.iter().any(|set| &set.id == id))
        {
            return Err("Backup-code set order is invalid.".into());
        }
        vault.preferences.recovery_order = ids;
        Ok(())
    })
}
#[tauri::command(rename = "update_preferences")]
fn update_preferences(
    mut preferences: Preferences,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if preferences
        .camera_device_id
        .as_ref()
        .is_some_and(|value| value.len() > 1024)
    {
        return Err("The saved camera identifier is invalid.".into());
    }
    update_vault(&state, |vault| {
        let totp_ids: std::collections::HashSet<_> = vault
            .totp_entries
            .iter()
            .map(|entry| entry.id.as_str())
            .collect();
        let recovery_ids: std::collections::HashSet<_> = vault
            .recovery_sets
            .iter()
            .map(|set| set.id.as_str())
            .collect();
        preferences
            .totp_order
            .retain(|id| totp_ids.contains(id.as_str()));
        preferences
            .recovery_order
            .retain(|id| recovery_ids.contains(id.as_str()));
        vault.preferences = preferences;
        Ok(())
    })
}
#[tauri::command(rename = "change_master_password")]
fn change_master_password(
    current_password: String,
    new_password: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    validate_password(&new_password)?;
    let mut guard = get_session(&state)?;
    let session = guard.as_mut().ok_or("The vault is locked")?;
    let candidate = Zeroizing::new(current_password.into_bytes());
    if !constant_time_eq::constant_time_eq(session.password.as_slice(), candidate.as_slice()) {
        return Err("The current master password is incorrect.".into());
    }
    let next = Zeroizing::new(new_password.into_bytes());
    let encrypted = encrypt_vault(&session.vault, &next)?;
    atomic_write_replace(&session.path, &encrypted, "vault")?;
    session.password = next;
    Ok(())
}
#[tauri::command(rename = "export_vault")]
fn export_vault(destination: String, state: State<'_, AppState>) -> Result<(), String> {
    let guard = get_session(&state)?;
    let session = guard.as_ref().ok_or("The vault is locked")?;
    let bytes = encrypt_vault(&session.vault, session.password.as_slice())?;
    atomic_write_replace(Path::new(&destination), &bytes, "backup")
}

#[derive(Debug, Deserialize)]
struct ImportRequest {
    format: String,
    content: String,
    #[serde(default)]
    password: Option<String>,
}
#[derive(Debug, Deserialize)]
struct ImportFileRequest {
    path: String,
    #[serde(default)]
    password: Option<String>,
}
fn parse_import(
    format: &str,
    content: &str,
    password: Option<&str>,
) -> Result<Vec<ImportCandidate>, String> {
    if content.len() > MAX_IMPORT_BYTES {
        return Err("The selected import is too large.".into());
    }
    let records = match format.to_ascii_lowercase().as_str() {
        "otpauth" => vec![parse_otpauth(content)?],
        "google-migration" => parse_google_migration(content)?,
        "aegis-json" | "json" => parse_aegis_or_bitwarden(content, password)?,
        "bitwarden-json" => parse_bitwarden_json(content)?,
        "bitwarden-csv" | "csv" => parse_bitwarden_csv(content)?,
        _ => return Err("This import format is not supported. Choose an otpauth link, Aegis or Bitwarden export, or Google transfer QR.".into()),
    };
    if records.is_empty() {
        return Err("No supported TOTP accounts were found in this import.".into());
    }
    if records.len() > MAX_ENTRIES {
        return Err("The import contains too many accounts.".into());
    }
    Ok(records)
}
fn parse_otpauth(content: &str) -> Result<ImportCandidate, String> {
    let parsed = url::Url::parse(content.trim())
        .map_err(|_| "This is not a valid TOTP enrollment link.".to_string())?;
    if parsed.scheme() != "otpauth" || parsed.host_str() != Some("totp") {
        return Err("This is not a TOTP enrollment link. HOTP links are not supported.".into());
    }
    let mut secret = None;
    let mut issuer = None;
    let mut algorithm = OtpAlgorithmKind::Sha1;
    let mut digits = 6u32;
    let mut period = 30u32;
    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "secret" => secret = Some(value.into_owned()),
            "issuer" => issuer = Some(value.into_owned()),
            "algorithm" => algorithm = parse_algorithm(&value)?,
            "digits" => {
                digits = value
                    .parse()
                    .map_err(|_| "The TOTP digit count is invalid.".to_string())?
            }
            "period" => {
                period = value
                    .parse()
                    .map_err(|_| "The TOTP period is invalid.".to_string())?
            }
            _ => {}
        }
    }
    let encoded_label = parsed.path().trim_start_matches('/');
    let label = url::form_urlencoded::parse(format!("label={encoded_label}").as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default();
    let (path_issuer, account) = label
        .split_once(':')
        .map(|(issuer, account)| (Some(issuer.to_owned()), account.to_owned()))
        .unwrap_or((None, label));
    if issuer.as_ref().is_some_and(|value| {
        path_issuer
            .as_ref()
            .is_some_and(|path| !path.is_empty() && path != value)
    }) {
        return Err("The issuer in this TOTP link does not match its account label.".into());
    }
    let issuer = issuer
        .filter(|value| !value.is_empty())
        .or(path_issuer.filter(|value| !value.is_empty()));
    let name = issuer.clone().unwrap_or_else(|| {
        if account.is_empty() {
            "Authenticator".into()
        } else {
            account.clone()
        }
    });
    let candidate = ImportCandidate {
        name,
        subtitle: if issuer.is_some() {
            account
        } else {
            String::new()
        },
        secret: secret
            .ok_or("The TOTP enrollment link does not contain a shared key.")?
            .trim()
            .replace([' ', '-'], "")
            .to_ascii_uppercase(),
        algorithm,
        digits,
        period,
    };
    validate_totp_fields(
        &candidate.name,
        &candidate.secret,
        candidate.digits,
        candidate.period,
    )?;
    Ok(candidate)
}
fn parse_aegis_or_bitwarden(
    content: &str,
    password: Option<&str>,
) -> Result<Vec<ImportCandidate>, String> {
    let value: Value = serde_json::from_str(content)
        .map_err(|_| "The JSON export is invalid or incomplete.".to_string())?;
    if value.get("items").is_some() {
        return parse_bitwarden_json_value(&value);
    }
    if value.pointer("db.entries").is_none() && value.get("db").and_then(Value::as_str).is_some() {
        return parse_encrypted_aegis(
            &value,
            password.ok_or(
                "This Aegis export is encrypted. Enter its export password and try again.",
            )?,
        );
    }
    parse_aegis_value(&value)
}
fn parse_aegis_value(value: &Value) -> Result<Vec<ImportCandidate>, String> {
    let entries = value
        .pointer("db.entries")
        .or_else(|| {
            value
                .get("db")
                .filter(|database| database.is_object())
                .and_then(|database| database.get("entries"))
        })
        .and_then(Value::as_array)
        .ok_or("This is not a supported Aegis JSON export.")?;
    let mut output = Vec::new();
    for entry in entries {
        let kind = entry.get("type").and_then(Value::as_str).unwrap_or("totp");
        if kind != "totp" {
            continue;
        }
        let info = entry
            .get("info")
            .ok_or("An Aegis TOTP record is missing its settings.")?;
        let secret = info
            .get("secret")
            .and_then(Value::as_str)
            .ok_or("An Aegis TOTP record is missing its secret.")?;
        let label = entry
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("Authenticator");
        let issuer = entry
            .get("issuer")
            .and_then(Value::as_str)
            .filter(|item| !item.is_empty())
            .unwrap_or(label);
        let algorithm =
            parse_algorithm(info.get("algo").and_then(Value::as_str).unwrap_or("SHA1"))?;
        let candidate = ImportCandidate {
            name: issuer.to_owned(),
            subtitle: if issuer != label {
                label.to_owned()
            } else {
                String::new()
            },
            secret: secret.trim().to_ascii_uppercase(),
            algorithm,
            digits: info.get("digits").and_then(Value::as_u64).unwrap_or(6) as u32,
            period: info.get("period").and_then(Value::as_u64).unwrap_or(30) as u32,
        };
        validate_totp_fields(
            &candidate.name,
            &candidate.secret,
            candidate.digits,
            candidate.period,
        )?;
        output.push(candidate);
    }
    Ok(output)
}
fn parse_bitwarden_json(content: &str) -> Result<Vec<ImportCandidate>, String> {
    let value: Value = serde_json::from_str(content)
        .map_err(|_| "The Bitwarden JSON export is invalid.".to_string())?;
    parse_bitwarden_json_value(&value)
}
fn parse_bitwarden_json_value(value: &Value) -> Result<Vec<ImportCandidate>, String> {
    let items = value
        .get("items")
        .and_then(Value::as_array)
        .ok_or("This Bitwarden export has no item list.")?;
    let mut output = Vec::new();
    for item in items {
        let login = match item.get("login") {
            Some(login) => login,
            None => continue,
        };
        let otp = match login
            .get("totp")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            Some(otp) => otp,
            None => continue,
        };
        let mut candidate = parse_otpauth(otp)?;
        if candidate.name == "Authenticator" {
            candidate.name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("Authenticator")
                .to_owned();
        }
        if candidate.subtitle.is_empty() {
            candidate.subtitle = login
                .get("username")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
        }
        check_label(&candidate.name, &candidate.subtitle)?;
        output.push(candidate);
    }
    Ok(output)
}
fn parse_bitwarden_csv(content: &str) -> Result<Vec<ImportCandidate>, String> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::Headers)
        .from_reader(content.as_bytes());
    let headers = reader
        .headers()
        .map_err(|_| "The Bitwarden CSV header is invalid.".to_string())?
        .clone();
    let col = |name: &str| {
        headers
            .iter()
            .position(|header| header.trim().eq_ignore_ascii_case(name))
    };
    let totp_col = col("login_totp")
        .or_else(|| col("totp"))
        .ok_or("The Bitwarden CSV has no TOTP column.")?;
    let name_col = col("name");
    let username_col = col("login_username").or_else(|| col("username"));
    let mut output = Vec::new();
    for row in reader.records() {
        let row = row.map_err(|_| "A row in the Bitwarden CSV is malformed.".to_string())?;
        let otp = row
            .get(totp_col)
            .filter(|value| !value.trim().is_empty())
            .or_else(|| row.iter().skip(headers.len()).last())
            .unwrap_or("")
            .trim();
        if otp.is_empty() {
            continue;
        }
        let mut candidate = if otp.starts_with("otpauth://") {
            parse_otpauth(otp)?
        } else {
            parse_totp_secret(otp, "Authenticator", "")?
        };
        if let Some(index) = name_col {
            let name = row.get(index).unwrap_or("").trim();
            if !name.is_empty() && candidate.name == "Authenticator" {
                candidate.name = name.to_owned();
            }
        }
        if let Some(index) = username_col {
            let username = row.get(index).unwrap_or("").trim();
            if candidate.subtitle.is_empty() {
                candidate.subtitle = username.to_owned();
            }
        }
        if let Some(index) = row
            .iter()
            .position(|value| !value.trim().is_empty() && value.trim().starts_with("otpauth://"))
        {
            candidate = parse_otpauth(row.get(index).unwrap_or(otp))?;
        }
        if candidate.name == "Authenticator" {
            candidate.name = name_col
                .and_then(|index| row.get(index))
                .unwrap_or("Authenticator")
                .to_owned();
        }
        if candidate.subtitle.is_empty()
            && let Some(username) = row.get(9).filter(|value| !value.trim().is_empty())
        {
            candidate.subtitle = username.trim().to_owned();
        }
        output.push(candidate);
    }
    Ok(output)
}
fn parse_totp_secret(secret: &str, name: &str, subtitle: &str) -> Result<ImportCandidate, String> {
    let candidate = ImportCandidate {
        name: name.to_owned(),
        subtitle: subtitle.to_owned(),
        secret: secret.trim().replace([' ', '-'], "").to_ascii_uppercase(),
        algorithm: OtpAlgorithmKind::Sha1,
        digits: 6,
        period: 30,
    };
    validate_totp_fields(
        &candidate.name,
        &candidate.secret,
        candidate.digits,
        candidate.period,
    )?;
    Ok(candidate)
}
fn parse_algorithm(value: &str) -> Result<OtpAlgorithmKind, String> {
    match value.to_ascii_uppercase().as_str() {
        "SHA1" | "SHA-1" => Ok(OtpAlgorithmKind::Sha1),
        "SHA256" | "SHA-256" => Ok(OtpAlgorithmKind::Sha256),
        "SHA512" | "SHA-512" => Ok(OtpAlgorithmKind::Sha512),
        _ => Err(format!(
            "The import uses the unsupported algorithm {value}."
        )),
    }
}

fn read_varint(bytes: &[u8], offset: &mut usize) -> Result<u64, String> {
    let mut result = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes
            .get(*offset)
            .ok_or("The Google transfer QR is truncated")?;
        *offset += 1;
        if shift == 63 && byte > 1 {
            return Err("The Google transfer QR contains an invalid integer.".into());
        }
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
    }
    Err("The Google transfer QR contains an invalid integer.".into())
}
fn read_proto_fields(bytes: &[u8]) -> Result<Vec<(u32, u8, Vec<u8>)>, String> {
    let mut offset = 0;
    let mut fields = Vec::new();
    while offset < bytes.len() {
        let key = read_varint(bytes, &mut offset)?;
        let number = (key >> 3) as u32;
        let wire = (key & 7) as u8;
        if number == 0 {
            return Err("The Google transfer QR has an invalid field.".into());
        }
        let data = match wire {
            0 => read_varint(bytes, &mut offset)?.to_le_bytes().to_vec(),
            1 => {
                let end = offset
                    .checked_add(8)
                    .filter(|end| *end <= bytes.len())
                    .ok_or("The Google transfer QR is truncated")?;
                let result = bytes[offset..end].to_vec();
                offset = end;
                result
            }
            2 => {
                let len = usize::try_from(read_varint(bytes, &mut offset)?)
                    .map_err(|_| "The Google transfer QR is too large")?;
                let end = offset
                    .checked_add(len)
                    .filter(|end| *end <= bytes.len())
                    .ok_or("The Google transfer QR is truncated")?;
                let result = bytes[offset..end].to_vec();
                offset = end;
                result
            }
            5 => {
                let end = offset
                    .checked_add(4)
                    .filter(|end| *end <= bytes.len())
                    .ok_or("The Google transfer QR is truncated")?;
                let result = bytes[offset..end].to_vec();
                offset = end;
                result
            }
            _ => return Err("The Google transfer QR uses an unsupported encoding.".into()),
        };
        fields.push((number, wire, data));
    }
    Ok(fields)
}
fn proto_text(fields: &[(u32, u8, Vec<u8>)], number: u32) -> Option<String> {
    fields
        .iter()
        .find(|(field, wire, _)| *field == number && *wire == 2)
        .and_then(|(_, _, value)| String::from_utf8(value.clone()).ok())
}
fn proto_int(fields: &[(u32, u8, Vec<u8>)], number: u32) -> Option<u64> {
    fields
        .iter()
        .find(|(field, wire, _)| *field == number && *wire == 0)
        .and_then(|(_, _, value)| value.get(..8))
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
}
fn parse_google_migration(content: &str) -> Result<Vec<ImportCandidate>, String> {
    let url = url::Url::parse(content.trim())
        .map_err(|_| "This is not a valid Google transfer QR.".to_string())?;
    if url.scheme() != "otpauth-migration" || url.host_str() != Some("offline") {
        return Err("This is not a Google authenticator transfer QR.".into());
    }
    let encoded = url
        .query_pairs()
        .find(|(key, _)| key == "data")
        .map(|(_, value)| value.into_owned())
        .ok_or("The Google transfer QR contains no account data.")?;
    let payload = BASE64
        .decode(&encoded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&encoded))
        .map_err(|_| "The Google transfer QR data is invalid.".to_string())?;
    let fields = read_proto_fields(&payload)?;
    if proto_int(&fields, 2).is_some_and(|version| version != 1) {
        return Err("This Google transfer QR version is not supported.".into());
    }
    let mut output = Vec::new();
    for (_, wire, entry_bytes) in fields
        .iter()
        .filter(|(number, wire, _)| *number == 1 && *wire == 2)
    {
        let entry = read_proto_fields(entry_bytes)?;
        let secret = entry
            .iter()
            .find(|(number, wire, _)| *number == 1 && *wire == 2)
            .map(|(_, _, value)| value)
            .ok_or("A Google transfer account is missing its secret.")?;
        let name = proto_text(&entry, 2).unwrap_or_else(|| "Authenticator".into());
        let issuer = proto_text(&entry, 3).unwrap_or_default();
        let kind = proto_int(&entry, 6).unwrap_or(2);
        if kind != 2 {
            continue;
        }
        let algorithm = match proto_int(&entry, 4).unwrap_or(1) {
            1 => OtpAlgorithmKind::Sha1,
            2 => OtpAlgorithmKind::Sha256,
            3 => OtpAlgorithmKind::Sha512,
            other => {
                return Err(format!(
                    "Google transfer algorithm {other} is not supported."
                ));
            }
        };
        let digits = match proto_int(&entry, 5).unwrap_or(1) {
            1 => 6,
            2 => 8,
            other => {
                return Err(format!(
                    "Google transfer digit setting {other} is not supported."
                ));
            }
        };
        let candidate = ImportCandidate {
            name: if issuer.is_empty() {
                name.clone()
            } else {
                issuer.clone()
            },
            subtitle: if issuer.is_empty() {
                String::new()
            } else {
                name
            },
            secret: base32::encode(base32::Alphabet::Rfc4648 { padding: false }, secret),
            algorithm,
            digits,
            period: 30,
        };
        validate_totp_fields(
            &candidate.name,
            &candidate.secret,
            candidate.digits,
            candidate.period,
        )?;
        output.push(candidate);
        let _ = wire;
    }
    Ok(output)
}

fn decode_aegis_hex(value: Option<&Value>, label: &str) -> Result<Vec<u8>, String> {
    let encoded = value
        .and_then(Value::as_str)
        .ok_or_else(|| format!("The Aegis {label} is missing."))?;
    hex::decode(encoded).map_err(|_| format!("The Aegis {label} is invalid."))
}

fn parse_encrypted_aegis(value: &Value, password: &str) -> Result<Vec<ImportCandidate>, String> {
    // Aegis encrypts its database with AES-GCM and derives the slot key with scrypt.
    let database = value
        .get("db")
        .and_then(Value::as_str)
        .ok_or("The encrypted Aegis database is missing.")?;
    let encrypted_database = Zeroizing::new(
        BASE64
            .decode(database)
            .map_err(|_| "The encrypted Aegis database is invalid.".to_string())?,
    );
    let slots = value
        .pointer("header.slots")
        .and_then(Value::as_array)
        .ok_or("The encrypted Aegis password slot is missing.")?;
    let db_params = value
        .pointer("header.params")
        .ok_or("The encrypted Aegis database settings are missing.")?;
    let db_nonce = decode_aegis_hex(db_params.get("nonce"), "database nonce")?;
    let db_tag = decode_aegis_hex(db_params.get("tag"), "database tag")?;
    if db_nonce.len() != 12 || db_tag.len() != 16 {
        return Err("The Aegis database authentication settings are invalid.".into());
    }

    for slot in slots {
        let data = slot.get("slot").unwrap_or(slot);
        let slot_type = data.get("type").and_then(Value::as_u64).or_else(|| {
            data.get("type")
                .and_then(Value::as_str)
                .and_then(|text| text.parse().ok())
        });
        if slot_type != Some(1) {
            continue;
        }
        let n = data.get("n").and_then(Value::as_u64).unwrap_or(0);
        let r = data
            .get("r")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0);
        let p = data
            .get("p")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0);
        if n < 2
            || !n.is_power_of_two()
            || n > 1 << 20
            || !(1..=32).contains(&r)
            || !(1..=16).contains(&p)
        {
            return Err("The Aegis export uses unsafe or unsupported password settings.".into());
        }
        let salt = decode_aegis_hex(data.get("salt"), "password salt")?;
        if salt.len() < 16 || salt.len() > 64 {
            return Err("The Aegis password salt is invalid.".into());
        }
        let params = ScryptParams::new(n.trailing_zeros() as u8, r, p, 32)
            .map_err(|_| "The Aegis password settings are invalid.".to_string())?;
        let mut wrapping_key = Zeroizing::new([0u8; 32]);
        scrypt(password.as_bytes(), &salt, &params, wrapping_key.as_mut())
            .map_err(|_| "Could not derive the Aegis export key.".to_string())?;
        let key_params = data
            .get("key_params")
            .or_else(|| data.get("keyParams"))
            .ok_or("The Aegis password authentication settings are missing.")?;
        let wrap_nonce = decode_aegis_hex(key_params.get("nonce"), "password nonce")?;
        let wrap_tag = decode_aegis_hex(key_params.get("tag"), "password tag")?;
        let mut wrapped_key = decode_aegis_hex(data.get("key"), "wrapped database key")?;
        if wrap_nonce.len() != 12 || wrap_tag.len() != 16 || wrapped_key.len() != 32 {
            continue;
        }
        wrapped_key.extend_from_slice(&wrap_tag);
        let wrapping = Aes256Gcm::new_from_slice(wrapping_key.as_ref())
            .map_err(|_| "Could not initialize Aegis password decryption.".to_string())?;
        let Ok(database_key) =
            wrapping.decrypt(Nonce::from_slice(&wrap_nonce), wrapped_key.as_ref())
        else {
            continue;
        };
        let database_key = Zeroizing::new(database_key);
        let cipher = Aes256Gcm::new_from_slice(database_key.as_ref())
            .map_err(|_| "Could not initialize Aegis database decryption.".to_string())?;
        let mut ciphertext_and_tag = encrypted_database.to_vec();
        ciphertext_and_tag.extend_from_slice(&db_tag);
        let Ok(plaintext) =
            cipher.decrypt(Nonce::from_slice(&db_nonce), ciphertext_and_tag.as_ref())
        else {
            continue;
        };
        let plaintext = Zeroizing::new(plaintext);
        let database: Value = serde_json::from_slice(&plaintext)
            .map_err(|_| "The decrypted Aegis database is invalid.".to_string())?;
        return parse_aegis_value(&database);
    }
    Err("The Aegis export password is incorrect, or its encryption format is unsupported.".into())
}

#[tauri::command(rename = "parse_import")]
fn parse_import_command(request: ImportRequest) -> Result<Vec<ImportCandidate>, String> {
    parse_import(
        &request.format,
        &request.content,
        request.password.as_deref(),
    )
}
#[tauri::command(rename = "parse_import_file")]
fn parse_import_file(request: ImportFileRequest) -> Result<Vec<ImportCandidate>, String> {
    let path = Path::new(&request.path);
    let metadata =
        fs::metadata(path).map_err(|error| format!("Cannot read the selected export: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_IMPORT_BYTES as u64 {
        return Err(
            "The selected export is not a regular file or exceeds the 16 MiB limit.".into(),
        );
    }
    let bytes =
        fs::read(path).map_err(|error| format!("Cannot read the selected export: {error}"))?;
    let content = String::from_utf8(bytes)
        .map_err(|_| "The selected export is not valid UTF-8 JSON, CSV, or text.".to_string())?;
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let format = match extension.as_str() {
        "csv" => "bitwarden-csv",
        "txt" => "otpauth",
        "json" => "json",
        _ => return Err("Choose a supported JSON, CSV, text, or encrypted vault export.".into()),
    };
    if format == "otpauth" {
        return parse_otpauth(content.trim()).map(|candidate| vec![candidate]);
    }
    parse_import(format, &content, request.password.as_deref())
}
#[tauri::command(rename = "import_qr_image")]
fn import_qr_image(path: String) -> Result<ImportCandidate, String> {
    let metadata =
        fs::metadata(&path).map_err(|error| format!("Cannot open the QR image: {error}"))?;
    if !metadata.is_file() || metadata.len() > 16 * 1024 * 1024 {
        return Err("The QR image is not a regular image file or exceeds the 16 MiB limit.".into());
    }
    let image = image::open(&path)
        .map_err(|_| "The selected image could not be decoded.".to_string())?
        .to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(image);
    for grid in prepared.detect_grids() {
        if let Ok((_meta, content)) = grid.decode() {
            if content.starts_with("otpauth-migration://") {
                return parse_google_migration(&content)?
                    .into_iter()
                    .next()
                    .ok_or("The Google transfer QR did not contain a TOTP account.".into());
            }
            if content.starts_with("otpauth://") {
                return parse_otpauth(&content);
            }
        }
    }
    Err("No supported TOTP QR code was found in the selected image.".into())
}

fn canonical_secret(secret: &str) -> Result<Vec<u8>, String> {
    Secret::Encoded(secret.trim().replace([' ', '-'], "").to_ascii_uppercase())
        .to_bytes()
        .map_err(|_| "An authenticator secret is invalid.".into())
}
fn same_totp(left: &TotpRecord, right: &TotpRecord) -> bool {
    left.algorithm == right.algorithm
        && left.digits == right.digits
        && left.period == right.period
        && canonical_secret(&left.secret)
            .ok()
            .zip(canonical_secret(&right.secret).ok())
            .is_some_and(|(a, b)| constant_time_eq::constant_time_eq(&a, &b))
}
fn same_label(
    left_name: &str,
    left_subtitle: &str,
    right_name: &str,
    right_subtitle: &str,
) -> bool {
    left_name.trim().eq_ignore_ascii_case(right_name.trim())
        && left_subtitle
            .trim()
            .eq_ignore_ascii_case(right_subtitle.trim())
}
fn totp_conflict(left: &TotpRecord, right: &TotpRecord) -> bool {
    same_label(&left.name, &left.subtitle, &right.name, &right.subtitle) || same_totp(left, right)
}
fn recovery_conflict(left: &RecoverySet, right: &RecoverySet) -> bool {
    same_label(&left.name, &left.subtitle, &right.name, &right.subtitle)
        || left.codes.iter().any(|code| {
            right
                .codes
                .iter()
                .any(|imported| code.value == imported.value)
        })
}
fn recovery_detail(set: &RecoverySet) -> String {
    format!(
        "{} codes ({} usable, {} used)",
        set.codes.len(),
        set.codes.iter().filter(|code| !code.used).count(),
        set.codes.iter().filter(|code| code.used).count()
    )
}
fn build_conflict_view(
    id: String,
    existing: &RestoreRecord,
    imported: &RestoreRecord,
) -> RestoreConflictView {
    match (existing, imported) {
        (RestoreRecord::Totp(current), RestoreRecord::Totp(backup)) => RestoreConflictView {
            id,
            kind: "totp",
            current_name: current.name.clone(),
            current_subtitle: current.subtitle.clone(),
            imported_name: backup.name.clone(),
            imported_subtitle: backup.subtitle.clone(),
            current_detail: format!(
                "{} · {} digits · {} seconds",
                current.algorithm.as_label(),
                current.digits,
                current.period
            ),
            imported_detail: format!(
                "{} · {} digits · {} seconds",
                backup.algorithm.as_label(),
                backup.digits,
                backup.period
            ),
        },
        (RestoreRecord::Recovery(current), RestoreRecord::Recovery(backup)) => {
            RestoreConflictView {
                id,
                kind: "recovery",
                current_name: current.name.clone(),
                current_subtitle: current.subtitle.clone(),
                imported_name: backup.name.clone(),
                imported_subtitle: backup.subtitle.clone(),
                current_detail: recovery_detail(current),
                imported_detail: recovery_detail(backup),
            }
        }
        _ => unreachable!(),
    }
}
fn inspect_restore_conflicts(
    current: &VaultData,
    imported: &VaultData,
) -> Result<(Vec<RestoreConflictView>, Vec<PendingConflict>), String> {
    let mut views = Vec::new();
    let mut conflicts = Vec::new();
    for record in &imported.totp_entries {
        if let Some(existing) = current
            .totp_entries
            .iter()
            .find(|existing| totp_conflict(existing, record))
        {
            let id = random_id()?;
            let old = RestoreRecord::Totp(existing.clone());
            let new = RestoreRecord::Totp(record.clone());
            views.push(build_conflict_view(id.clone(), &old, &new));
            conflicts.push(PendingConflict {
                id,
                existing_id: existing.id.clone(),
                imported_id: record.id.clone(),
                record: new,
            });
        }
    }
    for record in &imported.recovery_sets {
        if let Some(existing) = current
            .recovery_sets
            .iter()
            .find(|existing| recovery_conflict(existing, record))
        {
            let id = random_id()?;
            let old = RestoreRecord::Recovery(existing.clone());
            let new = RestoreRecord::Recovery(record.clone());
            views.push(build_conflict_view(id.clone(), &old, &new));
            conflicts.push(PendingConflict {
                id,
                existing_id: existing.id.clone(),
                imported_id: record.id.clone(),
                record: new,
            });
        }
    }
    Ok((views, conflicts))
}
fn merge_restore(
    current: &mut VaultData,
    imported: &VaultData,
    conflicts: &[PendingConflict],
    choices: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    let mut conflicted_imports = std::collections::HashSet::new();
    for conflict in conflicts {
        conflicted_imports.insert(conflict.imported_id.clone());
        let choice = choices
            .get(&conflict.id)
            .map(String::as_str)
            .ok_or("Choose an action for every backup conflict")?;
        match choice {
            "keep current" | "skip" => {}
            "replace" => match &conflict.record {
                RestoreRecord::Totp(record) => {
                    if let Some(current) = current
                        .totp_entries
                        .iter_mut()
                        .find(|item| item.id == conflict.existing_id)
                    {
                        *current = record.clone();
                    }
                }
                RestoreRecord::Recovery(record) => {
                    if let Some(current) = current
                        .recovery_sets
                        .iter_mut()
                        .find(|item| item.id == conflict.existing_id)
                    {
                        *current = record.clone();
                    }
                }
            },
            "keep both" => match &conflict.record {
                RestoreRecord::Totp(record) => {
                    let mut record = record.clone();
                    record.id = random_id()?;
                    current.totp_entries.push(record);
                }
                RestoreRecord::Recovery(record) => {
                    let mut record = record.clone();
                    record.id = random_id()?;
                    current.recovery_sets.push(record);
                }
            },
            _ => return Err("A backup conflict has an unknown action.".into()),
        }
    }
    for record in &imported.recovery_sets {
        if !conflicted_imports.contains(&record.id)
            && !current
                .recovery_sets
                .iter()
                .any(|existing| existing.id == record.id)
        {
            current.recovery_sets.push(record.clone());
        }
    }
    for record in &imported.totp_entries {
        if !conflicted_imports.contains(&record.id)
            && !current
                .totp_entries
                .iter()
                .any(|existing| existing.id == record.id)
        {
            current.totp_entries.push(record.clone());
        }
    }
    if current.totp_entries.len() > MAX_ENTRIES || current.recovery_sets.len() > MAX_ENTRIES {
        return Err("The restored vault would exceed the record limit.".into());
    }
    validate_vault(current)
}
#[tauri::command(rename = "restore_vault")]
fn restore_vault(
    source: String,
    backup_password: String,
    state: State<'_, AppState>,
) -> Result<Vec<RestoreConflictView>, String> {
    let (_path, imported, _password) = unlock_path(PathBuf::from(source), backup_password)?;
    let mut guard = get_session(&state)?;
    let session = guard.as_mut().ok_or("The vault is locked")?;
    let (views, conflicts) = inspect_restore_conflicts(&session.vault, &imported)?;
    if conflicts.is_empty() {
        let previous = session.vault.clone();
        merge_restore(
            &mut session.vault,
            &imported,
            &[],
            &std::collections::HashMap::new(),
        )?;
        if let Err(error) = save_session(session) {
            session.vault = previous;
            return Err(error);
        }
        return Ok(views);
    }
    *state
        .pending_restore
        .lock()
        .map_err(|_| "Vault restore state is unavailable")? = Some(PendingRestore {
        baseline: session.vault.clone(),
        imported,
        conflicts,
    });
    Ok(views)
}
#[tauri::command(rename = "apply_restore_conflicts")]
fn apply_restore_conflicts(
    choices: Vec<RestoreChoice>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut pending_guard = state
        .pending_restore
        .lock()
        .map_err(|_| "Vault restore state is unavailable")?;
    let pending = pending_guard
        .as_ref()
        .ok_or("There is no backup waiting for conflict review")?;
    if choices.len() != pending.conflicts.len() {
        return Err("Choose an action for every backup conflict.".into());
    }
    let choices: std::collections::HashMap<_, _> = choices
        .into_iter()
        .map(|item| (item.id, item.choice))
        .collect();
    if choices.len() != pending.conflicts.len()
        || pending
            .conflicts
            .iter()
            .any(|item| !choices.contains_key(&item.id))
    {
        return Err("Backup conflict choices are incomplete or duplicated.".into());
    }
    let mut session_guard = get_session(&state)?;
    let session = session_guard.as_mut().ok_or("The vault is locked")?;
    if session.vault != pending.baseline {
        return Err("The vault changed while backup conflicts were being reviewed. Start the restore again.".into());
    }
    let mut merged = session.vault.clone();
    merge_restore(&mut merged, &pending.imported, &pending.conflicts, &choices)?;
    let previous = std::mem::replace(&mut session.vault, merged);
    if let Err(error) = save_session(session) {
        session.vault = previous;
        return Err(error);
    }
    *pending_guard = None;
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MonitorBounds {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub scale_factor: f32,
}
#[cfg(windows)]
use screen_capture::{begin_screen_capture, capture_screen_region, get_primary_monitor_bounds};
#[cfg(windows)]
use xcap::Monitor;

pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_process::init())
        .manage(AppState::default())
        .on_window_event(|window, event| {
            if window.label() != "main" {
                return;
            }
            match event {
                tauri::WindowEvent::Focused(false) => {
                    if let Ok(mut lost_at) = window.state::<AppState>().focus_lost_at.lock() {
                        *lost_at = Some(std::time::Instant::now());
                    }
                    let _ = window.emit("app-focus-lost", ());
                }
                tauri::WindowEvent::Focused(true) => {
                    if let Ok(mut lost_at) = window.state::<AppState>().focus_lost_at.lock() {
                        *lost_at = None;
                    }
                    let _ = window.emit("app-focus-gained", ());
                }
                _ => {}
            }
        });
    #[cfg(windows)]
    let builder = builder.invoke_handler(tauri::generate_handler![
        get_default_vault_path,
        vault_exists,
        resolve_vault_path,
        setup_vault,
        unlock_vault,
        lock_vault,
        get_vault_path,
        get_recovery_set,
        get_vault_summary,
        get_totp_codes,
        touch_vault_activity,
        add_totp,
        update_totp,
        delete_totp,
        reorder_totp,
        add_recovery_set,
        update_recovery_set,
        set_recovery_code_used,
        delete_recovery_set,
        reorder_recovery_sets,
        update_preferences,
        change_master_password,
        export_vault,
        restore_vault,
        apply_restore_conflicts,
        parse_import_command,
        parse_import_file,
        import_qr_image,
        begin_screen_capture,
        capture_screen_region,
        get_primary_monitor_bounds
    ]);
    #[cfg(not(windows))]
    let builder = builder.invoke_handler(tauri::generate_handler![
        get_default_vault_path,
        vault_exists,
        resolve_vault_path,
        setup_vault,
        unlock_vault,
        lock_vault,
        get_vault_path,
        get_recovery_set,
        get_vault_summary,
        get_totp_codes,
        touch_vault_activity,
        add_totp,
        update_totp,
        delete_totp,
        reorder_totp,
        add_recovery_set,
        update_recovery_set,
        set_recovery_code_used,
        delete_recovery_set,
        reorder_recovery_sets,
        update_preferences,
        change_master_password,
        export_vault,
        restore_vault,
        apply_restore_conflicts,
        parse_import_command,
        parse_import_file,
        import_qr_image
    ]);
    builder
        .run(tauri::generate_context!())
        .expect("error while running Offline Authenticator");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn password_policy_requires_length_and_no_space() {
        assert!(validate_password("short").is_err());
        assert!(validate_password("long enough pass").is_err());
        assert!(validate_password("longenoughpass").is_ok());
    }
    #[test]
    fn encrypted_vault_round_trip_and_reject_wrong_password() {
        let password = b"longenoughpass";
        let bytes = encrypt_vault(&initialized_vault(), password).unwrap();
        assert_eq!(
            decrypt_vault(&bytes, password).unwrap(),
            initialized_vault()
        );
        assert!(decrypt_vault(&bytes, b"incorrectpassword").is_err());
    }
    #[test]
    fn encrypted_vault_rejects_tampering() {
        let mut bytes = encrypt_vault(&initialized_vault(), b"longenoughpass").unwrap();
        let last = bytes.len() - 2;
        bytes[last] ^= 1;
        assert!(decrypt_vault(&bytes, b"longenoughpass").is_err());
    }
    #[test]
    fn kdf_rejects_unsafe_cost() {
        assert!(derive_key(b"x", &[0; 16], 1, 1, 1).is_err());
        assert!(derive_key(b"x", &[0; 16], MAX_KDF_MEMORY_KIB + 1, 1, 1).is_err());
    }
    #[test]
    fn otpauth_import_preserves_parameters() {
        let item = parse_otpauth("otpauth://totp/GitHub:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60").unwrap();
        assert_eq!(item.name, "GitHub");
        assert_eq!(item.subtitle, "alice@example.com");
        assert_eq!(item.algorithm, OtpAlgorithmKind::Sha256);
        assert_eq!(item.digits, 8);
        assert_eq!(item.period, 60);
    }
    #[test]
    fn rejects_hotp_and_bad_otpauth() {
        assert!(parse_otpauth("otpauth://hotp/account?secret=JBSWY3DPEHPK3PXP&counter=0").is_err());
        assert!(parse_otpauth("https://example.com").is_err());
    }
    #[test]
    fn totp_rfc6238_vectors() {
        let secret = Secret::Raw(b"12345678901234567890".to_vec())
            .to_bytes()
            .unwrap();
        let token = TOTP::new(OtpAlgorithm::SHA1, 8, 0, 30, secret, None, "test".into()).unwrap();
        assert_eq!(token.generate(59), "94287082");
        assert_eq!(token.generate(1111111109), "07081804");
    }
    #[test]
    fn countdown_obeys_period_boundary() {
        let remaining = |now: u64, period: u64| period - now % period;
        assert_eq!(remaining(29, 30), 1);
        assert_eq!(remaining(30, 30), 30);
    }
    #[test]
    fn bitwarden_import_reads_standard_json() {
        let parsed=parse_bitwarden_json(r#"{"items":[{"name":"GitHub","login":{"username":"alice","totp":"otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"}}]}"#).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].subtitle, "alice");
    }
    #[test]
    fn csv_parser_handles_quoted_commas() {
        let parsed=parse_bitwarden_csv("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,0,login,\"Work, GitHub\",,,,,,alice,,JBSWY3DPEHPK3PXP\n").unwrap();
        assert_eq!(parsed[0].name, "Work, GitHub");
    }
    #[test]
    fn unencrypted_aegis_import_rejects_non_totp() {
        let parsed=parse_aegis_value(&serde_json::json!({"db":{"entries":[{"type":"hotp","name":"x"},{"type":"totp","name":"GitHub","issuer":"GitHub","info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":30}}]}})).unwrap();
        assert_eq!(parsed.len(), 1);
    }
    #[test]
    fn google_migration_wire_decoder_reads_integer_fields() {
        let bytes = [0x08, 0x01, 0x10, 0x03];
        let fields = read_proto_fields(&bytes).unwrap();
        assert_eq!(proto_int(&fields, 1), Some(1));
        assert_eq!(proto_int(&fields, 2), Some(3));
    }
    #[test]
    fn detects_import_conflicts_without_merging_secrets() {
        let a = TotpRecord {
            id: "a".into(),
            name: "GitHub".into(),
            subtitle: "Alice".into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            algorithm: OtpAlgorithmKind::Sha1,
            digits: 6,
            period: 30,
            added_at: 0,
            recovery_set_id: None,
        };
        let mut b = a.clone();
        b.id = "b".into();
        b.name = "github".into();
        assert!(totp_conflict(&a, &b));
        assert!(!same_label("A", "one", "A", "two"));
    }
    #[test]
    fn recovery_conflict_comparison_is_exact_for_code_values() {
        let make = |id: &str, value: &str| RecoverySet {
            id: id.into(),
            name: id.into(),
            subtitle: String::new(),
            codes: vec![RecoveryCode {
                id: "c".into(),
                value: value.into(),
                used: false,
                added_at: 0,
            }],
            added_at: 0,
        };
        assert!(recovery_conflict(&make("A", "exact"), &make("B", "exact")));
        assert!(!recovery_conflict(&make("A", "exact"), &make("B", "EXACT")));
    }
    #[test]
    fn restore_resolver_requires_each_conflict_and_applies_all_choices() {
        let set = initialized_vault();
        let (views, conflicts) = inspect_restore_conflicts(&set, &set).unwrap();
        assert!(views.is_empty());
        assert!(conflicts.is_empty());
        let mut target = initialized_vault();
        let mut imported = initialized_vault();
        let record = TotpRecord {
            id: "a".into(),
            name: "A".into(),
            subtitle: String::new(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            algorithm: OtpAlgorithmKind::Sha1,
            digits: 6,
            period: 30,
            added_at: 0,
            recovery_set_id: None,
        };
        target.totp_entries.push(record.clone());
        let mut other = record.clone();
        other.id = "b".into();
        imported.totp_entries.push(other);
        let (_views, conflicts) = inspect_restore_conflicts(&target, &imported).unwrap();
        let mut choices = std::collections::HashMap::new();
        assert!(merge_restore(&mut target, &imported, &conflicts, &choices).is_err());
        choices.insert(conflicts[0].id.clone(), "keep both".into());
        merge_restore(&mut target, &imported, &conflicts, &choices).unwrap();
        assert_eq!(target.totp_entries.len(), 2);
    }
    #[test]
    fn vault_uses_argon2id_and_xchacha_authenticated_header() {
        let bytes = encrypt_vault(&initialized_vault(), b"longenoughpass").unwrap();
        assert_eq!(&bytes[..8], FORMAT_MAGIC);
        assert_eq!(
            u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
            FORMAT_VERSION
        );
    }
}
