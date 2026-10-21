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
use tauri::{Emitter, State};
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
pub enum OtpAlgorithmKind { Sha1, Sha256, Sha512 }
impl OtpAlgorithmKind {
    fn to_totp(&self) -> OtpAlgorithm { match self { Self::Sha1 => OtpAlgorithm::SHA1, Self::Sha256 => OtpAlgorithm::SHA256, Self::Sha512 => OtpAlgorithm::SHA512 } }
    fn as_label(&self) -> &'static str { match self { Self::Sha1 => "SHA-1", Self::Sha256 => "SHA-256", Self::Sha512 => "SHA-512" } }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct TotpRecord {
    #[zeroize(skip)] pub id: String,
    #[zeroize(skip)] pub name: String,
    #[serde(default)] #[zeroize(skip)] pub subtitle: String,
    #[serde(default)] pub secret: String,
    #[serde(default = "default_algorithm")] #[zeroize(skip)] pub algorithm: OtpAlgorithmKind,
    #[serde(default = "default_digits")] #[zeroize(skip)] pub digits: u32,
    #[serde(default = "default_period")] #[zeroize(skip)] pub period: u32,
    #[zeroize(skip)] pub added_at: u64,
    #[serde(default)] #[zeroize(skip)] pub recovery_set_id: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCode { #[zeroize(skip)] pub id: String, pub value: String, #[zeroize(skip)] pub used: bool, #[zeroize(skip)] pub added_at: u64 }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RecoverySet { pub id: String, pub name: String, #[serde(default)] pub subtitle: String, #[serde(default)] pub codes: Vec<RecoveryCode>, pub added_at: u64 }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Appearance { System, Light, Dark }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Preferences {
    #[serde(default = "default_true")] pub ask_after_copy: bool,
    #[serde(default = "default_true")] pub clear_clipboard: bool,
    #[serde(default = "default_appearance")] pub appearance: Appearance,
    #[serde(default)] pub camera_device_id: Option<String>,
    #[serde(default)] pub totp_order: Vec<String>,
    #[serde(default)] pub recovery_order: Vec<String>,
}
impl Default for Preferences {
    fn default() -> Self { Self { ask_after_copy: true, clear_clipboard: true, appearance: Appearance::System, camera_device_id: None, totp_order: Vec::new(), recovery_order: Vec::new() } }
}
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct VaultData {
    pub version: u32,
    #[serde(default)] pub totp_entries: Vec<TotpRecord>,
    #[serde(default)] pub recovery_sets: Vec<RecoverySet>,
    #[serde(default)] pub preferences: Preferences,
}
#[derive(Debug, Deserialize)]
pub struct TotpInput { pub name: String, #[serde(default)] pub subtitle: String, pub secret: String, #[serde(default = "default_algorithm")] pub algorithm: OtpAlgorithmKind, #[serde(default = "default_digits")] pub digits: u32, #[serde(default = "default_period")] pub period: u32, #[serde(default)] pub recovery_set_id: Option<String> }
#[derive(Debug, Deserialize)]
pub struct RecoverySetInput { pub name: String, #[serde(default)] pub subtitle: String, pub codes: Vec<String> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TotpRecordSummary { pub id: String, pub name: String, pub subtitle: String, pub algorithm: OtpAlgorithmKind, pub digits: u32, pub period: u32, pub added_at: u64, pub recovery_set_id: Option<String> }
fn totp_summary(record: &TotpRecord) -> TotpRecordSummary { TotpRecordSummary { id: record.id.clone(), name: record.name.clone(), subtitle: record.subtitle.clone(), algorithm: record.algorithm.clone(), digits: record.digits, period: record.period, added_at: record.added_at, recovery_set_id: record.recovery_set_id.clone() } }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultSummary { pub version: u32, pub totp_entries: Vec<TotpRecordSummary>, pub recovery_sets: Vec<RecoverySetSummary>, pub preferences: Preferences }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoverySetSummary { pub id: String, pub name: String, pub subtitle: String, pub available_count: usize, pub used_count: usize, pub added_at: u64 }
fn vault_summary(vault: &VaultData) -> VaultSummary {
    VaultSummary { version: vault.version, totp_entries: vault.totp_entries.iter().map(totp_summary).collect(), recovery_sets: vault.recovery_sets.iter().map(|set| RecoverySetSummary { id: set.id.clone(), name: set.name.clone(), subtitle: set.subtitle.clone(), available_count: set.codes.iter().filter(|code| !code.used).count(), used_count: set.codes.iter().filter(|code| code.used).count(), added_at: set.added_at }).collect(), preferences: vault.preferences.clone() }
}
#[derive(Debug, Serialize)]
pub struct TotpDisplay { pub id: String, pub name: String, pub subtitle: String, pub code: String, pub remaining_seconds: u32, pub period: u32, pub has_recovery_set: bool }
#[derive(Clone, Debug, Serialize, Zeroize)]
pub struct ImportCandidate { #[zeroize(skip)] pub name: String, #[zeroize(skip)] pub subtitle: String, pub secret: String, #[zeroize(skip)] pub algorithm: OtpAlgorithmKind, #[zeroize(skip)] pub digits: u32, #[zeroize(skip)] pub period: u32 }
#[derive(Debug, Serialize, Deserialize)]
struct VaultHeader { version: u32, memory_kib: u32, iterations: u32, lanes: u32, salt: String, nonce: String, ciphertext: String }
#[derive(Serialize, Deserialize)]
struct BackupPayload { backup_version: u32, vault: VaultData }
#[derive(Clone)]
enum RestoreRecord { Totp(TotpRecord), Recovery(RecoverySet) }
struct PendingConflict { id: String, existing_id: String, imported_id: String, record: RestoreRecord }
struct PendingRestore { baseline: VaultData, imported: VaultData, conflicts: Vec<PendingConflict> }
#[derive(Serialize)]
struct RestoreConflictView { id: String, kind: &'static str, current_name: String, current_subtitle: String, imported_name: String, imported_subtitle: String, current_detail: String, imported_detail: String }
#[derive(Deserialize)]
struct RestoreChoice { id: String, choice: String }
struct Session { path: PathBuf, password: Zeroizing<Vec<u8>>, vault: VaultData }
impl Drop for Session {
    fn drop(&mut self) { self.password.zeroize(); for record in &mut self.vault.totp_entries { record.zeroize(); } for set in &mut self.vault.recovery_sets { for code in &mut set.codes { code.zeroize(); } } }
}
#[derive(Default)]
pub struct AppState { session: Mutex<Option<Session>>, activity: Mutex<Option<InstantTracker>>, focus_lost_at: Mutex<Option<std::time::Instant>>, pending_restore: Mutex<Option<PendingRestore>> }
#[derive(Clone, Copy)]
struct InstantTracker(std::time::Instant);
impl InstantTracker { fn expired(&self, now: std::time::Instant) -> bool { now.duration_since(self.0) >= std::time::Duration::from_secs(300) } }
fn default_true() -> bool { true }
fn default_digits() -> u32 { 6 }
fn default_period() -> u32 { 30 }
fn default_algorithm() -> OtpAlgorithmKind { OtpAlgorithmKind::Sha1 }
fn default_appearance() -> Appearance { Appearance::System }
fn unix_seconds() -> Result<u64, String> { SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_secs()).map_err(|_| "System clock is before the Unix epoch".into()) }
fn random_id() -> Result<String, String> { let mut bytes = [0u8; 16]; getrandom::getrandom(&mut bytes).map_err(|error| format!("Could not create a secure random identifier: {error}"))?; Ok(hex::encode(bytes)) }
fn validate_password(password: &str) -> Result<(), String> { let count = password.chars().count(); if count < 12 { return Err("Use at least 12 characters for the master password.".into()); } if password.chars().any(char::is_whitespace) { return Err("The master password cannot contain whitespace.".into()); } if count > 1024 { return Err("The master password is too long.".into()); } Ok(()) }

fn derive_key(password: &[u8], salt: &[u8], memory_kib: u32, iterations: u32, lanes: u32) -> Result<Zeroizing<[u8; 32]>, String> {
    if salt.len() != 16 { return Err("The vault salt is invalid.".into()); }
    if !(8_192..=MAX_KDF_MEMORY_KIB).contains(&memory_kib) || !(1..=MAX_KDF_ITERATIONS).contains(&iterations) || !(1..=8).contains(&lanes) { return Err("The vault uses unsafe or unsupported password-hashing settings.".into()); }
    let params = ArgonParams::new(memory_kib, iterations, lanes, Some(32)).map_err(|_| "The vault password settings are invalid".to_string())?;
    let argon = Argon2::new(ArgonAlgorithm::Argon2id, ArgonVersion::V0x13, params);
    let mut output = Zeroizing::new([0u8; 32]);
    argon.hash_password_into(password, salt, output.as_mut()).map_err(|_| "Could not derive a vault key".to_string())?;
    Ok(output)
}
fn encrypt_vault(data: &VaultData, password: &[u8]) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; 16]; let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut salt).map_err(|error| format!("Could not create a vault salt: {error}"))?;
    getrandom::getrandom(&mut nonce).map_err(|error| format!("Could not create a vault nonce: {error}"))?;
    let key = derive_key(password, &salt, DEFAULT_MEMORY_KIB, DEFAULT_ITERATIONS, DEFAULT_LANES)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| "Could not initialize vault encryption".to_string())?;
    let plaintext = Zeroizing::new(serde_json::to_vec(data).map_err(|_| "Could not encode vault data".to_string())?);
    let header_aad = format!("offline-authenticator:{FORMAT_VERSION}");
    let encrypted = Zeroizing::new(cipher.encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext.as_slice(), aad: header_aad.as_bytes() }).map_err(|_| "Could not encrypt the vault".to_string())?);
    let header = VaultHeader { version: FORMAT_VERSION, memory_kib: DEFAULT_MEMORY_KIB, iterations: DEFAULT_ITERATIONS, lanes: DEFAULT_LANES, salt: BASE64.encode(salt), nonce: BASE64.encode(nonce), ciphertext: BASE64.encode(encrypted.as_slice()) };
    let body = serde_json::to_vec(&header).map_err(|_| "Could not encode encrypted vault".to_string())?;
    let mut out = Vec::with_capacity(FORMAT_MAGIC.len() + 4 + body.len());
    out.extend_from_slice(FORMAT_MAGIC); out.extend_from_slice(&FORMAT_VERSION.to_be_bytes()); out.extend_from_slice(&body);
    salt.zeroize(); nonce.zeroize(); Ok(out)
}
fn decrypt_vault(bytes: &[u8], password: &[u8]) -> Result<VaultData, String> {
    if bytes.len() < 12 || bytes.len() as u64 > MAX_VAULT_BYTES { return Err("The vault file is empty, too large, or incomplete.".into()); }
    if &bytes[..8] != FORMAT_MAGIC { return Err("This is not a supported encrypted authenticator vault.".into()); }
    let outer_version = u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| "The vault header is incomplete")?);
    if outer_version != FORMAT_VERSION { return Err("This vault version is not supported.".into()); }
    let header: VaultHeader = serde_json::from_slice(&bytes[12..]).map_err(|_| "The encrypted vault header is damaged or unsupported".to_string())?;
    if header.version != FORMAT_VERSION { return Err("This vault version is not supported.".into()); }
    let salt = Zeroizing::new(BASE64.decode(&header.salt).map_err(|_| "The encrypted vault salt is invalid".to_string())?);
    let nonce = Zeroizing::new(BASE64.decode(&header.nonce).map_err(|_| "The encrypted vault nonce is invalid".to_string())?);
    if nonce.len() != 24 { return Err("The encrypted vault nonce is invalid.".into()); }
    let ciphertext = Zeroizing::new(BASE64.decode(&header.ciphertext).map_err(|_| "The encrypted vault data is invalid".to_string())?);
    if ciphertext.len() > MAX_VAULT_BYTES as usize { return Err("The encrypted vault data is too large.".into()); }
    let key = derive_key(password, &salt, header.memory_kib, header.iterations, header.lanes)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| "Could not initialize vault encryption".to_string())?;
    let aad = format!("offline-authenticator:{}", header.version);
    let plaintext = Zeroizing::new(cipher.decrypt(XNonce::from_slice(&nonce), Payload { msg: ciphertext.as_slice(), aad: aad.as_bytes() }).map_err(|_| "The password is incorrect, or this vault has been changed.".to_string())?);
    let data: VaultData = serde_json::from_slice(&plaintext).map_err(|_| "The decrypted vault data is not valid.".to_string())?;
    validate_vault(&data)?; Ok(data)
}
fn validate_vault(vault: &VaultData) -> Result<(), String> {
    if vault.version > 1 { return Err("This vault was made by a newer version of the app.".into()); }
    if vault.totp_entries.len() > MAX_ENTRIES || vault.recovery_sets.len() > MAX_ENTRIES { return Err("This vault contains too many records.".into()); }
    let mut totp_ids = std::collections::HashSet::new();
    for record in &vault.totp_entries {
        validate_totp_fields(&record.name, &record.secret, record.digits, record.period)?;
        if record.subtitle.chars().count() > 300 || record.name.chars().count() > 120 { return Err("Authenticator labels are too long.".into()); }
        if record.name.trim().is_empty() { return Err("Authenticator names cannot be empty.".into()); }
        if !totp_ids.insert(&record.id) { return Err("This vault contains duplicate authenticator identifiers.".into()); }
    }
    let mut set_ids = std::collections::HashSet::new();
    for set in &vault.recovery_sets {
        if set.name.trim().is_empty() || set.name.chars().count() > 120 || set.subtitle.chars().count() > 300 { return Err("Recovery-code set labels are invalid or too long.".into()); }
        if set.codes.is_empty() || set.codes.len() > MAX_ENTRIES { return Err("A recovery-code set must contain between 1 and 10,000 codes.".into()); }
        if !set_ids.insert(&set.id) { return Err("This vault contains duplicate recovery-code identifiers.".into()); }
        let mut code_ids = std::collections::HashSet::new(); let mut code_values = std::collections::HashSet::new();
        for code in &set.codes {
            if code.value.trim().is_empty() || code.value.len() > 512 || code.value.chars().any(char::is_control) { return Err("This vault contains an invalid recovery code.".into()); }
            if !code_ids.insert(&code.id) || !code_values.insert(&code.value) { return Err("This vault contains duplicate recovery codes.".into()); }
        }
    }
    Ok(())
}
fn validate_totp_fields(name: &str, secret: &str, digits: u32, period: u32) -> Result<(), String> {
    if name.trim().is_empty() || name.chars().count() > 120 { return Err("Enter a name between 1 and 120 characters.".into()); }
    if !(6..=8).contains(&digits) { return Err("Authenticator codes must use 6, 7, or 8 digits.".into()); }
    if !(1..=300).contains(&period) { return Err("The code period must be between 1 and 300 seconds.".into()); }
    let cleaned = secret.trim().replace(' ', "").replace('-', "").to_ascii_uppercase();
    let decoded = Secret::Encoded(cleaned).to_bytes().map_err(|_| "The shared key is not valid Base32.".to_string())?;
    if decoded.len() < 10 || decoded.len() > 128 { return Err("The shared key must be between 10 and 128 bytes.".into()); }
    Ok(())
}
fn totp_for_record(entry: &TotpRecord) -> Result<TOTP, String> {
    validate_totp_fields(&entry.name, &entry.secret, entry.digits, entry.period)?;
    let secret = Secret::Encoded(entry.secret.trim().replace(' ', "").replace('-', "").to_ascii_uppercase()).to_bytes().map_err(|_| "The shared key is not valid Base32".to_string())?;
    TOTP::new(entry.algorithm.to_totp(), entry.digits as usize, 0, entry.period as u64, secret, None, entry.name.clone()).map_err(|_| "The shared key or code settings are invalid".to_string())
}
fn replace_vault_file(temp: &Path, destination: &Path) -> Result<(), String> {
    #[cfg(windows)] { use std::os::windows::ffi::OsStrExt; use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW}; let source: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect(); let target: Vec<u16> = destination.as_os_str().encode_wide().chain(Some(0)).collect(); let result = unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) }; if result == 0 { return Err(format!("Cannot replace the current vault: {}", std::io::Error::last_os_error())); } Ok(()) }
    #[cfg(not(windows))] { fs::rename(temp, destination).map_err(|error| format!("Cannot replace the current vault: {error}")) }
}
fn atomic_write_replace(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    let parent = path.parent().ok_or("The destination folder is not valid")?;
    fs::create_dir_all(parent).map_err(|error| format!("Cannot create the destination folder: {error}"))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|error| format!("Cannot create a safe temporary {label}: {error}"))?;
    temp.write_all(bytes).map_err(|error| format!("Cannot write the encrypted {label}: {error}"))?;
    temp.as_file().sync_all().map_err(|error| format!("Cannot flush the encrypted {label}: {error}"))?;
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; let mut permissions = temp.as_file().metadata().map_err(|error| format!("Cannot inspect encrypted file permissions: {error}"))?.permissions(); permissions.set_mode(0o600); temp.as_file().set_permissions(permissions).map_err(|error| format!("Cannot secure encrypted file permissions: {error}"))?; }
    let (file, temp_path) = temp.keep().map_err(|error| format!("Cannot stage encrypted {label}: {}", error.error))?; drop(file);
    if let Err(error) = replace_vault_file(&temp_path, path) { let _ = fs::remove_file(&temp_path); return Err(error); }
    if let Ok(dir) = File::open(parent) { let _ = dir.sync_all(); } Ok(())
}
fn atomic_save(path: &Path, data: &VaultData, password: &[u8]) -> Result<(), String> { let bytes = encrypt_vault(data, password)?; atomic_write_replace(path, &bytes, "vault") }
fn initialized_vault() -> VaultData { VaultData { version: FORMAT_VERSION, ..VaultData::default() } }
fn get_session<'a>(state: &'a State<'_, AppState>) -> Result<std::sync::MutexGuard<'a, Option<Session>>, String> {
    let mut guard = state.session.lock().map_err(|_| "Vault state is unavailable".to_string())?;
    if guard.is_none() { return Err("The vault is locked.".into()); }
    let tracker = state.activity.lock().map_err(|_| "Vault activity state is unavailable")?;
    if tracker.is_some_and(|item| item.expired(std::time::Instant::now())) {
        drop(tracker); *guard = None;
        if let Ok(mut activity) = state.activity.lock() { *activity = None; }
        if let Ok(mut focus) = state.focus_lost_at.lock() { *focus = None; }
        if let Ok(mut pending) = state.pending_restore.lock() { *pending = None; }
        return Err("The vault was locked after five minutes without activity. Unlock it to continue.".into());
    }
    Ok(guard)
}
#[tauri::command(rename = "touch_vault_activity")]
fn touch_vault_activity(state: State<'_, AppState>) -> Result<(), String> { let _session = get_session(&state)?; let mut activity = state.activity.lock().map_err(|_| "Vault activity state is unavailable")?; *activity = Some(InstantTracker(std::time::Instant::now())); Ok(()) }
fn save_session(session: &Session) -> Result<(), String> { atomic_save(&session.path, &session.vault, session.password.as_slice()) }
fn unlock_path(path: PathBuf, password: String) -> Result<(PathBuf, VaultData, Zeroizing<Vec<u8>>), String> {
    let mut password_bytes = Zeroizing::new(password.into_bytes());
    let metadata = fs::metadata(&path).map_err(|error| format!("Cannot open the selected vault: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_VAULT_BYTES { return Err("The selected vault file is not valid or exceeds the size limit.".into()); }
    let file = File::open(&path).map_err(|error| format!("Cannot read the selected vault: {error}"))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(MAX_VAULT_BYTES + 1).read_to_end(&mut bytes).map_err(|error| format!("Cannot read the selected vault: {error}"))?;
    let vault = decrypt_vault(&bytes, &password_bytes)?;
    Ok((path, vault, std::mem::take(&mut password_bytes)))
}

#[tauri::command(rename = "vault_exists")]
fn vault_exists(path: String) -> Result<bool, String> { Ok(PathBuf::from(path).is_file()) }
#[tauri::command(rename = "setup_vault")]
fn setup_vault(path: String, password: String) -> Result<(), String> { validate_password(&password)?; atomic_write_new(Path::new(&path), &encrypt_vault(&initialized_vault(), password.as_bytes())?) }
#[tauri::command(rename = "resolve_vault_path")]
fn resolve_vault_path(path: String, portable: bool) -> Result<String, String> {
    if portable { let exe = std::env::current_exe().map_err(|error| format!("Cannot locate the app folder: {error}"))?; return validate_writable_folder(exe.parent().ok_or("Cannot locate the app folder")?); }
    let requested = PathBuf::from(path); validate_writable_folder(requested.parent().ok_or("Choose a folder for the vault")?)
}
fn validate_writable_folder(folder: &Path) -> Result<String, String> {
    fs::create_dir_all(folder).map_err(|error| format!("Cannot create the vault folder: {error}"))?;
    let probe = folder.join(format!(".authenticator-write-test-{}.tmp", random_id()?));
    let result = OpenOptions::new().write(true).create_new(true).open(&probe).map_err(|error| format!("This vault folder is not writable: {error}"))?;
    drop(result); fs::remove_file(&probe).map_err(|error| format!("Cannot verify the vault folder: {error}"))?;
    Ok(folder.join("vault.authvault").display().to_string())
}
#[tauri::command(rename = "unlock_vault")]
fn unlock_vault(path: String, password: String, state: State<'_, AppState>) -> Result<VaultSummary, String> {
    let (path, vault, password) = unlock_path(PathBuf::from(path), password)?;
    *state.session.lock().map_err(|_| "Vault state is unavailable".to_string())? = Some(Session { path, password, vault: vault.clone() });
    *state.activity.lock().map_err(|_| "Vault activity state is unavailable".to_string())? = Some(InstantTracker(std::time::Instant::now()));
    *state.focus_lost_at.lock().map_err(|_| "Vault focus state is unavailable".to_string())? = None;
    Ok(vault_summary(&vault))
}
#[tauri::command(rename = "lock_vault")]
fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    *state.session.lock().map_err(|_| "Vault state is unavailable".to_string())? = None;
    *state.activity.lock().map_err(|_| "Vault activity state is unavailable".to_string())? = None;
    *state.focus_lost_at.lock().map_err(|_| "Vault focus state is unavailable".to_string())? = None;
    *state.pending_restore.lock().map_err(|_| "Vault restore state is unavailable".to_string())? = None; Ok(())
}
#[tauri::command(rename = "get_vault_path")]
fn get_vault_path(state: State<'_, AppState>) -> Result<String, String> { Ok(get_session(&state)?.as_ref().ok_or("The vault is locked")?.path.display().to_string()) }
#[tauri::command(rename = "get_recovery_set")]
fn get_recovery_set(set_id: String, state: State<'_, AppState>) -> Result<RecoverySet, String> { get_session(&state)?.as_ref().ok_or("The vault is locked")?.vault.recovery_sets.iter().find(|set| set.id == set_id).cloned().ok_or_else(|| "Recovery-code set not found".to_string()) }
#[tauri::command(rename = "get_vault_summary")]
fn get_vault_summary(state: State<'_, AppState>) -> Result<VaultSummary, String> { Ok(vault_summary(&get_session(&state)?.as_ref().ok_or("The vault is locked")?.vault)) }
#[tauri::command(rename = "get_totp_codes")]
fn get_totp_codes(state: State<'_, AppState>) -> Result<Vec<TotpDisplay>, String> {
    let guard = get_session(&state)?; let session = guard.as_ref().ok_or("The vault is locked")?;
    session.vault.totp_entries.iter().map(|entry| { let totp = totp_for_record(entry)?; let now = unix_seconds()?; let code = totp.generate(now); let remaining_seconds = (entry.period as u64 - now % entry.period as u64) as u32; Ok(TotpDisplay { id: entry.id.clone(), name: entry.name.clone(), subtitle: entry.subtitle.clone(), code, remaining_seconds, period: entry.period, has_recovery_set: entry.recovery_set_id.as_ref().is_some_and(|id| session.vault.recovery_sets.iter().any(|set| &set.id == id)) }) }).collect()
}
#[tauri::command(rename = "add_totp")]
fn add_totp(input: TotpInput, state: State<'_, AppState>) -> Result<TotpRecordSummary, String> {
    validate_totp_fields(&input.name, &input.secret, input.digits, input.period)?;
    let record = TotpRecord { id: random_id()?, name: input.name.trim().to_owned(), subtitle: input.subtitle.trim().to_owned(), secret: input.secret.trim().replace(' ', "").replace('-', "").to_ascii_uppercase(), algorithm: input.algorithm, digits: input.digits, period: input.period, added_at: unix_seconds()?, recovery_set_id: input.recovery_set_id };
    totp_for_record(&record)?; let mut guard = get_session(&state)?; let session = guard.as_mut().ok_or("The vault is locked")?;
    if session.vault.totp_entries.len() >= MAX_ENTRIES { return Err("This vault already contains too many authenticators.".into()); }
    session.vault.totp_entries.push(record.clone()); if let Err(error) = save_session(session) { session.vault.totp_entries.pop(); return Err(error); } Ok(totp_summary(&record))
}
#[tauri::command(rename = "update_totp")]
fn update_totp(mut record: TotpRecord, state: State<'_, AppState>) -> Result<(), String> {
    if record.subtitle.chars().count() > 300 { return Err("The account label is too long.".into()); }
    let mut guard = get_session(&state)?; let session = guard.as_mut().ok_or("The vault is locked")?;
    let index = session.vault.totp_entries.iter().position(|item| item.id == record.id).ok_or("Authenticator not found")?;
    if record.secret.trim().is_empty() { record.secret = session.vault.totp_entries[index].secret.clone(); }
    record.name = record.name.trim().to_owned(); record.subtitle = record.subtitle.trim().to_owned(); validate_totp_fields(&record.name, &record.secret, record.digits, record.period)?;
    let old = std::mem::replace(&mut session.vault.totp_entries[index], record); if let Err(error) = save_session(session) { session.vault.totp_entries[index] = old; return Err(error); } Ok(())
}
#[tauri::command(rename = "delete_totp")]
fn delete_totp(id: String, state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = get_session(&state)?; let session = guard.as_mut().ok_or("The vault is locked")?; let index = session.vault.totp_entries.iter().position(|entry| entry.id == id).ok_or("Authenticator not found")?;
    let old = session.vault.totp_entries.remove(index); let previous_order = session.vault.preferences.totp_order.clone(); session.vault.preferences.totp_order.retain(|record_id| record_id != &id);
    if let Err(error) = save_session(session) { session.vault.totp_entries.insert(index, old); session.vault.preferences.totp_order = previous_order; return Err(error); } Ok(())
}
#[tauri::command(rename = "reorder_totp")]
fn reorder_totp(ids: Vec<String>, state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = get_session(&state)?; let session = guard.as_mut().ok_or("The vault is locked")?;
    if ids.len() != session.vault.totp_entries.len() || ids.iter().collect::<std::collections::HashSet<_>>().len() != ids.len() || ids.iter().any(|id| !session.vault.totp_entries.iter().any(|entry| &entry.id == id)) { return Err("Authenticator order is invalid.".into()); }
    let previous = std::mem::replace(&mut session.vault.preferences.totp_order, ids); if let Err(error) = save_session(session) { session.vault.preferences.totp_order = previous; return Err(error); } Ok(())
}

// Authenticator CRUD, import parsing, QR handling, backup/restore conflict management are below.
