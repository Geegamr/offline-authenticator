import { invoke, isTauri } from "@tauri-apps/api/core";
import * as Clipboard from "@tauri-apps/plugin-clipboard-manager";
import { open, save } from "@tauri-apps/plugin-dialog";
import { readTextFile } from "@tauri-apps/plugin-fs";
import { TOTP } from "otpauth";

export type Tab = "codes" | "backup" | "settings";
export type Algorithm = "sha1" | "sha256" | "sha512";
export type Appearance = "system" | "light" | "dark";
export type TotpRecord = {
  id: string;
  name: string;
  subtitle: string;
  secret: string;
  algorithm: Algorithm;
  digits: number;
  period: number;
  added_at: number;
  recovery_set_id?: string | null;
};
export type RecoverySetSummary = {
  id: string;
  name: string;
  subtitle: string;
  available_count: number;
  used_count: number;
  added_at: number;
};
export type RecoveryCode = { id: string; value: string; used: boolean; added_at: number };
export type RecoverySet = { id: string; name: string; subtitle: string; codes: RecoveryCode[]; added_at: number };
export type Preferences = {
  ask_after_copy: boolean;
  clear_clipboard: boolean;
  appearance: Appearance;
  camera_device_id: string | null;
  totp_order: string[];
  recovery_order: string[];
};
export type VaultSummary = {
  version: number;
  totp_entries: TotpRecord[];
  recovery_sets: RecoverySetSummary[];
  preferences: Preferences;
};
export type TotpDisplay = {
  id: string;
  name: string;
  subtitle: string;
  code: string;
  remaining_seconds: number;
  period: number;
  has_recovery_set: boolean;
};
export type ImportCandidate = {
  name: string;
  subtitle: string;
  secret: string;
  algorithm: Algorithm;
  digits: number;
  period: number;
};

export const DEMO_SUMMARY: VaultSummary = {
  version: 1,
  totp_entries: [
    { id: "demo-git", name: "GitHub", subtitle: "alex@northstar.studio", secret: "JBSWY3DPEHPK3PXP", algorithm: "sha1", digits: 6, period: 30, added_at: 1_728_000_000, recovery_set_id: null },
    { id: "demo-notion", name: "Notion", subtitle: "alex@northstar.studio", secret: "JBSWY3DPEHPK3PXP", algorithm: "sha1", digits: 6, period: 30, added_at: 1_728_000_001, recovery_set_id: null },
    { id: "demo-aws", name: "Amazon Web Services", subtitle: "Northstar studio", secret: "JBSWY3DPEHPK3PXP", algorithm: "sha256", digits: 6, period: 30, added_at: 1_728_000_002, recovery_set_id: "demo-recovery" },
  ],
  recovery_sets: [{ id: "demo-recovery", name: "Amazon Web Services", subtitle: "Root account", available_count: 7, used_count: 1, added_at: 1_728_000_003 }],
  preferences: { ask_after_copy: true, clear_clipboard: true, appearance: "system", camera_device_id: null, totp_order: [], recovery_order: [] },
};

let demoSummary: VaultSummary | null = null;
const demoRecoverySets: Record<string, RecoverySet> = {};
let demoClipboard = "";
let demoCopiedAt = 0;
const sampleCodes = ["autumn-river-27", "copper-field-84", "quiet-window-19", "silver-forest-52", "bright-harbor-63", "cedar-morning-08", "blue-meadow-41", "paper-mountain-76"];
function id() { return crypto.randomUUID(); }
function copySummary(summary: VaultSummary): VaultSummary { return structuredClone(summary); }
function requireDemo(): VaultSummary { if (!demoSummary) throw new Error("The demo vault is locked."); return demoSummary; }
function demoCode(record: TotpRecord, now = Date.now()) {
  const totp = new TOTP({ issuer: record.name, label: record.subtitle, algorithm: record.algorithm.toUpperCase() as "SHA1" | "SHA256" | "SHA512", digits: record.digits, period: record.period, secret: record.secret });
  const code = totp.generate({ timestamp: now });
  const remaining = record.period - Math.floor((now / 1000) % record.period);
  return { id: record.id, name: record.name, subtitle: record.subtitle, code, remaining_seconds: remaining, period: record.period, has_recovery_set: !!record.recovery_set_id };
}

export async function defaultVaultPath(portable: boolean): Promise<string> {
  if (isTauri()) return invoke<string>("get_default_vault_path", { portable });
  return portable ? "portable/vault.authvault" : "local/vault.authvault";
}
export async function vaultExists(path: string): Promise<boolean> {
  if (isTauri()) return invoke<boolean>("vault_exists", { path });
  return false;
}
export async function resolveVaultPath(path: string, portable: boolean): Promise<string> {
  if (isTauri()) return invoke<string>("resolve_vault_path", { path, portable });
  return path;
}
export async function setupVault(path: string, password: string): Promise<void> {
  if (isTauri()) return invoke("setup_vault", { path, password });
  demoSummary = copySummary({ ...DEMO_SUMMARY, totp_entries: [], recovery_sets: [] });
}
export async function unlockVault(path: string, password: string): Promise<VaultSummary> {
  if (isTauri()) return invoke<VaultSummary>("unlock_vault", { path, password });
  if (!password || password.length < 12 || password !== "demo-password") throw new Error("The demo password is demo-password.");
  demoSummary = copySummary(DEMO_SUMMARY);
  return copySummary(demoSummary);
}
export async function touchVaultActivity() { if (isTauri()) return invoke("touch_vault_activity"); }
export async function lockVault() {
  if (isTauri()) return invoke("lock_vault");
  demoSummary = null;
}
export async function getVaultPath() {
  if (isTauri()) return invoke<string>("get_vault_path");
  return "Demo only — no vault file is saved";
}
export async function getTotpCodes(): Promise<TotpDisplay[]> {
  if (isTauri()) return invoke<TotpDisplay[]>("get_totp_codes");
  return requireDemo().totp_entries.map((record) => demoCode(record));
}
export async function getVaultSummary(): Promise<VaultSummary> {
  if (isTauri()) return invoke<VaultSummary>("get_vault_summary");
  return copySummary(requireDemo());
}
export async function getRecoverySet(setId: string): Promise<RecoverySet> {
  if (isTauri()) return invoke<RecoverySet>("get_recovery_set", { setId });
  const cached = demoRecoverySets[setId];
  if (cached) return structuredClone(cached);
  if (setId !== "demo-recovery") throw new Error("Recovery-code set not found.");
  const set: RecoverySet = { id: setId, name: "Amazon Web Services", subtitle: "Root account", added_at: 1_728_000_003, codes: sampleCodes.map((value, index) => ({ id: `demo-code-${index}`, value, used: index === 3, added_at: 1_728_000_003 + index })) };
  demoRecoverySets[setId] = structuredClone(set);
  return set;
}
export async function addTotpBatch(inputs: ImportCandidate[]) {
  if (isTauri()) return invoke("add_totp_batch", { inputs });
  const summary = requireDemo();
  if (summary.totp_entries.length + inputs.length > 10_000) throw new Error("This vault already contains too many authenticators.");
  const records = inputs.map((input) => ({ ...input, id: id(), added_at: Date.now() / 1000 }));
  summary.totp_entries.push(...records);
}
export async function addTotp(input: Omit<ImportCandidate, "secret"> & { secret: string; recovery_set_id?: string | null }): Promise<TotpRecord> {
  if (isTauri()) return invoke<TotpRecord>("add_totp", { input });
  const record: TotpRecord = { ...input, id: id(), added_at: Date.now() / 1000 };
  requireDemo().totp_entries.push(record);
  return record;
}
export async function updateTotp(record: TotpRecord & { secret?: string }) {
  if (isTauri()) return invoke("update_totp", { record });
  const summary = requireDemo();
  const index = summary.totp_entries.findIndex((entry) => entry.id === record.id);
  if (index >= 0) summary.totp_entries[index] = { ...summary.totp_entries[index], ...record };
}
export async function deleteTotp(recordId: string) {
  if (isTauri()) return invoke("delete_totp", { id: recordId });
  const summary = requireDemo(); summary.totp_entries = summary.totp_entries.filter((entry) => entry.id !== recordId);
}
export async function reorderTotp(ids: string[]) { if (isTauri()) return invoke("reorder_totp", { ids }); requireDemo().preferences.totp_order = ids; }
export async function addRecoverySet(input: { name: string; subtitle: string; codes: string[] }): Promise<RecoverySetSummary> {
  if (isTauri()) return invoke("add_recovery_set", { input });
  const set: RecoverySet = { id: id(), name: input.name, subtitle: input.subtitle, added_at: Date.now() / 1000, codes: input.codes.map((value) => ({ id: id(), value, used: false, added_at: Date.now() / 1000 })) };
  demoRecoverySets[set.id] = set;
  const summary = requireDemo();
  const meta = { id: set.id, name: set.name, subtitle: set.subtitle, available_count: set.codes.length, used_count: 0, added_at: set.added_at };
  summary.recovery_sets.push(meta);
  return meta;
}
export async function updateRecoverySet(set: RecoverySet) { if (isTauri()) return invoke("update_recovery_set", { set }); demoRecoverySets[set.id] = structuredClone(set); const summary = requireDemo(); const item = summary.recovery_sets.find((entry) => entry.id === set.id); if (item) { item.available_count = set.codes.filter((code) => !code.used).length; item.used_count = set.codes.filter((code) => code.used).length; } }
export async function setRecoveryCodeUsed(setId: string, codeId: string, used: boolean) { if (isTauri()) return invoke("set_recovery_code_used", { setId, codeId, used }); const set = await getRecoverySet(setId); const code = set.codes.find((entry) => entry.id === codeId); if (!code) throw new Error("Recovery code not found."); code.used = used; await updateRecoverySet(set); }
export async function deleteRecoverySet(setId: string) { if (isTauri()) return invoke("delete_recovery_set", { id: setId }); const summary = requireDemo(); summary.recovery_sets = summary.recovery_sets.filter((entry) => entry.id !== setId); for (const record of summary.totp_entries) if (record.recovery_set_id === setId) record.recovery_set_id = null; delete demoRecoverySets[setId]; }
export async function reorderRecoverySets(ids: string[]) { if (isTauri()) return invoke("reorder_recovery_sets", { ids }); requireDemo().preferences.recovery_order = ids; }
export async function updatePreferences(preferences: Preferences) { if (isTauri()) return invoke("update_preferences", { preferences }); requireDemo().preferences = preferences; }
export async function changeMasterPassword(currentPassword: string, newPassword: string) { if (isTauri()) return invoke("change_master_password", { currentPassword, newPassword }); if (currentPassword !== "demo-password") throw new Error("The demo password is demo-password."); }
export async function deleteVault(password: string) { if (isTauri()) return invoke("delete_vault", { password }); throw new Error("Deleting a vault is only available in the Windows desktop app."); }
export async function copySecret(value: string, clearAfterThirtySeconds: boolean) {
  if (isTauri()) {
    await Clipboard.writeText(value);
    if (clearAfterThirtySeconds) {
      const copied = value;
      window.setTimeout(async () => { try { if ((await Clipboard.readText()) === copied) await Clipboard.writeText(""); } catch { /* Clipboard was unavailable or changed. */ } }, 30_000);
    }
    return;
  }
  demoClipboard = value; demoCopiedAt = Date.now();
  if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(value).catch(() => undefined);
  if (clearAfterThirtySeconds) window.setTimeout(async () => { if (demoClipboard === value && Date.now() - demoCopiedAt >= 29_000) { demoClipboard = ""; if (navigator.clipboard?.readText && navigator.clipboard?.writeText) { const current = await navigator.clipboard.readText().catch(() => null); if (current === value) await navigator.clipboard.writeText("").catch(() => undefined); } } }, 30_000);
}
export async function parseImport(format: string, content: string, password?: string): Promise<ImportCandidate[]> { if (isTauri()) return invoke("parse_import", { request: { format, content, password } }); return parseDemoImport(format, content); }
export async function parseImportFile(path: string, password?: string): Promise<ImportCandidate[]> {
  if (!isTauri()) throw new Error("File imports require the Windows desktop app.");
  return invoke<ImportCandidate[]>("parse_import_file", { request: { path, password } });
}
function parseDemoImport(format: string, content: string): ImportCandidate[] {
  if (format === "otpauth") { const url = new URL(content.trim()); if (url.protocol !== "otpauth:" || url.hostname.toLowerCase() !== "totp") throw new Error("This is not a valid TOTP enrollment link."); const [labelIssuer, accountLabel] = decodeURIComponent(url.pathname.replace(/^\//, "")).split(":", 2); const issuer = url.searchParams.get("issuer") || labelIssuer; const otp = new TOTP({issuer: issuer || undefined, label: accountLabel || labelIssuer || "account", algorithm: (url.searchParams.get("algorithm") || "SHA1").toUpperCase() as "SHA1" | "SHA256" | "SHA512", digits: Number(url.searchParams.get("digits") || 6), period: Number(url.searchParams.get("period") || 30), secret: url.searchParams.get("secret") || ""}); return [{ name: issuer || accountLabel || labelIssuer || "New authenticator", subtitle: accountLabel || "", secret: otp.secret.base32, algorithm: otp.algorithm.toLowerCase() as Algorithm, digits: otp.digits, period: otp.period }]; }
  if (format === "bitwarden-json") { const parsed = JSON.parse(content); return (parsed.items ?? []).flatMap((item: { name?: string; login?: { username?: string; totp?: string } }) => { if (!item.login?.totp) return []; const row = parseDemoImport("otpauth", item.login.totp)[0]!; return [{ ...row, name: row.name || item.name || "Authenticator", subtitle: row.subtitle || item.login.username || "" }]; }); }
  if (format === "aegis-json") { const parsed = JSON.parse(content); if (typeof parsed.db === "string") throw new Error("Encrypted Aegis exports can only be decrypted in the installed Windows app."); const entries = parsed.db?.entries ?? []; return entries.flatMap((entry: { type: string; name: string; issuer?: string; info: { secret: string; algo?: string; digits?: number; period?: number } }) => { if (entry.type !== "totp") return []; return [{ name: entry.issuer || entry.name, subtitle: entry.name, secret: entry.info.secret, algorithm: (entry.info.algo ?? "SHA1").toLowerCase() as Algorithm, digits: entry.info.digits ?? 6, period: entry.info.period ?? 30 }]; }); }
  if (format === "google-migration") throw new Error("Google transfer QR decoding is available in the installed app, not the preview.");
  if (format === "bitwarden-csv") throw new Error("CSV imports are only supported by the installed app.");
  throw new Error("This import type is not supported in the preview.");
}
export async function chooseImportFile(extensions = ["json", "csv", "txt", "authvault"]): Promise<string | null> {
  const selection = await open({ multiple: false, filters: [{ name: "Authenticator files", extensions }] });
  if (!selection) return null;
  return Array.isArray(selection) ? selection[0] ?? null : selection;
}
export async function chooseQrImage(): Promise<string | null> {
  const selection = await open({ multiple: false, filters: [{ name: "QR image", extensions: ["png", "jpg", "jpeg", "bmp", "gif"] }] });
  if (!selection) return null;
  return Array.isArray(selection) ? selection[0]! : selection;
}
export async function chooseBackupPath(defaultName: string): Promise<string | null> { const path = await save({ defaultPath: defaultName, filters: [{ name: "Encrypted vault backup", extensions: ["authvault"] }] }); return typeof path === "string" ? path : null; }
export async function chooseVaultFolder(): Promise<string | null> { const path = await open({ directory: true, multiple: false, title: "Choose a writable vault folder" }); return typeof path === "string" ? path : Array.isArray(path) ? path[0] ?? null : null; }
export async function readFile(path: string) { if (!isTauri()) return ""; return readTextFile(path); }
export async function exportVault(destination: string) { if (isTauri()) return invoke("export_vault", { destination }); }
export type RestoreConflict = { id: string; kind: "totp" | "recovery"; current_name: string; current_subtitle: string; imported_name: string; imported_subtitle: string; current_detail: string; imported_detail: string };
export type RestoreChoice = { id: string; choice: "keep current" | "replace" | "keep both" | "skip" };
export async function restoreVault(source: string, backupPassword: string): Promise<RestoreConflict[]> { if (isTauri()) return invoke("restore_vault", { source, backupPassword }); return []; }
export async function applyRestoreConflicts(choices: RestoreChoice[]) { if (isTauri()) return invoke("apply_restore_conflicts", { choices }); }

export async function screenScan(selection: { x: number; y: number; width: number; height: number }): Promise<ImportCandidate> { if (isTauri()) return invoke("capture_screen_region", { request: selection }); throw new Error("Screen scan requires the Windows desktop app."); }
export async function importQrImage(path: string): Promise<ImportCandidate> { if (isTauri()) return invoke("import_qr_image", { path }); throw new Error("QR image import requires the Windows desktop app."); }
export async function readClipboard(): Promise<string> { if (isTauri()) return Clipboard.readText(); return navigator.clipboard?.readText() ?? ""; }
export function clearDemoVault() { demoSummary = null; for (const key of Object.keys(demoRecoverySets)) delete demoRecoverySets[key]; }
