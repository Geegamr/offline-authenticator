import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { register } from "@tauri-apps/plugin-global-shortcut";
import * as QRScanner from "jsqr";
import {
  addRecoverySet, addTotp, applyRestoreConflicts, changeMasterPassword, chooseBackupPath, chooseImportFile, chooseQrImage,
  chooseVaultFolder, copySecret, defaultVaultPath, deleteRecoverySet, deleteTotp,
  exportVault, getRecoverySet, getTotpCodes, importQrImage, lockVault, parseImport, parseImportFile, reorderRecoverySets, reorderTotp, restoreVault,
  resolveVaultPath, setRecoveryCodeUsed, setupVault, touchVaultActivity, updatePreferences, updateRecoverySet, updateTotp, unlockVault,
  vaultExists, type Algorithm, type ImportCandidate, type Preferences, type RecoverySet, type RecoverySetSummary,
  type RestoreChoice, type Tab, type TotpDisplay, type TotpRecord, type VaultSummary,
} from "./authenticator";
import "./App.css";
import "./index.css";

type Toast = { message: string; tone?: "success" | "error" };
type ImportMode = "manual" | "link" | "image" | "camera" | "screen" | "bulk" | null;
type DialogState = { title: string; message: string; confirm?: string; cancel?: string; destructive?: boolean; onConfirm?: () => void } | null;
const PASSCODE_HINT = "Use 12 or more characters. Skip spaces. There is no reset if the password is lost.";
const ALGORITHMS: { value: Algorithm; label: string }[] = [{ value: "sha1", label: "SHA-1" }, { value: "sha256", label: "SHA-256" }, { value: "sha512", label: "SHA-512" }];
const NAVIGATION: { key: Tab; label: string; icon: string }[] = [
  { key: "codes", label: "2FA Codes", icon: "codes" },
  { key: "backup", label: "Backup Codes", icon: "backup" },
  { key: "settings", label: "Settings", icon: "settings" },
];
function prettifyError(error: unknown) { return typeof error === "string" ? error : error instanceof Error ? error.message.replace(/^Error: /, "") : "That did not work. Please try again."; }
function Icon({ name, size = 18 }: { name: string; size?: number }) {
  const props = { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, "aria-hidden": true as const };
  const shapes: Record<string, React.ReactNode> = {
    lock: <><rect x="4.5" y="10" width="15" height="11" rx="2"/><path d="M8 10V7a4 4 0 1 1 8 0v3"/><path d="M12 14v3"/></>,
    codes: <><circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="4.2"/><path d="M17.7 6.3 16.3 7.7"/></>,
    backup: <><path d="M5 7.5h14l-1 13H6l-1-13Z"/><path d="M3.5 4.5h17M9 4.5a3 3 0 0 1 6 0M12 11v6m-2-2 2 2 2-2"/></>,
    settings: <><circle cx="12" cy="12" r="3"/><path d="m19.4 15 .1.1a1.7 1.7 0 1 1-2.4 2.4l-.1-.1a1.7 1.7 0 0 0-2.9 1.2v.4a1.7 1.7 0 1 1-3.4 0v-.2a1.7 1.7 0 0 0-2.9-1.2l-.1.1a1.7 1.7 0 1 1-2.4-2.4l.1-.1a1.7 1.7 0 0 0-1.2-2.9h-.4a1.7 1.7 0 1 1 0-3.4H4a1.7 1.7 0 0 0 1.2-2.9l-.1-.1a1.7 1.7 0 1 1 2.4-2.4l.1.1a1.7 1.7 0 0 0 2.9-1.2v-.4a1.7 1.7 0 1 1 3.4 0V2a1.7 1.7 0 0 0 2.9 1.2l.1-.1a1.7 1.7 0 1 1 2.4 2.4l-.1.1a1.7 1.7 0 0 0 1.2 2.9h.4a1.7 1.7 0 1 1 0 3.4H20a1.7 1.7 0 0 0-.6 3.1Z" transform="translate(0.8 1.2) scale(.94)"/></>,
    add: <><path d="M12 5v14m-7-7h14"/></>,
    search: <><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 4.2 4.2"/></>,
    arrow: <><path d="M5 12h14m-6-6 6 6-6 6"/></>,
    copy: <><rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h2"/></>,
    close: <><path d="m18 6-12 12M6 6l12 12"/></>,
    shield: <><path d="M12 21s8-3.8 8-10V5l-8-3-8 3v6c0 6.2 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></>,
    key: <><circle cx="8" cy="15" r="4.5"/><path d="m11 12 8-8 2 2-2 2 2 2-3 3-2-2-2 2"/></>,
    file: <><path d="M6 3h8l5 5v13H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z"/><path d="M14 3v5h5M8 13h8m-8 4h8"/></>,
    camera: <><path d="M4 8a2 2 0 0 1 2-2h2l1.5-2h5L16 6h2a2 2 0 0 1 2 2v10H4V8Z"/><circle cx="12" cy="13" r="3.5"/></>,
    menu: <><path d="M5 7h14M5 12h14M5 17h14"/></>,
    sun: <><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></>,
    moon: <><path d="M19.7 15.3A8.2 8.2 0 0 1 8.7 4.3a8.3 8.3 0 1 0 11 11Z"/></>,
    drag: <><circle cx="9" cy="6" r="1" fill="currentColor"/><circle cx="15" cy="6" r="1" fill="currentColor"/><circle cx="9" cy="12" r="1" fill="currentColor"/><circle cx="15" cy="12" r="1" fill="currentColor"/><circle cx="9" cy="18" r="1" fill="currentColor"/><circle cx="15" cy="18" r="1" fill="currentColor"/></>,
    back: <><path d="m15 18-6-6 6-6"/><path d="M20 12H9"/></>,
    check: <><path d="m5 12 4 4L19 6"/></>,
    warning: <><path d="M12 3 2 21h20L12 3Z"/><path d="M12 9v4m0 4h.01"/></>,
  };
  return <svg {...props}>{shapes[name] ?? shapes.codes}</svg>;
}

export default function App() {
  const [summary, setSummary] = useState<VaultSummary | null>(null);
  const [path, setPath] = useState("");
  const [onboardStage, setOnboardStage] = useState<"loading" | "choose-location" | "setup" | "unlock" | "ready">("loading");
  const [portable, setPortable] = useState(false);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [tab, setTab] = useState<Tab>("codes");
  const [search, setSearch] = useState("");
  const [totp, setTotp] = useState<TotpDisplay[]>([]);
  const [activeSet, setActiveSet] = useState<RecoverySet | null>(null);
  const [importMode, setImportMode] = useState<ImportMode>(null);
  const [clipboardPrompt, setClipboardPrompt] = useState<{ codeId: string; setId: string } | null>(null);
  const [toast, setToast] = useState<Toast | null>(null);
  const [dialog, setDialog] = useState<DialogState>(null);
  const [working, setWorking] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const [copyAskAfter, setCopyAskAfter] = useState<string | null>(null);
  const [windowMaximized, setWindowMaximized] = useState(false);
  const [screenScanSupported, setScreenScanSupported] = useState(false);
  const mediaStreamRef = useRef<MediaStream | null>(null);
  const screenCaptureActiveRef = useRef(false);

  async function chooseScreenRegion(): Promise<ImportCandidate | null> {
    if (!isTauri()) throw new Error("Screen selection requires the Windows desktop app.");
    screenCaptureActiveRef.current = true;
    return new Promise<ImportCandidate | null>((resolve, reject) => {
      let regionUnlisten: (() => void) | undefined;
      let cancelUnlisten: (() => void) | undefined;
      let timeout = 0;
      let settled = false;
      const finish = (result: ImportCandidate | null, error?: unknown) => {
        if (settled) return;
        settled = true;
        window.clearTimeout(timeout);
        screenCaptureActiveRef.current = false;
        regionUnlisten?.();
        cancelUnlisten?.();
        if (error) reject(error); else resolve(result);
      };
      void (async () => {
        try {
          cancelUnlisten = await listen("screen-capture-cancelled", () => {
            void invoke("cancel_screen_capture").catch(() => undefined);
            finish(null);
          });
          regionUnlisten = await listen<{ x: number; y: number; width: number; height: number }>("screen-capture-region", async (event) => {
            try {
              const candidate = await invoke<ImportCandidate>("capture_screen_region", { request: event.payload });
              finish(candidate);
            } catch (error) {
              await invoke("cancel_screen_capture").catch(() => undefined);
              finish(null, error);
            }
          });
          timeout = window.setTimeout(() => {
            void invoke("cancel_screen_capture").catch(() => undefined);
            finish(null, new Error("Screen scanning timed out and was cancelled. Try again."));
          }, 120_000);
          await invoke("begin_screen_capture");
        } catch (error) {
          void invoke("cancel_screen_capture").catch(() => undefined);
          finish(null, error);
        }
      })();
    });
  }

  const [pendingImport, setPendingImport] = useState<ImportCandidate[]>([]);

  const notify = useCallback((message: string, tone: Toast["tone"] = "success") => { setToast({ message, tone }); window.setTimeout(() => setToast(null), 3200); }, []);
  const fail = useCallback((error: unknown) => notify(prettifyError(error), "error"), [notify]);
  const refresh = useCallback(() => setReloadKey((value) => value + 1), []);

  const setupPath = useCallback(async () => {
    try {
      const nextPath = await defaultVaultPath(portable);
      setPath(nextPath);
      const exists = await vaultExists(nextPath);
      setOnboardStage(exists ? "unlock" : portable ? "setup" : "choose-location");
    } catch (error) { fail(error); }
  }, [portable, fail]);
  useEffect(() => { void setupPath(); }, [setupPath]);

  useEffect(() => {
    if (onboardStage !== "ready" || !summary) return;
    const refreshCodes = async () => { try { setTotp(await getTotpCodes()); } catch (error) { fail(error); } };
    void refreshCodes();
    const timer = window.setInterval(() => { void refreshCodes(); }, 1000);
    return () => window.clearInterval(timer);
  }, [onboardStage, summary, reloadKey, fail]);

  useEffect(() => {
    if (!summary) return;
    const root = document.documentElement;
    root.dataset.appearance = summary.preferences.appearance;
  }, [summary]);

  useEffect(() => {
    if (!isTauri() || onboardStage !== "ready") return;
    let unlisten: (() => void) | undefined;
    let gainedUnlisten: (() => void) | undefined;
    let focusTimer = 0;
    let locked = false;
    const lockForInactivity = () => {
      if (locked) return;
      locked = true;
      setSummary(null);
      setTotp([]);
      setActiveSet(null);
      setPassword("");
      void lockVault().finally(() => setOnboardStage("unlock"));
    };
    void listen("app-focus-lost", () => {
      window.clearTimeout(focusTimer);
      focusTimer = window.setTimeout(lockForInactivity, 300_000);
    }).then((fn) => { unlisten = fn; });
    void listen("app-focus-gained", () => window.clearTimeout(focusTimer)).then((fn) => { gainedUnlisten = fn; });
    const checkSleep = () => { if (!screenCaptureActiveRef.current && Date.now() - lastTick > 60_000) lockForInactivity(); lastTick = Date.now(); };
    let lastTick = Date.now();
    const sleepTimer = window.setInterval(checkSleep, 15_000);
    const visibility = () => { if (document.hidden && !screenCaptureActiveRef.current) lockForInactivity(); };
    document.addEventListener("visibilitychange", visibility);
    let lastActivity = Date.now();
    let lastActivitySent = 0;
    const recordActivity = () => {
      lastActivity = Date.now();
      if (lastActivity - lastActivitySent > 5_000) {
        lastActivitySent = lastActivity;
        void touchVaultActivity().catch(lockForInactivity);
      }
    };
    const activityEvents: Array<keyof WindowEventMap> = ["pointerdown", "keydown", "mousemove", "wheel", "touchstart"];
    activityEvents.forEach((event) => window.addEventListener(event, recordActivity, { passive: true }));
    const idleLock = window.setInterval(() => { if (!screenCaptureActiveRef.current && Date.now() - lastActivity >= 300_000) lockForInactivity(); }, 5_000);
    void register("CommandOrControl+Shift+L", () => { setSummary(null); setOnboardStage("unlock"); setPassword(""); void lockVault(); });
    return () => { unlisten?.(); gainedUnlisten?.(); window.clearTimeout(focusTimer); window.clearInterval(sleepTimer); window.clearInterval(idleLock); document.removeEventListener("visibilitychange", visibility); activityEvents.forEach((event) => window.removeEventListener(event, recordActivity)); };
  }, [onboardStage]);

  useEffect(() => {
    if (!isTauri()) return;
    setScreenScanSupported(true);
    const appWindow = getCurrentWindow();
    let unlistenResize: (() => void) | undefined;
    void appWindow.isMaximized().then(setWindowMaximized).catch(() => undefined);
    void appWindow.onResized(() => { void appWindow.isMaximized().then(setWindowMaximized).catch(() => undefined); }).then((fn) => { unlistenResize = fn; });
    return () => unlistenResize?.();
  }, []);

  function toggleMaximize() {
    if (!isTauri()) return;
    const appWindow = getCurrentWindow();
    void appWindow.toggleMaximize()
      .then(() => appWindow.isMaximized())
      .then(setWindowMaximized)
      .catch(fail);
  }

  function renderWindowControls() {
    if (!isTauri()) return null;
    const appWindow = getCurrentWindow();
    const runWindowAction = (action: () => Promise<void>) => {
      void action().catch(fail);
    };
    return <div className="window-controls" aria-label="Window controls">
      <button type="button" className="window-control" aria-label="Minimize" title="Minimize" onClick={() => runWindowAction(() => appWindow.minimize())}><span aria-hidden="true">-</span></button>
      <button type="button" className="window-control" aria-label={windowMaximized ? "Restore" : "Maximize"} title={windowMaximized ? "Restore" : "Maximize"} onClick={toggleMaximize}><span className={windowMaximized ? "restore-glyph" : "maximize-glyph"} aria-hidden="true" /></button>
      <button type="button" className="window-control window-control-close" aria-label="Close" title="Close" onClick={() => runWindowAction(() => appWindow.close())}><span aria-hidden="true">×</span></button>
    </div>;
  }

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 3200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const visibleTotp = useMemo(() => {
    const lower = search.trim().toLocaleLowerCase();
    const order = summary?.preferences.totp_order ?? [];
    return [...totp].sort((a, b) => { const ia = order.indexOf(a.id); const ib = order.indexOf(b.id); if (ia >= 0 && ib >= 0) return ia - ib; if (ia >= 0) return -1; if (ib >= 0) return 1; return (summary?.totp_entries.find((entry) => entry.id === a.id)?.added_at ?? 0) - (summary?.totp_entries.find((entry) => entry.id === b.id)?.added_at ?? 0); }).filter((entry) => !lower || `${entry.name} ${entry.subtitle}`.toLocaleLowerCase().includes(lower));
  }, [totp, search, summary]);
  const visibleRecovery = useMemo(() => {
    const lower = search.trim().toLocaleLowerCase();
    const order = summary?.preferences.recovery_order ?? [];
    return [...(summary?.recovery_sets ?? [])].sort((a, b) => { const ia = order.indexOf(a.id); const ib = order.indexOf(b.id); if (ia >= 0 && ib >= 0) return ia - ib; if (ia >= 0) return -1; if (ib >= 0) return 1; return a.added_at - b.added_at; }).filter((set) => !lower || `${set.name} ${set.subtitle}`.toLocaleLowerCase().includes(lower));
  }, [summary, search]);

  async function openVault() {
    setWorking(true);
    try { const data = await unlockVault(path, password); if (isTauri()) await invoke("remember_vault_path", { path }); setSummary(data); setPassword(""); setOnboardStage("ready"); notify("Vault unlocked"); }
    catch (error) { fail(error); }
    finally { setWorking(false); }
  }
  async function createVault() {
    if (password !== confirmPassword) { fail("The passwords do not match."); return; }
    setWorking(true);
    try { await setupVault(path, password); const data = await unlockVault(path, password); if (isTauri()) await invoke("remember_vault_path", { path }); setSummary(data); setPassword(""); setConfirmPassword(""); setOnboardStage("ready"); notify("Your vault is ready"); }
    catch (error) { fail(error); }
    finally { setWorking(false); }
  }
  async function lockNow() { await lockVault(); setSummary(null); setPassword(""); setConfirmPassword(""); setSearch(""); setOnboardStage("unlock"); setActiveSet(null); notify("Vault locked"); }
  async function copyCode(value: string, name: string, ask?: { codeId: string; setId: string }) {
    try {
      await copySecret(value, summary?.preferences.clear_clipboard ?? true);
      if (ask && summary?.preferences.ask_after_copy) setClipboardPrompt(ask);
      else { setCopyAskAfter(name); window.setTimeout(() => setCopyAskAfter(null), 1600); }
    } catch (error) { fail(error); }
  }
  async function updatePreference(patch: Partial<Preferences>) { if (!summary) return; const preferences = { ...summary.preferences, ...patch }; setSummary({ ...summary, preferences }); try { await updatePreferences(preferences); } catch (error) { setSummary(summary); fail(error); } }

  async function startAdd(mode: Exclude<ImportMode, null>) {
    setImportMode(mode);
    if (mode === "image") {
      try { const selected = await chooseQrImage(); if (selected) { const parsed = await importQrImage(selected); setImportMode("manual"); setPendingImport([parsed]); setAddDialog(true); } }
      catch (error) { fail(error); }
    } else if (mode === "screen") {
      setAddDialog(false);
      try {
        const parsed = await chooseScreenRegion();
        setImportMode("screen");
        if (!parsed) { setAddDialog(true); return; }
        setPendingImport([parsed]); setImportMode("manual"); setAddDialog(true);
      } catch (error) { fail(error); setImportMode("screen"); setAddDialog(true); }
    }
  }

  const [addDialog, setAddDialog] = useState(false);
  const [editTarget, setEditTarget] = useState<TotpRecord | null>(null);
  const [selectedRecoveryToEdit, setSelectedRecoveryToEdit] = useState<RecoverySet | null>(null);
  const [showRecoveryDialog, setShowRecoveryDialog] = useState(false);
  const [dragId, setDragId] = useState<string | null>(null);
  const [showMasterPasswordDialog, setShowMasterPasswordDialog] = useState(false);
  const [restoreConflicts, setRestoreConflicts] = useState<import("./authenticator").RestoreConflict[]>([]);
  const [restoreChoices, setRestoreChoices] = useState<Record<string, RestoreChoice["choice"]>>({});

  async function importFile() {
    try {
      if (!window.confirm("The selected export may contain your authenticator keys. It will be read on this device and only saved after you review the entries. Continue?")) return;
      const selected = await chooseImportFile(["json", "csv", "txt"]);
      if (!selected) return;
      const extension = selected.split(".").pop()?.toLowerCase();
      let sourcePassword: string | undefined;
      if (extension === "json") {
        sourcePassword = window.prompt("If this is an encrypted Aegis export, enter its export password. Leave blank for Bitwarden or an unencrypted Aegis export.") ?? undefined;
        if (sourcePassword === undefined) return;
        if (!sourcePassword) sourcePassword = undefined;
      }
      const parsed = await parseImportFile(selected, sourcePassword);
      setPendingImport(parsed); setImportMode("bulk"); setAddDialog(true);
    } catch (error) { fail(error); }
  }

  async function importUri(input: string) {
    try { const parsed = await parseImport("otpauth", input); setPendingImport(parsed); setImportMode("manual"); setAddDialog(true); }
    catch (error) { fail(error); }
  }

  async function submitReview(records: ImportCandidate[]) {
    setWorking(true);
    try { for (const item of records) await addTotp(item); setAddDialog(false); setPendingImport([]); setImportMode(null); refresh(); notify(records.length === 1 ? "Authenticator added" : `${records.length} authenticators added`); }
    catch (error) { fail(error); }
    finally { setWorking(false); }
  }

  async function showRecoverySet(meta: RecoverySetSummary) {
    try { setActiveSet(await getRecoverySet(meta.id)); }
    catch (error) { fail(error); }
  }

  async function toggleRecoveryCode(set: RecoverySet, codeId: string, used: boolean) {
    try { await setRecoveryCodeUsed(set.id, codeId, used); setActiveSet(await getRecoverySet(set.id)); refresh(); }
    catch (error) { fail(error); }
  }

  function askToReset(set: RecoverySet, codeId: string) {
    setDialog({ title: "Make this code usable again?", message: "The code will be marked usable. Only reset it if you still have it and it has not been used.", confirm: "Reset code", cancel: "Keep used", onConfirm: () => { void toggleRecoveryCode(set, codeId, false); setDialog(null); } });
  }

  if (onboardStage !== "ready" || !summary) {
    return <main className="app-shell onboarding-app-shell"><header className="custom-titlebar">
      <div className="titlebar-brand"><span className="titlebar-mark"><Icon name="shield" size={16} /></span><span>Offline Authenticator</span></div>
      <div className="titlebar-drag" data-tauri-drag-region onDoubleClick={toggleMaximize} />
      {renderWindowControls()}
    </header><section className="onboarding-shell"><section className="onboarding-card">
      <div className="brand-mark"><Icon name="shield" size={28} /></div>
      <div className="brand-eyebrow">OFFLINE AUTHENTICATOR</div>
      {onboardStage === "loading" && <div className="setup-copy"><h1>Opening your vault</h1><p>Keeping your keys on this device.</p></div>}
      {onboardStage === "choose-location" && <><div className="setup-copy"><h1>Choose where your vault lives.</h1><p>Pick a writable folder that is separate from the app. Your codes stay in one encrypted file and never leave this device.</p></div><label className="field-label" htmlFor="vault-location">Vault folder</label><div className="path-control"><input id="vault-location" value={path} onChange={(event) => setPath(event.target.value)} spellCheck={false} /><button className="icon-button browse-button" type="button" onClick={async () => { const folder = await chooseVaultFolder(); if (folder) setPath(`${folder.replace(/[\\/]$/, "")}\\vault.authvault`); }}>Choose</button></div><label className="check-row"><input type="checkbox" checked={portable} onChange={(event) => setPortable(event.target.checked)} /><span><strong>Portable folder</strong><small>Keep the encrypted vault beside the app. Use a folder you can write to.</small></span></label><button className="primary-button full-button" disabled={!path.trim()} onClick={async () => { try { const resolved = await resolveVaultPath(path, portable); setPath(resolved); const exists = await vaultExists(resolved); setOnboardStage(exists ? "unlock" : "setup"); } catch (error) { fail(error); } }}>{"Continue"}<Icon name="arrow" /></button></>}
      {onboardStage === "setup" && <><div className="setup-copy"><h1>Make a new vault.</h1><p>The master password encrypts this file on your computer. If it is lost, the vault cannot be opened. There is no password reset.</p></div><label className="field-label" htmlFor="master-password">Master password</label><input id="master-password" className="form-control" type="password" autoComplete="new-password" minLength={12} value={password} onChange={(event) => setPassword(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") document.getElementById("confirm-password")?.focus(); }} /><p className="field-help">{PASSCODE_HINT}</p><label className="field-label" htmlFor="confirm-password">Confirm password</label><input id="confirm-password" className="form-control" type="password" autoComplete="new-password" minLength={12} value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && !working) void createVault(); }} /><button className="primary-button full-button" disabled={working || password.length < 12 || confirmPassword.length < 12} onClick={() => void createVault()}>{working ? "Creating vaultâ€¦" : "Create vault"}<Icon name="arrow" /></button><button className="text-button back-button" onClick={() => setOnboardStage("choose-location")}><Icon name="back" /> Back to vault location</button></>}
      {onboardStage === "unlock" && <><div className="setup-copy"><h1>Welcome back.</h1><p>Your vault is locked. Enter your master password to open it.</p></div><div className="vault-path" title={path}>{path}</div><label className="field-label" htmlFor="unlock-password">Master password</label><input id="unlock-password" className="form-control" type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && !working) void openVault(); }} autoFocus /><button className="primary-button full-button" disabled={working || !password} onClick={() => void openVault()}>{working ? "Unlockingâ€¦" : "Unlock vault"}<Icon name="arrow" /></button><button className="text-button back-button" onClick={() => { setPassword(""); setOnboardStage("choose-location"); }}>Choose a different vault</button></>}
      <div className="onboarding-footnote"><Icon name="shield" size={15} /><span>Nothing is sent to a server. Your vault is only on this device.</span></div>
    </section><ToastMessage toast={toast} onClose={() => setToast(null)} /></section></main>;
  }


  return <main className="app-shell" onPointerDown={() => { if (copyAskAfter) setCopyAskAfter(null); }}>
    <header className="custom-titlebar">
      <div className="titlebar-brand" data-tauri-drag-region><span className="titlebar-mark" data-tauri-drag-region><Icon name="shield" size={16} /></span><span data-tauri-drag-region>Offline Authenticator</span></div>
      <div className="titlebar-drag" data-tauri-drag-region />
      {renderWindowControls()}
    </header>
    <header className="topbar">
      {activeSet ? <button className="top-icon" aria-label="Back to backup codes" onClick={() => setActiveSet(null)}><Icon name="back" /></button> : <div className="top-app-mark"><Icon name="shield" size={19} /></div>}
      <span className="app-title">{activeSet?.name ?? "Offline Authenticator"}</span>
      <button className="lock-action" onClick={() => void lockNow()} title="Lock vault"><Icon name="lock" size={15} /><span>Lock</span></button>
    </header>

    {activeSet ? <section className="content-area recovery-detail" key={activeSet.id}>
      <div className="section-heading detail-heading"><div><p className="eyebrow">BACKUP CODES</p><h1>{activeSet.name}</h1>{activeSet.subtitle && <p className="heading-subtitle">{activeSet.subtitle}</p>}</div><button className="icon-button subtle-button" aria-label="Edit backup set" onClick={() => { setSelectedRecoveryToEdit(activeSet); setShowRecoveryDialog(true); }}><Icon name="settings" /></button></div>
      <p className="list-intro">Each code can only be used once. Codes you've used cannot be copied.</p>
      <div className="recovery-code-list" role="list" aria-label={`${activeSet.name} backup codes`}>
        {activeSet.codes.map((code) => <RecoveryCodeRow key={code.id} code={code} onCopy={() => { if (!code.used) void copyCode(code.value, activeSet.name, { codeId: code.id, setId: activeSet.id }); }} onDoubleClick={() => { if (!code.used) { void copyCode(code.value, activeSet.name); void toggleRecoveryCode(activeSet, code.id, true); } else askToReset(activeSet, code.id); }} onKeyAction={(event) => { if ((event.key === "Enter" || event.key === " ") && !code.used) { event.preventDefault(); void copyCode(code.value, activeSet.name, { codeId: code.id, setId: activeSet.id }); } if (event.key.toLowerCase() === "u") askToReset(activeSet, code.id); }} />)}
      </div>
      {copyAskAfter && <div className="inline-success" role="status"><Icon name="check" size={15} />Copied {copyAskAfter} code</div>}
    </section> : <>
      {tab !== "settings" && <div className="search-row"><Icon name="search" size={17} /><input aria-label={`Search ${tab === "codes" ? "authenticators" : "backup-code sets"}`} placeholder={tab === "codes" ? "Search authenticators" : "Search backup-code sets"} value={search} onChange={(event) => setSearch(event.target.value)} />{search && <button aria-label="Clear search" className="clear-search" onClick={() => setSearch("")}><Icon name="close" size={15} /></button>}</div>}
      {tab === "codes" && <section className="content-area codes-area">
        <div className="section-heading"><div><p className="eyebrow">YOUR ACCOUNTS</p><h1>2FA Codes</h1><p className="heading-subtitle">Tap a code to copy it. It refreshes every 30 seconds.</p></div><button className="add-button" aria-label="Add authenticator" onClick={() => { setEditTarget(null); setPendingImport([]); setImportMode(null); setAddDialog(true); }}><Icon name="add" size={19} /></button></div>
        {visibleTotp.length ? <div className="totp-list" aria-label="Authenticator codes">{visibleTotp.map((entry,index)=><TotpRow key={entry.id} entry={entry} index={index} canMove={visibleTotp.length>1} copied={copyAskAfter===entry.name} onCopy={()=>void copyCode(entry.code.replace(/\s/g,""),entry.name)} onEdit={()=>{const record=summary.totp_entries.find((item)=>item.id===entry.id);if(record){setEditTarget(record);setPendingImport([]);setImportMode("manual");setAddDialog(true);}}} onDelete={()=>setDialog({title:`Remove ${entry.name}?`,message:"This authenticator will be removed from the encrypted vault. You cannot undo this change.",confirm:"Remove authenticator",cancel:"Keep it",destructive:true,onConfirm:async()=>{await deleteTotp(entry.id);setDialog(null);refresh();notify("Authenticator removed");}})} onMove={(direction)=>{const ids=visibleTotp.map((item)=>item.id);const next=index+direction;if(next<0||next>=ids.length)return;[ids[index],ids[next]]=[ids[next]!,ids[index]!];void reorderTotp(ids).then(refresh).catch(fail);}} onDragStart={()=>setDragId(entry.id)} onDrop={()=>{if(dragId&&dragId!==entry.id){const ids=visibleTotp.map((item)=>item.id);const from=ids.indexOf(dragId);const to=ids.indexOf(entry.id);const [moved]=ids.splice(from,1);ids.splice(to,0,moved!);void reorderTotp(ids).then(refresh).catch(fail);}setDragId(null);}} />)}</div> : search ? <EmptyState icon="search" title="No matches" copy="Try a different name or account label." /> : <EmptyState icon="codes" title="Your codes live here." copy="Start with an authenticator entry, or import the accounts you already use." actions={<><button className="primary-button" onClick={()=>{setEditTarget(null);setPendingImport([]);setImportMode(null);setAddDialog(true);}}><Icon name="add"/>Add new codes</button><button className="secondary-button" onClick={()=>void importFile()}><Icon name="file"/>Import existing</button></>} />}
        {visibleTotp.length>0&&<button className="add-row-button" onClick={()=>{setEditTarget(null);setPendingImport([]);setImportMode(null);setAddDialog(true);}}><Icon name="add" size={18}/>Add a code</button>}
      </section>}
      {tab === "backup" && <section className="content-area codes-area">
        <div className="section-heading"><div><p className="eyebrow">SAFE AND READY</p><h1>Backup Codes</h1><p className="heading-subtitle">One-time codes for getting back into your accounts.</p></div><button className="add-button" aria-label="Add recovery-code set" onClick={()=>{setSelectedRecoveryToEdit(null);setShowRecoveryDialog(true);}}><Icon name="add" size={19}/></button></div>
        {visibleRecovery.length? <div className="recovery-set-list">{visibleRecovery.map((set,index)=><RecoverySetRow key={set.id} set={set} index={index} onOpen={()=>void showRecoverySet(set)} onEdit={()=>void getRecoverySet(set.id).then((item)=>{setSelectedRecoveryToEdit(item);setShowRecoveryDialog(true);}).catch(fail)} onDelete={()=>setDialog({title:`Remove ${set.name}?`,message:"This deletes the stored backup codes from the vault.",confirm:"Remove code set",cancel:"Keep it",destructive:true,onConfirm:async()=>{await deleteRecoverySet(set.id);setDialog(null);setActiveSet(null);refresh();notify("Backup-code set removed");}})} onMove={(direction)=>{const ids=visibleRecovery.map((item)=>item.id);const next=index+direction;if(next<0||next>=ids.length)return;[ids[index],ids[next]]=[ids[next]!,ids[index]!];void reorderRecoverySets(ids).then(refresh).catch(fail);}} onDragStart={()=>setDragId(set.id)} onDrop={()=>{if(dragId&&dragId!==set.id){const ids=visibleRecovery.map((item)=>item.id);const from=ids.indexOf(dragId);const to=ids.indexOf(set.id);const [moved]=ids.splice(from,1);ids.splice(to,0,moved!);void reorderRecoverySets(ids).then(refresh).catch(fail);}setDragId(null);}}/> )}</div> : search?<EmptyState icon="search" title="No matches" copy="Try searching for a different account."/>:<EmptyState icon="backup" title="Keep a way back in." copy="Save the one-time codes your accounts give you, so you're ready if you lose access." actions={<button className="primary-button" onClick={()=>{setSelectedRecoveryToEdit(null);setShowRecoveryDialog(true);}}><Icon name="add"/>Add backup codes</button>}/>}
        {visibleRecovery.length>0&&<button className="add-row-button" onClick={()=>{setSelectedRecoveryToEdit(null);setShowRecoveryDialog(true);}}><Icon name="add" size={18}/>Add a backup-code set</button>}
      </section>}
      {tab === "settings" && <SettingsPanel summary={summary} vaultPath={path} portable={portable} onToggle={(key,value)=>void updatePreference({[key]:value})} onAppearance={(appearance)=>void updatePreference({appearance})} onAddAccount={()=>void importFile()} onChangePassword={()=>setShowMasterPasswordDialog(true)} onBackup={()=>void handleExportVault()} onRestore={()=>void handleRestore()} onPickCamera={(deviceId)=>void updatePreference({camera_device_id:deviceId})} onChooseLocation={()=>void handleVaultLocation()} fail={fail} />}
    </>}

    <nav className="bottom-nav" aria-label="Main tabs">{NAVIGATION.map((item)=><button key={item.key} className={`nav-item ${tab===item.key?"is-active":""}`} aria-current={tab===item.key?"page":undefined} onClick={()=>{setActiveSet(null);setTab(item.key);setSearch("");}}><Icon name={item.key===tab?item.icon:""} size={20}/><span>{item.label}</span></button>)}</nav>
    {addDialog && <Modal title={editTarget?"Edit authenticator":importMode === "bulk" ? "Review your accounts" : "Add a 2FA code"} subtitle={importMode === "bulk" ? `${pendingImport.length} accounts found. Check each label before saving.` : "The code key stays in your encrypted vault."} onClose={()=>{setAddDialog(false);setImportMode(null);setPendingImport([]);setEditTarget(null);}}><AddTotpForm initial={editTarget ? [{...editTarget, secret: ""}] : pendingImport} mode={importMode} working={working} onMode={(mode)=>setImportMode(mode)} onImportFile={()=>void importFile()} onChooseImage={()=>void startAdd("image")} onScreenScan={()=>void startAdd("screen")} onPasteLink={(value)=>void importUri(value)} onReview={(records)=>{if(editTarget){void handleUpdateTotp(records[0]!);}else{void submitReview(records);}}} onRemove={(index)=>setPendingImport((items)=>items.filter((_,itemIndex)=>itemIndex!==index))} onStopCamera={stopCamera} screenScanSupported={screenScanSupported}/></Modal>}
    {showRecoveryDialog && <Modal title={selectedRecoveryToEdit ? "Edit backup codes" : "Add backup codes"} subtitle="Paste a full list or enter each code on its own line." onClose={()=>{setShowRecoveryDialog(false);setSelectedRecoveryToEdit(null);}}><RecoverySetForm initial={selectedRecoveryToEdit} working={working} onSave={async(input)=>{setWorking(true);try{if(selectedRecoveryToEdit){const updated={...selectedRecoveryToEdit,name:input.name,subtitle:input.subtitle,codes:input.codes.map((value,index)=>selectedRecoveryToEdit.codes[index]??{id:crypto.randomUUID(),value,used:false,added_at:Date.now()/1000})};await updateRecoverySet(updated);}else{await addRecoverySet(input);}setShowRecoveryDialog(false);setSelectedRecoveryToEdit(null);refresh();notify("Backup codes saved");}catch(error){fail(error);}finally{setWorking(false);}}} /></Modal>}
    {clipboardPrompt && <Dialog title="Did you use this code?" message="The code was copied. Mark it as used if you signed in with it." confirm="Yes, mark used" cancel="No, keep usable" onConfirm={()=>{void toggleRecoveryCode(activeSet!,clipboardPrompt.codeId,true);setClipboardPrompt(null);}} onCancel={()=>setClipboardPrompt(null)}/>}
    {dialog && <Dialog title={dialog.title} message={dialog.message} confirm={dialog.confirm} cancel={dialog.cancel} destructive={dialog.destructive} onConfirm={dialog.onConfirm??(()=>setDialog(null))} onCancel={()=>setDialog(null)}/>}
    {restoreConflicts.length > 0 && <Modal title="Review backup conflicts" subtitle="Choose what to do with each matching record. Other records will be added after you confirm." onClose={() => { setRestoreConflicts([]); setRestoreChoices({}); }}><div className="restore-conflict-list">{restoreConflicts.map((conflict) => <article className="restore-conflict" key={conflict.id}><h3>{conflict.kind === "totp" ? "Authenticator" : "Backup-code set"}</h3><div className="conflict-comparison"><div><strong>Current: {conflict.current_name}</strong><small>{conflict.current_subtitle} · {conflict.current_detail}</small></div><div><strong>Backup: {conflict.imported_name}</strong><small>{conflict.imported_subtitle} · {conflict.imported_detail}</small></div></div><label className="field-label" htmlFor={`restore-choice-${conflict.id}`}>Action</label><select id={`restore-choice-${conflict.id}`} value={restoreChoices[conflict.id] ?? ""} onChange={(event) => setRestoreChoices((items) => ({ ...items, [conflict.id]: event.target.value as RestoreChoice["choice"] }))}><option value="">Choose an action</option><option value="keep current">Keep current</option><option value="replace">Replace with backup</option><option value="keep both">Keep both</option><option value="skip">Skip this entry</option></select></article>)}</div><div className="modal-form-actions"><button className="primary-button" disabled={restoreConflicts.some((item) => !restoreChoices[item.id])} onClick={async () => { try { await applyRestoreConflicts(restoreConflicts.map((item) => ({ id: item.id, choice: restoreChoices[item.id]! }))); setRestoreConflicts([]); setRestoreChoices({}); refresh(); notify("Backup restored"); } catch (error) { fail(error); } }}>Apply choices</button></div></Modal>}
    {showMasterPasswordDialog && <Modal title="Change master password" subtitle="The vault will be encrypted again with the new password." onClose={()=>setShowMasterPasswordDialog(false)}><ChangePasswordForm working={working} onSave={async(current,next)=>{setWorking(true);try{await changeMasterPassword(current,next);setShowMasterPasswordDialog(false);notify("Master password changed");}catch(error){fail(error);}finally{setWorking(false);}}}/></Modal>}
    <ToastMessage toast={toast} onClose={()=>setToast(null)}/>
  </main>;

  async function handleUpdateTotp(candidate: ImportCandidate) { if (!editTarget) return; setWorking(true); try { await updateTotp({...editTarget,...candidate,secret:(candidate.secret||"")}); setAddDialog(false);setEditTarget(null);setPendingImport([]);refresh();notify("Authenticator updated");}catch(error){fail(error);}finally{setWorking(false);} }
  async function handleExportVault(){try{const destination=await chooseBackupPath("vault-backup.authvault");if(!destination)return;await exportVault(destination);notify("Encrypted backup saved");}catch(error){fail(error);}}
  async function handleRestore(){try{    const selected = await chooseImportFile(["authvault"]);if(!selected)return;const pass=window.prompt("Enter the password used for this backup.");if(!pass)return;const conflicts=await restoreVault(selected,pass);if(conflicts.length){setRestoreConflicts(conflicts);setRestoreChoices({});}else{refresh();notify("Backup restored");}}catch(error){fail(error);}}
  async function handleVaultLocation(){const folder=await chooseVaultFolder();if(folder){fail("Vault relocation is not available yet. Export an encrypted backup, create a vault in the new folder, and restore it there.");}}
  async function stopCamera(){mediaStreamRef.current?.getTracks().forEach((track)=>track.stop());mediaStreamRef.current=null;}
}

function ToastMessage({toast,onClose}:{toast:Toast|null;onClose:()=>void}){if(!toast)return null;return <div className={`toast toast-${toast.tone??"success"}`} role={toast.tone==="error"?"alert":"status"}><Icon name={toast.tone==="error"?"warning":"check"} size={16}/><span>{toast.message}</span><button className="toast-close" aria-label="Dismiss message" onClick={onClose}><Icon name="close" size={14}/></button></div>;}
function EmptyState({icon,title,copy,actions}:{icon:string;title:string;copy:string;actions?:React.ReactNode}){return <div className="empty-state"><div className="empty-art"><span className="art-ring ring-one"/><span className="art-ring ring-two"/><span className="art-center"><Icon name={icon} size={27}/></span><span className="art-dot dot-one"/><span className="art-dot dot-two"/></div><h2>{title}</h2><p>{copy}</p>{actions&&<div className="empty-actions">{actions}</div>}</div>;}

function TotpRow({entry,index:_index,canMove:_canMove,copied,onCopy,onEdit,onDelete,onMove,onDragStart,onDrop}:{entry:TotpDisplay;index:number;canMove:boolean;copied:boolean;onCopy:()=>void;onEdit:()=>void;onDelete:()=>void;onMove:(direction:number)=>void;onDragStart:()=>void;onDrop:()=>void}){const [menuOpen,setMenuOpen]=useState(false);const progress=entry.remaining_seconds/30;const circumference=2*Math.PI*10;return <div className="totp-row-wrap" draggable onDragStart={onDragStart} onDragOver={(event)=>event.preventDefault()} onDrop={onDrop}><button className={`totp-row ${copied?"copied":""}`} onClick={onCopy} aria-label={`Copy ${entry.name} code ${entry.code.replace(/\s/g,"")}, ${entry.remaining_seconds} seconds remaining`}><span className="service-dot" aria-hidden="true">{entry.name.slice(0,1).toUpperCase()}</span><span className="account-details"><strong>{entry.name}</strong><span>{entry.subtitle || "Authenticator entry"}{entry.has_recovery_set&&<span className="recovery-marker" title="Has backup codes" aria-label="Has backup codes"><Icon name="key" size={12}/></span>}</span></span><span className="code-wrap"><span className="totp-code">{entry.code}</span><span className="code-bottom"><span className="countdown-ring" aria-label={`${entry.remaining_seconds} seconds remaining`}><svg viewBox="0 0 24 24"><circle className="ring-track" cx="12" cy="12" r="10"/><circle className="ring-progress" cx="12" cy="12" r="10" strokeDasharray={circumference} strokeDashoffset={circumference*(1-progress)}/></svg></span><span>{entry.remaining_seconds}s</span></span></span></button><div className="row-actions"><button className="drag-handle" title="Move authenticator" aria-label={`Reorder ${entry.name}`} onClick={(event)=>{event.stopPropagation();setMenuOpen(!menuOpen);}}><Icon name="drag" size={17}/></button>{menuOpen&&<div className="row-menu"><button onClick={()=>{onMove(-1);setMenuOpen(false);}}>Move up</button><button onClick={()=>{onMove(1);setMenuOpen(false);}}>Move down</button><button onClick={()=>{onEdit();setMenuOpen(false);}}>Edit</button><button className="danger-text" onClick={()=>{onDelete();setMenuOpen(false);}}>Remove</button></div>}<button className="edit-row-button" aria-label={`Edit ${entry.name}`} onClick={onEdit}><Icon name="settings" size={15}/></button></div></div>;}
function RecoverySetRow({set,index:_index,onOpen,onEdit,onDelete,onMove,onDragStart,onDrop}:{set:RecoverySetSummary;index:number;onOpen:()=>void;onEdit:()=>void;onDelete:()=>void;onMove:(direction:number)=>void;onDragStart:()=>void;onDrop:()=>void}){const[menuOpen,setMenuOpen]=useState(false);return <div className="recovery-set-wrap" draggable onDragStart={onDragStart} onDragOver={(event)=>event.preventDefault()} onDrop={onDrop}><button className="recovery-set-row" onClick={onOpen}><span className="backup-icon"><Icon name="key" size={18}/></span><span className="account-details"><strong>{set.name}</strong><span>{set.subtitle||"Recovery codes"}</span></span><span className="code-count"><b>{set.available_count}</b><small>left</small></span><Icon name="arrow" size={17}/></button><button className="drag-handle set-drag" title="Reorder backup-code set" aria-label={`Reorder ${set.name}`} onClick={()=>setMenuOpen(!menuOpen)}><Icon name="drag" size={17}/></button>{menuOpen&&<div className="row-menu set-menu"><button onClick={()=>{onMove(-1);setMenuOpen(false);}}>Move up</button><button onClick={()=>{onMove(1);setMenuOpen(false);}}>Move down</button><button onClick={()=>{onEdit();setMenuOpen(false);}}>Edit</button><button className="danger-text" onClick={()=>{onDelete();setMenuOpen(false);}}>Remove</button></div>}</div>;}
function RecoveryCodeRow({code,onCopy,onDoubleClick,onKeyAction}:{code:RecoverySet["codes"][number];onCopy:()=>void;onDoubleClick:()=>void;onKeyAction:(event:React.KeyboardEvent<HTMLButtonElement>)=>void}){const timer=useRef<number|null>(null);const[menuOpen,setMenuOpen]=useState(false);return <div className={`recovery-code-row ${code.used?"code-used":""}`} onContextMenu={(event)=>{event.preventDefault();setMenuOpen(!menuOpen);}}><button className="recovery-code-button" onClick={onCopy} onDoubleClick={(event)=>{event.preventDefault();onDoubleClick();}} onKeyDown={onKeyAction} onPointerDown={()=>{if(code.used)timer.current=window.setTimeout(()=>{onDoubleClick();},650);}} onPointerUp={()=>{if(timer.current)window.clearTimeout(timer.current);}} onPointerLeave={()=>{if(timer.current)window.clearTimeout(timer.current);}} aria-label={`${code.used?"Used":"Usable"} backup code. ${code.used?"Press and hold to reset":"Double click to copy and mark used"}`} disabled={code.used}><span className="status-pip"/><code>{code.used?"â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢":code.value}</code><span className={`code-status-text ${code.used?"used-label":"usable-label"}`}>{code.used?"Used":"Usable"}</span>{!code.used&&<Icon name="copy" size={15}/>}</button>{code.used&&<button className="reset-code-button" aria-label="Reset used code" onClick={onDoubleClick}>Reset</button>}{menuOpen&&<div className="row-menu code-menu">{code.used?<button onClick={()=>{onDoubleClick();setMenuOpen(false);}}>Reset to usable</button>:<><button onClick={()=>{onCopy();setMenuOpen(false);}}>Copy code</button><button onClick={()=>{onDoubleClick();setMenuOpen(false);}}>Copy and mark used</button></>}</div>}</div>;}
function Modal({title,subtitle,children,onClose}:{title:string;subtitle?:string;children:React.ReactNode;onClose:()=>void}){useEffect(()=>{function onKeyDown(event:KeyboardEvent){if(event.key==="Escape")onClose();}window.addEventListener("keydown",onKeyDown);return()=>window.removeEventListener("keydown",onKeyDown);},[onClose]);return <div className="modal-backdrop" role="presentation" onMouseDown={(event)=>{if(event.target===event.currentTarget)onClose();}}><section className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="dialog-heading"><div className="modal-header"><div><h2 id="dialog-heading">{title}</h2>{subtitle&&<p>{subtitle}</p>}</div><button className="icon-button" aria-label="Close" onClick={onClose}><Icon name="close" size={17}/></button></div>{children}</section></div>;}
function Dialog({title,message,confirm,cancel,destructive,onConfirm,onCancel}:{title:string;message:string;confirm?:string;cancel?:string;destructive?:boolean;onConfirm:()=>void;onCancel:()=>void}){return <div className="modal-backdrop"><section className="confirm-dialog" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" aria-describedby="confirm-message"><div className={`confirm-icon ${destructive?"warning-icon":""}`}><Icon name={destructive?"warning":"key"}/></div><h2 id="confirm-title">{title}</h2><p id="confirm-message">{message}</p><div className="dialog-actions"><button className="secondary-button" onClick={onCancel}>{cancel??"Cancel"}</button><button className={`primary-button ${destructive?"danger-button":""}`} onClick={onConfirm}>{confirm??"Confirm"}</button></div></section></div>;}
function SettingsPanel({summary,vaultPath,portable,onToggle,onAppearance,onAddAccount,onChangePassword,onBackup,onRestore,onPickCamera,onChooseLocation,fail}: {summary:VaultSummary; vaultPath:string; portable:boolean; onToggle:(key:"ask_after_copy"|"clear_clipboard",value:boolean)=>void; onAppearance:(value:Preferences["appearance"])=>void; onAddAccount:()=>void; onChangePassword:()=>void; onBackup:()=>void; onRestore:()=>void; onPickCamera:(device:string|null)=>void; onChooseLocation:()=>void; fail:(error:unknown)=>void}): React.ReactElement {const [devices,setDevices]=useState<MediaDeviceInfo[]>([]);const [showDevices,setShowDevices]=useState(false);async function loadDevices(){try{if(!navigator.mediaDevices?.enumerateDevices)throw new Error("Camera selection requires the desktop app.");const all=await navigator.mediaDevices.enumerateDevices();setDevices(all.filter((device)=>device.kind==="videoinput"));setShowDevices(true);}catch(error){fail(error);}}return <section className="content-area settings-area"><div className="section-heading"><div><p className="eyebrow">PRIVATE BY DESIGN</p><h1>Settings</h1><p className="heading-subtitle">Change how your vault works.</p></div></div><div className="settings-group"><h2>Appearance</h2><div className="appearance-options" role="radiogroup" aria-label="Appearance">{(["system","light","dark"] as const).map((value)=><button key={value} role="radio" aria-checked={summary.preferences.appearance===value} className={`appearance-button ${summary.preferences.appearance===value?"selected":""}`} onClick={()=>onAppearance(value)}><Icon name={value==="dark"?"moon":value==="light"?"sun":"settings"} size={17}/><span>{value[0]!.toUpperCase()+value.slice(1)}</span></button>)}</div></div><div className="settings-group"><h2>Copy and locking</h2><SettingToggle label="Ask after copying a backup code" copy="Mark each code as used only after you say it was." checked={summary.preferences.ask_after_copy} onChange={(value)=>onToggle("ask_after_copy",value)}/><SettingToggle label="Clear copied codes after 30 seconds" copy="Only clear the clipboard if it still holds the code you copied here." checked={summary.preferences.clear_clipboard} onChange={(value)=>onToggle("clear_clipboard",value)}/><div className="setting-row"><span><strong>Auto-lock</strong><small>After 5 minutes away from the app.</small></span><span className="setting-value">On</span></div></div><div className="settings-group"><h2>Back up and import</h2><button className="settings-action" onClick={onAddAccount}><Icon name="file"/><span><strong>Import accounts</strong><small>Bring in TOTP keys from another app.</small></span><Icon name="arrow"/></button><button className="settings-action" onClick={onBackup}><Icon name="shield"/><span><strong>Export encrypted backup</strong><small>Save a password-protected copy.</small></span><Icon name="arrow"/></button><button className="settings-action" onClick={onRestore}><Icon name="backup"/><span><strong>Restore backup</strong><small>Review and restore a saved copy.</small></span><Icon name="arrow"/></button></div><div className="settings-group"><h2>Privacy and security</h2><button className="settings-action" onClick={onChangePassword}><Icon name="key"/><span><strong>Change master password</strong><small>Re-encrypt your vault with a new password.</small></span><Icon name="arrow"/></button><div className="setting-row vault-location-setting"><span><strong>Vault location</strong><small title={vaultPath}>{vaultPath}</small></span><button className="small-action" onClick={onChooseLocation}>Change</button></div><p className="security-note"><Icon name="shield" size={15}/><span>Codes stay on this device. The app does not use an account, send telemetry or call a server.</span></p></div><div className="settings-group"><h2>Camera</h2><button className="settings-action" onClick={()=>void loadDevices()}><Icon name="camera"/><span><strong>Remember a camera</strong><small>Camera is only on while you scan.</small></span><Icon name="arrow"/></button>{showDevices&&<div className="device-picker"><button onClick={()=>onPickCamera(null)} aria-current={!summary.preferences.camera_device_id}>No saved camera</button>{devices.map((device,index)=><button key={device.deviceId} onClick={()=>onPickCamera(device.deviceId)} aria-current={summary.preferences.camera_device_id===device.deviceId}>{device.label||`Camera ${index+1}`}</button>)}{devices.length===0&&<p>No camera devices found.</p>}</div>}</div><p className="settings-build">{portable?"Portable copy":"Installed copy"} · encrypted vault</p></section>;}
function SettingToggle({label,copy,checked,onChange}:{label:string;copy:string;checked:boolean;onChange:(value:boolean)=>void}){return <label className="setting-row toggle-setting"><span><strong>{label}</strong><small>{copy}</small></span><input type="checkbox" checked={checked} onChange={(event)=>onChange(event.target.checked)}/></label>;}
function AddTotpForm({initial,mode,working,onMode,onImportFile,onChooseImage,onScreenScan,onPasteLink,onReview,onRemove,onStopCamera,screenScanSupported}:{initial:ImportCandidate[];mode:ImportMode;working:boolean;onMode:(mode:ImportMode)=>void;onImportFile:()=>void;onChooseImage:()=>void;onScreenScan:()=>void;onPasteLink:(value:string)=>void;onReview:(records:ImportCandidate[])=>void;onRemove:(index:number)=>void;onStopCamera:()=>Promise<void>;screenScanSupported:boolean}){const[rows,setRows]=useState<ImportCandidate[]>(initial.length?initial:[{name:"",subtitle:"",secret:"",algorithm:"sha1",digits:6,period:30}]);const[link,setLink]=useState("");const[cameraError,setCameraError]=useState("");const[scanning,setScanning]=useState(false);const video=useRef<HTMLVideoElement|null>(null);const stream=useRef<MediaStream|null>(null);const raf=useRef<number>(0);const canvas=useRef<HTMLCanvasElement|null>(null);useEffect(()=>{setRows(initial.length?initial:[{name:"",subtitle:"",secret:"",algorithm:"sha1",digits:6,period:30}]);},[initial]);useEffect(()=>{if(mode!=="camera")void stop();return()=>{stream.current?.getTracks().forEach((track)=>track.stop());};},[mode]);async function stop(){stream.current?.getTracks().forEach((track)=>track.stop());stream.current=null;await onStopCamera();setScanning(false);}async function start(){if(!navigator.mediaDevices?.getUserMedia){setCameraError("Camera access is not available in this preview.");return;}try{stream.current=await navigator.mediaDevices.getUserMedia({video:{facingMode:"environment"},audio:false});if(video.current){video.current.srcObject=stream.current;await video.current.play();setScanning(true);void scanFrame();}}catch(error){setCameraError(error instanceof Error&&error.name==="NotAllowedError"?"Camera access was denied. Allow it in Windows Settings, then try again.":"No camera was found. Connect a camera and try again.");}}async function scanFrame(){if(!video.current||!canvas.current||!stream.current)return;const frame=video.current;if(frame.readyState>=2){canvas.current.width=frame.videoWidth;canvas.current.height=frame.videoHeight;const context=canvas.current.getContext("2d");context?.drawImage(frame,0,0);const image=context?.getImageData(0,0,canvas.current.width,canvas.current.height);const qr=image?QRScanner.default(image.data,image.width,image.height,{inversionAttempts:"dontInvert"}):null;if(qr?.data?.startsWith("otpauth://")){await stop();onPasteLink(qr.data);return;}}raf.current=window.requestAnimationFrame(()=>void scanFrame());}function update(index:number,patch:Partial<ImportCandidate>){setRows((items)=>items.map((item,itemIndex)=>itemIndex===index?{...item,...patch}:item));}function addBlank(){setRows((items)=>[...items,{name:"",subtitle:"",secret:"",algorithm:"sha1",digits:6,period:30}]);}function save(){const ready=rows.filter((row)=>row.name.trim()&&row.secret.trim());if(ready.length!==rows.length){setCameraError("Add a name and shared key to each account before saving.");return;}onReview(ready);}return <div className="add-form">          <div className="import-tabs" role="tablist" aria-label="Add authenticator method">{[{key:"manual",label:"Manual"},{key:"link",label:"Link"},{key:"image",label:"QR image"},{key:"camera",label:"Camera"},{key:"screen",label:"Screen"}].map((item)=><button role="tab" aria-selected={(mode??"manual")===item.key} className={(mode??"manual")===item.key?"selected":""} key={item.key} onClick={()=>onMode(item.key as ImportMode)}>{item.label}</button>)}</div>{mode==="bulk"&&<div className="review-banner"><Icon name="shield" size={17}/><span>Source exports can contain all of your code keys. They are read locally and stored in the vault only after you save.</span></div>}{(mode===null||mode==="manual"||mode==="bulk")&&rows.map((item,index)=><div className="import-account" key={`${index}-${item.name}`}><div className="import-account-heading"><span>Account {index+1}</span>{rows.length>1&&<button className="remove-account" onClick={()=>onRemove(index)} aria-label={`Remove account ${index+1}`}><Icon name="close" size={14}/></button>}</div><div className="form-field"><label>Name</label><input value={item.name} onChange={(event)=>update(index,{name:event.target.value})} placeholder="GitHub" autoFocus={index===0&&mode!=="bulk"}/></div><div className="form-field"><label>Account or email <span>Optional</span></label><input value={item.subtitle} onChange={(event)=>update(index,{subtitle:event.target.value})} placeholder="you@example.com"/></div><div className="form-field"><label>Shared key</label><input value={item.secret} onChange={(event)=>update(index,{secret:event.target.value.toUpperCase()})} placeholder="PASTE YOUR SHARED KEY" autoCapitalize="characters" spellCheck={false}/><small>Found in your account's 2FA setup screen.</small></div><details className="advanced-settings"><summary>Advanced code settings</summary><div className="advanced-grid"><label>Algorithm<select value={item.algorithm} onChange={(event)=>update(index,{algorithm:event.target.value as Algorithm})}>{ALGORITHMS.map((algorithm)=><option value={algorithm.value} key={algorithm.value}>{algorithm.label}</option>)}</select></label><label>Digits<select value={item.digits} onChange={(event)=>update(index,{digits:Number(event.target.value)})}><option value={6}>6 digits</option><option value={7}>7 digits</option><option value={8}>8 digits</option></select></label><label>Period in seconds<input type="number" min="1" max="300" value={item.period} onChange={(event)=>update(index,{period:Number(event.target.value)})}/></label></div></details></div>)}{mode==="manual"&&<button className="text-button add-another" onClick={addBlank}><Icon name="add" size={15}/>Add another code</button>}{mode==="link"&&<div className="form-field"><label>Authenticator link</label><textarea value={link} onChange={(event)=>setLink(event.target.value)} placeholder="otpauth://totp/Service:account?..." rows={4}/><button className="secondary-button full-button" onClick={()=>onPasteLink(link)}>Review this code</button></div>}{mode==="image"&&<div className="scan-panel"><div className="scan-icon"><Icon name="file" size={25}/></div><h3>Read a QR code image</h3><p>Choose a saved QR image. The code will be shown for review before it is added.</p><button className="secondary-button" onClick={onChooseImage}><Icon name="file"/>Choose image</button></div>}{mode==="screen"&&<div className="scan-panel"><div className="scan-icon"><Icon name="codes" size={25}/></div><h3>Scan a QR on your screen</h3><p>We capture the screen only after this panel is hidden. Choose the part of the screen that shows the QR.</p><button className="secondary-button" disabled={!screenScanSupported} onClick={onScreenScan}>{screenScanSupported?"Start screen scan":"Available in the desktop app"}</button></div>}{mode==="camera"&&<div className="camera-panel"><video ref={video} muted playsInline aria-label="Live camera preview"/><canvas ref={canvas} hidden/><div className="camera-status">{scanning?"Point your camera at a TOTP QR code":"Camera stays off until you start scanning."}</div>{cameraError&&<p className="inline-error" role="alert">{cameraError}</p>}{scanning?<button className="secondary-button full-button" onClick={()=>void stop()}>Stop camera</button>:<button className="secondary-button full-button" onClick={()=>void start()}><Icon name="camera"/>Start camera</button>}<span className="field-help">The camera stops when you leave this screen.</span></div>}{cameraError&&mode!=="camera"&&<p className="inline-error" role="alert">{cameraError}</p>}<div className="modal-form-actions"><button className="primary-button" disabled={working||mode==="link"||mode==="image"||mode==="camera"||mode==="screen"} onClick={save}>{working?"Savingâ€¦":rows.length>1?"Review and save":"Save authenticator"}</button></div>{mode==="bulk"&&<button className="text-button bulk-import-trigger" onClick={onImportFile}>Choose a different export</button>}</div>;}
function RecoverySetForm({initial,working,onSave}:{initial:RecoverySet|null;working:boolean;onSave:(input:{name:string;subtitle:string;codes:string[]})=>void}){const[name,setName]=useState(initial?.name??"");const[subtitle,setSubtitle]=useState(initial?.subtitle??"");const[lines,setLines]=useState(initial?.codes.map((code)=>code.value).join("\n")??"");const[review,setReview]=useState(false);const codes=useMemo(()=>lines.split(/\r?\n/).map((line)=>line.trim()).filter(Boolean),[lines]);const duplicates=codes.length!==new Set(codes).size;return <div className="recovery-form"><div className="form-field"><label>Account name</label><input value={name} onChange={(event)=>setName(event.target.value)} placeholder="Amazon Web Services" autoFocus/></div><div className="form-field"><label>Subtitle <span>Optional</span></label><input value={subtitle} onChange={(event)=>setSubtitle(event.target.value)} placeholder="Root account"/></div><div className="form-field"><label>Recovery codes</label><textarea rows={7} value={lines} onChange={(event)=>{setLines(event.target.value);setReview(false);}} placeholder={"Paste one code on each line\n1234-5678-90ab\nabcd-efgh-ijkl"} spellCheck={false}/><small>Lines are only saved to the encrypted vault after you review them.</small></div>{duplicates&&<p className="inline-error">Remove repeated codes before saving.</p>}{review&&<div className="review-banner"><Icon name="check" size={17}/><span>{codes.length} codes are ready to save. Check the list above, then confirm.</span></div>}<div className="form-footer"><span>{codes.length} codes</span><button className="primary-button" disabled={working||!name.trim()||!codes.length||duplicates} onClick={()=>{if(!review){setReview(true);return;}onSave({name:name.trim(),subtitle:subtitle.trim(),codes});}}>{working?"Savingâ€¦":review?"Save recovery codes":"Review codes"}</button></div></div>;}
function ChangePasswordForm({working,onSave}:{working:boolean;onSave:(current:string,next:string)=>void}){const[current,setCurrent]=useState("");const[next,setNext]=useState("");const[confirm,setConfirm]=useState("");return <form className="password-change-form" onSubmit={(event)=>{event.preventDefault();if(next!==confirm)return;onSave(current,next);}}><div className="form-field"><label>Current password</label><input type="password" autoComplete="current-password" value={current} onChange={(event)=>setCurrent(event.target.value)} autoFocus/></div><div className="form-field"><label>New password</label><input type="password" autoComplete="new-password" minLength={12} value={next} onChange={(event)=>setNext(event.target.value)}/><small>12 or more characters, no spaces.</small></div><div className="form-field"><label>Confirm new password</label><input type="password" autoComplete="new-password" value={confirm} onChange={(event)=>setConfirm(event.target.value)}/></div>{next&&confirm&&next!==confirm&&<p className="inline-error">The passwords do not match.</p>}<div className="modal-form-actions"><button className="primary-button" disabled={working||next.length<12||next!==confirm}>{working?"Changingâ€¦":"Change password"}</button></div></form>;}
