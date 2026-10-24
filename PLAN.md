# Implementation Plan: Local Windows Authenticator

## Goal and target

Create a greenfield, offline-first authenticator desktop app in the workspace root. Target Windows 10/11 x64, with an installable package and a separate portable ZIP or folder.

The app uses Rust for application logic, vault storage, cryptography, OTP generation, and import handling. A locally bundled web UI runs inside Tauri. The app has no user account, hosted service, telemetry, or app-originated network requests.

**Proposed stack:** Tauri v2, a Rust core and commands, and a bundled local TypeScript/Vite UI. React is a reasonable choice for the multi-view interface, but the UI framework is not a user-specified requirement. Sensitive vault and credential operations stay in Rust.

The product name is temporary until branding is chosen.

## Main window and visual system

- Fixed portrait window, approximately 390 × 760 px of content, and not maximizable.
- Lists scroll while the bottom navigation remains fixed.
- Exactly three bottom tabs: **2FA Codes**, **Backup Codes**, and **Settings**.
- Quiet, high-legibility utility design that follows Windows light/dark appearance, with a Settings override if practical.
- Use long horizontal rows rather than nested cards.
- Provide clear focus states, sufficient contrast, and screen-reader names.
- Proposed palette:
  - Porcelain: `#F4F6F8`
  - White: `#FFFFFF`
  - Ink: `#1D2733`
  - Muted slate: `#647386`
  - Calm blue: `#5B7599`
  - Usable green: `#2F7A57`
  - Used red: `#B54747`
- Always pair semantic colors with text or icon labels.
- Use Segoe UI or the system sans-serif for interface text, and a clear fixed-width numeric face for live OTPs.
- Keep system typefaces and palette local; use no remote fonts or assets.

```text
┌────────────────────────────┐
│ Temporary app name     Lock│
│ Search…                   +│
│                            │
│ [Name                 123456│
│  email / account       timer│
│                            │
│     scrollable rows        │
│                            │
├────────────────────────────┤
│ 2FA Codes Backup Codes Settings │
└────────────────────────────┘
```

## Records and primary flows

### 2FA Codes

- The **+** button adds one TOTP entry.
- Manual setup allows a custom name and subtitle.
- For imported `otpauth` records, prefill the bold name from the issuer and the subtitle from the account/login label; let the user edit both.
- Each long horizontal row shows:
  - Bold name at the top left.
  - Optional subtitle below it.
  - The current TOTP at the right, with the remaining-period indication.
- Clicking anywhere in a row copies the current code.
- If an entry has a recovery-code set, show a small indicator without a count. Keep recovery-code records separate.
- Search the active tab by name and subtitle.
- Default order is oldest added to newest. Support persisted drag reordering and keyboard-accessible move controls.
- If the vault has no entries, show **Add new codes** and **Import existing** actions.
- Manual TOTP defaults: SHA-1, 6 digits, and a 30-second period. Provide optional advanced overrides.
- Preserve supported imported issuer/account labels, algorithm, digits, period, and secret exactly. Reject unsupported or malformed input with a specific error.

### Backup Codes

- Manage recovery-code sets separately, each with its own name and optional subtitle. Do not link them automatically to TOTP records.
- The **+** button creates a recovery-code set.
- Support newline-separated paste, with a review step before saving, and individual code entry.
- Rows show the name, subtitle, and remaining usable count.
- Selecting a row opens its individual codes. Each code is labelled and shown as **Usable** (green) or **Used** (red). Never communicate status through color alone.
- Used codes cannot be copied.
- With the default **ask after copy** setting enabled, clicking a usable code copies it and asks, “Did you use it?”
  - **Yes** marks it Used.
  - **No** leaves it Usable.
- If the prompt is disabled, clicking copies without changing status.
- Double-clicking a usable code copies it and marks it Used directly.
- Holding a Used code asks for confirmation before resetting it to Usable.
- Provide equivalent keyboard and context-menu actions, including confirmed individual-code deletion. Deleting the last code is handled by deleting the whole set.
- Search by name and subtitle.
- Persist chronological default order and manual reordering, as on the TOTP tab.

### Settings

Include:

- Master-password change.
- Lock behavior and the recovery-code copy prompt.
- System/light/dark appearance.
- Remembered camera-device preference. Remember the preference, but never start the camera automatically.
- Bulk authenticator import.
- Encrypted vault export and restore.
- Vault-location display and an appropriate location action for the build.

## Adding and importing TOTP entries

The single-entry **+** flow supports:

- Manual setup.
- Pasting an `otpauth://` link.
- Scanning a QR image file.
- Webcam scanning.

Settings handles bulk migration imports and encrypted vault backup/restore. The empty state offers both one-entry setup and bulk import.

First-release import sources:

- Standard `otpauth://` links and QR codes.
- Published Aegis vault exports.
- Bitwarden Authenticator JSON/CSV.
- Best-effort Google Authenticator multi-account migration QR parsing.

Requirements:

- Warn before reading plaintext source exports and encrypt imported data immediately on save.
- Request the source export password for password-protected Aegis exports.
- Parse accounts and require review and confirmation before saving.
- Never auto-open URLs from imported data.
- Do not promise independent import of 2FAS or Proton-native backups in v1; the reviewed public documentation does not specify a complete stable format.
- Microsoft Authenticator has no general TOTP-seed export; provide re-enrollment and recovery guidance.
- Describe Google migration QR support as best-effort, not a stable-format guarantee.

## QR scanning modes

### Webcam scan

- Request camera access only after the user explicitly starts scanning.
- Show a preview and stop the camera on completion or cancellation.
- Remember the chosen camera preference, but keep the camera off at startup.
- Provide usable guidance when permission is denied or no camera is available.

Also support QR image files and pasted `otpauth://` links. Treat all scan and import data as untrusted until parsed and reviewed.

## Vault, encryption, and locking

- Store TOTP and recovery records, labels, OTP parameters, code state, order, and app preferences in one versioned encrypted vault.
- Never store the master password in the vault.
- Use Argon2id and XChaCha20-Poly1305 with:
  - A random per-vault salt.
  - A fresh random nonce for every encryption.
  - Authenticated, versioned headers.
  - Validated KDF limits.
  - Fail-closed authentication.
- Benchmark a defensible Argon2id cost on supported Windows hardware and persist parameters so future versions can migrate.
- Use maintained Rust cryptography crates; do not implement cryptographic primitives.

### Master password

- Require at least 12 characters.
- Reject all whitespace.
- Do not require uppercase letters, digits, or symbols.
- On first run, explain offline guessing and unrecoverability, require password confirmation, and warn that there is no reset or recovery key.
- Make clear that a lost password makes the encrypted vault inaccessible.
- Do not claim encryption defeats malware or an attacker controlling Windows while the vault is unlocked.

### Locking and secret handling

Lock after any of the following:

- Five minutes of no keyboard/mouse activity in the app.
- Five minutes since losing focus.
- System sleep.
- Manual lock.
- Closing or exiting the app.

The visible **Lock** control is in the top bar. An optional keyboard shortcut may be offered.

Locking clears active decrypted view state and minimizes secret lifetime in memory. Zeroization is best-effort and is not a defense against a compromised operating system.

TOTP and recovery-code copy clears the clipboard after 30 seconds, but only if it still contains exactly the code copied by this app. Do not erase newer clipboard contents copied by another app.

Use safe atomic vault updates. Avoid plaintext temporary files, logs, crash diagnostics, and unencrypted credential exports.

## Vault locations, backup, and conflict handling

- **Installed build:** First-run setup asks for a separate writable vault folder—not the protected app-install folder—and Settings displays its path.
- **Portable build:** Store the encrypted vault beside the executable in the portable folder. If the folder is not writable, explain the issue and require the user to extract or move the app to a writable location rather than silently writing elsewhere.
- Export only an encrypted vault backup using the master password.
- Include labels, TOTP seeds and settings, recovery codes and statuses, ordering, and preferences in the backup.
- Require the password to restore.
- Changing the master password re-encrypts the current vault.
- Provide no plaintext credential export or password-reset bypass.
- Restore merges non-conflicting entries and pauses for per-conflict review. Never overwrite or merge silently.
- For each conflict, offer:
  - Keep current.
  - Replace with imported.
  - Keep both.
  - Skip.

Conflict detection:

- TOTP records conflict if trimmed, case-insensitive name and subtitle match, or if the canonical TOTP secret and all OTP settings match.
- Recovery-code sets conflict if trimmed, case-insensitive name and subtitle match, or if any exact recovery-code value overlaps.
- Show the compared records and require an explicit choice for each conflict.

## Windows packaging

- Produce an unsigned Windows 10/11 x64 installer and a portable ZIP or folder.
- Document the Windows SmartScreen warning. Signing can be a later release milestone.
- Tauri requires WebView2 on Windows.
- The portable launch flow must check for WebView2 before starting the app. If it is missing, ask the user to install it and provide a manual installation route.
- The installer may offer or install the Microsoft Evergreen WebView2 bootstrapper when required.
- The authenticator itself remains offline. Any WebView2 installation or download is explicit setup behavior, not telemetry or app-service traffic.
- Build a small native preflight/launcher if necessary so the prompt appears before Tauri tries to create its window.

## Verification and acceptance criteria

### Setup and vault security

- Fresh setup creates the vault, confirms the master password, rejects passwords shorter than 12 characters and passwords containing whitespace, and explains unrecoverability.
- The correct password opens the vault.
- Incorrect passwords and tampered files fail closed.
- Encryption/decryption, wrong passwords, tampering, parameter limits, atomic saves, export/restore, and every conflict choice are tested.
- Backups restore all defined vault fields.

### TOTP and clipboard

- RFC-compatible TOTP test vectors pass.
- Boundary and countdown behavior is tested.
- Imported standard parameters produce the expected codes.
- Clicking a TOTP row copies the currently displayed code.
- Clipboard clearing follows the 30-second and unchanged-content rules.

### Interface and recovery codes

- The three tabs, fixed bottom navigation, search, empty state, row layout, chronological default order, persisted reordering, and keyboard equivalents work at the fixed portrait size.
- Recovery-code add/paste/edit, status colors and labels, single-click prompt flow, prompt-off behavior, double-click mark-used, hold-to-reset confirmation, and Used-code copy prevention all work.

### Imports, scanning, and Windows builds

- Import parsers are tested with representative fixtures and malformed inputs.
- Plaintext warnings, best-effort Google behavior, review-before-save, and unsupported-format guidance are explicit.
- Auto-lock works for both timers, system sleep, manual lock, and app exit.
- The camera stays off until requested and stops after use.
- Test webcam scanning on actual Windows 10/11, including denied camera permission.
- Build and test the Windows installer and portable ZIP.
- Verify missing-WebView2 preflight and prompts, writable-vault-folder errors, and launch behavior on supported Windows versions.

### Accessibility and operational review

- Review keyboard navigation, focus visibility, contrast, screen-reader labels, and reduced-motion behavior.
- Review secret handling and dependency permissions.
- Verify the absence of app telemetry and network calls.

## Research basis and known tradeoffs

- Tauri Windows installer and WebView2 setup.
- Microsoft WebView2 distribution.
- RFC 9106: Argon2.
- RustCrypto XChaCha20-Poly1305.
- Aegis vault format.
- Bitwarden Authenticator import/export.
- Google Authenticator transfer guidance.

The workspace was empty at planning time. On approval, build this as a new project at the workspace root and verify the implementation against the acceptance criteria above. No files were created or modified during the planning phase.