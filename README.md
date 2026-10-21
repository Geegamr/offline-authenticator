# Offline Authenticator

Offline Authenticator is a Windows desktop app for storing time-based sign-in codes and account recovery codes in an encrypted file on your computer.

## What it does

- Creates TOTP codes from manual keys, authenticator links, QR images, a camera, or a screen scan.
- Imports TOTP entries from Aegis and Bitwarden exports, plus Google transfer QR codes.
- Keeps recovery codes in separate named lists and tracks which ones have been used.
- Encrypts the vault with a password before saving it. There is no password reset.
- Saves password-protected backups that can be restored to another vault.

The app does not use an account, send telemetry, or make network requests. Imports are read locally. Review imported entries before saving them. Google transfer QR support is best effort. Microsoft Authenticator does not provide a general TOTP-key export; accounts may need to be set up again using their recovery options. The app does not import 2FAS or Proton native backups.

## Build on Windows

Install Node.js, Rust with the MSVC toolchain, Visual Studio C++ Build Tools, and the Windows SDK. Tauri also needs the Microsoft Edge WebView2 Runtime.

```sh
npm install
npm run tauri -- dev
```

Run checks and create Windows packages:

```sh
npm run verify
npm run tauri -- build
```

The installer builds are unsigned, so Windows may show a SmartScreen warning. The installer includes the WebView2 offline installer. A portable folder can be made from the executable and its required runtime files; place it in a writable folder. The portable build needs WebView2 installed on the computer.

## Vault and backups

Choose a writable folder for the vault. The master password must be at least 12 characters and cannot contain whitespace. If it is lost, the encrypted vault cannot be opened. This protection does not secure a computer that is already compromised while the vault is unlocked.

Backups are encrypted. Keep the backup password safe and separate from the backup file. There is no plain text export.

## License

MIT. See [LICENSE](LICENSE).
