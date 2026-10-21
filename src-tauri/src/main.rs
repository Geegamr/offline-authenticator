// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(windows)]
fn webview2_installed() -> bool {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ, RegCloseKey, RegOpenKeyExW,
        RegQueryValueExW,
    };

    fn read_runtime_version(root: HKEY, subkey: &str) -> Option<String> {
        let key_name: Vec<u16> = OsStr::new(subkey).encode_wide().chain(Some(0)).collect();
        let value_name: Vec<u16> = OsStr::new("pv").encode_wide().chain(Some(0)).collect();
        let mut key: HKEY = ptr::null_mut();
        if unsafe { RegOpenKeyExW(root, key_name.as_ptr(), 0, KEY_READ, &mut key) } != 0 {
            return None;
        }
        let mut value_type = 0;
        let mut byte_len = 0;
        let query = unsafe {
            RegQueryValueExW(
                key,
                value_name.as_ptr(),
                ptr::null(),
                &mut value_type,
                ptr::null_mut(),
                &mut byte_len,
            )
        };
        if query != 0 || value_type != REG_SZ || !(4..=512).contains(&byte_len) {
            unsafe { RegCloseKey(key) };
            return None;
        }
        let mut value = vec![0u16; byte_len as usize / 2];
        let query = unsafe {
            RegQueryValueExW(
                key,
                value_name.as_ptr(),
                ptr::null(),
                &mut value_type,
                value.as_mut_ptr().cast(),
                &mut byte_len,
            )
        };
        unsafe { RegCloseKey(key) };
        if query != 0 || value_type != REG_SZ {
            return None;
        }
        let version = String::from_utf16_lossy(&value);
        let version = version.trim_matches('\0').trim();
        (!version.is_empty() && version != "0.0.0.0").then(|| version.to_owned())
    }

    let machine_key = format!(
        "SOFTWARE\\WOW6432Node\\Microsoft\\EdgeUpdate\\Clients\\{}",
        offline_authenticator_lib::WEBVIEW2_CLIENT_GUID
    );
    let user_key = format!(
        "Software\\Microsoft\\EdgeUpdate\\Clients\\{}",
        offline_authenticator_lib::WEBVIEW2_CLIENT_GUID
    );
    read_runtime_version(HKEY_LOCAL_MACHINE, &machine_key).is_some()
        || read_runtime_version(HKEY_CURRENT_USER, &user_key).is_some()
}

#[cfg(windows)]
fn show_webview2_setup_prompt() -> bool {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_DEFBUTTON1, MB_ICONWARNING, MB_YESNO, MessageBoxW,
    };

    let title: Vec<u16> = OsStr::new("WebView2 is required")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let message: Vec<u16> = OsStr::new(
        "Offline Authenticator needs the Microsoft Edge WebView2 Runtime to open.\n\nOpen Microsoft’s download page now? You can also install the Evergreen Standalone x64 Runtime manually.",
    )
    .encode_wide()
    .chain(Some(0))
    .collect();
    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON1,
        ) == IDYES
    }
}

#[cfg(windows)]
fn open_webview2_download_page() {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let operation: Vec<u16> = OsStr::new("open").encode_wide().chain(Some(0)).collect();
    let url: Vec<u16> = OsStr::new("https://developer.microsoft.com/microsoft-edge/webview2/")
        .encode_wide()
        .chain(Some(0))
        .collect();
    unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            operation.as_ptr(),
            url.as_ptr(),
            ptr::null(),
            ptr::null(),
            SW_SHOWNORMAL,
        );
    }
}

#[cfg(windows)]
fn main() {
    if !webview2_installed() {
        if show_webview2_setup_prompt() {
            open_webview2_download_page();
        }
        return;
    }
    offline_authenticator_lib::run()
}

#[cfg(not(windows))]
fn main() {
    offline_authenticator_lib::run()
}
