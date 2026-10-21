use crate::{parse_google_migration, parse_otpauth, ImportCandidate, Monitor, MonitorBounds};
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};

#[derive(Debug, serde::Deserialize)]
pub struct ScreenSelectionRequest {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

#[tauri::command(rename = "begin_screen_capture")]
pub fn begin_screen_capture(app: AppHandle) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        let _ = app;
        return Err("Screen scanning is only available on Windows.".into());
    }
    #[cfg(windows)]
    {
        if app.get_webview_window("screen-capture").is_some() {
            return Err("A screen scan is already open.".into());
        }
        let bounds = crate::get_primary_monitor_bounds()?;
        let scale = f64::from(bounds.scale_factor.max(1.0));
        WebviewWindowBuilder::new(
            &app,
            "screen-capture",
            WebviewUrl::App("screen-capture.html".into()),
        )
        .title("Select the authenticator QR code")
        .decorations(false)
        .transparent(true)
        .always_on_top(true)
        .skip_taskbar(true)
        .resizable(false)
        .shadow(false)
        .position(f64::from(bounds.x) / scale, f64::from(bounds.y) / scale)
        .inner_size(f64::from(bounds.width) / scale, f64::from(bounds.height) / scale)
        .build()
        .map_err(|error| format!("Cannot open the screen selection frame: {error}"))?;
        Ok(())
    }
}

#[tauri::command(rename = "capture_screen_region")]
pub fn capture_screen_region(
    app: AppHandle,
    request: ScreenSelectionRequest,
) -> Result<ImportCandidate, String> {
    #[cfg(not(windows))]
    {
        let _ = (app, request);
        return Err("Screen scanning is only available on Windows.".into());
    }
    #[cfg(windows)]
    {
        let selection_window = app
            .get_webview_window("screen-capture")
            .ok_or("The screen selection frame is unavailable")?;
        selection_window
            .hide()
            .map_err(|error| format!("Cannot hide the selection frame: {error}"))?;
        let main_window = app
            .get_webview_window("main")
            .ok_or("The main app window is unavailable")?;
        main_window
            .hide()
            .map_err(|error| format!("Cannot hide the app before screen capture: {error}"))?;
        std::thread::sleep(std::time::Duration::from_millis(250));

        let capture_result = (|| {
            let monitors = Monitor::all()
                .map_err(|error| format!("Cannot list displays for screen capture: {error}"))?;
            let monitor = monitors
                .into_iter()
                .find(|monitor| monitor.is_primary().unwrap_or(false))
                .ok_or_else(|| "No primary display is available for screen capture.".to_string())?;
            let scale = monitor
                .scale_factor()
                .map_err(|error| format!("Cannot inspect display scaling: {error}"))?;
            let physical_x = request.x as f64 * f64::from(scale);
            let physical_y = request.y as f64 * f64::from(scale);
            let physical_width = (request.width as f64 * f64::from(scale)).ceil();
            let physical_height = (request.height as f64 * f64::from(scale)).ceil();
            let monitor_width = monitor
                .width()
                .map_err(|error| format!("Cannot inspect display: {error}"))?;
            let monitor_height = monitor
                .height()
                .map_err(|error| format!("Cannot inspect display: {error}"))?;
            if request.x < 0
                || request.y < 0
                || request.width < 40
                || request.height < 40
                || physical_width > 8000.0
                || physical_height > 8000.0
                || physical_x + physical_width > f64::from(monitor_width)
                || physical_y + physical_height > f64::from(monitor_height)
            {
                return Err("Select a screen area at least 40 pixels wide and high, within the primary display.".into());
            }
            let image = monitor
                .capture_region(
                    physical_x.floor() as u32,
                    physical_y.floor() as u32,
                    physical_width as u32,
                    physical_height as u32,
                )
                .map_err(|error| format!("Cannot capture the selected screen area: {error}"))?;
            let gray = xcap::image::DynamicImage::ImageRgba8(image).to_luma8();
            let mut prepared = rqrr::PreparedImage::prepare(gray);
            for grid in prepared.detect_grids() {
                if let Ok((_metadata, content)) = grid.decode() {
                    if content.starts_with("otpauth-migration://") {
                        return parse_google_migration(&content)?
                            .into_iter()
                            .next()
                            .ok_or_else(|| "The Google transfer QR did not contain an account.".into());
                    }
                    if content.starts_with("otpauth://") {
                        return parse_otpauth(&content);
                    }
                }
            }
            Err("No supported TOTP QR code was found in that screen area.".into())
        })();

        let _ = main_window.show();
        let _ = selection_window.close();
        capture_result
    }
}

#[tauri::command(rename = "get_primary_monitor_bounds")]
pub fn get_primary_monitor_bounds() -> Result<MonitorBounds, String> {
    let monitors = Monitor::all()
        .map_err(|error| format!("Cannot list the display information: {error}"))?;
    let mut candidates = Vec::new();
    for monitor in monitors {
        let bounds = MonitorBounds {
            x: monitor.x().map_err(|error| format!("Cannot locate display: {error}"))?,
            y: monitor.y().map_err(|error| format!("Cannot locate display: {error}"))?,
            width: monitor.width().map_err(|error| format!("Cannot inspect display: {error}"))?,
            height: monitor.height().map_err(|error| format!("Cannot inspect display: {error}"))?,
            scale_factor: monitor.scale_factor().map_err(|error| format!("Cannot inspect display scaling: {error}"))?,
        };
        if monitor.is_primary().unwrap_or(false) {
            return Ok(bounds);
        }
        candidates.push(bounds);
    }
    candidates.into_iter().next().ok_or_else(|| "No display is available for screen scanning.".to_string())
}
