use tauri::{
    AppHandle, Emitter, Manager,
    menu::{MenuBuilder, MenuItem, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};

struct TrayRuntimeMenu {
    status: MenuItem<tauri::Wry>,
    pause_5m: MenuItem<tauri::Wry>,
    pause_30m: MenuItem<tauri::Wry>,
    pause_1h: MenuItem<tauri::Wry>,
    resume: MenuItem<tauri::Wry>,
}

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    let show = MenuItemBuilder::with_id("show", "显示窗口").build(app)?;
    let status = MenuItemBuilder::with_id("runtime_status", "状态：正在连接…")
        .enabled(false)
        .build(app)?;
    let pause_5m = MenuItemBuilder::with_id("pause_5m", "暂停过滤 5 分钟")
        .enabled(false)
        .build(app)?;
    let pause_30m = MenuItemBuilder::with_id("pause_30m", "暂停过滤 30 分钟")
        .enabled(false)
        .build(app)?;
    let pause_1h = MenuItemBuilder::with_id("pause_1h", "暂停过滤 1 小时")
        .enabled(false)
        .build(app)?;
    let resume = MenuItemBuilder::with_id("resume", "立即恢复过滤")
        .enabled(false)
        .build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "退出").build(app)?;
    let menu = MenuBuilder::new(app)
        .item(&status)
        .separator()
        .item(&pause_5m)
        .item(&pause_30m)
        .item(&pause_1h)
        .item(&resume)
        .separator()
        .item(&show)
        .separator()
        .item(&quit)
        .build()?;

    app.manage(TrayRuntimeMenu {
        status,
        pause_5m,
        pause_30m,
        pause_1h,
        resume,
    });

    let mut builder = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("DnsBlackhole")
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => show_main_window(app),
            "quit" => app.exit(0),
            "pause_5m" | "pause_30m" | "pause_1h" | "resume" => {
                let _ = app.emit("tray-protection-action", event.id().as_ref());
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

pub fn update_runtime_status(
    app: &AppHandle,
    running: bool,
    protection_paused: bool,
    paused_until: Option<u64>,
) -> tauri::Result<()> {
    let menu = app.state::<TrayRuntimeMenu>();
    let status = if !running {
        "状态：DNS 服务已停止".to_string()
    } else if protection_paused {
        let remaining = paused_until
            .map(|deadline| deadline.saturating_sub(unix_now()))
            .unwrap_or_default();
        if remaining >= 3600 {
            format!("状态：过滤已暂停（剩余 {} 小时）", remaining.div_ceil(3600))
        } else {
            format!("状态：过滤已暂停（剩余 {} 分钟）", remaining.div_ceil(60))
        }
    } else {
        "状态：DNS 保护运行中".to_string()
    };
    menu.status.set_text(status)?;
    menu.pause_5m.set_enabled(running && !protection_paused)?;
    menu.pause_30m.set_enabled(running && !protection_paused)?;
    menu.pause_1h.set_enabled(running && !protection_paused)?;
    menu.resume.set_enabled(running && protection_paused)?;
    if let Some(tray) = app.tray_by_id("main") {
        let tooltip = if !running {
            "DnsBlackhole · DNS 服务已停止"
        } else if protection_paused {
            "DnsBlackhole · 过滤已暂停"
        } else {
            "DnsBlackhole · DNS 保护运行中"
        };
        tray.set_tooltip(Some(tooltip))?;
    }
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub fn show_main_window(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}
