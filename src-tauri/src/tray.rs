use std::sync::Mutex;

use tauri::{
    AppHandle, Emitter, Manager,
    menu::{MenuBuilder, MenuItem, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};

/// 托盘文案。界面语言存在前端，启动后由 `set_tray_locale` 同步过来，
/// 因此这里保留一份可切换的静态文案表，而不是把语言写进配置。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TrayLocale {
    ZhCn,
    EnUs,
}

impl TrayLocale {
    fn from_tag(tag: &str) -> Self {
        if tag.starts_with("en") {
            Self::EnUs
        } else {
            Self::ZhCn
        }
    }

    fn show(self) -> &'static str {
        match self {
            Self::ZhCn => "显示窗口",
            Self::EnUs => "Show window",
        }
    }

    fn quit(self) -> &'static str {
        match self {
            Self::ZhCn => "退出",
            Self::EnUs => "Quit",
        }
    }

    fn pause_5m(self) -> &'static str {
        match self {
            Self::ZhCn => "暂停过滤 5 分钟",
            Self::EnUs => "Pause filtering for 5 minutes",
        }
    }

    fn pause_30m(self) -> &'static str {
        match self {
            Self::ZhCn => "暂停过滤 30 分钟",
            Self::EnUs => "Pause filtering for 30 minutes",
        }
    }

    fn pause_1h(self) -> &'static str {
        match self {
            Self::ZhCn => "暂停过滤 1 小时",
            Self::EnUs => "Pause filtering for 1 hour",
        }
    }

    fn resume(self) -> &'static str {
        match self {
            Self::ZhCn => "立即恢复过滤",
            Self::EnUs => "Resume filtering now",
        }
    }

    fn connecting(self) -> &'static str {
        match self {
            Self::ZhCn => "状态：正在连接…",
            Self::EnUs => "Status: connecting…",
        }
    }

    fn stopped(self) -> String {
        match self {
            Self::ZhCn => "状态：DNS 服务已停止".into(),
            Self::EnUs => "Status: DNS service stopped".into(),
        }
    }

    fn running(self) -> String {
        match self {
            Self::ZhCn => "状态：DNS 保护运行中".into(),
            Self::EnUs => "Status: DNS protection active".into(),
        }
    }

    fn paused_hours(self, hours: u64) -> String {
        match self {
            Self::ZhCn => format!("状态：过滤已暂停（剩余 {hours} 小时）"),
            Self::EnUs => format!("Status: filtering paused ({hours} h left)"),
        }
    }

    fn paused_minutes(self, minutes: u64) -> String {
        match self {
            Self::ZhCn => format!("状态：过滤已暂停（剩余 {minutes} 分钟）"),
            Self::EnUs => format!("Status: filtering paused ({minutes} min left)"),
        }
    }

    fn tooltip_stopped(self) -> &'static str {
        match self {
            Self::ZhCn => "DnsBlackhole · DNS 服务已停止",
            Self::EnUs => "DnsBlackhole · DNS service stopped",
        }
    }

    fn tooltip_paused(self) -> &'static str {
        match self {
            Self::ZhCn => "DnsBlackhole · 过滤已暂停",
            Self::EnUs => "DnsBlackhole · Filtering paused",
        }
    }

    fn tooltip_running(self) -> &'static str {
        match self {
            Self::ZhCn => "DnsBlackhole · DNS 保护运行中",
            Self::EnUs => "DnsBlackhole · DNS protection active",
        }
    }
}

struct TrayRuntimeMenu {
    status: MenuItem<tauri::Wry>,
    pause_5m: MenuItem<tauri::Wry>,
    pause_30m: MenuItem<tauri::Wry>,
    pause_1h: MenuItem<tauri::Wry>,
    resume: MenuItem<tauri::Wry>,
    show: MenuItem<tauri::Wry>,
    quit: MenuItem<tauri::Wry>,
    /// 最近一次的运行状态，切换语言时用它重绘状态行，避免文案回退成"正在连接"。
    last_status: Mutex<Option<(bool, bool, Option<u64>)>>,
    locale: Mutex<TrayLocale>,
}

pub fn create(app: &AppHandle) -> tauri::Result<()> {
    let locale = TrayLocale::ZhCn;
    let show = MenuItemBuilder::with_id("show", locale.show()).build(app)?;
    let status = MenuItemBuilder::with_id("runtime_status", locale.connecting())
        .enabled(false)
        .build(app)?;
    let pause_5m = MenuItemBuilder::with_id("pause_5m", locale.pause_5m())
        .enabled(false)
        .build(app)?;
    let pause_30m = MenuItemBuilder::with_id("pause_30m", locale.pause_30m())
        .enabled(false)
        .build(app)?;
    let pause_1h = MenuItemBuilder::with_id("pause_1h", locale.pause_1h())
        .enabled(false)
        .build(app)?;
    let resume = MenuItemBuilder::with_id("resume", locale.resume())
        .enabled(false)
        .build(app)?;
    let quit = MenuItemBuilder::with_id("quit", locale.quit()).build(app)?;
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
        show,
        quit,
        last_status: Mutex::new(None),
        locale: Mutex::new(locale),
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

/// 切换托盘语言。界面加载完成和用户改语言时各调用一次。
pub fn set_locale(app: &AppHandle, tag: &str) -> tauri::Result<()> {
    let menu = app.state::<TrayRuntimeMenu>();
    let locale = TrayLocale::from_tag(tag);
    {
        let Ok(mut current) = menu.locale.lock() else {
            return Ok(());
        };
        if *current == locale {
            return Ok(());
        }
        *current = locale;
    }
    menu.show.set_text(locale.show())?;
    menu.quit.set_text(locale.quit())?;
    menu.pause_5m.set_text(locale.pause_5m())?;
    menu.pause_30m.set_text(locale.pause_30m())?;
    menu.pause_1h.set_text(locale.pause_1h())?;
    menu.resume.set_text(locale.resume())?;

    let last = menu.last_status.lock().ok().and_then(|value| *value);
    match last {
        Some((running, paused, until)) => update_runtime_status(app, running, paused, until),
        None => menu.status.set_text(locale.connecting()),
    }
}

pub fn update_runtime_status(
    app: &AppHandle,
    running: bool,
    protection_paused: bool,
    paused_until: Option<u64>,
) -> tauri::Result<()> {
    let menu = app.state::<TrayRuntimeMenu>();
    let locale = menu
        .locale
        .lock()
        .map(|value| *value)
        .unwrap_or(TrayLocale::ZhCn);
    if let Ok(mut last) = menu.last_status.lock() {
        *last = Some((running, protection_paused, paused_until));
    }
    let status = if !running {
        locale.stopped()
    } else if protection_paused {
        let remaining = paused_until
            .map(|deadline| deadline.saturating_sub(unix_now()))
            .unwrap_or_default();
        if remaining >= 3600 {
            locale.paused_hours(remaining.div_ceil(3600))
        } else {
            locale.paused_minutes(remaining.div_ceil(60))
        }
    } else {
        locale.running()
    };
    menu.status.set_text(status)?;
    menu.pause_5m.set_enabled(running && !protection_paused)?;
    menu.pause_30m.set_enabled(running && !protection_paused)?;
    menu.pause_1h.set_enabled(running && !protection_paused)?;
    menu.resume.set_enabled(running && protection_paused)?;
    if let Some(tray) = app.tray_by_id("main") {
        let tooltip = if !running {
            locale.tooltip_stopped()
        } else if protection_paused {
            locale.tooltip_paused()
        } else {
            locale.tooltip_running()
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
