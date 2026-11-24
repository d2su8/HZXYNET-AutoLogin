//! 贺州学院校园网认证 - 纯 Win32 原生 GUI(零依赖,单 exe)
#![windows_subsystem = "windows"]

use campus_auth::{auth, autostart, common, net, selfsvc};

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontW, GetStockObject, GetSysColorBrush, InvalidateRect, RedrawWindow, SetBkColor,
    SetBkMode, SetTextColor, UpdateWindow, WHITE_BRUSH,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows_sys::Win32::UI::Controls::BST_CHECKED;
use windows_sys::Win32::UI::HiDpi::{
    GetDpiForSystem, SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_SYSTEM_AWARE,
};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::Win32::UI::WindowsAndMessaging::{LoadCursorW, IDC_ARROW};

use campus_auth::net::Adapter;
use campus_auth::store::Store;

// ---------------------------------------------------------------------------
// 控件 ID
// ---------------------------------------------------------------------------
const IDC_ADAPTER: u32 = 101;
const IDC_BTN_REFRESH: u32 = 102;
const IDC_INFO: u32 = 103;
const IDC_ED_USER: u32 = 104;
const IDC_ED_PASS: u32 = 105;
const IDC_CHK_SHOW: u32 = 106;
const IDC_CHK_SAVE: u32 = 107;
const IDC_RB_PC: u32 = 108;
const IDC_RB_MOBILE: u32 = 109;
const IDC_BTN_TEST: u32 = 110;
const IDC_BTN_LOGIN: u32 = 111;
const IDC_BTN_HISTORY: u32 = 112;
const IDC_BTN_CLEAR: u32 = 113;
const IDC_BTN_SELF: u32 = 114;
const IDC_LBL_STATUS: u32 = 115;
const IDC_ED_LOG: u32 = 116;
const IDC_BTN_OFFLINE: u32 = 117;
const IDC_ED_PORTAL: u32 = 118;
const IDC_BTN_DETECT: u32 = 119;
const IDC_DIAG_FILTER: u32 = 127;
const IDC_DIAG_COPY: u32 = 128;
const IDC_DIAG_STAGES: u32 = 129;
const IDC_DIAG_TITLE: u32 = 130;
const IDC_LBL_AUTO_GROUP: u32 = 131;
const IDC_LBL_DIAG_GROUP: u32 = 132;
const IDC_LBL_ADAPTER_GROUP: u32 = 133;
const IDC_LBL_LOGIN_GROUP: u32 = 134;
const WINDOW_STYLE: u32 = WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN;
const STAGES: [(auth::AuthStage, &str); 4] = [
    (auth::AuthStage::Probe, "探测"),
    (auth::AuthStage::Portal, "识别门户"),
    (auth::AuthStage::Submit, "认证"),
    (auth::AuthStage::Verify, "复核"),
];
/// 开机自启并自动认证 复选框
const IDC_CHK_AUTOSTART: u32 = 120;
/// 掉线自动重连 复选框
const IDC_CHK_REAUTH: u32 = 121;
/// 自动重连: 重试间隔(秒) 输入框
const IDC_ED_INTERVAL: u32 = 123;
/// 自动重连: 重试次数 输入框
const IDC_ED_RETRIES: u32 = 124;
/// 掉线/重连统计标签
const IDC_LBL_STATS: u32 = 125;
/// 自动认证分组内的说明文字
/// 给 Edit 设置灰色占位提示(windows-sys 未导出该常量)
const EM_SETCUEBANNER: u32 = 0x1501;
/// Edit 通知: 内容变化
const EN_CHANGE: u32 = 0x0300;

// 样式常量(SDK 值,统一 u32; crate 内同名常量是 i32,本地定义遮蔽保证类型一致)
const WS_EX_CLIENTEDGE: u32 = 0x0000_0200;
const CBS_DROPDOWNLIST: u32 = 0x0003;
const BS_PUSHBUTTON: u32 = 0x0000_0000;
const BS_DEFPUSHBUTTON: u32 = 0x0000_0001;
const BS_AUTOCHECKBOX: u32 = 0x0000_0002;
const BS_GROUPBOX: u32 = 0x0000_0007;
const BS_AUTORADIOBUTTON: u32 = 0x0000_0009;
const SS_LEFT: u32 = 0x0000_0000;
const ES_LEFT: u32 = 0x0000_0000;
const ES_AUTOHSCROLL: u32 = 0x0000_0080;
const ES_AUTOVSCROLL: u32 = 0x0000_0040;
const ES_MULTILINE: u32 = 0x0000_0004;
const ES_READONLY: u32 = 0x0000_0800;
const ES_PASSWORD: u32 = 0x0000_0020;
/// Edit 只允许输入数字
const ES_NUMBER: u32 = 0x0000_2000;
const WS_GROUP: u32 = 0x0002_0000;
const EM_SETSEL: u32 = 0x00B1;
const EM_SCROLLCARET: u32 = 0x00B5;
const EM_SETPASSWORDCHAR: u32 = 0x00CC;

// ---------------------------------------------------------------------------
// 工作线程 -> UI 的消息
// ---------------------------------------------------------------------------


enum UiMsg {
    Log(String),
    TestDone { verdict: Option<bool> },
    Phase(auth::AuthStage),
    OperationStarted(&'static str),
    ReauthDone { code: &'static str, ok: bool },
    LoginDone { ok: bool, code: &'static str, detail: String },
    /// 下线流程②: 结束(成功或失败)
    OfflineDone { ok: bool, detail: String },
    /// 门户探测结束(Some=门户基地址)
    PortalFound { found: Option<String> },
    /// 请求执行一次自动认证(开机自启的等待线程发出)
    AutoLogin { reason: String },
    /// 只更新状态标签(不动按钮可用性)
    /// 更新掉线/重连统计标签
    Stats { drops: u64, reauths: u64 },
}

struct App {
    hwnd: isize,
    rx: Mutex<Receiver<UiMsg>>,
    tx: Mutex<Sender<UiMsg>>,
    store: Arc<Mutex<Store>>,
    adapters: Mutex<Vec<Adapter>>,
    busy: AtomicBool,
    config_generation: AtomicU64,
    credential_generation: AtomicU64,
    diagnostics: Mutex<Diagnostics>,
}

impl App {
    fn hwnd(&self) -> HWND {
        self.hwnd as HWND
    }
}

static APP: OnceLock<App> = OnceLock::new();
static FONT_UI: OnceLock<isize> = OnceLock::new();
static FONT_HEADER: OnceLock<isize> = OnceLock::new();
static FONT_MONO: OnceLock<isize> = OnceLock::new();

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

unsafe fn set_text(h: HWND, text: &str) {
    let w = utf16(text);
    SendMessageW(h, WM_SETTEXT, 0, w.as_ptr() as isize);
}

unsafe fn get_text(h: HWND) -> String {
    // 注: 不用 WM_GETTEXTLENGTH —— Edit 设置过 cue banner 后它可能返回 0;
    // WM_GETTEXT 实测可靠, 直接用固定缓冲读取
    let mut buf = [0u16; 512];
    let n = SendMessageW(h, WM_GETTEXT, 512, buf.as_mut_ptr() as isize);
    let n = n.max(0) as usize;
    String::from_utf16_lossy(&buf[..n.min(512)])
}

// Win32 控件创建辅助函数参数众多是固有形态, 逐项传参比装箱成结构体更直白
#[allow(clippy::too_many_arguments)]
unsafe fn create_ctrl(
    cls: &str,
    text: &str,
    style: u32,
    ex: u32,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: u32,
    parent: HWND,
    font: isize,
) -> HWND {
    let cls_w = utf16(cls);
    let txt_w = utf16(text);
    let ctrl = CreateWindowExW(
        ex,
        cls_w.as_ptr(),
        txt_w.as_ptr(),
        WS_CHILD | WS_VISIBLE | style,
        dp(x),
        dp(y),
        dp(w),
        dp(h),
        parent,
        id as *mut core::ffi::c_void,
        GetModuleHandleW(std::ptr::null()),
        std::ptr::null(),
    );
    SendMessageW(ctrl, WM_SETFONT, font as usize, 1);
    ctrl
}

fn dp(v: i32) -> i32 {
    let dpi = unsafe { GetDpiForSystem() };
    (v * dpi as i32) / 96
}

/// 发日志到 UI(由 WM_TIMER 落控件 + 落盘)
fn log_line(msg: &str) {
    if let Some(app) = APP.get() {
        let _ = app.tx.lock().unwrap().send(UiMsg::Log(msg.to_string()));
    }
}

// ---------------------------------------------------------------------------
// 窗口过程
// ---------------------------------------------------------------------------

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => {
            // 控件不在这里创建: 实测在 WM_CREATE(窗口尚未显示)里创建子控件时,
            // comctl32 v6 主题复选框的首帧只会画出部分边框(表现为"刚打开显示
            // 不全、鼠标悬停后才完整"); 改为窗口创建后、显示前由 run_gui
            // 显式调用 build_controls(父窗口已可见, 子控件创建即正常绘制)。
            return 0;
        }
        // 灰底主题: Static 文字背景与窗口一致; 状态标签绿色; 只读日志 Edit 白底
        WM_CTLCOLORSTATIC => {
            let hdc = wparam as windows_sys::Win32::Graphics::Gdi::HDC;
            let hctl = lparam as HWND;
            let id = GetDlgCtrlID(hctl) as u32;
            if id == IDC_LBL_STATUS {
                SetTextColor(hdc, 0x0000_8000); // 绿色 (COLORREF 0x00BBGGRR)
                SetBkMode(hdc, 1 /* TRANSPARENT */);
                return GetSysColorBrush(15) as LRESULT;
            }
            if id == IDC_ED_LOG {
                // 只读日志框: 纯黑 + 不透明白底。两条上色路径(未聚焦 CTLCOLORSTATIC /
                // 聚焦后 CTLCOLOREDIT)必须完全一致; 且 ClearType 需要不透明背景,
                // 否则初次绘制会出现彩色毛边、点击聚焦后又变清晰的不一致现象。
                SetTextColor(hdc, 0x0000_0000);
                SetBkColor(hdc, 0x00FF_FFFF);
                SetBkMode(hdc, 2 /* OPAQUE */);
                return GetStockObject(WHITE_BRUSH) as LRESULT;
            }
            SetTextColor(hdc, 0x0000_0000);
            SetBkMode(hdc, 1 /* TRANSPARENT */);
            return GetSysColorBrush(15) as LRESULT;
        }
        WM_CTLCOLOREDIT => {
            // 与 WM_CTLCOLORSTATIC 的日志路径完全统一(同字体颜色/同背景)
            let hdc = wparam as windows_sys::Win32::Graphics::Gdi::HDC;
            SetTextColor(hdc, 0x0000_0000);
            SetBkColor(hdc, 0x00FF_FFFF);
            SetBkMode(hdc, 2 /* OPAQUE */);
            return GetStockObject(WHITE_BRUSH) as LRESULT;
        }
        WM_COMMAND => {
            let code = ((wparam >> 16) & 0xffff) as u32;
            let id = (wparam & 0xffff) as u32;
            handle_command(hwnd, id, code);
            return 0;
        }
        WM_SIZE => layout_diagnostics(hwnd),
        WM_GETMINMAXINFO => {
            let info = &mut *(lparam as *mut MINMAXINFO);
            info.ptMinTrackSize.x = dp(796);
            info.ptMinTrackSize.y = dp(609);
            return 0;
        }
        WM_TIMER => drain_messages(),
        WM_DESTROY => {
            PostQuitMessage(0);
            return 0;
        }
        _ => {}
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

#[derive(Default)]
struct Diagnostics {
    phase: Option<auth::AuthStage>,
    events: Vec<(Option<auth::AuthStage>, String)>,
}

unsafe fn diag_event(phase: Option<auth::AuthStage>, message: &str) {
    let Some(app) = APP.get() else { return };
    if let Ok(mut diagnostics) = app.diagnostics.lock() {
        if diagnostics.events.len() == 200 {
            diagnostics.events.remove(0);
        }
        diagnostics.events.push((phase, format!("{}  {}", common::now_str(), message)));
    }
    render_diagnostics();
}

unsafe fn begin_operation(title: &'static str) {
    let Some(app) = APP.get() else { return };
    if let Ok(mut diagnostics) = app.diagnostics.lock() {
        diagnostics.phase = None;
    }
    diag_event(None, title);
}

unsafe fn finish_operation(summary: &str) {
    let Some(app) = APP.get() else { return };
    let current = app.diagnostics.lock().ok().and_then(|d| d.phase);
    diag_event(current, summary);
    app.busy.store(false, Ordering::Release);
    set_busy(false, summary);
}

unsafe fn render_diagnostics() {
    let Some(app) = APP.get() else { return };
    let Ok(diag) = app.diagnostics.lock() else { return };
    let selection = SendMessageW(GetDlgItem(app.hwnd(), IDC_DIAG_FILTER as i32), CB_GETCURSEL, 0, 0);
    let selected = usize::try_from(selection - 1).ok().and_then(|i| STAGES.get(i)).map(|(stage, _)| *stage);
    let lines = diag.events.iter().filter(|(stage, _)| selected.is_none() || *stage == selected)
        .map(|(_, line)| line.as_str()).collect::<Vec<_>>().join("\r\n");
    let output = GetDlgItem(app.hwnd(), IDC_ED_LOG as i32);
    set_text(output, &lines);
    SendMessageW(output, EM_SETSEL, usize::MAX, -1);
    SendMessageW(output, EM_SCROLLCARET, 0, 0);
    let current = diag.phase.and_then(|phase| STAGES.iter().position(|(stage, _)| *stage == phase));
    let flow = STAGES.iter().enumerate().map(|(i, (_, label))| {
        match current {
            Some(active) if active == i => format!("[{label}]"),
            Some(active) if i < active => format!("✓ {label}"),
            _ => label.to_string(),
        }
    }).collect::<Vec<_>>().join("   →   ");
    set_text(GetDlgItem(app.hwnd(), IDC_DIAG_STAGES as i32), &flow);
}

unsafe fn layout_diagnostics(hwnd: HWND) {
    let mut rect: RECT = std::mem::zeroed();
    GetClientRect(hwnd, &mut rect);
    let x = dp(355);
    let width = (rect.right - x - dp(16)).max(dp(400));
    let height = (rect.bottom - dp(64)).max(dp(490));
    let controls = [
        (IDC_LBL_DIAG_GROUP, x, dp(58), width, height),
        (IDC_DIAG_TITLE, x + dp(16), dp(84), width - dp(32), dp(24)),
        (IDC_DIAG_STAGES, x + dp(16), dp(114), width - dp(32), dp(28)),
        (IDC_DIAG_FILTER, x + dp(16), dp(151), dp(120), dp(144)),
        (IDC_DIAG_COPY, x + width - dp(152), dp(148), dp(136), dp(28)),
        (IDC_ED_LOG, x + dp(16), dp(188), width - dp(32), height - dp(150)),
    ];
    for (id, left, top, w, h) in controls {
        let control = GetDlgItem(hwnd, id as i32);
        if !control.is_null() {
            MoveWindow(control, left, top, w, h, 1);
        }
    }
}

unsafe fn build_controls(hwnd: HWND) {
    let font = FONT_UI.get().copied().unwrap_or(0);
    let ctrl = |cls, text, style, ex, x, y, w, h, id|
        create_ctrl(cls, text, style, ex, x, y, w, h, id, hwnd, font);
    let label = |text, x, y, w, h, id| ctrl("STATIC", text, SS_LEFT, 0, x, y, w, h, id);
    let button = |text, x, y, w, id| ctrl("BUTTON", text, BS_PUSHBUTTON | WS_TABSTOP,
        0, x, y, w, 26, id);
    let group = |text, y, h, id| ctrl("BUTTON", text, BS_GROUPBOX, 0, 16, y, 322, h, id);
    let edit = |x, y, w, flags, id| ctrl("EDIT", "", ES_AUTOHSCROLL | WS_TABSTOP | flags,
        WS_EX_CLIENTEDGE, x, y, w, 24, id);
    let check = |text, x, y, w, id| ctrl("BUTTON", text, BS_AUTOCHECKBOX | WS_TABSTOP,
        0, x, y, w, 20, id);

    let heading = label("校园网诊断工作台", 16, 12, 328, 34, 0);
    SendMessageW(heading, WM_SETFONT, FONT_HEADER.get().copied().unwrap_or(font) as usize, 1);
    label("状态: 就绪", 355, 17, 401, 26, IDC_LBL_STATUS);
    group("网络接口", 58, 111, IDC_LBL_ADAPTER_GROUP);
    ctrl("COMBOBOX", "", CBS_DROPDOWNLIST | WS_TABSTOP, WS_EX_CLIENTEDGE,
        30, 82, 226, 155, IDC_ADAPTER);
    button("刷新", 263, 80, 60, IDC_BTN_REFRESH);
    label("请选择网卡", 30, 112, 293, 48, IDC_INFO);

    group("设备身份与认证", 177, 216, IDC_LBL_LOGIN_GROUP);
    ctrl("BUTTON", "电脑槽", BS_AUTORADIOBUTTON | WS_GROUP | WS_TABSTOP,
        0, 30, 199, 94, 21, IDC_RB_PC);
    ctrl("BUTTON", "手机槽", BS_AUTORADIOBUTTON | WS_TABSTOP,
        0, 126, 199, 94, 21, IDC_RB_MOBILE);
    SendMessageW(GetDlgItem(hwnd, IDC_RB_PC as i32), BM_SETCHECK, BST_CHECKED as usize, 0);
    label("账号", 30, 232, 54, 20, 0);
    edit(85, 228, 238, 0, IDC_ED_USER);
    label("密码", 30, 263, 54, 20, 0);
    edit(85, 258, 182, ES_PASSWORD, IDC_ED_PASS);
    check("显示", 272, 260, 53, IDC_CHK_SHOW);
    label("门户", 30, 293, 54, 20, 0);
    let portal = edit(85, 289, 171, 0, IDC_ED_PORTAL);
    let cue = utf16("填写或检测后确认");
    SendMessageW(portal, EM_SETCUEBANNER, 0, cue.as_ptr() as isize);
    button("检测", 263, 288, 60, IDC_BTN_DETECT);
    check("保存账号密码", 30, 323, 133, IDC_CHK_SAVE);
    ctrl("BUTTON", "一键认证", BS_DEFPUSHBUTTON | WS_TABSTOP, 0,
        208, 318, 115, 28, IDC_BTN_LOGIN);
    button("联通测试", 30, 355, 91, IDC_BTN_TEST);
    button("下线本设备", 129, 355, 96, IDC_BTN_OFFLINE);
    button("自助管理", 233, 355, 90, IDC_BTN_SELF);

    group("自动认证", 400, 121, IDC_LBL_AUTO_GROUP);
    check("开机自动认证", 30, 422, 148, IDC_CHK_AUTOSTART);
    check("掉线自动重连", 179, 422, 145, IDC_CHK_REAUTH);
    label("间隔（秒）", 30, 454, 82, 20, 0);
    edit(111, 449, 52, ES_NUMBER, IDC_ED_INTERVAL);
    label("最多尝试", 179, 454, 83, 20, 0);
    edit(271, 449, 52, ES_NUMBER, IDC_ED_RETRIES);
    label("掉线 0 次 · 重连成功 0 次", 30, 484, 293, 22, IDC_LBL_STATS);
    button("清除已保存", 16, 530, 122, IDC_BTN_CLEAR);
    button("历史日志", 145, 530, 108, IDC_BTN_HISTORY);

    ctrl("BUTTON", "诊断", BS_GROUPBOX, 0, 355, 58, 413, 490, IDC_LBL_DIAG_GROUP);
    label("认证流程", 371, 84, 370, 24, IDC_DIAG_TITLE);
    label("", 371, 114, 370, 28, IDC_DIAG_STAGES);
    let filter = ctrl("COMBOBOX", "", CBS_DROPDOWNLIST | WS_TABSTOP, 0,
        371, 151, 120, 144, IDC_DIAG_FILTER);
    for item in ["所有阶段"].into_iter().chain(STAGES.iter().map(|(_, label)| *label)) {
        let text = utf16(item);
        SendMessageW(filter, CB_ADDSTRING, 0, text.as_ptr() as isize);
    }
    SendMessageW(filter, CB_SETCURSEL, 0, 0);
    button("复制脱敏诊断", 617, 148, 136, IDC_DIAG_COPY);
    ctrl("EDIT", "", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | WS_TABSTOP,
        WS_EX_CLIENTEDGE, 371, 188, 381, 341, IDC_ED_LOG);
    layout_diagnostics(hwnd);
    render_diagnostics();
}

unsafe fn handle_command(hwnd: HWND, id: u32, code: u32) {
    // 注意: 不要在这里无条件 log_line —— 日志写入日志 Edit 又会触发 EN_* 通知, 造成死循环
    match (id, code) {
        (IDC_BTN_REFRESH, _) => refresh_adapters(true),
        (IDC_DIAG_FILTER, CBN_SELCHANGE) => render_diagnostics(),
        (IDC_DIAG_COPY, _) => {
            let log = GetDlgItem(hwnd, IDC_ED_LOG as i32);
            SendMessageW(log, EM_SETSEL, 0, -1);
            SendMessageW(log, WM_COPY, 0, 0);
            SendMessageW(log, EM_SETSEL, usize::MAX, -1);
        }
        (IDC_ADAPTER, CBN_SELCHANGE) => update_info_panel(),
        (IDC_CHK_SHOW, _) => {
            let chk = GetDlgItem(hwnd, IDC_CHK_SHOW as i32);
            // BS_AUTOCHECKBOX 在本环境下鼠标点击后状态不自翻(实测),
            // 因此收到点击通知后由程序主动取反并同步勾选框显示
            let was_checked = SendMessageW(chk, BM_GETCHECK, 0, 0) == BST_CHECKED as isize;
            let new_state = if was_checked { 0usize } else { BST_CHECKED as usize };
            SendMessageW(chk, BM_SETCHECK, new_state, 0);
            let checked = new_state != 0;
            let ed_pass = GetDlgItem(hwnd, IDC_ED_PASS as i32);
            SendMessageW(
                ed_pass,
                EM_SETPASSWORDCHAR,
                if checked { 0 } else { '*' as usize },
                0,
            );
            // EM_SETPASSWORDCHAR 后必须强制完整重绘才能生效
            InvalidateRect(ed_pass, std::ptr::null(), 1);
            UpdateWindow(ed_pass);
        }
        (IDC_CHK_SAVE, _) => {
            // BS_AUTOCHECKBOX 在本环境下点击后状态不自翻(与「显示」同因), 程序主动取反并同步勾选显示
            let chk = GetDlgItem(hwnd, IDC_CHK_SAVE as i32);
            let was_checked = SendMessageW(chk, BM_GETCHECK, 0, 0) == BST_CHECKED as isize;
            let new_state = if was_checked { 0usize } else { BST_CHECKED as usize };
            SendMessageW(chk, BM_SETCHECK, new_state, 0);
        }
        (IDC_CHK_AUTOSTART, _) => on_toggle_autostart(hwnd),
        (IDC_CHK_REAUTH, _) => on_toggle_reauth(hwnd),
        (IDC_ED_INTERVAL, EN_CHANGE) => on_reauth_params_changed(),
        (IDC_ED_RETRIES, EN_CHANGE) => on_reauth_params_changed(),
        // 设备类型 radio 同样存在不自翻问题: 点击后由程序主动置位(SETCHECK 为绝对设置, 幂等)
        (IDC_RB_PC, _) => {
            SendMessageW(GetDlgItem(hwnd, IDC_RB_PC as i32), BM_SETCHECK, BST_CHECKED as usize, 0);
            SendMessageW(GetDlgItem(hwnd, IDC_RB_MOBILE as i32), BM_SETCHECK, 0, 0);
        }
        (IDC_RB_MOBILE, _) => {
            SendMessageW(GetDlgItem(hwnd, IDC_RB_MOBILE as i32), BM_SETCHECK, BST_CHECKED as usize, 0);
            SendMessageW(GetDlgItem(hwnd, IDC_RB_PC as i32), BM_SETCHECK, 0, 0);
        }
        (IDC_BTN_TEST, _) => on_connectivity_test(),
        (IDC_BTN_OFFLINE, _) => on_offline(),
        (IDC_BTN_DETECT, _) => on_detect_portal(),
        (IDC_BTN_LOGIN, _) => on_login(),
        (IDC_BTN_HISTORY, _) => open_history_window(),
        (IDC_BTN_CLEAR, _) => on_clear_saved(),
        (IDC_BTN_SELF, _) => {
            let base = APP
                .get()
                .and_then(|a| a.store.lock().ok().map(|s| s.data.portal_url.clone()))
                .unwrap_or_default();
            let url = utf16(&common::self_service_url(&base));
            let op = utf16("open");
            ShellExecuteW(
                hwnd,
                op.as_ptr(),
                url.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            );
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// 业务动作
// ---------------------------------------------------------------------------

struct TaskParams {
    user: String,
    pass: String,
    ua_kind: String,
    source: Option<std::net::Ipv4Addr>,
    adapter_name: String,
    save: bool,
    /// 「门户地址」输入框内容(留空 = 靠 302 劫持自动发现)
    portal: String,
    /// 所选网卡的 MAC(无分隔符大写), 下线时用来匹配"本机"
    mac_nosep: String,
    /// 配置里记住的网关参数(新版门户接口必填; 设备在线时靠它调接口)
    acip: String,
    acname: String,
}

fn current_ua_kind() -> String {
    unsafe {
        let Some(app) = APP.get() else { return "pc".into() };
        // 以「手机端」是否选中为准; 两个都没选中(异常状态)时兜底为电脑端
        let rb_mobile = GetDlgItem(app.hwnd(), IDC_RB_MOBILE as i32);
        if SendMessageW(rb_mobile, BM_GETCHECK, 0, 0) == BST_CHECKED as isize {
            "mobile".into()
        } else {
            "pc".into()
        }
    }
}

unsafe fn selected_adapter() -> Option<Adapter> {
    let app = APP.get()?;
    let cmb = GetDlgItem(app.hwnd(), IDC_ADAPTER as i32);
    let idx = SendMessageW(cmb, CB_GETCURSEL, 0, 0);
    if idx < 0 {
        return None;
    }
    let adapters = app.adapters.lock().ok()?;
    adapters.get(idx as usize).cloned()
}

unsafe fn update_info_panel() {
    let Some(app) = APP.get() else { return };
    let info = GetDlgItem(app.hwnd(), IDC_INFO as i32);
    let Some(a) = selected_adapter() else {
        set_text(info, "未选择网卡");
        return;
    };
    let ipv4 = a.ipv4.first().map_or("等待 IPv4".into(), |ip| ip.to_string());
    set_text(info, &format!("{} · {}\r\nIPv4  {}", a.name, a.status, ipv4));
}

unsafe fn refresh_adapters(log_it: bool) {
    let Some(app) = APP.get() else { return };
    let adapters = net::list_adapters();
    let cmb = GetDlgItem(app.hwnd(), IDC_ADAPTER as i32);
    SendMessageW(cmb, CB_RESETCONTENT, 0, 0);
    let saved_name = app
        .store
        .lock()
        .ok()
        .map(|s| s.data.adapter.clone())
        .unwrap_or_default();
    let mut select_idx: i32 = -1;
    let mut campus_idx: i32 = -1;
    let mut wlan_idx: i32 = -1;
    for (i, a) in adapters.iter().enumerate() {
        let label = format!(
            "{}  |  {}  |  {}",
            a.name,
            a.ipv4
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            a.mac
        );
        let w = utf16(&label);
        SendMessageW(cmb, CB_ADDSTRING, 0, w.as_ptr() as isize);
        if !saved_name.is_empty() && a.name == saved_name && select_idx < 0 {
            select_idx = i as i32;
        }
        if a.is_campus() && campus_idx < 0 {
            campus_idx = i as i32;
        }
        if a.name.to_ascii_lowercase().contains("wlan") && wlan_idx < 0 {
            wlan_idx = i as i32;
        }
    }
    let final_idx = if select_idx >= 0 {
        select_idx
    } else if campus_idx >= 0 {
        campus_idx
    } else if wlan_idx >= 0 {
        wlan_idx
    } else if !adapters.is_empty() {
        0
    } else {
        -1
    };
    if final_idx >= 0 {
        SendMessageW(cmb, CB_SETCURSEL, final_idx as usize, 0);
    }
    if let Ok(mut guard) = app.adapters.lock() {
        *guard = adapters;
    }
    update_info_panel();
    if log_it {
        log_line("网卡列表已刷新");
    }
}

unsafe fn collect_params() -> Option<TaskParams> {
    let app = APP.get()?;
    let user = get_text(GetDlgItem(app.hwnd(), IDC_ED_USER as i32))
        .trim()
        .to_string();
    let pass = get_text(GetDlgItem(app.hwnd(), IDC_ED_PASS as i32));
    let adapter = selected_adapter()?;
    let source = Some(*adapter.ipv4.first()?);
    let ua_kind = current_ua_kind();
    let save = SendMessageW(
        GetDlgItem(app.hwnd(), IDC_CHK_SAVE as i32),
        BM_GETCHECK,
        0,
        0,
    ) == BST_CHECKED as isize;
    let portal = get_text(GetDlgItem(app.hwnd(), IDC_ED_PORTAL as i32))
        .trim()
        .to_string();
    let (acip, acname) = app
        .store
        .lock()
        .map(|st| (st.data.wlanacip.clone(), st.data.wlanacname.clone()))
        .unwrap_or_default();
    Some(TaskParams {
        user,
        pass,
        ua_kind,
        source,
        mac_nosep: selfsvc::norm_mac(&adapter.mac),
        acip,
        acname,
        adapter_name: adapter.name,
        save,
        portal,
    })
}

unsafe fn set_busy(busy: bool, status: &str) {
    let Some(app) = APP.get() else { return };
    for id in [IDC_BTN_TEST, IDC_BTN_LOGIN, IDC_BTN_REFRESH, IDC_BTN_OFFLINE] {
        EnableWindow(GetDlgItem(app.hwnd(), id as i32), if busy { 0 } else { 1 });
    }
    set_text(
        GetDlgItem(app.hwnd(), IDC_LBL_STATUS as i32),
        &format!("状态: {status}"),
    );
}

unsafe fn on_connectivity_test() {
    let Some(app) = APP.get() else { return };
    if app.busy.swap(true, Ordering::SeqCst) {
        return;
    }
    let Some(params) = collect_params() else {
        app.busy.store(false, Ordering::SeqCst);
        let msg = utf16("请先选择一块有 IPv4 地址的网卡.");
        let cap = utf16("提示");
        MessageBoxW(app.hwnd(), msg.as_ptr(), cap.as_ptr(), MB_ICONWARNING);
        return;
    };
    set_busy(true, "联通测试中...");
    log_line("---- 联通测试 ----");
    let tx = app.tx.lock().unwrap().clone();
    begin_operation("联通测试");
    thread::spawn(move || {
        let log_fn = |_message: &str| {};
        let a = auth::Auth::new(&params.ua_kind, params.source, &log_fn);
        let _ = tx.send(UiMsg::Phase(auth::AuthStage::Probe));
        let (verdict, _) = a.connectivity_test();
        let _ = tx.send(UiMsg::TestDone { verdict });
    });
}

unsafe fn on_login() {
    let Some(app) = APP.get() else { return };
    if app.busy.swap(true, Ordering::SeqCst) {
        return;
    }
    let Some(params) = collect_params() else {
        app.busy.store(false, Ordering::SeqCst);
        let msg = utf16("请先填写账号密码并选择一块有 IPv4 地址的网卡.");
        let cap = utf16("提示");
        MessageBoxW(app.hwnd(), msg.as_ptr(), cap.as_ptr(), MB_ICONWARNING);
        return;
    };
    if params.user.is_empty() || params.pass.is_empty() {
        app.busy.store(false, Ordering::SeqCst);
        let msg = utf16("请先输入账号和密码.");
        let cap = utf16("提示");
        MessageBoxW(app.hwnd(), msg.as_ptr(), cap.as_ptr(), MB_ICONWARNING);
        return;
    }
    let mut params = params;
    params.portal = normalize_portal(&params.portal).unwrap_or_default();
    let device = if params.ua_kind == "mobile" { "手机端(手机槽)" } else { "电脑端(PC 槽)" };
    let confirm_text = format!(
        "即将使用以下配置提交登录认证:\n\n网卡: {} ({})\n设备类型: {}\n门户地址: {}\n保存账号密码: {}\n\n注意: 认证会占用对应设备槽位; 若槽位已被占用,\n程序只会提示手动下线, 不会自动顶号.\n\n确定继续?",
        params.adapter_name,
        params
            .source
            .map(|i| i.to_string())
            .unwrap_or_else(|| "自动".into()),
        device,
        if params.portal.is_empty() { "待确认（尚未授权提交凭据）" } else { &params.portal },
        if params.save { "是(DPAPI 加密)" } else { "否" }
    );
    let text = utf16(&confirm_text);
    let cap = utf16("确认认证");
    let ret = MessageBoxW(
        app.hwnd(),
        text.as_ptr(),
        cap.as_ptr(),
        MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2,
    );
    if ret != 6 /* IDYES */ {
        app.busy.store(false, Ordering::SeqCst);
        log_line("用户取消了本次认证(未提交任何登录请求)");
        return;
    }

    set_busy(true, "认证中...");
    begin_operation("手动认证");
    let tx = app.tx.lock().unwrap().clone();
    spawn_login(params, tx);
}

/// 后台登录线程(手动认证 / 开机自动认证 / 掉线重连共用)
fn spawn_login(params: TaskParams, tx: Sender<UiMsg>) {
    let app = APP.get().unwrap();
    let generation = app.credential_generation.load(Ordering::Acquire);
    thread::spawn(move || {
        let log_fn = |message: &str| {
            let _ = tx.send(UiMsg::Log(common::redact_credentials(message, &params.user, &params.pass)));
        };
        let progress = |stage| { let _ = tx.send(UiMsg::Phase(stage)); };
        let cancelled = || app.credential_generation.load(Ordering::Acquire) != generation;
        let mut a = auth::Auth::new(&params.ua_kind, params.source, &log_fn);
        a.set_portal_url(Some(params.portal.clone()));
        a.set_portal_ac(&params.acip, &params.acname);
        a.set_progress(&progress);
        a.set_cancelled(&cancelled);
        let (ok, code, detail) = a.login(&params.user, &params.pass);
        if ok {
            if let Ok(mut store) = app.store.lock() {
                if !cancelled() {
                    // Release of the probe alone cannot validate newly entered credentials.
                    if !params.save || code == auth::CODE_OK || a.discovered_base.lock().is_ok_and(|base| base.is_some()) {
                        if let Err(e) = store.set_credentials(&params.user, Some(&params.pass),
                            params.save, &params.ua_kind, &params.adapter_name) {
                            let _ = tx.send(UiMsg::Log(format!("保存凭据失败: {e}")));
                        }
                    }
                    if let Some(origin) = auth::portal_origin(&params.portal) {
                        store.data.portal_url = params.portal.clone();
                        store.data.trusted_portal_origin = origin;
                    }
                    if let Some((ip, name)) = a.discovered_ac.lock().ok().and_then(|g| g.clone()) {
                        store.data.wlanacip = ip;
                        store.data.wlanacname = name;
                    }
                    store.save();
                    app.config_generation.fetch_add(1, Ordering::Release);
                }
            }
        }
        let detail = common::redact_credentials(&detail, &params.user, &params.pass);
        let _ = tx.send(UiMsg::LoginDone { ok, code, detail });
    });
}

fn normalize_portal(portal: &str) -> Option<String> {
    let portal = portal.trim();
    let url = if portal.contains("://") { portal.to_string() } else { format!("http://{portal}") };
    auth::portal_origin(&url).map(|_| url)
}

fn trusted_portal(data: &campus_auth::store::StoreData) -> Option<String> {
    normalize_portal(&data.portal_url).filter(|url| {
        auth::portal_origin(url).as_deref() == Some(&data.trusted_portal_origin)
    })
}

// ---------------------------------------------------------------------------
// 开机自启 / 掉线自动重连
// ---------------------------------------------------------------------------

/// 只更新状态标签(不碰按钮可用性; 供后台线程经消息队列调用)
fn auto_adapter(adapter_name: &str) -> Option<Adapter> {
    net::list_adapters().into_iter().find(|adapter| {
        !adapter.ipv4.is_empty() && if adapter_name.is_empty() {
            adapter.is_campus()
        } else {
            adapter.name == adapter_name
        }
    })
}

fn build_auto_params() -> Option<TaskParams> {
    let app = APP.get()?;
    let data = app.store.lock().ok()?.data.clone();
    let portal = trusted_portal(&data)?;
    if !data.save_password {
        return None;
    }
    let pass = campus_auth::crypto::unprotect(&data.password_dpapi).ok()?;
    if data.username.is_empty() || pass.is_empty() {
        return None;
    }
    let ad = auto_adapter(&data.adapter)?;
    Some(TaskParams {
        user: data.username,
        pass,
        ua_kind: data.ua,
        source: ad.ipv4.first().copied(),
        adapter_name: ad.name,
        save: true,
        portal,
        mac_nosep: selfsvc::norm_mac(&ad.mac),
        acip: data.wlanacip,
        acname: data.wlanacname,
    })
}

/// 自动认证(开机自启用): 用已保存凭据, 不弹确认框
unsafe fn auto_login(reason: &str) {
    let Some(app) = APP.get() else { return };
    if app.busy.swap(true, Ordering::SeqCst) {
        return;
    }
    let Some(params) = build_auto_params() else {
        app.busy.store(false, Ordering::SeqCst);
        log_line(&format!("{reason}: 没有可用的已保存凭据或网卡, 跳过"));
        return;
    };
    set_busy(true, "自动认证中...");
    begin_operation("开机自动认证");
    let tx = app.tx.lock().unwrap().clone();
    spawn_login(params, tx);
}

/// 「开机自启并自动认证」复选框: 写/删注册表 Run 项
unsafe fn on_toggle_autostart(hwnd: HWND) {
    let Some(app) = APP.get() else { return };
    let chk = GetDlgItem(hwnd, IDC_CHK_AUTOSTART as i32);
    let was_checked = SendMessageW(chk, BM_GETCHECK, 0, 0) == BST_CHECKED as isize;
    let new_checked = !was_checked;
    if new_checked {
        // 开机自动认证依赖已保存凭据; 没有就拒绝开启并提示
        let has_creds = app
            .store
            .lock()
            .map(|s| s.has_usable_credentials() && trusted_portal(&s.data).is_some())
            .unwrap_or(false);
        if !has_creds {
            messagebox_warn(
                hwnd,
                "开机自动认证需要已保存的账号密码:\n请确认门户地址，勾选「保存账号密码」并完成一次登录。",
            );
            return; // 保持未勾选
        }
    }
    SendMessageW(
        chk,
        BM_SETCHECK,
        if new_checked { BST_CHECKED as usize } else { 0 },
        0,
    );
    match autostart::set_enabled(new_checked) {
        Ok(()) => {
            if let Ok(mut s) = app.store.lock() {
                s.data.auto_start = new_checked;
                s.save();
            }
            if new_checked {
                log_line("已开启开机自启: 重启后用保存的账号自动认证(最小化启动)");
            } else {
                log_line("已关闭开机自启(注册表启动项已删除)");
            }
        }
        Err(e) => {
            // 注册表写失败: 还原勾选与配置, 不让界面说谎
            SendMessageW(
                chk,
                BM_SETCHECK,
                if was_checked { BST_CHECKED as usize } else { 0 },
                0,
            );
            log_line(&format!("开机自启设置失败: {e}"));
            messagebox_warn(hwnd, &format!("开机自启设置失败:\n{e}"));
        }
    }
}

/// 「掉线自动重连」复选框
unsafe fn on_toggle_reauth(hwnd: HWND) {
    let Some(app) = APP.get() else { return };
    let chk = GetDlgItem(hwnd, IDC_CHK_REAUTH as i32);
    let was_checked = SendMessageW(chk, BM_GETCHECK, 0, 0) == BST_CHECKED as isize;
    let new_checked = !was_checked;
    if new_checked {
        let has_creds = app
            .store
            .lock()
            .map(|s| s.has_usable_credentials() && trusted_portal(&s.data).is_some())
            .unwrap_or(false);
        if !has_creds {
            messagebox_warn(
                hwnd,
                "掉线自动重连需要已保存的账号密码:\n请确认门户地址，勾选「保存账号密码」并完成一次登录。",
            );
            return;
        }
    }
    SendMessageW(
        chk,
        BM_SETCHECK,
        if new_checked { BST_CHECKED as usize } else { 0 },
        0,
    );
    if let Ok(mut s) = app.store.lock() {
        app.config_generation.fetch_add(1, Ordering::Release);
        s.data.auto_reauth = new_checked;
        s.save();
    }
    log_line(if new_checked {
        "已开启掉线自动重连"
    } else {
        "已关闭掉线自动重连"
    });
}

/// 重试间隔/次数输入框变化: 合法才落库(输入中途不抢)
unsafe fn on_reauth_params_changed() {
    let Some(app) = APP.get() else { return };
    let interval = get_text(GetDlgItem(app.hwnd(), IDC_ED_INTERVAL as i32))
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|v| (5..=3600).contains(v));
    let retries = get_text(GetDlgItem(app.hwnd(), IDC_ED_RETRIES as i32))
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|v| (1..=20).contains(v));
    if interval.is_none() && retries.is_none() {
        return;
    }
    if let Ok(mut s) = app.store.lock() {
        if interval.is_some_and(|v| v != s.data.reauth_interval_secs)
            || retries.is_some_and(|v| v != s.data.reauth_max_retries) {
            app.config_generation.fetch_add(1, Ordering::Release);
        }
        if let Some(v) = interval {
            s.data.reauth_interval_secs = v;
        }
        if let Some(v) = retries {
            s.data.reauth_max_retries = v;
        }
        s.save();
    }
}

fn wait_for_retry(app: &App, generation: u64, seconds: u32) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds.into());
    while std::time::Instant::now() < deadline {
        if app.config_generation.load(Ordering::Acquire) != generation {
            return false;
        }
        thread::sleep(std::time::Duration::from_millis(100));
    }
    app.config_generation.load(Ordering::Acquire) == generation
}

unsafe fn spawn_reauth_monitor() {
    thread::spawn(move || {
        let app = APP.get().unwrap();
        let tx = app.tx.lock().unwrap().clone();
        let mut was_online = false;
        let mut observed_generation = 0;
        loop {
            thread::sleep(std::time::Duration::from_secs(5));
            let (generation, enabled, adapter, interval, retries) = {
                let Ok(store) = app.store.lock() else { continue };
                (app.config_generation.load(Ordering::Acquire),
                    store.data.auto_reauth && store.has_usable_credentials() && trusted_portal(&store.data).is_some(),
                    store.data.adapter.clone(), store.data.reauth_interval_secs.clamp(5, 3600),
                    store.data.reauth_max_retries.clamp(1, 20))
            };
            if observed_generation != generation {
                observed_generation = generation;
                was_online = false;
            }
            if !enabled || app.busy.load(Ordering::Acquire) {
                continue;
            }
            let Some(adapter) = auto_adapter(&adapter) else { continue };
            let quiet = |_: &str| {};
            let probe = auth::Auth::new("pc", adapter.ipv4.first().copied(), &quiet);
            match probe.connectivity_test().0 {
                Some(true) => { was_online = true; continue; }
                Some(false) if was_online => was_online = false,
                _ => continue,
            }
            if let Ok(mut store) = app.store.lock() {
                if app.config_generation.load(Ordering::Acquire) != generation {
                    continue;
                }
                store.data.drop_count += 1;
                store.save();
                let _ = tx.send(UiMsg::Stats { drops: store.data.drop_count, reauths: store.data.reauth_count });
            }

            for attempt in 1..=retries {
                if (attempt != 1 && !wait_for_retry(app, generation, interval))
                    || app.busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err()
                {
                    break;
                }
                let cancelled = || app.config_generation.load(Ordering::Acquire) != generation;
                let Some(params) = (!cancelled()).then(build_auto_params).flatten() else {
                    app.busy.store(false, Ordering::Release);
                    break;
                };
                let progress = |stage| { let _ = tx.send(UiMsg::Phase(stage)); };
                let mut auth = auth::Auth::new(&params.ua_kind, params.source, &quiet);
                auth.set_portal_url(Some(params.portal));
                auth.set_portal_ac(&params.acip, &params.acname);
                auth.set_progress(&progress);
                auth.set_cancelled(&cancelled);
                let _ = tx.send(UiMsg::OperationStarted("自动重连"));
                let (ok, code, _) = auth.login(&params.user, &params.pass);
                if ok {
                    was_online = true;
                    if let Ok(mut store) = app.store.lock() {
                        if !cancelled() {
                            store.data.reauth_count += 1;
                            store.save();
                            let _ = tx.send(UiMsg::Stats { drops: store.data.drop_count, reauths: store.data.reauth_count });
                        }
                    }
                }
                let _ = tx.send(UiMsg::ReauthDone { code, ok });
                if ok || cancelled() || matches!(code, auth::CODE_BADPASS | auth::CODE_CONFLICT | auth::CODE_UNTRUSTED_PORTAL) {
                    break;
                }
            }
        }
    });
}

/// 检测门户: 只做"找认证服务器"(探测劫持/验证已填地址), 不登录、不占用槽位
unsafe fn on_detect_portal() {
    let Some(app) = APP.get() else { return };
    if app.busy.swap(true, Ordering::SeqCst) {
        return;
    }
    let Some(params) = collect_params() else {
        app.busy.store(false, Ordering::SeqCst);
        let msg = utf16("请先选择一块有 IPv4 地址的网卡.");
        let cap = utf16("提示");
        MessageBoxW(app.hwnd(), msg.as_ptr(), cap.as_ptr(), MB_ICONWARNING);
        return;
    };
    set_busy(true, "检测门户中...");
    begin_operation("门户检测");
    diag_event(Some(auth::AuthStage::Portal), "扫描门户地址");
    log_line("---- 检测门户(只探测, 不登录) ----");
    let tx = app.tx.lock().unwrap().clone();
    thread::spawn(move || {
        let tx_log = Mutex::new(tx.clone());
        let log_fn = move |s: &str| {
            let _ = tx_log.lock().unwrap().send(UiMsg::Log(s.to_string()));
        };
        let mut a = auth::Auth::new(&params.ua_kind, params.source, &log_fn);
        a.set_portal_url(Some(params.portal.clone()));
        let found = a.detect_portal();
        let _ = tx.send(UiMsg::PortalFound { found });
    });
}

unsafe fn on_clear_saved() {
    let Some(app) = APP.get() else { return };
    let text = utf16("将删除本机保存的账号与密码(加密数据), 确定?");
    let cap = utf16("确认");
    if MessageBoxW(app.hwnd(), text.as_ptr(), cap.as_ptr(), MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2) != 6 {
        return;
    }
    let result = if let Ok(mut store) = app.store.lock() {
        app.credential_generation.fetch_add(1, Ordering::Release);
        app.config_generation.fetch_add(1, Ordering::Release);
        store.clear_credentials();
        // 凭据没了, 两个自动认证开关一并关闭(开机自启的注册表项也删掉)
        let startup = if store.data.auto_start { autostart::set_enabled(false) } else { Ok(()) };
        store.data.auto_start = false;
        store.data.auto_reauth = false;
        store.try_save().and(startup)
    } else {
        Err("无法取得本地设置".into())
    };
    // 界面上的账号密码输入框同步清空
    set_text(GetDlgItem(app.hwnd(), IDC_ED_USER as i32), "");
    set_text(GetDlgItem(app.hwnd(), IDC_ED_PASS as i32), "");
    SendMessageW(GetDlgItem(app.hwnd(), IDC_CHK_SAVE as i32), BM_SETCHECK, 0, 0);
    SendMessageW(GetDlgItem(app.hwnd(), IDC_CHK_AUTOSTART as i32), BM_SETCHECK, 0, 0);
    SendMessageW(GetDlgItem(app.hwnd(), IDC_CHK_REAUTH as i32), BM_SETCHECK, 0, 0);
    match result {
        Ok(()) => diag_event(None, "已清除凭据，自动认证已关闭"),
        Err(e) => {
            diag_event(None, "清除凭据时写入失败");
            messagebox_warn(app.hwnd(), &format!("无法确认本地凭据已清除：{e}"));
        }
    }
}

// ---------------------------------------------------------------------------
// 下线本设备(自助管理接口, 协议详见 src/selfsvc.rs 头注释)
// ---------------------------------------------------------------------------

unsafe fn messagebox_warn(h: HWND, text: &str) {
    let t = utf16(text);
    let c = utf16("提示");
    MessageBoxW(h, t.as_ptr(), c.as_ptr(), MB_ICONWARNING);
}

unsafe fn messagebox_yesno(h: HWND, text: &str, cap: &str) -> bool {
    let t = utf16(text);
    let c = utf16(cap);
    MessageBoxW(h, t.as_ptr(), c.as_ptr(), MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2) == 6
}


unsafe fn on_offline() {
    let Some(app) = APP.get() else { return };
    if app.busy.swap(true, Ordering::SeqCst) {
        return;
    }
    let Some(params) = collect_params() else {
        app.busy.store(false, Ordering::SeqCst);
        messagebox_warn(app.hwnd(), "请先选择一块有 IPv4 地址的网卡.");
        return;
    };
    if params.user.is_empty() || params.pass.is_empty() {
        app.busy.store(false, Ordering::SeqCst);
        messagebox_warn(
            app.hwnd(),
            "下线需要账号密码(新版门户用它换自助后台令牌):\n请先填写账号密码, 或使用「保存账号密码」后重试.",
        );
        return;
    }
    let Some(portal) = normalize_portal(&params.portal) else {
        app.busy.store(false, Ordering::Release);
        messagebox_warn(app.hwnd(), "请先填写并核对门户地址。");
        return;
    };
    let mut params = params;
    params.portal = portal;
    let confirm = format!(
        "将下线本机在校园网的在线会话, 并清除 MAC 绑定:\n\n门户: {}\n网卡: {} ({})\n\n        流程: 用账号密码换取自助后台令牌 → 查在线设备 → 匹配本机 → 强制下线 + 清绑定 + 复核.\n        仅操作本机会话, 不会影响账号下其它设备; 新版门户不再需要图片验证码.\n\n继续?",
        params.portal,
        params.adapter_name,
        params
            .source
            .map(|i| i.to_string())
            .unwrap_or_else(|| "自动".into())
    );
    if !messagebox_yesno(app.hwnd(), &confirm, "确认下线") {
        app.busy.store(false, Ordering::SeqCst);
        log_line("用户取消了下线操作");
        return;
    }
    set_busy(true, "下线中...");
    begin_operation("下线本设备");
    let tx = app.tx.lock().unwrap().clone();
    thread::spawn(move || {
        let log_fn = |s: &str| {
            let _ = tx.send(UiMsg::Log(common::redact_credentials(s, &params.user, &params.pass)));
        };
        match run_offline_new(&params, &log_fn) {
            Ok(detail) => {
                // 复核: 等 3 秒再探测, 回到劫持态即成功
                thread::sleep(std::time::Duration::from_secs(3));
                let a = auth::Auth::new("pc", params.source, &log_fn);
                let (conclusive, _) = a.connectivity_test();
                let detail = match conclusive {
                    Some(false) => format!("{detail}; 复核: 已断网(回到未认证状态)"),
                    Some(true) => format!("{detail}; 注意: 复核显示仍在线(门户可能有延迟)"),
                    None => detail,
                };
                let detail = common::redact_credentials(&detail, &params.user, &params.pass);
                let _ = tx.send(UiMsg::OfflineDone { ok: true, detail });
            }
            Err(e) => {
                let _ = tx.send(UiMsg::OfflineDone {
                    ok: false,
                    detail: common::redact_credentials(&e, &params.user, &params.pass),
                });
            }
        }
    });
}

/// 新版下线流程: 令牌(Web 认证接口给) → 在线设备 → 匹配本机 → 强制下线 → 清绑定
fn run_offline_new(
    params: &TaskParams,
    log: &(dyn Fn(&str) + Sync),
) -> Result<String, String> {
    // ① 令牌: 设备在线时接口照样返回令牌, 不会打扰在线会话
    let mut a = auth::Auth::new(&params.ua_kind, params.source, log);
    a.set_portal_url(Some(params.portal.clone()));
    a.set_portal_ac(&params.acip, &params.acname);
    let token = a.obtain_portal_token(&params.user, &params.pass)?;
    let base = a
        .discovered_base
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .filter(|b| !b.is_empty())
        .ok_or_else(|| "拿不到门户基地址".to_string())?;
    let api = selfsvc::PortalApi::new(params.source, &base, &token, log);
    // ② 在线设备
    let rows = api.online_users()?;
    if rows.is_empty() {
        return Ok("当前没有在线会话(可能本机已下线)".to_string());
    }
    // ③ 只下线本机(MAC 优先, 其次 IP), 绝不顶号
    let own_mac = params.mac_nosep.clone();
    let my_ip = params.source.map(|i| i.to_string()).unwrap_or_default();
    let Some(i) = selfsvc::find_own_row(&rows, &own_mac, &my_ip) else {
        return Err(format!(
            "在线列表有 {} 台设备, 但没有本机(MAC/IP 均不匹配).\n遵守「绝不顶号」原则, 未做任何下线操作.",
            rows.len()
        ));
    };
    let row = rows[i].clone();
    // ④ 强制下线
    let msg = api.force_offline(&row.ip, &row.mac)?;
    // ⑤ 清除 MAC 绑定(没有记录不算失败)
    let cleared = match api.clear_mac(&own_mac) {
        Ok(m) => m,
        Err(e) => format!("清除绑定失败(不影响下线): {e}"),
    };
    Ok(format!("{msg}; 清绑定: {cleared} (本机 {})", row.ip))
}

unsafe fn open_history_window() {
    let Some(app) = APP.get() else { return };
    let all = app
        .store
        .lock()
        .ok()
        .map(|s| s.data.log_lines.join("\r\n"))
        .unwrap_or_default();
    let cls = utf16("campus_auth_history_wnd");
    let title = utf16("历史日志(保留 7 天, 上限 2000 行)");
    // 客户区 866x564 -> 经 AdjustWindowRect 换算外框尺寸(否则标题栏挤掉底部按钮)
    let mut hrect = RECT { left: 0, top: 0, right: dp(866), bottom: dp(564) };
    AdjustWindowRect(&mut hrect, WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, 0);
    let h = CreateWindowExW(
        0,
        cls.as_ptr(),
        title.as_ptr(),
        WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN,
        120,
        120,
        hrect.right - hrect.left,
        hrect.bottom - hrect.top,
        app.hwnd(),
        std::ptr::null_mut(),
        GetModuleHandleW(std::ptr::null()),
        std::ptr::null(),
    );
    let mono = FONT_MONO.get().copied().unwrap_or(0);
    let ed = create_ctrl(
        "EDIT",
        "",
        ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | ES_LEFT,
        WS_EX_CLIENTEDGE,
        8,
        8,
        850,
        496,
        900,
        h,
        mono,
    );
    set_text(ed, &if all.is_empty() { "(暂无日志)".to_string() } else { all });
    create_ctrl(
        "BUTTON",
        "清除日志",
        BS_PUSHBUTTON | WS_TABSTOP,
        0,
        8,
        508,
        120,
        28,
        IDC_BTN_HIST_CLEAR,
        h,
        mono,
    );
    let hint = create_ctrl(
        "STATIC",
        "日志默认保留 7 天, 过期自动删除; 上限 2000 行",
        SS_LEFT,
        0,
        140,
        514,
        480,
        18,
        0,
        h,
        FONT_UI.get().copied().unwrap_or(0),
    );
    let _ = hint;
    ShowWindow(h, SW_SHOW);
    UpdateWindow(h);
}

const IDC_BTN_HIST_CLEAR: u32 = 901;

/// 历史日志窗口过程: 处理「清除日志」按钮
unsafe extern "system" fn hist_wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg == WM_COMMAND && (wparam & 0xffff) as u32 == IDC_BTN_HIST_CLEAR {
        let text = utf16("将清空全部历史日志(程序日志与认证记录), 确定?");
        let cap = utf16("确认");
        if MessageBoxW(hwnd, text.as_ptr(), cap.as_ptr(), MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2) == 6 {
            if let Some(app) = APP.get() {
                if let Ok(mut store) = app.store.lock() {
                    store.clear_logs();
                }
            }
            set_text(GetDlgItem(hwnd, 900), "(日志已清空)");
            if let Some(app) = APP.get() {
                set_text(GetDlgItem(app.hwnd(), IDC_ED_LOG as i32), "");
            }
        }
        return 0;
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

fn auth_summary(ok: bool, code: &str) -> &'static str {
    match (ok, code) {
        (true, auth::CODE_ALREADY) => "已在线",
        (true, _) => "认证成功",
        (_, "cancelled") => "认证已取消",
        (_, auth::CODE_CONFLICT) => "槽位冲突，请检查自助管理",
        (_, auth::CODE_BADPASS) => "账号或密码错误",
        (_, auth::CODE_UNTRUSTED_PORTAL) => "请确认门户地址",
        (_, auth::CODE_NO_PORTAL) => "未找到认证门户",
        (_, auth::CODE_UNREACHABLE) => "门户连接失败",
        _ => "认证失败，详见历史日志",
    }
}

unsafe fn drain_messages() {
    let Some(app) = APP.get() else { return };
    loop {
        let msg = {
            let Ok(rx) = app.rx.lock() else { return };
            match rx.try_recv() {
                Ok(m) => m,
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => return,
            }
        };
        match msg {
            UiMsg::Log(line) => {
                if let Ok(mut store) = app.store.lock() {
                    store.append_log(&line);
                }
            }
            UiMsg::Phase(stage) => {
                if let Ok(mut diag) = app.diagnostics.lock() {
                    diag.phase = Some(stage);
                }
                if let Some((_, label)) = STAGES.iter().find(|(value, _)| *value == stage) {
                    diag_event(Some(stage), label);
                }
            }
            UiMsg::OperationStarted(title) => {
                begin_operation(title);
                set_busy(true, title);
            }
            UiMsg::TestDone { verdict } => finish_operation(match verdict {
                Some(true) => "探测通过",
                Some(false) => "需要门户认证",
                None => "探测无结论",
            }),
            UiMsg::AutoLogin { reason } => auto_login(&reason),
            UiMsg::Stats { drops, reauths } => set_text(
                GetDlgItem(app.hwnd(), IDC_LBL_STATS as i32),
                &format!("掉线 {drops} 次 · 重连成功 {reauths} 次"),
            ),
            UiMsg::LoginDone { ok, code, detail } => {
                if !detail.is_empty() {
                    log_line(&detail);
                }
                finish_operation(auth_summary(ok, code));
            }
            UiMsg::ReauthDone { ok, code } => finish_operation(auth_summary(ok, code)),
            UiMsg::PortalFound { found } => {
                if let Some(base) = found {
                    set_text(GetDlgItem(app.hwnd(), IDC_ED_PORTAL as i32), &base);
                    finish_operation("已发现门户，请核对地址后认证");
                } else {
                    finish_operation("未发现门户，可手动填写地址");
                }
            }
            UiMsg::OfflineDone { ok, detail } => {
                log_line(&detail);
                finish_operation(if ok { "下线请求已完成" } else { "下线失败" });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

fn main() {
    unsafe { run_gui() };
}

unsafe fn run_gui() {
    // DPI 感知(system aware, 坐标按系统 DPI 缩放)
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_SYSTEM_AWARE);

    let instance = GetModuleHandleW(std::ptr::null());
    let dpi = GetDpiForSystem();

    // 界面字体: Microsoft YaHei UI 9pt; 日志: 同样微软雅黑(颜色浅灰,不刺眼)
    let ui_h = -(9 * dpi as i32 / 72);
    let ui_name: Vec<u16> = "Microsoft YaHei UI".encode_utf16().chain([0]).collect();
    let hfont_ui = CreateFontW(
        ui_h, 0, 0, 0, 400, 0, 0, 0,
        1, /* DEFAULT_CHARSET */
        0, 0, 5, 0, /* CLEARTYPE_QUALITY */
        ui_name.as_ptr(),
    ) as isize;
    let _ = FONT_UI.set(hfont_ui);
    let header = CreateFontW(
        -(15 * dpi as i32 / 72), 0, 0, 0, 600, 0, 0, 0,
        1, 0, 0, 5, 0, ui_name.as_ptr(),
    ) as isize;
    let _ = FONT_HEADER.set(header);
    let mono_name: Vec<u16> = "Microsoft YaHei UI".encode_utf16().chain([0]).collect();
    let hfont_mono = CreateFontW(
        ui_h, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0,
        mono_name.as_ptr(),
    ) as isize;
    let _ = FONT_MONO.set(hfont_mono);

    // 数据文件(exe 同目录, 单文件承载配置+加密凭据+日志)
    let store = Arc::new(Mutex::new(Store::load(Store::default_path())));
    if let Ok(mut s) = store.lock() {
        s.append_log("程序启动(会话开始)");
    }

    let (tx, rx) = channel::<UiMsg>();

    // 主窗口类
    let class_name: Vec<u16> = "campus_auth_main_wnd".encode_utf16().chain([0]).collect();
    let wc = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(wndproc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: instance,
        hIcon: std::ptr::null_mut(),
        hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
        hbrBackground: GetSysColorBrush(15 /* COLOR_BTNFACE 浅灰,同 tkinter */),
        lpszMenuName: std::ptr::null(),
        lpszClassName: class_name.as_ptr(),
    };
    RegisterClassW(&wc);

    // 历史日志窗口类(纯 DefWindowProc)
    let hist_class: Vec<u16> = "campus_auth_history_wnd".encode_utf16().chain([0]).collect();
    let wc2 = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(hist_wndproc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: instance,
        hIcon: std::ptr::null_mut(),
        hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
        hbrBackground: GetSysColorBrush(5),
        lpszMenuName: std::ptr::null(),
        lpszClassName: hist_class.as_ptr(),
    };
    RegisterClassW(&wc2);

    let title: Vec<u16> = "贺州学院校园网认证".encode_utf16().chain([0]).collect();
    // 客户区 720x800(比旧布局高 88: 新增「自动认证」分组)
    let mut rect = RECT { left: 0, top: 0, right: dp(918), bottom: dp(610) };
    AdjustWindowRect(&mut rect, WINDOW_STYLE, 0);

    let hwnd = CreateWindowExW(
        0,
        class_name.as_ptr(),
        title.as_ptr(),
        // WS_VISIBLE: 创建即可见 —— 之后紧接着创建的控件走"父窗口已可见"路径,
        // 主题复选框首帧绘制才完整(见 WM_CREATE 注释)
        WINDOW_STYLE | WS_VISIBLE,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        rect.right - rect.left,
        rect.bottom - rect.top,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        instance,
        std::ptr::null(),
    );

    let _ = APP.set(App {
        hwnd: hwnd as isize,
        rx: Mutex::new(rx),
        tx: Mutex::new(tx),
        store,
        adapters: Mutex::new(Vec::new()),
        busy: AtomicBool::new(false),
        config_generation: AtomicU64::new(0),
        credential_generation: AtomicU64::new(0),
        diagnostics: Mutex::new(Diagnostics::default()),
    });
    // 窗口已创建(且已 WS_VISIBLE)后再建控件: 避免 WM_CREATE 时序下主题复选框首帧残缺
    build_controls(hwnd);
    let app = APP.get().unwrap();

    // 恢复已保存的账号信息
    let (saved_user, saved_pw, saved_ua) = {
        let s = app.store.lock().unwrap();
        let pw = if s.data.save_password { s.get_password() } else { None };
        (s.data.username.clone(), pw, s.data.ua.clone())
    };
    // 恢复已保存的门户地址(留空 = 自动检测)
    let saved_portal = {
        let s = app.store.lock().unwrap();
        s.data.portal_url.clone()
    };
    if !saved_portal.is_empty() {
        set_text(GetDlgItem(hwnd, IDC_ED_PORTAL as i32), &saved_portal);
    }

    if !saved_user.is_empty() {
        set_text(GetDlgItem(hwnd, IDC_ED_USER as i32), &saved_user);
        if let Some(p) = &saved_pw {
            set_text(GetDlgItem(hwnd, IDC_ED_PASS as i32), p);
            SendMessageW(GetDlgItem(hwnd, IDC_CHK_SAVE as i32), BM_SETCHECK, BST_CHECKED as usize, 0);
        }
        if saved_ua == "mobile" {
            SendMessageW(GetDlgItem(hwnd, IDC_RB_MOBILE as i32), BM_SETCHECK, BST_CHECKED as usize, 0);
            SendMessageW(GetDlgItem(hwnd, IDC_RB_PC as i32), BM_SETCHECK, 0, 0);
        }
    }
    diag_event(None, "就绪");

    refresh_adapters(false);

    // ---- 恢复「自动认证」设置 ----
    let (auto_start, auto_reauth, interval, retries, drops, reauths) = {
        let s = app.store.lock().unwrap();
        (
            s.data.auto_start,
            s.data.auto_reauth,
            s.data.reauth_interval_secs,
            s.data.reauth_max_retries,
            s.data.drop_count,
            s.data.reauth_count,
        )
    };
    set_text(GetDlgItem(hwnd, IDC_ED_INTERVAL as i32), &interval.to_string());
    set_text(GetDlgItem(hwnd, IDC_ED_RETRIES as i32), &retries.to_string());
    set_text(
        GetDlgItem(hwnd, IDC_LBL_STATS as i32),
        &format!("掉线 {drops} 次 · 重连成功 {reauths} 次"),
    );
    if auto_reauth {
        SendMessageW(GetDlgItem(hwnd, IDC_CHK_REAUTH as i32), BM_SETCHECK, BST_CHECKED as usize, 0);
    }
    // 开机自启以注册表实际状态为准(dat 可能从别的机器拷来);
    // 已开启则顺带自愈: 把入口命令改指向当前 exe
    let reg_enabled = autostart::sync_if_enabled();
    if reg_enabled != auto_start {
        if let Ok(mut s) = app.store.lock() {
            s.data.auto_start = reg_enabled;
            s.save();
        }
        log_line(if reg_enabled {
            "检测到开机自启注册表项已开启(与数据文件不一致, 已同步)"
        } else {
            "开机自启注册表项不存在, 已同步关闭数据文件里的开关"
        });
    }
    if reg_enabled {
        SendMessageW(GetDlgItem(hwnd, IDC_CHK_AUTOSTART as i32), BM_SETCHECK, BST_CHECKED as usize, 0);
    }

    // 掉线自动重连监控(常驻线程; 开关/参数以 store 为准, 界面改动即时生效)
    spawn_reauth_monitor();

    // ---- 开机自启启动(--auto): 最小化 + 等网络就绪后自动认证 ----
    let auto_flag = std::env::args().any(|a| a == "--auto");
    if auto_flag {
        log_line("开机自动启动: 等待网络就绪后自动认证(窗口已最小化)");
        let tx_auto = app.tx.lock().unwrap().clone();
        thread::spawn(move || {
            // 等校园网网卡拿到 IPv4(开机网卡初始化可能要几秒), 最多 90 秒
            let mut ready = false;
            for _ in 0..45 {
                thread::sleep(std::time::Duration::from_secs(2));
                let Some(adapter) = APP.get().and_then(|app| app.store.lock().ok()).and_then(|store| {
                    (store.data.auto_start && store.has_usable_credentials() && trusted_portal(&store.data).is_some())
                        .then(|| store.data.adapter.clone())
                }) else {
                    return;
                };
                if auto_adapter(&adapter).is_some() {
                    ready = true;
                    break;
                }
            }
            if !ready {
                let _ = tx_auto.send(UiMsg::Log(
                    "开机自动认证: 等待 90 秒仍无可用网络, 放弃本次自动认证".into(),
                ));
                return;
            }
            thread::sleep(std::time::Duration::from_secs(1)); // 稳一秒让 AC/门户就绪
            // 仅当自启开关仍开着且凭据齐全才认证(用户可能中途取消过)
            let go = APP.get().is_some_and(|app| {
                app.store
                    .lock()
                    .map(|s| s.data.auto_start && s.has_usable_credentials() && trusted_portal(&s.data).is_some())
                    .unwrap_or(false)
            });
            if !go {
                let _ = tx_auto.send(UiMsg::Log(
                    "开机自动认证: 自启已关闭或没有保存凭据, 跳过".into(),
                ));
                return;
            }
            let _ = tx_auto.send(UiMsg::AutoLogin {
                reason: "开机自动认证".into(),
            });
        });
    }

    ShowWindow(hwnd, if auto_flag { SW_SHOWMINIMIZED } else { SW_SHOW });
    // 首帧完整重绘: 主题绘制的复选框首帧可能只画出部分边框(表现为
    // "刚打开显示不全、鼠标一放上去才完整")。用 RedrawWindow 一次性按
    // 系统正确顺序(父窗口 + 全部子控件)重绘; 注意不能用"逐个子控件
    // UpdateWindow"的循环, 那会按 z-order 反向把底层 groupbox 的背景
    // 盖到复选框上, 反而制造残缺。
    // 标志: RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW
    RedrawWindow(
        hwnd,
        std::ptr::null(),
        std::ptr::null_mut(),
        0x0001 | 0x0004 | 0x0080 | 0x0100,
    );
    SetTimer(hwnd, 1, 80, None);

    let mut msg: MSG = std::mem::zeroed();
    while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
        if IsDialogMessageW(hwnd, &msg) == 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
