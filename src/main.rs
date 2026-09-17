//! 贺州学院校园网认证 - 纯 Win32 原生 GUI(零依赖,单 exe)
#![windows_subsystem = "windows"]

mod auth;
mod common;
mod crypto;
mod net;
mod selfsvc;
mod store;

use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontW, DeleteObject, GetStockObject, GetSysColorBrush, InvalidateRect, SetBkColor,
    SetBkMode, SetTextColor, UpdateWindow, WHITE_BRUSH,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows_sys::Win32::UI::Controls::BST_CHECKED;
use windows_sys::Win32::UI::HiDpi::{
    GetDpiForSystem, SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_SYSTEM_AWARE,
};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::Win32::UI::WindowsAndMessaging::{LoadCursorW, IDC_ARROW};

use crate::net::Adapter;
use crate::store::Store;

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
const IDC_BTN_SLOTHELP: u32 = 120;
/// 给 Edit 设置灰色占位提示(windows-sys 未导出该常量)
const EM_SETCUEBANNER: u32 = 0x1501;

// 下线验证码对话框控件 ID
const IDC_CAP_IMG: u32 = 910;
const IDC_CAP_EDIT: u32 = 911;
const IDC_CAP_OK: u32 = 912;
const IDC_CAP_CANCEL: u32 = 913;
const IDC_CAP_HINT: u32 = 914;
const SS_BITMAP: u32 = 0x000E;
const SS_CENTER: u32 = 0x0001;
const STM_SETIMAGE: u32 = 0x0172;

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
const WS_GROUP: u32 = 0x0002_0000;
const EM_SETSEL: u32 = 0x00B1;
const EM_REPLACESEL: u32 = 0x00C2;
const EM_SCROLLCARET: u32 = 0x00B5;
const EM_SETPASSWORDCHAR: u32 = 0x00CC;

// ---------------------------------------------------------------------------
// 工作线程 -> UI 的消息
// ---------------------------------------------------------------------------

/// 下线流程上下文: 验证码阶段携带到对话框, 提交后交给②阶段线程
struct CaptchaCtx {
    png: Vec<u8>,
    cookie: String,
    account: String,
    password: String,
    source: Option<std::net::Ipv4Addr>,
    mac_nosep: String,
    my_ip: String,
}

enum UiMsg {
    Log(String),
    TestDone,
    LoginDone { ok: bool, code: &'static str, detail: String },
    /// 下线流程①: 验证码已取到, 弹图等待人工输入
    OfflineCaptcha { ctx: CaptchaCtx },
    /// 下线流程②: 结束(成功或失败)
    OfflineDone { ok: bool, detail: String },
    /// 门户探测结束(Some=门户基地址)
    PortalFound { found: Option<String> },
}

struct App {
    hwnd: isize,
    rx: Mutex<Receiver<UiMsg>>,
    tx: Mutex<Sender<UiMsg>>,
    store: Arc<Mutex<Store>>,
    adapters: Mutex<Vec<Adapter>>,
    busy: AtomicBool,
    /// 验证码对话框「确定」后为 true: 其 WM_DESTROY 不再回滚 busy 状态
    offline_submitting: AtomicBool,
}

impl App {
    fn hwnd(&self) -> HWND {
        self.hwnd as HWND
    }
}

static APP: OnceLock<App> = OnceLock::new();
static FONT_UI: OnceLock<isize> = OnceLock::new();
static FONT_MONO: OnceLock<isize> = OnceLock::new();
static CAPTCHA_CTX: Mutex<Option<CaptchaCtx>> = Mutex::new(None);
static CAPTCHA_BMP: AtomicIsize = AtomicIsize::new(0);
static CAPTCHA_CLASS: OnceLock<()> = OnceLock::new();

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

unsafe fn append_log_ctl(h: HWND, line: &str) {
    // 防止 Edit 无限增长: 超过约 8 万字符时裁掉前一半
    let tail = SendMessageW(h, WM_GETTEXTLENGTH, 0, 0) as i32;
    if tail > 80_000 {
        SendMessageW(h, EM_SETSEL, 0, (tail / 2) as isize);
        SendMessageW(h, 0x0303 /* WM_CLEAR */, 0, 0);
    }
    let len = SendMessageW(h, WM_GETTEXTLENGTH, 0, 0) as i32;
    SendMessageW(h, EM_SETSEL, len as usize, len as isize);
    // 每条日志自带行尾换行,保证多条日志各自成行
    let w = utf16(&format!("{line}\r\n"));
    SendMessageW(h, EM_REPLACESEL, 0, w.as_ptr() as isize);
    SendMessageW(h, EM_SCROLLCARET, 0, 0);
}

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
        x,
        y,
        w,
        h,
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
            build_controls(hwnd);
            return 0;
        }
        // 灰底主题: Static 文字背景与窗口一致; 状态标签绿色; 只读日志 Edit 白底
        WM_CTLCOLORSTATIC => {
            let hdc = wparam as windows_sys::Win32::Graphics::Gdi::HDC;
            let hctl = lparam as HWND;
            let id = GetDlgCtrlID(hctl) as u32;
            if id == IDC_LBL_STATUS {
                SetTextColor(hdc, 0x0080_00); // 绿色 (COLORREF 0x00BBGGRR)
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
        WM_TIMER => drain_messages(),
        WM_DESTROY => {
            PostQuitMessage(0);
            return 0;
        }
        _ => {}
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

unsafe fn build_controls(hwnd: HWND) {
    let font = FONT_UI.get().copied().unwrap_or(0);
    let mono = FONT_MONO.get().copied().unwrap_or(0);

    // ===== 网卡选择 =====
    create_ctrl("BUTTON", "网卡选择", BS_GROUPBOX, 0, 16, 10, 688, 116, 0, hwnd, font);
    create_ctrl("STATIC", "网卡:", SS_LEFT, 0, 32, 32, 66, 18, 0, hwnd, font);
    create_ctrl(
        "COMBOBOX",
        "",
        CBS_DROPDOWNLIST | WS_TABSTOP,
        WS_EX_CLIENTEDGE,
        104,
        30,
        440,
        240,
        IDC_ADAPTER,
        hwnd,
        font,
    );
    create_ctrl("BUTTON", "刷新", BS_PUSHBUTTON | WS_TABSTOP, 0, 556, 29, 120, 26, IDC_BTN_REFRESH, hwnd, font);
    create_ctrl(
        "STATIC",
        "正在加载网卡信息...",
        SS_LEFT,
        0,
        104,
        66,
        560,
        52,
        IDC_INFO,
        hwnd,
        font,
    );

    // ===== 账号与认证方式(账号/密码竖排,登录按钮在密码框右侧) =====
    create_ctrl("BUTTON", "账号与认证方式", BS_GROUPBOX, 0, 16, 136, 688, 158, 0, hwnd, font);
    create_ctrl("STATIC", "账号:", SS_LEFT, 0, 32, 164, 66, 18, 0, hwnd, font);
    create_ctrl(
        "EDIT",
        "",
        ES_LEFT | ES_AUTOHSCROLL | WS_TABSTOP,
        WS_EX_CLIENTEDGE,
        104,
        162,
        456,
        26,
        IDC_ED_USER,
        hwnd,
        font,
    );
    create_ctrl("STATIC", "密码:", SS_LEFT, 0, 32, 200, 66, 18, 0, hwnd, font);
    create_ctrl(
        "EDIT",
        "",
        ES_LEFT | ES_AUTOHSCROLL | ES_PASSWORD | WS_TABSTOP,
        WS_EX_CLIENTEDGE,
        104,
        198,
        456,
        26,
        IDC_ED_PASS,
        hwnd,
        font,
    );
    // 登录按钮上移, 与账号/密码两行等高(右列一个整块, 给下面的门户地址行让出空间)
    create_ctrl("BUTTON", "一键认证登录", BS_DEFPUSHBUTTON | WS_TABSTOP, 0, 572, 162, 112, 64, IDC_BTN_LOGIN, hwnd, font);

    create_ctrl(
        "BUTTON",
        "保存账号密码(加密存储)",
        BS_AUTOCHECKBOX | WS_TABSTOP,
        0,
        104,
        236,
        190,
        20,
        IDC_CHK_SAVE,
        hwnd,
        font,
    );
    create_ctrl("BUTTON", "显示", BS_AUTOCHECKBOX | WS_TABSTOP, 0, 312, 236, 60, 20, IDC_CHK_SHOW, hwnd, font);
    // 门户地址: 留空 = 靠 302 劫持自动发现; 检测不到时可点右侧按钮看手动获取步骤
    create_ctrl("STATIC", "门户地址:", SS_LEFT, 0, 32, 264, 66, 18, 0, hwnd, font);
    let ed_portal = create_ctrl(
        "EDIT",
        "",
        ES_LEFT | ES_AUTOHSCROLL | WS_TABSTOP,
        WS_EX_CLIENTEDGE,
        104,
        260,
        440,
        26,
        IDC_ED_PORTAL,
        hwnd,
        font,
    );
    // 占位提示(灰字), 不占实际内容
    {
        let cue = utf16("留空=自动检测（检测不到时点右侧「检测门户」看手动获取步骤）");
        SendMessageW(ed_portal, EM_SETCUEBANNER, 1, cue.as_ptr() as isize);
    }
    create_ctrl("BUTTON", "检测门户", BS_PUSHBUTTON | WS_TABSTOP, 0, 552, 259, 132, 28, IDC_BTN_DETECT, hwnd, font);

    create_ctrl("STATIC", "设备类型:", SS_LEFT, 0, 388, 236, 66, 18, 0, hwnd, font);
    create_ctrl(
        "BUTTON",
        "电脑端",
        BS_AUTORADIOBUTTON | WS_TABSTOP | WS_GROUP,
        0,
        456,
        234,
        76,
        20,
        IDC_RB_PC,
        hwnd,
        font,
    );
    create_ctrl(
        "BUTTON",
        "手机端",
        BS_AUTORADIOBUTTON | WS_TABSTOP,
        0,
        540,
        234,
        76,
        20,
        IDC_RB_MOBILE,
        hwnd,
        font,
    );
    // Win32 radio 创建后默认全部不选中; 显式默认选中「电脑端」,
    // 否则未选择任何设备类型时 current_ua_kind 会误判为手机端
    SendMessageW(
        GetDlgItem(hwnd, IDC_RB_PC as i32),
        BM_SETCHECK,
        BST_CHECKED as usize,
        0,
    );
    // 设备槽位说明改为「提示」按钮弹窗(原来这行静态文字会被下面的门户地址行压住)
    create_ctrl("BUTTON", "提示", BS_PUSHBUTTON | WS_TABSTOP, 0, 624, 232, 68, 22, IDC_BTN_SLOTHELP, hwnd, font);

    // ===== 操作按钮行(5 键等宽) =====
    create_ctrl("BUTTON", "联通测试", BS_PUSHBUTTON | WS_TABSTOP, 0, 24, 306, 126, 30, IDC_BTN_TEST, hwnd, font);
    create_ctrl("BUTTON", "下线本设备", BS_PUSHBUTTON | WS_TABSTOP, 0, 160, 306, 126, 30, IDC_BTN_OFFLINE, hwnd, font);
    create_ctrl("BUTTON", "历史日志", BS_PUSHBUTTON | WS_TABSTOP, 0, 296, 306, 126, 30, IDC_BTN_HISTORY, hwnd, font);
    create_ctrl("BUTTON", "清除已保存", BS_PUSHBUTTON | WS_TABSTOP, 0, 432, 306, 126, 30, IDC_BTN_CLEAR, hwnd, font);
    create_ctrl("BUTTON", "自助管理", BS_PUSHBUTTON | WS_TABSTOP, 0, 568, 306, 126, 30, IDC_BTN_SELF, hwnd, font);
    // 状态行(按钮行下方独立一行)
    create_ctrl("STATIC", "状态: 就绪", SS_LEFT, 0, 16, 346, 400, 18, IDC_LBL_STATUS, hwnd, font);

    // ===== 日志区 =====
    let ed_log = create_ctrl(
        "EDIT",
        "",
        ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL | ES_LEFT | WS_TABSTOP,
        WS_EX_CLIENTEDGE,
        28,
        374,
        664,
        296,
        IDC_ED_LOG,
        hwnd,
        mono,
    );
    SendMessageW(ed_log, 0x00C5 /* EM_SETLIMITTEXT */, 0x7FFF_FFFE, 0);
    let _ = ed_log;
}


unsafe fn handle_command(hwnd: HWND, id: u32, code: u32) {
    // 注意: 不要在这里无条件 log_line —— 日志写入日志 Edit 又会触发 EN_* 通知, 造成死循环
    match (id, code) {
        (IDC_BTN_REFRESH, _) => refresh_adapters(true),
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
        (IDC_BTN_SLOTHELP, _) => on_slot_help(),
        (IDC_BTN_LOGIN, _) => on_login(),
        (IDC_BTN_HISTORY, _) => open_history_window(),
        (IDC_BTN_CLEAR, _) => on_clear_saved(),
        (IDC_BTN_SELF, _) => {
            let url = utf16(crate::common::SELF_SERVICE_URL);
            let op = utf16("open");
            ShellExecuteW(
                hwnd,
                op.as_ptr(),
                url.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL as i32,
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
    let campus_hint = if a.is_campus() {
        "提示: 该网卡在校园网段(10.200/10.202), 适合用于认证"
    } else {
        "注意: 该网卡不在校园网段(10.200/10.202), 认证可能不适用"
    };
    set_text(
        info,
        &format!(
            "名称: {}    状态: {}    MAC: {}\r\nIPv4: {}    适配器: {}\r\n{}",
            a.name,
            a.status,
            a.mac,
            a.ipv4
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            a.desc,
            campus_hint
        ),
    );
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
    let source = adapter.ipv4.first().copied();
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
    Some(TaskParams {
        user,
        pass,
        ua_kind,
        source,
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
    thread::spawn(move || {
        let tx_log = Mutex::new(tx.clone());
        let log_fn = move |s: &str| {
            let _ = tx_log.lock().unwrap().send(UiMsg::Log(s.to_string()));
        };
        let a = auth::Auth::new(&params.ua_kind, params.source, &log_fn);
        let (conclusive, _) = a.connectivity_test();
        match conclusive {
            Some(true) => {
                let _ = tx.send(UiMsg::Log("结论: 已联网(已认证), 无需登录".into()));
            }
            Some(false) => {
                let _ = tx.send(UiMsg::Log("结论: 未认证(被门户劫持), 可执行一键认证".into()));
            }
            None => {
                let _ = tx.send(UiMsg::Log("结论: 无法判定, 网卡可能未连接或网络异常".into()));
            }
        }
        let _ = tx.send(UiMsg::TestDone);
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
    let device = if params.ua_kind == "mobile" { "手机端(手机槽)" } else { "电脑端(PC 槽)" };
    let confirm_text = format!(
        "即将使用以下配置提交登录认证:\n\n账号: {}\n网卡: {} ({})\n设备类型: {}\n保存账号密码: {}\n\n注意: 认证会占用对应设备槽位; 若槽位已被占用,\n程序只会提示手动下线, 不会自动顶号.\n\n确定继续?",
        params.user,
        params.adapter_name,
        params
            .source
            .map(|i| i.to_string())
            .unwrap_or_else(|| "自动".into()),
        device,
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
    log_line(&format!(
        "---- 一键认证: 账号={} 网卡={} 设备={} 保存={} ----",
        params.user,
        params.adapter_name,
        device,
        if params.save { "是" } else { "否" }
    ));
    let tx = app.tx.lock().unwrap().clone();
    thread::spawn(move || {
        let tx_log = Mutex::new(tx.clone());
        let log_fn = move |s: &str| {
            let _ = tx_log.lock().unwrap().send(UiMsg::Log(s.to_string()));
        };
        let mut a = auth::Auth::new(&params.ua_kind, params.source, &log_fn);
        a.set_portal_url(Some(params.portal.clone()));
        let (ok, code, detail) = a.login(&params.user, &params.pass);
        // 自动发现的成果写回数据文件(只存 scheme://host, 不含会过期的会话参数)
        let discovered = a
            .discovered_base
            .lock()
            .ok()
            .and_then(|g| g.clone());
        if let Some(app) = APP.get() {
            if let Ok(mut store) = app.store.lock() {
                let pw = if params.save { Some(params.pass.as_str()) } else { None };
                let _ = store.set_credentials(
                    &params.user,
                    pw,
                    params.save,
                    &params.ua_kind,
                    &params.adapter_name,
                );
                if let Some(base) = discovered {
                    if params.portal.trim().is_empty() {
                        let _ = tx.send(UiMsg::Log(format!("已记住门户地址: {base}")));
                        store.data.portal_url = base;
                        store.save();
                    }
                }
            }
        }
        let _ = tx.send(UiMsg::LoginDone { ok, code, detail });
    });
}

/// 设备槽位说明(原来放在界面上的静态提示, 位置被门户地址行占用后改为弹窗)
unsafe fn on_slot_help() {
    let Some(app) = APP.get() else { return };
    let text = utf16(
        "请选择要占用的设备槽位, 每个校园网账号同时只能占 1 个电脑槽 + 1 个手机槽:\n\
         \x20   · 选「电脑端」→ 认证后占用电脑槽\n\
         \x20   · 选「手机端」→ 认证后占用手机槽\n\n\
         槽位由门户按认证时的 User-Agent 判定, 并且建立 MAC 绑定后有粘性:\n\
         想换设备类型时, 建议先点「下线本设备」(会同时清除 MAC 绑定),\n\
         否则重新认证可能仍被识别为原来的槽位。\n\n\
         同类型重复登录会被判为「槽位冲突」—— 本程序不会自动顶号,\n\
         只会提示你到自助管理界面手动下线占用设备。",
    );
    let cap = utf16("设备槽位说明");
    MessageBoxW(app.hwnd(), text.as_ptr(), cap.as_ptr(), MB_ICONINFORMATION);
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
    if let Ok(mut store) = app.store.lock() {
        store.clear_credentials();
    }
    // 界面上的账号密码输入框同步清空
    set_text(GetDlgItem(app.hwnd(), IDC_ED_USER as i32), "");
    set_text(GetDlgItem(app.hwnd(), IDC_ED_PASS as i32), "");
    SendMessageW(GetDlgItem(app.hwnd(), IDC_CHK_SAVE as i32), BM_SETCHECK, 0, 0);
    log_line("已清除保存的账号密码信息");
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

/// 收集下线所需参数: 账号密码(输入框优先, 其次已保存凭据) + 选中的网卡
unsafe fn collect_offline_params() -> Option<(String, String, Adapter)> {
    let app = APP.get()?;
    let mut user = get_text(GetDlgItem(app.hwnd(), IDC_ED_USER as i32))
        .trim()
        .to_string();
    let mut pass = get_text(GetDlgItem(app.hwnd(), IDC_ED_PASS as i32));
    if user.is_empty() || pass.is_empty() {
        if let Ok(s) = app.store.lock() {
            if user.is_empty() {
                user = s.data.username.clone();
            }
            if pass.is_empty() && s.data.save_password {
                pass = s.get_password().unwrap_or_default();
            }
        }
    }
    let adapter = selected_adapter()?;
    Some((user, pass, adapter))
}

unsafe fn on_offline() {
    let Some(app) = APP.get() else { return };
    if app.busy.swap(true, Ordering::SeqCst) {
        return;
    }
    let Some((user, pass, adapter)) = collect_offline_params() else {
        app.busy.store(false, Ordering::SeqCst);
        messagebox_warn(app.hwnd(), "请先选择一块有 IPv4 地址的网卡.");
        return;
    };
    if user.is_empty() || pass.is_empty() {
        app.busy.store(false, Ordering::SeqCst);
        messagebox_warn(
            app.hwnd(),
            "下线需要账号密码登录自助系统:\n请先填写账号密码, 或使用「保存账号密码」后重试.",
        );
        return;
    }
    let confirm = format!(
        "将下线本机在校园网的在线会话, 并同时清除 MAC 绑定:\n\n账号: {}\n网卡: {} ({})\n\n流程: 自动获取验证码 → 输入图中 4 位验证码 → 下线+清绑定+复核.\n仅操作本机会话, 不会影响账号下其它设备;\n下次认证将按所选设备类型重新分类槽位.\n\n继续?",
        user,
        adapter.name,
        adapter
            .ipv4
            .first()
            .map(|i| i.to_string())
            .unwrap_or_default()
    );
    if !messagebox_yesno(app.hwnd(), &confirm, "确认下线") {
        app.busy.store(false, Ordering::SeqCst);
        log_line("用户取消了下线操作");
        return;
    }
    set_busy(true, "获取验证码...");
    log_line("---- 下线本设备: 获取验证码 ----");
    let source = adapter.ipv4.first().copied();
    let mac_nosep = selfsvc::norm_mac(&adapter.mac);
    let my_ip = adapter
        .ipv4
        .first()
        .map(|i| i.to_string())
        .unwrap_or_default();
    let tx = app.tx.lock().unwrap().clone();
    thread::spawn(move || {
        let tx_log = Mutex::new(tx.clone());
        let log_fn = move |s: &str| {
            let _ = tx_log.lock().unwrap().send(UiMsg::Log(s.to_string()));
        };
        let mut spa = selfsvc::Spa::new(source, &log_fn);
        match spa.tologin() {
            Ok(cap) => {
                let _ = tx.send(UiMsg::OfflineCaptcha {
                    ctx: CaptchaCtx {
                        png: cap.png,
                        cookie: cap.cookie,
                        account: user,
                        password: pass,
                        source,
                        mac_nosep,
                        my_ip,
                    },
                });
            }
            Err(e) => {
                let _ = tx.send(UiMsg::OfflineDone {
                    ok: false,
                    detail: format!("获取验证码失败: {e}"),
                });
            }
        }
    });
}

unsafe fn show_captcha_dialog(ctx: CaptchaCtx) {
    let Some(app) = APP.get() else { return };
    if CAPTCHA_CLASS.get().is_none() {
        let cls = cls_name();
        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(captcha_wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: GetModuleHandleW(std::ptr::null()),
            hIcon: std::ptr::null_mut(),
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            hbrBackground: GetSysColorBrush(15),
            lpszMenuName: std::ptr::null(),
            lpszClassName: cls.as_ptr(),
        };
        RegisterClassW(&wc);
        let _ = CAPTCHA_CLASS.set(());
    }
    *CAPTCHA_CTX.lock().unwrap() = Some(ctx);
    let mut rect = RECT { left: 0, top: 0, right: dp(210), bottom: dp(168) };
    AdjustWindowRect(&mut rect, WS_CAPTION | WS_SYSMENU, 0);
    let title: Vec<u16> = "下线本设备 - 输入验证码".encode_utf16().chain([0]).collect();
    let h = CreateWindowExW(
        0,
        cls_name().as_ptr(),
        title.as_ptr(),
        WS_CAPTION | WS_SYSMENU,
        120,
        120,
        rect.right - rect.left,
        rect.bottom - rect.top,
        app.hwnd(),
        std::ptr::null_mut(),
        GetModuleHandleW(std::ptr::null()),
        std::ptr::null(),
    );
    ShowWindow(h, SW_SHOW);
    UpdateWindow(h);
}

/// 类名字符串(每次调用生成, 仅需在 CreateWindowExW 调用期间有效)
fn cls_name() -> Vec<u16> {
    "campus_auth_captcha_wnd".encode_utf16().chain([0]).collect()
}

unsafe fn build_captcha_controls(hwnd: HWND) {
    let font = FONT_UI.get().copied().unwrap_or(0);
    create_ctrl("STATIC", "", SS_BITMAP, 0, 40, 12, 130, 44, IDC_CAP_IMG, hwnd, font);
    create_ctrl("STATIC", "请输入图片中的 4 位验证码", SS_CENTER, 0, 10, 64, 190, 16, IDC_CAP_HINT, hwnd, font);
    let edit = create_ctrl(
        "EDIT",
        "",
        ES_LEFT | ES_AUTOHSCROLL | WS_TABSTOP,
        WS_EX_CLIENTEDGE,
        55,
        88,
        100,
        24,
        IDC_CAP_EDIT,
        hwnd,
        font,
    );
    SendMessageW(edit, 0x00C5 /* EM_SETLIMITTEXT */, 4, 0);
    create_ctrl("BUTTON", "确定", BS_DEFPUSHBUTTON | WS_TABSTOP, 0, 22, 124, 76, 26, IDC_CAP_OK, hwnd, font);
    create_ctrl("BUTTON", "取消", BS_PUSHBUTTON | WS_TABSTOP, 0, 112, 124, 76, 26, IDC_CAP_CANCEL, hwnd, font);
    SetFocus(edit);
    // 解码验证码图并贴到静态控件; 失败则回退为系统看图程序打开
    let png = CAPTCHA_CTX
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|c| c.png.clone()));
    if let Some(png) = png {
        match selfsvc::decode_png_to_hbitmap(&png) {
            Ok(hbmp) => {
                CAPTCHA_BMP.store(hbmp, Ordering::SeqCst);
                SendMessageW(
                    GetDlgItem(hwnd, IDC_CAP_IMG as i32),
                    STM_SETIMAGE,
                    0, // IMAGE_BITMAP
                    hbmp,
                );
            }
            Err(e) => {
                let path = std::env::temp_dir().join("campus-auth-captcha.png");
                let wp: Vec<u16> = path.as_os_str().to_string_lossy().encode_utf16().chain([0]).collect();
                let op: Vec<u16> = "open".encode_utf16().chain([0]).collect();
                ShellExecuteW(hwnd, op.as_ptr(), wp.as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL as i32);
                set_text(
                    GetDlgItem(hwnd, IDC_CAP_HINT as i32),
                    "已用系统看图程序打开验证码图片",
                );
                let _ = e;
            }
        }
    }
}

unsafe extern "system" fn captcha_wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            build_captcha_controls(hwnd);
            return 0;
        }
        WM_COMMAND => {
            let id = (wparam & 0xffff) as u32;
            match id {
                IDC_CAP_OK => {
                    on_captcha_ok(hwnd);
                    return 0;
                }
                IDC_CAP_CANCEL => {
                    DestroyWindow(hwnd);
                    return 0;
                }
                _ => {}
            }
        }
        WM_CLOSE => {
            DestroyWindow(hwnd);
            return 0;
        }
        WM_DESTROY => {
            let bmp = CAPTCHA_BMP.swap(0, Ordering::SeqCst);
            if bmp != 0 {
                DeleteObject(bmp as _);
            }
            let _ = CAPTCHA_CTX.lock().unwrap().take();
            if let Some(app) = APP.get() {
                if !app.offline_submitting.load(Ordering::SeqCst) {
                    app.busy.store(false, Ordering::SeqCst);
                    set_busy(false, "就绪");
                    log_line("下线流程已取消(未提交任何请求)");
                }
            }
            return 0;
        }
        _ => {}
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

unsafe fn on_captcha_ok(hwnd: HWND) {
    let Some(app) = APP.get() else { return };
    let code = get_text(GetDlgItem(hwnd, IDC_CAP_EDIT as i32)).trim().to_string();
    if code.chars().count() < 4 {
        messagebox_warn(hwnd, "请输入完整的 4 位验证码");
        return;
    }
    let Some(ctx) = CAPTCHA_CTX.lock().ok().and_then(|mut g| g.take()) else { return };
    app.offline_submitting.store(true, Ordering::SeqCst);
    DestroyWindow(hwnd);
    set_busy(true, "下线本设备中...");
    log_line("---- 下线本设备: 提交验证码 ----");
    let tx = app.tx.lock().unwrap().clone();
    thread::spawn(move || {
        let tx_log = Mutex::new(tx.clone());
        let log_fn = move |s: &str| {
            let _ = tx_log.lock().unwrap().send(UiMsg::Log(s.to_string()));
        };
        let result = run_offline_flow(&ctx, &code, &log_fn);
        let ok = result.is_ok();
        let mut detail = match &result {
            Ok(d) => d.clone(),
            Err(e) => e.clone(),
        };
        if ok {
            thread::sleep(std::time::Duration::from_secs(3));
            let auth = auth::Auth::new("pc", ctx.source, &log_fn);
            let (conclusive, _) = auth.connectivity_test();
            match conclusive {
                Some(false) => detail.push_str("; 复核: 已断网(回到未认证状态)"),
                Some(true) => detail.push_str("; 注意: 复核显示仍在线"),
                None => {}
            }
        }
        let _ = tx.send(UiMsg::OfflineDone { ok, detail });
    });
}

/// 下线主流程②: 登录自助 → 查设备列表 → 匹配本机行 → 踢下线
fn run_offline_flow(
    ctx: &CaptchaCtx,
    code: &str,
    log: &(dyn Fn(&str) + Sync),
) -> Result<String, String> {
    let mut spa = selfsvc::Spa::new(ctx.source, log);
    spa.cookie = ctx.cookie.clone();
    spa.login(&ctx.account, &ctx.password, code)?;
    let rows = spa.getonline(&ctx.account)?;
    if rows.is_empty() {
        return Ok("当前没有在线会话(可能本机已下线)".into());
    }
    match selfsvc::find_own_row(&rows, &ctx.mac_nosep, &ctx.my_ip) {
        Some(i) => {
            let row = &rows[i];
            // 一律按 MAC 下线并清绑定: 槽位分类存在「绑定粘性」(详见 docs/PROTOCOL.md §7),
            // 清绑定后下次认证将按所选设备类型重新分类
            let msg = spa.kick_by_mac(&ctx.account, row)?;
            // 用完即弃自助会话(下线动作已完成, 不留登录态)
            spa.logout();
            Ok(format!("{} (本机 {})", msg, row.account_ip))
        }
        None => Err(format!(
            "在线列表有 {} 台设备, 但没有本机(MAC/IP 均不匹配).\n遵守「绝不顶号」原则, 未做任何下线操作.",
            rows.len()
        )),
    }
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
        WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
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
        dp(850),
        dp(496),
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

unsafe fn drain_messages() {
    let Some(app) = APP.get() else { return };
    let ed_log = GetDlgItem(app.hwnd(), IDC_ED_LOG as i32);
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
                append_log_ctl(ed_log, &line);
                if let Ok(mut s) = app.store.lock() {
                    s.append_log(&line);
                }
            }
            UiMsg::TestDone => {
                app.busy.store(false, Ordering::SeqCst);
                set_busy(false, "就绪");
            }
            UiMsg::LoginDone { ok, code, detail } => {
                app.busy.store(false, Ordering::SeqCst);
                match (ok, code) {
                    (true, auth::CODE_ALREADY) => {
                        set_busy(false, "已在线");
                        let msg = utf16("本机已在线, 无需认证.");
                        let cap = utf16("联通正常");
                        MessageBoxW(app.hwnd(), msg.as_ptr(), cap.as_ptr(), MB_ICONINFORMATION);
                    }
                    (true, _) => {
                        set_busy(false, "已上线");
                        let msg = utf16("认证成功, 已上线!");
                        let cap = utf16("认证成功");
                        MessageBoxW(app.hwnd(), msg.as_ptr(), cap.as_ptr(), MB_ICONINFORMATION);
                    }
                    (false, auth::CODE_CONFLICT) => {
                        set_busy(false, "槽位冲突");
                        let text = utf16(&format!(
                            "该设备槽位已被占用(或在线终端数超限).\n\n请打开自助管理界面手动下线占用设备后重试:\n{}\n\n(点击「自助管理」按钮可直达; 「下线本设备」可下线本机并清绑定)",
                            crate::common::SELF_SERVICE_URL
                        ));
                        let cap = utf16("槽位冲突");
                        MessageBoxW(app.hwnd(), text.as_ptr(), cap.as_ptr(), MB_ICONWARNING);
                    }
                    (false, auth::CODE_NO_PORTAL) => {
                        set_busy(false, "未找到门户");
                        let text = utf16(
                            "没有探测到校园网认证门户(可能本机不在校园网, 或该校 AC 不用 302 劫持).\n\n\
                             手动填写门户地址的办法:\n\
                             1. 用浏览器打开任意一个 http 网站, 例如\n   http://www.msftconnecttest.com/connecttest.txt\n\
                             2. 浏览器会自动跳到校园网认证页 — 把地址栏里那条地址整个复制下来\n\
                             3. 粘贴到本窗口的「门户地址」框(可以只留 http://IP 这一段), 再点「一键认证登录」\n\n\
                             填好后会自动记进数据文件, 下次不用再填.",
                        );
                        let cap = utf16("需要手动填写门户地址");
                        MessageBoxW(app.hwnd(), text.as_ptr(), cap.as_ptr(), MB_ICONWARNING);
                    }
                    (false, auth::CODE_BADPASS) => {
                        set_busy(false, "密码错误");
                        let msg = utf16("密码错误, 请检查后重试.");
                        let cap = utf16("认证失败");
                        MessageBoxW(app.hwnd(), msg.as_ptr(), cap.as_ptr(), MB_ICONERROR);
                    }
                    (false, _) => {
                        set_busy(false, "认证失败");
                        let msg = utf16(&format!("认证失败: {detail}"));
                        let cap = utf16("认证失败");
                        MessageBoxW(app.hwnd(), msg.as_ptr(), cap.as_ptr(), MB_ICONERROR);
                    }
                }
            }
            UiMsg::PortalFound { found } => {
                app.busy.store(false, Ordering::SeqCst);
                match found {
                    Some(base) => {
                        set_busy(false, &format!("门户: {base}"));
                        set_text(GetDlgItem(app.hwnd(), IDC_ED_PORTAL as i32), &base);
                        if let Ok(mut store) = app.store.lock() {
                            store.data.portal_url = base.clone();
                            store.save();
                        }
                        log_line(&format!("门户地址已填入并保存: {base}"));
                        let msg = utf16(&format!(
                            "找到门户: {base}\n\n已填进「门户地址」框并记入数据文件, 下次自动使用。"
                        ));
                        let cap = utf16("门户检测完成");
                        MessageBoxW(app.hwnd(), msg.as_ptr(), cap.as_ptr(), MB_ICONINFORMATION);
                    }
                    None => {
                        set_busy(false, "未找到门户");
                        let text = utf16(
                            "没有探测到门户劫持响应(本机可能已在线, 或该校 AC 不用 302 劫持).\n\n\
                             手动获取门户地址:\n\
                             1. 浏览器打开任意 http 网站, 例如\n   http://www.msftconnecttest.com/connecttest.txt\n\
                             2. 浏览器会跳到校园网认证页 — 把地址栏里的地址整条复制下来\n\
                             3. 粘贴到「门户地址」框, 再点「检测门户」验证, 或直接「一键认证登录」",
                        );
                        let cap = utf16("未找到门户");
                        MessageBoxW(app.hwnd(), text.as_ptr(), cap.as_ptr(), MB_ICONWARNING);
                    }
                }
            }
            UiMsg::OfflineCaptcha { ctx } => {
                set_busy(true, "等待输入验证码...");
                show_captcha_dialog(ctx);
            }
            UiMsg::OfflineDone { ok, detail } => {
                app.offline_submitting.store(false, Ordering::SeqCst);
                app.busy.store(false, Ordering::SeqCst);
                if ok {
                    set_busy(false, "已下线");
                    let msg = utf16(&format!("下线完成.\n\n{detail}"));
                    let cap = utf16("下线本设备");
                    MessageBoxW(app.hwnd(), msg.as_ptr(), cap.as_ptr(), MB_ICONINFORMATION);
                } else {
                    set_busy(false, "下线失败");
                    let msg = utf16(&format!("下线失败:\n\n{detail}"));
                    let cap = utf16("下线本设备");
                    MessageBoxW(app.hwnd(), msg.as_ptr(), cap.as_ptr(), MB_ICONERROR);
                }
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
    // 客户区 720x706
    let mut rect = RECT { left: 0, top: 0, right: dp(720), bottom: dp(704) };
    AdjustWindowRect(&mut rect, WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, 0);

    let hwnd = CreateWindowExW(
        0,
        class_name.as_ptr(),
        title.as_ptr(),
        WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
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
        offline_submitting: AtomicBool::new(false),
    });
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

    let log_ctl = GetDlgItem(hwnd, IDC_ED_LOG as i32);
    if !saved_user.is_empty() {
        set_text(GetDlgItem(hwnd, IDC_ED_USER as i32), &saved_user);
        if let Some(p) = &saved_pw {
            set_text(GetDlgItem(hwnd, IDC_ED_PASS as i32), p);
            SendMessageW(GetDlgItem(hwnd, IDC_CHK_SAVE as i32), BM_SETCHECK, BST_CHECKED as usize, 0);
        }
        if saved_ua == "mobile" {
            SendMessageW(GetDlgItem(hwnd, IDC_RB_MOBILE as i32), BM_SETCHECK, BST_CHECKED as usize, 0);
            SendMessageW(GetDlgItem(hwnd, IDC_RB_PC as i32), 0, 0, 0);
        }
        append_log_ctl(
            log_ctl,
            &format!(
                "已载入保存的账号: {saved_user}{}",
                if saved_pw.is_some() { "(含加密保存的密码)" } else { "" }
            ),
        );
    }
    // 恢复历史日志(最近 200 行)
    if let Ok(s) = app.store.lock() {
        let logs = &s.data.log_lines;
        let start = logs.len().saturating_sub(200);
        for line in &logs[start..] {
            append_log_ctl(log_ctl, line);
        }
    }
    log_line(&format!("数据文件: {}", Store::default_path().display()));
    log_line("就绪. 选择网卡 -> 输入账号密码 -> 一键认证登录.");

    refresh_adapters(false);

    ShowWindow(hwnd, SW_SHOW);
    SetTimer(hwnd, 1, 80, None);

    let mut msg: MSG = std::mem::zeroed();
    while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}
