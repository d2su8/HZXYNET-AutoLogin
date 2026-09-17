//! 自助管理(/self)JSON API 客户端: 在线设备列表 / 下线本设备 / 验证码解码
//!
//! 实测协议(2026-09-16, 详见 docs/PROTOCOL.md「自助管理下线接口」):
//! 1. 全部接口 POST + application/json(表单编码会被 415 拒绝), 建议 X-Requested-With
//! 2. tologin.do 下发 JSESSIONID-BOSS-1(与 web 认证同名但**独立会话**, 门户登录不贯通),
//!    login.do{accountId,password,verifyCode} 用同一 Cookie 后各接口才可用
//! 3. 响应统一 {"errcode":"0|-1","errmsg":"..","success":bool}; 未登录 errcode=-1「请重新登录」
//! 4. getonline.do rows 关键字段: accountId/accountMac/billingId/accountIp/serverIp/
//!    terminalType('a'=PC,'b'=手机)/osInfo/broswerType/onlineTime
//! 5. kickonline.do {accountId,accountIp,billingId,serverIp} → 「下线成功」, 3–4 秒内回 captive
//! 6. 设备分类是「MAC 绑定粘性」: 建绑定的那次登录按 UA 定分类, 之后同 MAC 换 UA 不变;
//!    换槽 = kickonlineByMac/clearusermac 清绑定 → 目标 UA 重登

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use crate::common::{decode_body, PORTAL_HOST, UA_PC};
use crate::net::HttpClient;

/// 本机在门户计费行中的会话记录
// 字段为门户 schema 全量映射, 部分字段仅 CLI 输出使用
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DeviceRow {
    pub account_id: String,
    pub account_mac: String,   // 形如 "BC:6E:E2:34:4F:63"
    pub billing_id: String,    // 每次会话不同, kickonline 必须用行内 live 值
    pub account_ip: String,
    pub server_ip: String,
    pub terminal_type: String, // 'a'=PC 槽, 'b'=手机槽
    pub os_info: String,
    pub online_time: String,
}

/// tologin 结果: 验证码图片 + 与其绑定的会话 Cookie
pub struct Captcha {
    pub cookie: String,
    pub png: Vec<u8>,
}

/// SPA 会话客户端(自行维护 Cookie, HttpClient 无 cookie jar)
pub struct Spa<'a> {
    client: HttpClient,
    pub cookie: String,
    log: &'a (dyn Fn(&str) + Sync),
}

struct SpaResp {
    value: Value,
    set_cookie: Option<String>,
}

impl<'a> Spa<'a> {
    pub fn new(source: Option<std::net::Ipv4Addr>, log: &'a (dyn Fn(&str) + Sync)) -> Self {
        Spa {
            client: HttpClient::new(source),
            cookie: String::new(),
            log,
        }
    }

    /// POST JSON 并解析响应; HTTP!=200 或非 JSON 一律报错(415=编码错, 400=参数/会话错)
    fn post(&self, path: &str, body: &Value) -> Result<SpaResp, String> {
        let url = format!("http://{PORTAL_HOST}/{path}");
        let body_str = body.to_string();
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if !self.cookie.is_empty() {
            headers.push(("Cookie", self.cookie.as_str()));
        }
        headers.push(("User-Agent", UA_PC));
        headers.push(("Accept", "application/json, text/plain, */*"));
        headers.push(("Content-Type", "application/json"));
        headers.push(("X-Requested-With", "XMLHttpRequest"));
        let resp = self
            .client
            .request("POST", &url, &headers, Some(&body_str))
            .map_err(|e| format!("{path} 请求失败: {e}"))?;
        let text = decode_body(&resp.body);
        if resp.status != 200 {
            let brief: String = text.chars().take(80).collect();
            return Err(format!("{path} HTTP {}: {}", resp.status, brief));
        }
        let value: Value =
            serde_json::from_str(&text).map_err(|e| format!("{path} 响应非 JSON: {e}"))?;
        let set_cookie = resp.header("Set-Cookie").map(|s| s.to_string());
        Ok(SpaResp { value, set_cookie })
    }

    fn adopt_cookie(&mut self, resp: &SpaResp) {
        if let Some(c) = &resp.set_cookie {
            let pair = c.split(';').next().unwrap_or("").trim().to_string();
            if !pair.is_empty() {
                self.cookie = pair;
            }
        }
    }

    fn check_errcode(_path: &str, v: &Value) -> Result<(), String> {
        if v["errcode"].as_str() == Some("0") {
            Ok(())
        } else {
            Err(v["errmsg"]
                .as_str()
                .unwrap_or("未知错误")
                .to_string())
        }
    }

    /// ① 取验证码(同时建立 SPA 会话); 验证码与会话绑定, 必须用返回的 cookie 提交 login
    pub fn tologin(&mut self) -> Result<Captcha, String> {
        (self.log)("自助接口: 获取验证码会话(tologin)...");
        let resp = self.post("self/tologin.do", &json!({}))?;
        Self::check_errcode("self/tologin.do", &resp.value)?;
        self.adopt_cookie(&resp);
        let b64 = resp.value["data"]["verifyCode"]
            .as_str()
            .ok_or("tologin 响应缺少验证码(data.verifyCode)")?;
        let png = B64
            .decode(b64)
            .map_err(|e| format!("验证码 base64 解码失败: {e}"))?;
        Ok(Captcha {
            cookie: self.cookie.clone(),
            png,
        })
    }

    /// ② SPA 登录(验证码人工识别后提交); 成功后当前会话升级为已登录
    pub fn login(&mut self, account: &str, password: &str, code: &str) -> Result<(), String> {
        (self.log)("自助接口: 登录自助系统(login)...");
        let resp = self.post(
            "self/login.do",
            &json!({"accountId": account, "password": password, "verifyCode": code}),
        )?;
        self.adopt_cookie(&resp);
        Self::check_errcode("self/login.do", &resp.value)
    }

    /// ③ 在线设备列表(每行即一个在线会话)
    pub fn getonline(&mut self, account: &str) -> Result<Vec<DeviceRow>, String> {
        (self.log)("自助接口: 查询在线设备(getonline)...");
        let resp = self.post("self/getonline.do", &json!({"accountId": account}))?;
        Self::check_errcode("self/getonline.do", &resp.value)?;
        let empty = Vec::new();
        let rows = resp.value["rows"].as_array().unwrap_or(&empty);
        Ok(rows
            .iter()
            .map(|r| DeviceRow {
                account_id: r["accountId"].as_str().unwrap_or("").to_string(),
                account_mac: r["accountMac"].as_str().unwrap_or("").to_string(),
                billing_id: r["billingId"].as_str().unwrap_or("").to_string(),
                account_ip: r["accountIp"].as_str().unwrap_or("").to_string(),
                server_ip: r["serverIp"].as_str().unwrap_or("").to_string(),
                terminal_type: r["terminalType"].as_str().unwrap_or("").to_string(),
                os_info: r["osInfo"].as_str().unwrap_or("").to_string(),
                online_time: r["onlineTime"].as_str().unwrap_or("").to_string(),
            })
            .collect())
    }

    /// ④ 下线指定设备(必须用 getonline 行内的 live 值; 只允许传本机行, 由调用方把关)。
    /// 注: 按行下线**不**清除 MAC 绑定; 产品流程固定走 kick_by_mac, 此接口保留以覆盖协议全集。
    #[allow(dead_code)]
    pub fn kickonline(&mut self, account: &str, row: &DeviceRow) -> Result<String, String> {
        (self.log)(&format!(
            "自助接口: 下线 {} ({}/{})...",
            row.account_ip,
            row.os_info,
            if row.terminal_type == "b" { "手机" } else { "PC" }
        ));
        let resp = self.post(
            "self/kickonline.do",
            &json!({
                "accountId": account,
                "accountIp": row.account_ip,
                "billingId": row.billing_id,
                "serverIp": row.server_ip,
            }),
        )?;
        Self::check_errcode("self/kickonline.do", &resp.value)?;
        Ok(resp.value["errmsg"].as_str().unwrap_or("下线成功").to_string())
    }

    /// ④' 按 MAC 下线并清除绑定(换设备槽位分类的唯一姿势, 见 §4.1 绑定粘性)。
    /// 只允许传本机行(调用方须先用 find_own_row 匹配)。
    pub fn kick_by_mac(&mut self, account: &str, row: &DeviceRow) -> Result<String, String> {
        (self.log)(&format!(
            "自助接口: 按 MAC 下线 {} (并清除绑定)...",
            row.account_mac
        ));
        let resp = self.post(
            "self/kickonlineByMac.do",
            &json!({
                "accountId": account,
                "accountMac": row.account_mac,
            }),
        )?;
        Self::check_errcode("self/kickonlineByMac.do", &resp.value)?;
        Ok(resp.value["errmsg"].as_str().unwrap_or("下线成功").to_string())
    }

    /// 退出自助系统(仅销毁 SPA 会话, 不影响网络在线); 用于验证码输错后的会话清理等
    pub fn logout(&mut self) {
        let _ = self.post("self/logout.do", &json!({}));
    }
}

/// MAC 归一化: 仅保留十六进制位并大写("BC-6E-.." 与 "BC:6E:.." 等价)
pub fn norm_mac(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// 在 rows 中定位「本机」会话: 先按 MAC, 再按 IP。找不到返回 None(调用方绝不能乱踢)。
pub fn find_own_row(rows: &[DeviceRow], mac_nosep: &str, ip: &str) -> Option<usize> {
    if !mac_nosep.is_empty() {
        if let Some(i) = rows
            .iter()
            .position(|r| norm_mac(&r.account_mac) == mac_nosep)
        {
            return Some(i);
        }
    }
    if !ip.is_empty() {
        if let Some(i) = rows
            .iter()
            .position(|r| r.account_ip.eq_ignore_ascii_case(ip))
        {
            return Some(i);
        }
    }
    None
}

/// 验证码 PNG 落盘(供 CLI/看图程序使用), 返回文件路径
#[allow(dead_code)] // 仅 CLI bin 使用
pub fn save_captcha_png(png: &[u8]) -> Result<std::path::PathBuf, String> {
    let path = std::env::temp_dir().join("campus-auth-captcha.png");
    std::fs::write(&path, png).map_err(|e| format!("写入验证码文件失败: {e}"))?;
    Ok(path)
}

/// 把验证码 PNG 解码为 HBITMAP(供 GUI 静态控件 STM_SETIMAGE 直接显示)。
/// 经临时文件走 GDI+(系统自带, 支持任意 PNG 变体); 失败时返回错误,
/// 调用方应回退为 save_captcha_png + ShellExecuteW 用系统看图程序打开。
#[allow(dead_code)] // 仅 GUI bin 使用
pub fn decode_png_to_hbitmap(png: &[u8]) -> Result<isize, String> {
    use windows_sys::Win32::Graphics::Gdi::HBITMAP;
    use windows_sys::Win32::Graphics::GdiPlus::{
        GdipCreateBitmapFromFile, GdipCreateHBITMAPFromBitmap, GdipDisposeImage, GdiplusShutdown,
        GdiplusStartup, GdiplusStartupInput, GpBitmap, GpImage,
    };

    // GDI+ 从文件加载, 先落临时文件
    let path = std::env::temp_dir().join("campus-auth-captcha.png");
    std::fs::write(&path, png).map_err(|e| format!("写入临时验证码失败: {e}"))?;
    let wide: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain([0])
        .collect();

    unsafe {
        let input = GdiplusStartupInput {
            GdiplusVersion: 1,
            DebugEventCallback: 0,
            SuppressBackgroundThread: 0,
            SuppressExternalCodecs: 0,
        };
        let mut token: usize = 0;
        if GdiplusStartup(&mut token, &input, std::ptr::null_mut()) != 0 {
            return Err("GDI+ 初始化失败".into());
        }
        let mut bitmap: *mut GpBitmap = std::ptr::null_mut();
        let st = GdipCreateBitmapFromFile(wide.as_ptr(), &mut bitmap);
        if st != 0 || bitmap.is_null() {
            GdiplusShutdown(token);
            return Err(format!("GDI+ 加载 PNG 失败 (status={st})"));
        }
        let mut hbmp: HBITMAP = std::ptr::null_mut();
        // 背景 0xFFFFFFFF(不透明白), 验证码本身不透明
        let st = GdipCreateHBITMAPFromBitmap(bitmap, &mut hbmp, 0xFFFF_FFFFu32);
        GdipDisposeImage(bitmap as *mut GpImage);
        GdiplusShutdown(token);
        if st != 0 || hbmp.is_null() {
            return Err(format!("GDI+ 转 HBITMAP 失败 (status={st})"));
        }
        let _ = std::fs::remove_file(&path);
        Ok(hbmp as isize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 8x8 纯色 PNG, 验证 GDI+ 解码链路(Startup/文件加载/HBITMAP 转换)整体可用
    #[test]
    fn gdiplus_decode_tiny_png() {
        const TEST_PNG: [u8; 74] = [
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x08, 0x02, 0x00, 0x00,
            0x00, 0x4b, 0x6d, 0x29, 0xdc, 0x00, 0x00, 0x00, 0x11, 0x49, 0x44, 0x41, 0x54, 0x78,
            0x9c, 0x63, 0x70, 0x68, 0x38, 0x80, 0x15, 0x31, 0x0c, 0x2d, 0x09, 0x00, 0x62, 0xf3,
            0x60, 0x01, 0x74, 0xa0, 0x94, 0xc3, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44,
            0xae, 0x42, 0x60, 0x82,
        ];
        let hbmp = decode_png_to_hbitmap(&TEST_PNG).expect("WIC 解码应成功");
        assert!(hbmp != 0);
        unsafe {
            windows_sys::Win32::Graphics::Gdi::DeleteObject(hbmp as _);
        }
    }

    #[test]
    fn mac_norm_and_row_match() {
        assert_eq!(norm_mac("bc-6e-e2-34-4f-63"), "BC6EE2344F63");
        let row = DeviceRow {
            account_id: "u".into(),
            account_mac: "BC:6E:E2:34:4F:63".into(),
            billing_id: "x".into(),
            account_ip: "10.200.0.9".into(),
            server_ip: "10.255.2.250".into(),
            terminal_type: "b".into(),
            os_info: "Android 1.x".into(),
            online_time: String::new(),
        };
        let rows = vec![row];
        assert!(find_own_row(&rows, "BC6EE2344F63", "").is_some());
        assert!(find_own_row(&rows, "", "10.200.0.9").is_some());
        assert!(find_own_row(&rows, "AABBCCDDEEFF", "").is_none());
    }
}
