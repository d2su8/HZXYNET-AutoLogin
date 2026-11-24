//! 认证引擎: 探测 -> GET 登录页 -> POST 表单 -> 复核放行
//!
//! 协议要点(全部实测验证,详见同目录使用说明):
//! 1. 未认证时任意 HTTP 出网请求被 AC 302 劫持到门户, query 里是会话绑定参数
//! 2. 登录 = 向带 query 的同一 URL POST 8 个配置字段 + 账号密码
//! 3. 是否上线只看复核探测的响应头(无 Location = 已放行), 不解析中文提示
//! 4. 撞槽位(已在线/超限)绝不自动顶号, 只提示手动下线

use std::thread;
use std::time::Duration;

use crate::common::{
    decode_body, extract_err_message, parse_form_fields, urlencode, BADPASS_KEYWORDS,
    detect_credential_fields, parse_form_inputs, BASE_FORM_DEFAULTS, CONFLICT_KEYWORDS, PROBE_URLS,
    UA_PC,
};
use crate::net::{HttpClient, HttpResponse};

pub enum ProbeState {
    /// 已放行(无重定向, 200/204)
    Online,
    /// 被劫持(重定向指向门户), 携带绝对 Location
    Captive(String),
    /// 网络不通
    Unreachable(String),
    /// 无结论(如 baidu http->https 的正常 302)
    Inconclusive,
    Mixed,
}

/// 认证结果代码
pub const CODE_ALREADY: &str = "already";
pub const CODE_OK: &str = "ok";
pub const CODE_BADPASS: &str = "badpass";
pub const CODE_CONFLICT: &str = "conflict";
pub const CODE_UNREACHABLE: &str = "unreachable";
/// 探测不到门户且未配置门户地址(需用户手动填写)
pub const CODE_NO_PORTAL: &str = "no-portal";
pub const CODE_UNTRUSTED_PORTAL: &str = "untrusted-portal";
pub const CODE_FAIL: &str = "fail";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthStage {
    Probe,
    Portal,
    Submit,
    Verify,
}

pub struct Auth<'a> {
    /// 完整 User-Agent 串
    pub ua: String,
    /// 是否手机端(随机 UA 下不能用 ua==UA_MOBILE 判断)
    pub is_mobile: bool,
    pub client: HttpClient,
    pub log: &'a (dyn Fn(&str) + Sync),
    /// 手动指定的门户地址(留空/None = 只用劫持自动发现);
    /// 可填基地址(http://10.10.0.1)或从浏览器抄来的完整登录页地址
    pub portal_url: Option<String>,
    trusted_origin: Option<String>,
    cancelled: Option<&'a (dyn Fn() -> bool + Sync)>,
    progress: Option<&'a (dyn Fn(AuthStage) + Sync)>,
    /// 本次认证实际用到的门户基地址(供上层写回配置)
    pub discovered_base: std::sync::Mutex<Option<String>>,
    /// 新版门户登录后返回的自助后台令牌(Bearer), 供下线流程复用;
    /// 老板牌门户(表单式)没有这个, 保持 None
    pub token: std::sync::Mutex<Option<String>>,
    /// 上次从劫持 URL / 登录页学到的网关参数 (wlanacip, wlanacname), 供在线时复用
    pub discovered_ac: std::sync::Mutex<Option<(String, String)>>,
    /// 配置里保存的网关参数兜底(设备在线、拿不到劫持 URL 时用)
    pub ac_hint: Option<(String, String)>,
}

/// Compare the scheme, host, and effective port. Reject ambiguous authorities.
pub fn portal_origin(url: &str) -> Option<String> {
    if url.bytes().any(|b| b.is_ascii_control() || b.is_ascii_whitespace() || b == b'\\') {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().ok().filter(|p| *p != 0)?),
        None => (authority, default_port),
    };
    if host.is_empty() || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)) {
        return None;
    }
    let host = host.to_ascii_lowercase();
    Some(if port == default_port {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    })
}

fn join_portal_location(url: &str, location: &str) -> Option<String> {
    let origin = portal_origin(url)?;
    let location = location.trim();
    if location.is_empty() || location.starts_with('#') {
        return None;
    }
    let joined = if location.starts_with("//") {
        format!("{}:{location}", origin.split(':').next()?)
    } else if location.starts_with('/') {
        format!("{origin}{location}")
    } else if location.split('/').next()?.contains(':') {
        location.to_string()
    } else {
        let authority = url.split_once("://")?.1;
        let path_index = authority.find(['/', '?', '#']).unwrap_or(authority.len());
        let path = authority[path_index..].split(['?', '#']).next()?;
        if location.starts_with('?') {
            format!("{origin}{path}{location}")
        } else {
            let directory = path.rsplit_once('/').map(|(parent, _)| parent).unwrap_or("");
            format!("{origin}{directory}/{location}")
        }
    };
    portal_origin(&joined).map(|_| joined)
}

fn probe_response_is_online(host: &str, path: &str, status: u16, body: &[u8]) -> bool {
    match (host, path) {
        ("www.msftconnecttest.com", "/connecttest.txt") =>
            status == 200 && String::from_utf8_lossy(body).trim() == "Microsoft Connect Test",
        ("connect.rom.miui.com", "/generate_204") => status == 204 && body.is_empty(),
        _ => status == 200 || status == 204,
    }
}

fn summarize_probes(states: impl IntoIterator<Item = ProbeState>) -> ProbeState {
    let mut online = false;
    let mut captive: Option<String> = None;
    let mut error = None;
    for state in states {
        match state {
            ProbeState::Online => online = true,
            ProbeState::Captive(url) => {
                if captive.as_ref().is_some_and(|first| portal_origin(first) != portal_origin(&url)) {
                    return ProbeState::Mixed;
                }
                captive.get_or_insert(url);
            }
            ProbeState::Unreachable(msg) => { error.get_or_insert(msg); }
            _ => {}
        }
    }
    match (online, captive, error) {
        (true, Some(_), _) => ProbeState::Mixed,
        (true, None, _) => ProbeState::Online,
        (false, Some(url), _) => ProbeState::Captive(url),
        (false, None, Some(msg)) => ProbeState::Unreachable(msg),
        _ => ProbeState::Inconclusive,
    }
}

/// 取 URL 里的主机名(不含 scheme/端口/路径)
pub fn url_host(url: &str) -> &str {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let end = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    let hostport = &rest[..end];
    // 去掉端口
    match hostport.find(':') {
        Some(i) => &hostport[..i],
        None => hostport,
    }
}

/// 取 URL 的"基地址" scheme://host[:port], 用于写回配置(不含会话参数)
pub fn url_base(url: &str) -> String {
    let scheme = if url.starts_with("https://") { "https" } else { "http" };
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let end = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    format!("{scheme}://{}", &rest[..end])
}

/// 判断某个 302 Location 是否属于"被门户劫持", 并归一化成可直接请求的绝对地址。
///
/// 判定规则(不依赖任何具体学校):
/// - 相对路径 `/xxx` → 劫持(AC 常见写法), 按请求所用的主机补全
/// - 绝对地址:
///   - 主机与"我们请求的主机"相同 → **不是**劫持(正常跳转, 如 http→https、加/去 www)
///   - 主机不同 → 是劫持(对 msftconnecttest/miui/baidu 这类探测地址, 正常服务器不会跳到别的域)
///
/// 返回 Some(绝对地址) = 被劫持; None = 正常跳转
pub fn captive_target(requested_host: &str, loc: &str) -> Option<String> {
    let loc = loc.trim();
    let url = join_portal_location(&format!("http://{requested_host}/"), loc)?;
    if loc.starts_with('/') && !loc.starts_with("//") {
        return Some(url);
    }
    if url_host(&url).eq_ignore_ascii_case(url_host(requested_host)) {
        return None;
    }
    Some(url)
}

/// 本次要探测的地址表: 默认用内置 3 个;
/// 环境变量 CAMPUS_AUTH_PROBE 可覆盖(逗号分隔, 形如 "127.0.0.1:8123/portal" 或 "host/path"),
/// 供测试(指向本地假门户)或换用自己的探测地址。
pub fn probe_targets() -> Vec<(String, String)> {
    if let Ok(v) = std::env::var("CAMPUS_AUTH_PROBE") {
        let list: Vec<(String, String)> = v
            .split(',')
            .filter_map(|s| {
                let s = s.trim();
                if s.is_empty() {
                    return None;
                }
                match s.find('/') {
                    Some(i) => Some((s[..i].to_string(), s[i..].to_string())),
                    None => Some((s.to_string(), "/".to_string())),
                }
            })
            .collect();
        if !list.is_empty() {
            return list;
        }
    }
    PROBE_URLS
        .iter()
        .map(|(h, p)| (h.to_string(), p.to_string()))
        .collect()
}

/// 取 URL query 中某个参数的值(百分号解码)。也接受相对路径形式 `?a=1&b=2`。
pub fn query_param(url: &str, key: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    for kv in q.split('&') {
        let (k, v) = match kv.split_once('=') {
            Some(x) => x,
            None => (kv, ""),
        };
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

/// 百分号解码(+ 视作空格), 错误序列按原样保留
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        if b[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(b[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// 该地址是否像门户登录页(含 password 输入框或门户特征词)
pub fn looks_like_portal_page(html: &str) -> bool {
    let lower = html.to_ascii_lowercase();
    if lower.contains("type=\"password\"") || lower.contains("type='password'") {
        return true;
    }
    // 没有 password 框时退一步看特征词(门户首页/跳转页)
    ["wlanuserip", "portal", "login.do", "self/index", "bossweb", "石斧"]
        .iter()
        .any(|k| lower.contains(k))
}

/// 真实手机型号池(知名旗舰/主流机型)
/// 全部 6 款均已实测(2026-09-16, 实机对门户逐个发送): 门户均正确下发
/// 手机模板 templatetype=2; 无 Mobile 标记/无机型名的 Linux UA 也判为手机,
/// 判定依据是 Linux/Android 标记而非机型库, 冷门机型不受「未被识别回退电脑」影响
const MOBILE_DEVICES: [&str; 6] = [
    "Pixel 7",
    "Pixel 7 Pro",
    "SM-S911B",      // Samsung Galaxy S24
    "SM-S916B",      // Samsung Galaxy S23 Ultra
    "Pixel 8",
    "SM-A546B",      // Samsung Galaxy A54
];

/// 手机端随机 UA: 机型随机, 其余分量与实测可识别的基准 UA 完全一致
fn random_mobile_ua() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
        .unwrap_or(12345);
    let idx = (seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407)
        % MOBILE_DEVICES.len() as u64) as usize;
    let device = MOBILE_DEVICES[idx];
    format!(
        "Mozilla/5.0 (Linux; Android 13; {}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        device
    )
}

impl<'a> Auth<'a> {
    pub fn new(
        ua_kind: &str,
        source: Option<std::net::Ipv4Addr>,
        log: &'a (dyn Fn(&str) + Sync),
    ) -> Self {
        let ua = match ua_kind {
            // 每次登录生成随机手机端标识(真实机型池), 降低被按 UA 指纹识别的概率
            "mobile" => random_mobile_ua(),
            "pc" => UA_PC.to_string(),
            other => other.to_string(), // 自定义 UA
        };
        let is_mobile = ua_kind == "mobile" || (ua_kind != "pc" && ua.contains("Mobile"));
        Auth {
            ua,
            is_mobile,
            client: HttpClient::new(source),
            log,
            portal_url: None,
            trusted_origin: None,
            progress: None,
            cancelled: None,
            discovered_base: std::sync::Mutex::new(None),
            token: std::sync::Mutex::new(None),
            discovered_ac: std::sync::Mutex::new(None),
            ac_hint: None,
        }
    }

    /// 设置手动门户地址(空串/None = 只用劫持自动发现)
    pub fn set_portal_url(&mut self, url: Option<String>) {
        self.portal_url = url.filter(|s| !s.trim().is_empty()).map(|url| {
            if url.contains("://") { url } else { format!("http://{url}") }
        });
        self.trusted_origin = self.portal_url.as_deref().and_then(portal_origin);
    }

    pub fn set_progress(&mut self, progress: &'a (dyn Fn(AuthStage) + Sync)) {
        self.progress = Some(progress);
    }

    pub fn set_cancelled(&mut self, cancelled: &'a (dyn Fn() -> bool + Sync)) {
        self.cancelled = Some(cancelled);
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.is_some_and(|cancelled| cancelled())
    }

    fn mark(&self, stage: AuthStage) {
        if let Some(report) = self.progress {
            report(stage);
        }
    }

    /// 设置网关参数兜底(配置里存下来的 wlanacip/wlanacname)
    pub fn set_portal_ac(&mut self, acip: &str, acname: &str) {
        let a = acip.trim();
        let n = acname.trim();
        if !a.is_empty() && !n.is_empty() {
            self.ac_hint = Some((a.to_string(), n.to_string()));
        }
    }

    pub fn device_label(&self) -> &'static str {
        if self.is_mobile {
            "手机端"
        } else {
            "电脑端"
        }
    }

    /// 单 URL 探测
    fn probe_one(&self, host: &str, path: &str) -> ProbeState {
        match self.client.request("GET", &format!("http://{host}{path}"), &[("Accept", "*/*")], None)
        {
            Ok(resp) => {
                if let Some(loc) = resp.header("Location").filter(|_| (300..400).contains(&resp.status)) {
                    // 跨主机/相对路径 => 被劫持; 同主机跳转(如 baidu->https) => 无结论
                    return match captive_target(host, loc) {
                        Some(url) if portal_origin(&url).is_some() => ProbeState::Captive(url),
                        _ => ProbeState::Inconclusive,
                    };
                }
                if resp.header("Location").is_none() && probe_response_is_online(host, path, resp.status, &resp.body) {
                    return ProbeState::Online;
                }
                ProbeState::Inconclusive
            }
            Err(e) => ProbeState::Unreachable(e),
        }
    }

    /// 跟随跳转抓取登录页, 返回 (最终 URL, HTML, Cookie)。最多 3 跳。
    /// 相对 Location 按当前 URL 补全, 因此不再依赖任何写死的门户地址。
    fn fetch_login_page(&self, start_url: &str, trusted_origin: Option<&str>) -> Result<(String, String, String), String> {
        let mut url = start_url.to_string();
        for hop in 0..3 {
            let origin = portal_origin(&url).ok_or("门户地址无效")?;
            if trusted_origin.is_some_and(|trusted| trusted != origin) {
                return Err(format!("门户跳转到了未确认的地址 {origin}"));
            }
            let resp = self.client.request(
                "GET",
                &url,
                &[
                    ("User-Agent", self.ua.as_str()),
                    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                    ("Accept-Language", "zh-CN,zh;q=0.9"),
                ],
                None,
            )?;
            if let Some(loc) = resp.header("Location").filter(|_| (300..400).contains(&resp.status)) {
                let next = join_portal_location(&url, loc).ok_or("门户跳转地址无效")?;
                url = next;
                if hop == 2 {
                    return Err("跳转次数过多, 未拿到登录页".into());
                }
                continue;
            }
            if resp.status != 200 {
                return Err(format!("登录页 HTTP {}", resp.status));
            }
            let html = decode_body(&resp.body);
            let cookie = resp
                .header("Set-Cookie")
                .and_then(|c| c.split(';').next())
                .unwrap_or("")
                .trim()
                .to_string();
            return Ok((url, html, cookie));
        }
        Err("未拿到登录页".into())
    }

    fn run_probes(&self) -> ProbeState {
        thread::scope(|scope| {
            let tasks: Vec<_> = probe_targets().into_iter()
                .map(|(host, path)| scope.spawn(move || self.probe_one(&host, &path)))
                .collect();
            summarize_probes(tasks.into_iter().map(|task| task.join().unwrap_or(ProbeState::Inconclusive)))
        })
    }

    pub fn connectivity_test(&self) -> (Option<bool>, String) {
        let (verdict, detail) = match self.run_probes() {
            ProbeState::Online => (Some(true), "探测通过".into()),
            ProbeState::Captive(url) => (Some(false), url_base(&url)),
            ProbeState::Mixed => (None, "探测结果冲突，暂缓认证".into()),
            ProbeState::Unreachable(e) => (None, e),
            ProbeState::Inconclusive => (None, "所有探测地址均无结论".into()),
        };
        (self.log)(&detail);
        (verdict, detail)
    }

    /// 只做"找认证服务器": 探测劫持(或验证已配置的门户地址), 返回门户基地址。
    /// 用于 `--detect-portal` 与界面「检测门户」, 不登录、不改任何状态。
    pub fn detect_portal(&self) -> Option<String> {
        for (host, path) in probe_targets() {
            if let ProbeState::Captive(url) = self.probe_one(&host, &path) {
                (self.log)(&format!("探测 {host}{path} -> 302 被劫持: {url}"));
                let base = url_base(&url);
                match self.fetch_login_page(&url, None) {
                    Ok((final_url, html, _)) => {
                        (self.log)(&format!(
                            "  登录页{} (最终地址 {final_url})",
                            if looks_like_portal_page(&html) { "正常" } else { "内容不像门户登录页" }
                        ));
                    }
                    Err(e) => (self.log)(&format!("  登录页抓取失败: {e}")),
                }
                return Some(base);
            }
        }
        // 没有劫持响应: 验证配置里的地址
        if let Some(p) = self.portal_url.as_deref() {
            (self.log)(&format!("无劫持响应, 验证配置的门户地址: {p}"));
            if let Ok((final_url, html, _)) = self.fetch_login_page(p, None) {
                (self.log)(&format!(
                    "  可达, {} (最终地址 {final_url})",
                    if looks_like_portal_page(&html) { "像门户登录页" } else { "内容不像门户登录页" }
                ));
                return Some(url_base(&final_url));
            }
        }
        None
    }

    /// 取自助后台令牌(下线流程用): 优先复用本次已拿到的; 否则重新探测门户 → 抓登录页 → 调认证接口。
    /// 设备已在线时接口也会返回令牌(提示放在 redirect.errorMsg), 不会打扰在线会话。
    pub fn obtain_portal_token(&self, username: &str, password: &str) -> Result<String, String> {
        if let Ok(g) = self.token.lock() {
            if let Some(t) = g.as_ref() {
                if !t.is_empty() {
                    return Ok(t.clone());
                }
            }
        }
        let origin = self.trusted_origin.as_deref().ok_or("请先确认门户地址")?;
        let loc = match self.run_probes() {
            ProbeState::Captive(url) => url,
            ProbeState::Mixed => return Err("探测结果冲突，已暂停下线".into()),
            _ => self.portal_url.clone().ok_or("请先确认门户地址")?,
        };
        let (final_url, html, _cookie) = self.fetch_login_page(&loc, Some(origin))?;
        if let Ok(mut g) = self.discovered_base.lock() {
            *g = Some(origin.to_string());
        }
        let fields = parse_form_fields(&html);
        let (uf, pf) = detect_credential_fields(&parse_form_inputs(&html));
        if pf.is_some() {
            return Err("该校门户仍是旧版表单式(没有自助令牌机制), 下线请用门户自己的自助管理页面".into());
        }
        let _ = uf;
        let mut errmsg = String::new();
        if let Err((code, msg)) = self.login_spa(&final_url, &fields, username, password, &mut errmsg) {
            return Err(format!("{msg}({code})"));
        }
        self.token
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .filter(|t| !t.is_empty())
            .ok_or_else(|| "门户没有返回自助令牌".to_string())
    }

    /// 新版门户(SPA)登录: POST {base}/portal/webauth/auth (表单编码, 响应 JSON)。
    /// Ok(true)  = 本机已在线(门户把提示放在 redirect 的 errorMsg 里), 视为成功;
    /// Ok(false) = 已受理, 交给上层做放行复核;
    /// Err(code, msg) = 失败(密码错/槽位冲突/其它)
    fn login_spa(
        &self,
        loc: &str,
        fields: &[(String, String)],
        username: &str,
        password: &str,
        errmsg_out: &mut String,
    ) -> Result<bool, (&'static str, String)> {
        let base = url_base(loc);
        let auth_url = format!("{base}/portal/webauth/auth");
        // 会话参数: 优先登录页隐藏域(#portalLegacyParams), 否则从劫持 Location 的 query 取
        let get = |k: &str| -> String {
            let v = fields
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
                .filter(|v| !v.is_empty())
                .or_else(|| query_param(loc, k))
                .unwrap_or_default();
            if !v.is_empty() {
                return v;
            }
            // 设备在线(拿不到劫持 URL)时用配置里记住的网关参数兜底
            match (k, self.ac_hint.as_ref()) {
                ("wlanacip", Some((a, _))) => a.clone(),
                ("wlanacname", Some((_, n))) => n.clone(),
                _ => String::new(),
            }
        };
        let (ip, acip, acname) = (get("wlanuserip"), get("wlanacip"), get("wlanacname"));
        if !acip.is_empty() && !acname.is_empty() {
            if let Ok(mut g) = self.discovered_ac.lock() {
                *g = Some((acip.clone(), acname.clone()));
            }
        }
        let mut pairs: Vec<(String, String)> = vec![
            ("userId".to_string(), username.to_string()),
            ("passwd".to_string(), password.to_string()),
            ("loginMode".to_string(), "password".to_string()),
            ("wlanuserip".to_string(), ip.clone()),
            ("wlanacip".to_string(), acip.clone()),
            ("wlanacname".to_string(), acname.clone()),
        ];
        let distoken = get("distoken");
        if !distoken.is_empty() {
            pairs.push(("distoken".to_string(), distoken));
        }
        let body = pairs
            .iter()
            .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
            .collect::<Vec<_>>()
            .join("&");
        (self.log)("  检测到新版门户(SPA, 登录页无表单), 走接口 /portal/webauth/auth");
        (self.log)("提交新版门户认证请求");
        let headers = [
            ("User-Agent", self.ua.as_str()),
            ("Accept", "application/json, text/plain, */*"),
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Referer", loc),
            ("Origin", base.as_str()),
        ];
        if self.is_cancelled() {
            return Err(("cancelled", "认证已取消".into()));
        }
        self.mark(AuthStage::Submit);
        let resp = self
            .client
            .request("POST", &auth_url, &headers, Some(&body))
            .map_err(|e| (CODE_UNREACHABLE, format!("接口请求失败: {e}")))?;
        let text = decode_body(&resp.body);
        (self.log)(&format!(
            "第 3 步完成: 接口 HTTP {} ({} 字节)",
            resp.status,
            resp.body.len()
        ));
        let v: serde_json::Value = serde_json::from_str(text.trim()).map_err(|e| {
            (
                CODE_FAIL,
                format!("接口响应不是 JSON({e}): {}", text.chars().take(160).collect::<String>()),
            )
        })?;
        let success = v["success"].as_bool().unwrap_or(false);
        let message = v["message"].as_str().unwrap_or("").to_string();
        if !success {
            (self.log)(&crate::common::redact_credentials(&format!("门户返回: {message}"), username, password));
            if message.contains("密码") || BADPASS_KEYWORDS.iter().any(|k| message.contains(k)) {
                return Err((CODE_BADPASS, message));
            }
            if CONFLICT_KEYWORDS.iter().any(|k| message.contains(k)) {
                (self.log)("!! 检测到槽位冲突(已在线/终端数超限类)");
                self.print_manual_offline_advice();
                return Err((CODE_CONFLICT, message));
            }
            return Err((CODE_FAIL, message));
        }
        let result = &v["result"];
        if let Some(tok) = result["token"].as_str() {
            if !tok.is_empty() {
                if let Ok(mut g) = self.token.lock() {
                    *g = Some(tok.to_string());
                }
                (self.log)("  已取得自助后台令牌(可用于下线本设备)");
            }
        }
        if let Some(e) = result["redirect"].as_str().and_then(|r| query_param(r, "errorMsg")) {
            (self.log)(&crate::common::redact_credentials(&format!("门户返回消息: {e}"), username, password));
            *errmsg_out = e.clone();
            if e.contains("已在线") {
                (self.log)("本机已在线, 无需重复认证");
                return Ok(true);
            }
        } else if !message.is_empty() {
            *errmsg_out = message;
        }
        Ok(false)
    }

    /// 完整登录流程. 返回 (成功?, code, detail)
    pub fn login(&self, username: &str, password: &str) -> (bool, &'static str, String) {
        if self.is_cancelled() {
            return (false, "cancelled", "认证已取消".into());
        }
        self.mark(AuthStage::Probe);
        let loc = match self.run_probes() {
            ProbeState::Online => return (true, CODE_ALREADY, "已在线".into()),
            ProbeState::Mixed => return (false, CODE_FAIL, "探测结果冲突，暂缓认证".into()),
            ProbeState::Captive(url) => Some(url),
            _ => self.portal_url.clone(),
        };
        let Some(loc) = loc else {
            return (false, CODE_NO_PORTAL, "未发现认证门户".into());
        };
        if self.is_cancelled() {
            return (false, "cancelled", "认证已取消".into());
        }
        self.mark(AuthStage::Portal);
        let candidate = portal_origin(&loc).unwrap_or_default();
        let Some(origin) = self.trusted_origin.as_deref().filter(|trusted| *trusted == candidate) else {
            return (false, CODE_UNTRUSTED_PORTAL, format!("请确认门户地址 {candidate}"));
        };
        let (loc, page_text, cookie) = match self.fetch_login_page(&loc, Some(origin)) {
            Ok(page) => page,
            Err(e) => return (false, CODE_UNREACHABLE, format!("门户连接失败: {e}")),
        };
        if let Ok(mut g) = self.discovered_base.lock() {
            *g = Some(origin.to_string());
        }
        if cookie.is_empty() {
            (self.log)("第 2 步完成: 门户未下发 Cookie, 继续尝试");
        } else {
            (self.log)(&format!(
                "第 2 步完成: 已取得会话 Cookie ({})",
                cookie.split('=').next().unwrap_or("?")
            ));
        }

        let fields = parse_form_fields(&page_text);
        let get_field = |name: &str| -> Option<String> {
            fields
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };
        let host_ip = get_field("hostIp").unwrap_or_else(|| {
            BASE_FORM_DEFAULTS
                .iter()
                .find(|(k, _)| *k == "hostIp")
                .unwrap()
                .1
                .to_string()
        });
        (self.log)(&format!("  登录页字段: hostIp={host_ip}"));

        let page_err = extract_err_message(&page_text);
        if !page_err.is_empty() {
            (self.log)(&crate::common::redact_credentials(&format!("注意: 登录页自带提示信息: {page_err}"), username, password));
        }

        // 门户按本次请求 UA 下发的模板类型(设备类型判定的直接证据)
        let page_tt = get_field("templatetype");
        let served_mobile = page_text.contains("uploads/mobile/");
        let served_pc = page_text.contains("uploads/pc/");
        let template_label = if served_mobile {
            "手机模板"
        } else if served_pc {
            "电脑模板"
        } else {
            "未知模板"
        };
        (self.log)(&format!(
            "  门户按本次 UA 下发: {template_label} (页面 templatetype={})",
            page_tt.unwrap_or_else(|| "?".into())
        ));
        if self.is_mobile && served_pc {
            (self.log)("  !! 警告: 手机端 UA 却被门户下发电脑模板, 设备类型可能被判为电脑");
        }

        // ---- 第 3 步: POST 登录 ------------------------------------------
        // 新版门户(SPA: 登录页只是个 JS 外壳, 没有表单)走接口 /portal/webauth/auth;
        // 老板牌表单式门户仍按页面字段构造表单提交。判据 = 页面里有没有 password 输入框。
        let inputs = parse_form_inputs(&page_text);
        let (uf_opt, pf_opt) = detect_credential_fields(&inputs);
        let mut errmsg = String::new();
        if pf_opt.is_none() {
            match self.login_spa(&loc, &fields, username, password, &mut errmsg) {
                Ok(true) => return (true, CODE_ALREADY, errmsg),
                Ok(false) => {}
                Err((code, msg)) => return (false, code, msg),
            }
        } else {
        // 注意: 门户(Java Servlet)的 getParameter 对字段名大小写敏感,
        // 字段名必须使用页面原始大小写(serverIp/hostIp/isBindMac1...),
        // 因此以【页面解析到的原始键名】为准, BASE_FORM_DEFAULTS 仅作值兜底
        // 与 Python 版完全对齐: 按【页面 input 出现顺序】构造表单,
        // 键名保留页面原始大小写(门户 getParameter 大小写敏感);
        // B 组默认值仅在页面缺失该字段时兜底
        let mut form_pairs: Vec<(String, String)> = fields.clone();
        for (base_k, dv) in BASE_FORM_DEFAULTS {
            if !form_pairs
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case(base_k))
            {
                form_pairs.push((base_k.to_string(), dv.to_string()));
            }
        }
        // 模板类型按设备类型显式指定: 门户按 UA 下发模板(手机UA=2/PC UA=1),
        // 显式写入以避免登录页动态值缺失时默认值(1=PC)覆盖手机端身份
        let tt = if self.is_mobile { "2" } else { "1" };
        if let Some(pair) = form_pairs
            .iter_mut()
            .find(|(k, _)| k.eq_ignore_ascii_case("templatetype"))
        {
            pair.1 = tt.to_string();
        }
        (self.log)(&format!("  认证身份: 设备={} templatetype={}", self.device_label(), tt));
        // 账号/密码字段名按登录页推断(老板牌是 userId/passwd, 别家门户可能叫 account/pwd/username...),
        // 推不出来时才回退到老板牌的固定名 —— 这样换学校也不用改代码
        let user_field = uf_opt.unwrap_or_else(|| "userId".to_string());
        let pass_field = pf_opt.unwrap_or_else(|| "passwd".to_string());
        (self.log)(&format!("  表单身份字段: 账号={user_field} 密码={pass_field}"));
        if let Some(pair) = form_pairs.iter_mut().find(|(k, _)| *k == user_field) {
            pair.1 = username.to_string();
        } else {
            form_pairs.push((user_field.clone(), username.to_string()));
        }
        if let Some(pair) = form_pairs.iter_mut().find(|(k, _)| *k == pass_field) {
            pair.1 = password.to_string();
        } else {
            form_pairs.push((pass_field.clone(), password.to_string()));
        }
        let body = form_pairs
            .iter()
            .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
            .collect::<Vec<_>>()
            .join("&");
        (self.log)(&format!("旧版表单已解析（{} 个字段）", form_pairs.len()));

        let headers = [
            ("User-Agent", self.ua.as_str()),
            ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            ("Accept-Language", "zh-CN,zh;q=0.9"),
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Referer", loc.as_str()),
            ("Cookie", cookie.as_str()),
        ];
        if self.is_cancelled() {
            return (false, "cancelled", "认证已取消".into());
        }
        self.mark(AuthStage::Submit);
        let resp: HttpResponse = match self.client.request("POST", &loc, &headers, Some(&body)) {
            Ok(r) => r,
            Err(e) => {
                (self.log)(&format!("!! 提交认证请求失败: {e}"));
                return (false, CODE_FAIL, format!("POST 失败: {e}"));
            }
        };
        (self.log)(&format!(
            "第 3 步完成: 认证请求已提交 (HTTP {}, {} 字节)",
            resp.status,
            resp.body.len()
        ));

        let resp_text = decode_body(&resp.body);
        errmsg = extract_err_message(&resp_text);
        if !errmsg.is_empty() {
            (self.log)(&crate::common::redact_credentials(&format!("门户返回消息: {errmsg}"), username, password));
            if BADPASS_KEYWORDS.iter().any(|k| errmsg.contains(k)) {
                return (false, CODE_BADPASS, errmsg);
            }
            if CONFLICT_KEYWORDS.iter().any(|k| errmsg.contains(k)) {
                (self.log)("!! 检测到槽位冲突(已在线/终端数超限类)");
                self.print_manual_offline_advice();
                return (false, CODE_CONFLICT, errmsg);
            }
            // 其余消息(如「正在进行外网拨号请稍候...」)视为进行中, 继续复核
        } else {
            (self.log)("  门户未返回错误消息, 视为受理");
        }

        } // 结束: 表单式门户分支

        self.mark(AuthStage::Verify);
        for attempt in 1..=2 {
            if self.is_cancelled() {
                return (false, "cancelled", "认证已取消".into());
            }
            (self.log)(&format!(
                "第 4 步: 等待 3 秒后复核放行 (第 {attempt}/2 次)..."
            ));
            thread::sleep(Duration::from_secs(3));
            if self.is_cancelled() {
                return (false, "cancelled", "认证已取消".into());
            }
            match self.run_probes() {
                ProbeState::Online => {
                    (self.log)("复核: 200/204 无重定向 -> 已放行");
                    (self.log)("=== 认证成功, 已上线! ===");
                    let detail = if errmsg.is_empty() {
                        String::new()
                    } else {
                        errmsg
                    };
                    return (true, CODE_OK, detail);
                }
                ProbeState::Captive(_) => {
                    (self.log)(&format!("复核第 {attempt} 次: 仍被劫持, 继续等待..."));
                }
                _ => {
                    (self.log)(&format!("复核第 {attempt} 次: 无结论, 继续等待..."));
                }
            }
        }
        (self.log)("=== 认证失败: 复核仍未放行 ===");
        if !errmsg.is_empty() {
            (self.log)(&crate::common::redact_credentials(&format!("最后的门户消息: {errmsg}"), username, password));
        }
        (false, CODE_FAIL, if errmsg.is_empty() { "复核未放行".into() } else { errmsg })
    }

    /// 手动下线指引(绝不自动顶号)
    pub fn print_manual_offline_advice(&self) {
        (self.log)("---- 请手动下线后重试 ----");
        let portal_base = self
            .discovered_base
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .or_else(|| self.portal_url.clone())
            .unwrap_or_default();
        (self.log)(&format!(
            "1. 打开自助管理界面: {}",
            crate::common::self_service_url(&portal_base)
        ));
        (self.log)("2. 在「在线设备 / 终端管理」中手动下线占用槽位的设备");
        (self.log)("3. 回到本程序重新点击认证");
        (self.log)("说明: 账号限 1 台电脑 + 1 台手机同时在线; 本程序不会自动顶号.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portal_origin_pins_scheme_host_and_port() {
        assert_eq!(portal_origin("http://Campus.Example:80/portal").as_deref(), Some("http://campus.example"));
        assert_ne!(portal_origin("https://campus.example"), portal_origin("http://campus.example"));
        assert_ne!(portal_origin("http://campus.example:8080"), portal_origin("http://campus.example"));
        assert!(portal_origin("http://campus.example@other.example").is_none());
    }

    #[test]
    fn conflicting_probe_results_are_inconclusive_in_either_order() {
        let redirected = || ProbeState::Captive("http://campus.example/portal".into());
        assert!(matches!(summarize_probes([ProbeState::Online, redirected()]), ProbeState::Mixed));
        assert!(matches!(summarize_probes([redirected(), ProbeState::Online]), ProbeState::Mixed));
        assert!(!probe_response_is_online("www.msftconnecttest.com", "/connecttest.txt", 200, b"<html>portal</html>"));
        assert!(probe_response_is_online("www.msftconnecttest.com", "/connecttest.txt", 200, b"Microsoft Connect Test"));
    }


    // ---- 劫持识别: 跨主机/相对路径算劫持, 同主机跳转不算 ----

    #[test]
    fn same_host_redirect_is_not_captive() {
        // baidu 的 http->https 正常跳转, 不能误判成被劫持
        assert_eq!(captive_target("www.baidu.com", "https://www.baidu.com/"), None);
        assert_eq!(captive_target("www.baidu.com", "http://www.baidu.com/index.html"), None);
        assert_eq!(captive_target("WWW.Baidu.com", "https://www.baidu.com/"), None);
    }

    #[test]
    fn other_school_portal_is_captive() {
        // 别的学校的门户: 绝对地址指向自己的私网 IP
        let got = captive_target("www.msftconnecttest.com", "http://10.10.0.1/portal/login?wlanuserip=1.2.3.4");
        assert_eq!(got.as_deref(), Some("http://10.10.0.1/portal/login?wlanuserip=1.2.3.4"));
        // 公网域名当门户(云端认证)同样算劫持
        assert!(captive_target("www.msftconnecttest.com", "http://auth.school.edu.cn/wifi/login").is_some());
        // 带端口的门户
        assert!(captive_target("connect.rom.miui.com", "http://10.0.0.9:8080/portal").is_some());
    }

    #[test]
    fn relative_location_resolved_against_requested_host() {
        // 相对路径: 不能再用写死的门户 IP 去拼
        let got = captive_target("www.msftconnecttest.com", "/portal/login?mac=aabbccddeeff");
        assert_eq!(got.as_deref(), Some("http://www.msftconnecttest.com/portal/login?mac=aabbccddeeff"));
    }

    #[test]
    fn empty_or_odd_location() {
        assert_eq!(captive_target("h", ""), None);
        assert_eq!(captive_target("h", "   "), None);
    }

    // ---- URL 工具 ----

    #[test]
    fn url_host_and_base() {
        assert_eq!(url_host("http://10.10.0.1:8080/portal/login?x=1"), "10.10.0.1");
        assert_eq!(url_host("https://www.msftconnecttest.com/connecttest.txt"), "www.msftconnecttest.com");
        assert_eq!(url_host("10.10.0.1/portal"), "10.10.0.1");
        assert_eq!(url_base("http://10.10.0.1:8080/portal/login?x=1"), "http://10.10.0.1:8080");
        assert_eq!(url_base("http://10.255.2.252/portal/login?wlanuserip=1.2.3.4"), "http://10.255.2.252");
    }

    // ---- 登录页特征 ----

    #[test]
    fn portal_page_detection() {
        assert!(looks_like_portal_page(r#"<input type="password" name="pwd">"#));
        assert!(looks_like_portal_page("...wlanuserip=1.2.3.4..."));
        assert!(looks_like_portal_page("<title>Portal Login</title>"));
        assert!(!looks_like_portal_page("<!doctype html><html><body>hello</body></html>"));
    }

    // ---- 探测地址可覆盖(测试钩子) ----

    #[test]
    fn probe_targets_override() {
        // 不设环境变量时用内置表
        std::env::remove_var("CAMPUS_AUTH_PROBE");
        assert_eq!(probe_targets().len(), PROBE_URLS.len());
        // 设了就只用自定义的, 且支持 host/path 与裸 host
        std::env::set_var("CAMPUS_AUTH_PROBE", "127.0.0.1:8123/portal, example.com");
        let t = probe_targets();
        assert_eq!(t.len(), 2);
        assert_eq!(t[0], ("127.0.0.1:8123".to_string(), "/portal".to_string()));
        assert_eq!(t[1], ("example.com".to_string(), "/".to_string()));
        std::env::remove_var("CAMPUS_AUTH_PROBE");
    }
}
