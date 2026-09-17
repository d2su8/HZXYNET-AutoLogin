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
}

/// 认证结果代码
pub const CODE_ALREADY: &str = "already";
pub const CODE_OK: &str = "ok";
pub const CODE_BADPASS: &str = "badpass";
pub const CODE_CONFLICT: &str = "conflict";
pub const CODE_UNREACHABLE: &str = "unreachable";
/// 探测不到门户且未配置门户地址(需用户手动填写)
pub const CODE_NO_PORTAL: &str = "no-portal";
pub const CODE_FAIL: &str = "fail";

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
    /// 本次认证实际用到的门户基地址(供上层写回配置)
    pub discovered_base: std::sync::Mutex<Option<String>>,
}

/// 取 URL 里的主机名(不含 scheme/端口/路径)
pub fn url_host(url: &str) -> &str {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let end = rest
        .find(|c| c == '/' || c == '?' || c == '#')
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
        .find(|c| c == '/' || c == '?' || c == '#')
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
    if loc.is_empty() {
        return None;
    }
    if loc.starts_with('/') {
        // 相对路径: 按请求主机补全(AC 会再次劫持/或直接给出门户页)
        return Some(format!("http://{requested_host}{loc}"));
    }
    if let Some(rest) = loc.strip_prefix("https://") {
        // 门户极少用 https; 若真给了, 说明是被指向了某个站点, 交给上层去请求(会走 https 分支失败)
        let host = rest.split(['/', ':']).next().unwrap_or("");
        return if host.eq_ignore_ascii_case(requested_host) {
            None
        } else {
            Some(loc.to_string())
        };
    }
    let host = url_host(loc);
    if host.is_empty() || host.eq_ignore_ascii_case(requested_host) {
        return None;
    }
    Some(loc.to_string())
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
            discovered_base: std::sync::Mutex::new(None),
        }
    }

    /// 设置手动门户地址(空串/None = 只用劫持自动发现)
    pub fn set_portal_url(&mut self, url: Option<String>) {
        self.portal_url = url.filter(|s| !s.trim().is_empty());
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
                if let Some(loc) = resp.header("Location") {
                    // 跨主机/相对路径 => 被劫持; 同主机跳转(如 baidu->https) => 无结论
                    return match captive_target(host, loc) {
                        Some(url) => ProbeState::Captive(url),
                        None => ProbeState::Inconclusive,
                    };
                }
                if resp.status == 200 || resp.status == 204 {
                    return ProbeState::Online;
                }
                ProbeState::Inconclusive
            }
            Err(e) => ProbeState::Unreachable(e),
        }
    }

    /// 跟随跳转抓取登录页, 返回 (最终 URL, HTML, Cookie)。最多 3 跳。
    /// 相对 Location 按当前 URL 补全, 因此不再依赖任何写死的门户地址。
    fn fetch_login_page(&self, start_url: &str) -> Result<(String, String, String), String> {
        let mut url = start_url.to_string();
        for hop in 0..3 {
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
            if let Some(loc) = resp.header("Location") {
                let next = if loc.trim().starts_with('/') {
                    format!("{}{}", url_base(&url), loc.trim())
                } else if loc.trim().starts_with("http://") || loc.trim().starts_with("https://") {
                    loc.trim().to_string()
                } else {
                    // 形如 "portal/login?...": 相对当前目录
                    let base = url.trim_end_matches('/');
                    format!("{base}/{}", loc.trim())
                };
                (self.log)(&format!(
                    "  跳转 {} -> {}",
                    url,
                    next
                ));
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

    /// 并发探测三个地址, 任一给出结论即返回
    /// 返回 (Some(true)=在线 / Some(false)=被劫持 / None=无结论, 详情)
    pub fn connectivity_test(&self) -> (Option<bool>, String) {
        let targets = probe_targets();
        (self.log)(&format!("联通测试开始(并发 {} 个探测地址)...", targets.len()));
        let (tx, rx) = std::sync::mpsc::channel();
        thread::scope(|s| {
            for (host, path) in &targets {
                let tx = tx.clone();
                let (h, p) = (host.clone(), path.clone());
                s.spawn(move || {
                    let state = self.probe_one(&h, &p);
                    let _ = tx.send((h, p, state));
                });
            }
            drop(tx);
            let mut unreachable_msg = String::new();
            for (host, path, state) in rx.iter() {
                match state {
                    ProbeState::Online => {
                        (self.log)(&format!("探测 {host}{path} -> 200/204 无重定向, 已联网(已认证)"));
                        return (Some(true), format!("{host}{path}"));
                    }
                    ProbeState::Captive(loc) => {
                        (self.log)(&format!("探测 {host}{path} -> 302 被劫持, 未认证"));
                        return (Some(false), loc);
                    }
                    ProbeState::Unreachable(e) => {
                        (self.log)(&format!("探测 {host}{path} -> 网络异常: {e}"));
                        unreachable_msg = e;
                    }
                    ProbeState::Inconclusive => {}
                }
            }
            if !unreachable_msg.is_empty() {
                (self.log)("三个探测地址均网络异常: 网卡可能未连接");
            } else {
                (self.log)("三个探测地址均无结论");
            }
            (None, unreachable_msg)
        })
    }

    /// 只做"找认证服务器": 探测劫持(或验证已配置的门户地址), 返回门户基地址。
    /// 用于 `--detect-portal` 与界面「检测门户」, 不登录、不改任何状态。
    pub fn detect_portal(&self) -> Option<String> {
        for (host, path) in probe_targets() {
            if let ProbeState::Captive(url) = self.probe_one(&host, &path) {
                (self.log)(&format!("探测 {host}{path} -> 302 被劫持: {url}"));
                let base = url_base(&url);
                match self.fetch_login_page(&url) {
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
            if let Ok((final_url, html, _)) = self.fetch_login_page(p) {
                (self.log)(&format!(
                    "  可达, {} (最终地址 {final_url})",
                    if looks_like_portal_page(&html) { "像门户登录页" } else { "内容不像门户登录页" }
                ));
                return Some(url_base(&final_url));
            }
        }
        None
    }

    /// 完整登录流程. 返回 (成功?, code, detail)
    pub fn login(&self, username: &str, password: &str) -> (bool, &'static str, String) {
        (self.log)(&format!(
            "=== 开始认证: 账号={username} 设备={} 源地址={} ===",
            self.device_label(),
            self.client
                .source
                .map(|i| i.to_string())
                .unwrap_or_else(|| "系统默认路由".into())
        ));
        (self.log)(&format!("本次 UA: {}", self.ua));

        // ---- 第 1 步: 探测, 拿劫持 Location ------------------------------
        let mut loc: Option<String> = None;
        for (host, path) in probe_targets() {
            match self.probe_one(&host, &path) {
                ProbeState::Online => {
                    (self.log)(&format!("探测 {host}{path} -> 已放行, 本机已在线"));
                    return (true, CODE_ALREADY, "已在线".into());
                }
                ProbeState::Captive(l) => {
                    loc = Some(l);
                    break;
                }
                _ => continue,
            }
        }
        // 探测不到劫持: 用配置里的门户地址; 也没有则提示手动获取
        let loc = match loc {
            Some(l) => {
                (self.log)("第 1 步完成: 未认证, 已取得会话绑定参数");
                (self.log)(&format!("  Location = {l}"));
                if let Ok(mut g) = self.discovered_base.lock() {
                    *g = Some(url_base(&l));
                }
                l
            }
            None => match self.portal_url.as_deref() {
                Some(p) => {
                    (self.log)(&format!(
                        "探测不到劫持响应, 改用配置的门户地址: {p}"
                    ));
                    p.to_string()
                }
                None => {
                    (self.log)("!! 探测不到门户劫持响应, 且未配置门户地址");
                    (self.log)("   手动获取办法: 浏览器打开任意 http 网站(如 http://www.msftconnecttest.com/connecttest.txt),");
                    (self.log)("   地址栏会跳到校园网认证页 — 把那个地址整条复制到「门户地址」框里再试。");
                    return (
                        false,
                        CODE_NO_PORTAL,
                        "未探测到门户, 请手动填写门户地址(浏览器打开任意 http 网站, 复制跳转后的地址)".into(),
                    );
                }
            },
        };

        // ---- 第 2 步: GET 登录页(跟随跳转), 种 Cookie + 动态解析字段 ------
        let (loc, page_text, cookie) = match self.fetch_login_page(&loc) {
            Ok(v) => v,
            Err(e) => {
                (self.log)(&format!("!! 获取登录页失败: {e}"));
                return (false, CODE_UNREACHABLE, format!("门户连接失败: {e}"));
            }
        };
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
            (self.log)(&format!("  注意: 登录页自带提示信息: {page_err}"));
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
        let (uf, pf) = detect_credential_fields(&parse_form_inputs(&page_text));
        let user_field = uf.unwrap_or_else(|| "userId".to_string());
        let pass_field = pf.unwrap_or_else(|| "passwd".to_string());
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
        // 调试可见性: 打印表单键名清单与关键身份字段(密码不出现在日志)
        let keys_dbg = form_pairs
            .iter()
            .map(|(k, v)| {
                if k.eq_ignore_ascii_case("passwd") {
                    format!("{}=***", k)
                } else {
                    format!("{}={}", k, v)
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        (self.log)(&format!("  表单明细: {}", keys_dbg));

        let headers = [
            ("User-Agent", self.ua.as_str()),
            ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            ("Accept-Language", "zh-CN,zh;q=0.9"),
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Referer", loc.as_str()),
            ("Cookie", cookie.as_str()),
        ];
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
        let errmsg = extract_err_message(&resp_text);
        if !errmsg.is_empty() {
            (self.log)(&format!("  门户返回消息: {errmsg}"));
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

        // ---- 第 4 步: 复核放行 --------------------------------------------
        for attempt in 1..=2 {
            (self.log)(&format!(
                "第 4 步: 等待 3 秒后复核放行 (第 {attempt}/2 次)..."
            ));
            thread::sleep(Duration::from_secs(3));
            // 复核用与探测同一批地址(默认即内置第一个), 换过探测地址时行为一致
            let (rh, rp) = probe_targets()
                .into_iter()
                .next()
                .unwrap_or_else(|| (PROBE_URLS[0].0.to_string(), PROBE_URLS[0].1.to_string()));
            match self.probe_one(&rh, &rp) {
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
            (self.log)(&format!("  最后的门户消息: {errmsg}"));
        }
        (false, CODE_FAIL, if errmsg.is_empty() { "复核未放行".into() } else { errmsg })
    }

    /// 手动下线指引(绝不自动顶号)
    pub fn print_manual_offline_advice(&self) {
        (self.log)("---- 请手动下线后重试 ----");
        (self.log)(&format!("1. 打开自助管理界面: {}", crate::common::SELF_SERVICE_URL));
        (self.log)("2. 在「在线设备 / 终端管理」中手动下线占用槽位的设备");
        (self.log)("3. 回到本程序重新点击认证");
        (self.log)("说明: 账号限 1 台电脑 + 1 台手机同时在线; 本程序不会自动顶号.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
