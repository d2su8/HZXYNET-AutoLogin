//! 认证引擎: 探测 -> GET 登录页 -> POST 表单 -> 复核放行
//!
//! 协议要点(全部实测验证,详见同目录使用说明):
//! 1. 未认证时任意 HTTP 出网请求被 AC 302 劫持到门户, query 里是会话绑定参数
//! 2. 登录 = 向带 query 的同一 URL POST 8 个配置字段 + 账号密码
//! 3. 是否上线只看复核探测的响应头(无 Location = 已放行), 不解析中文提示
//! 4. 撞槽位(已在线/超限)绝不自动顶号, 只提示手动下线

use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use crate::common::{
    decode_body, extract_err_message, parse_form_fields, urlencode, BADPASS_KEYWORDS,
    BASE_FORM_DEFAULTS, CONFLICT_KEYWORDS, PORTAL_HOST, PROBE_URLS, UA_MOBILE, UA_PC,
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
pub const CODE_FAIL: &str = "fail";

pub struct Auth<'a> {
    /// 完整 User-Agent 串
    pub ua: &'a str,
    /// 是否手机端(随机 UA 下不能用 ua==UA_MOBILE 判断)
    pub is_mobile: bool,
    pub client: HttpClient,
    pub log: &'a (dyn Fn(&str) + Sync),
}

fn is_portal_location(loc: &str) -> bool {
    if loc.starts_with('/') {
        return true; // 相对路径 = 门户自身
    }
    // 解析 host
    if let Some(rest) = loc.strip_prefix("http://") {
        let host = rest.split(['/', ':']).next().unwrap_or("");
        return host.eq_ignore_ascii_case(PORTAL_HOST);
    }
    false
}

fn absolute_location(loc: &str) -> String {
    if loc.starts_with('/') {
        format!("http://{PORTAL_HOST}{loc}")
    } else {
        loc.to_string()
    }
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
            "mobile" => {
                // 每次登录生成随机手机端标识(真实机型池), 降低被按 UA 指纹识别的概率
                let ua_random: &'static str =
                    Box::leak(random_mobile_ua().into_boxed_str());
                ua_random
            }
            "pc" => UA_PC,
            other => Box::leak(other.to_string().into_boxed_str()), // 自定义 UA
        };
        let is_mobile = ua_kind == "mobile" || (ua_kind != "pc" && ua.contains("Mobile"));
        Auth {
            ua,
            is_mobile,
            client: HttpClient::new(source),
            log,
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
                if let Some(loc) = resp.header("Location") {
                    if is_portal_location(loc) {
                        return ProbeState::Captive(absolute_location(loc));
                    }
                    return ProbeState::Inconclusive; // 302 到别处(如 baidu->https)
                }
                if resp.status == 200 || resp.status == 204 {
                    return ProbeState::Online;
                }
                ProbeState::Inconclusive
            }
            Err(e) => ProbeState::Unreachable(e),
        }
    }

    /// 并发探测三个地址, 任一给出结论即返回
    /// 返回 (Some(true)=在线 / Some(false)=被劫持 / None=无结论, 详情)
    pub fn connectivity_test(&self) -> (Option<bool>, String) {
        (self.log)("联通测试开始(并发 3 个探测地址)...");
        let (tx, rx) = mpsc_channel();
        thread::scope(|s| {
            for (host, path) in PROBE_URLS {
                let tx = tx.clone();
                s.spawn(move || {
                    let state = self.probe_one(host, path);
                    let _ = tx.send((host, path, state));
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
        match self.probe_one(PROBE_URLS[0].0, PROBE_URLS[0].1) {
            ProbeState::Online => {
                (self.log)("探测: 已放行, 本机已在线, 无需认证");
                return (true, CODE_ALREADY, "已在线".into());
            }
            ProbeState::Captive(l) => loc = Some(l),
            ProbeState::Inconclusive | ProbeState::Unreachable(_) => {
                for (host, path) in &PROBE_URLS[1..] {
                    match self.probe_one(host, path) {
                        ProbeState::Online => {
                            (self.log)("探测: 已放行, 本机已在线, 无需认证");
                            return (true, CODE_ALREADY, "已在线".into());
                        }
                        ProbeState::Captive(l) => {
                            loc = Some(l);
                            break;
                        }
                        _ => continue,
                    }
                }
            }
        }
        let loc = match loc {
            Some(l) => l,
            None => {
                (self.log)("!! 探测不到门户劫持响应: 网卡可能未连接校园网");
                return (
                    false,
                    CODE_UNREACHABLE,
                    "探测无劫持响应,无法取得会话参数".into(),
                );
            }
        };
        (self.log)("第 1 步完成: 未认证, 已取得会话绑定参数");
        (self.log)(&format!("  Location = {loc}"));

        // ---- 第 2 步: GET 登录页, 种 Cookie + 动态解析字段 ----------------
        let resp = match self.client.request(
            "GET",
            &loc,
            &[
                ("User-Agent", self.ua),
                ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                ("Accept-Language", "zh-CN,zh;q=0.9"),
            ],
            None,
        ) {
            Ok(r) => r,
            Err(e) => {
                (self.log)(&format!("!! 获取登录页失败: {e}"));
                return (false, CODE_UNREACHABLE, format!("门户连接失败: {e}"));
            }
        };
        if resp.status != 200 {
            (self.log)(&format!("!! 登录页返回 HTTP {}, 非预期", resp.status));
            return (false, CODE_FAIL, format!("登录页 HTTP {}", resp.status));
        }
        let cookie = resp
            .header("Set-Cookie")
            .and_then(|c| c.split(';').next())
            .unwrap_or("")
            .trim()
            .to_string();
        if cookie.is_empty() {
            (self.log)("第 2 步完成: 门户未下发 Cookie, 继续尝试");
        } else {
            (self.log)(&format!(
                "第 2 步完成: 已取得会话 Cookie ({})",
                cookie.split('=').next().unwrap_or("?")
            ));
        }

        let page_text = decode_body(&resp.body);
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
        // userId/passwd 覆盖页面值(保持页面出现顺序, 同浏览器表单提交)
        if let Some(pair) = form_pairs.iter_mut().find(|(k, _)| k == "userId") {
            pair.1 = username.to_string();
        }
        if let Some(pair) = form_pairs.iter_mut().find(|(k, _)| k == "passwd") {
            pair.1 = password.to_string();
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
            ("User-Agent", self.ua),
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
            match self.probe_one(PROBE_URLS[0].0, PROBE_URLS[0].1) {
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

// mpsc 的简短别名(避免直接依赖 std::sync::mpsc 全路径散落)
fn mpsc_channel<T>() -> (Sender<T>, std::sync::mpsc::Receiver<T>) {
    std::sync::mpsc::channel()
}
