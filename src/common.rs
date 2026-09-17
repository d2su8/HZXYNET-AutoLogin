// -*- coding: utf-8 -*-
//! 公共常量与工具函数

use windows_sys::Win32::Foundation::SYSTEMTIME;
use windows_sys::Win32::System::SystemInformation::GetLocalTime;

/// bossWeb 门户地址
pub const PORTAL_HOST: &str = "10.255.2.252";
/// 自助管理界面(手动下线用)
pub const SELF_SERVICE_URL: &str = "http://10.255.2.252/self/index.html#/Login";

/// 探测地址 (host, path),msft 优先
pub const PROBE_URLS: [(&str, &str); 3] = [
    ("www.msftconnecttest.com", "/connecttest.txt"),
    ("connect.rom.miui.com", "/generate_204"),
    ("www.baidu.com", "/"),
];

/// 电脑端 User-Agent (占 PC 槽)
pub const UA_PC: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

/// B 组配置字段默认值(优先从登录页动态解析,缺失时兜底)
pub const BASE_FORM_DEFAULTS: [(&str, &str); 9] = [
    ("scheme", "http"),
    ("serverIp", "tomcat_server:80"),
    ("hostIp", "http://127.0.0.1:8081/"), // WiFi 段=8081 有线段=8082,动态解析优先
    ("auth_type", "0"),
    ("isBindMac1", "0"),
    ("pageid", "-1"),
    ("templatetype", "1"),
    ("listbindmac", "0"),
    ("recordmac", "0"),
];

/// 槽位冲突关键词(命中 → 绝不自动顶号,引导手动下线)
pub const CONFLICT_KEYWORDS: [&str; 6] = ["已在线", "重复", "超限", "终端", "绑定", "占用"];
/// 凭据错误关键词
pub const BADPASS_KEYWORDS: [&str; 1] = ["密码错误"];

/// 当前本地时间 "YYYY-MM-DD HH:MM:SS"
pub fn now_str() -> String {
    unsafe {
        let mut st: SYSTEMTIME = std::mem::zeroed();
        GetLocalTime(&mut st);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
        )
    }
}

/// 计算 days 天前的本地时间字符串 "YYYY-MM-DD 00:00:00"
/// (用于日志过期判定: 同格式 ISO 字典序即时间序)
pub fn cutoff_str(days: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
        - days as i64 * 86_400;
    // Howard Hinnant civil_from_days 算法: epoch 天数 -> (年, 月, 日)
    let z = now.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02} 00:00:00", y, m, d)
}

/// 百分号编码(与 curl --data-urlencode 一致,空格 -> %20)
pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// body 解码: UTF-8 优先,失败回退 GBK
pub fn decode_body(body: &[u8]) -> String {
    let (t, _, had_err) = encoding_rs::UTF_8.decode(body);
    if !had_err {
        return t.into_owned();
    }
    let (t2, _, _) = encoding_rs::GBK.decode(body);
    t2.into_owned()
}

/// 从登录页提取所有未 disabled 的 <input> 的 name -> value
/// 注意: 属性名匹配用小写副本, 但属性值必须从原始文本切片(保留大小写),
/// 否则 serverIp/hostIp 等字段名会被小写化, 门户(大小写敏感)将视为缺失
pub fn parse_form_fields(html: &str) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    let lower = html.to_ascii_lowercase();
    let mut i = 0usize;
    while let Some(pos) = lower[i..].find("<input") {
        let tag_start = i + pos;
        let tag_end = match lower[tag_start..].find('>') {
            Some(p) => tag_start + p,
            None => break,
        };
        // to_ascii_lowercase 是逐字节 1:1 转换, 原文与副本偏移完全一致
        let tag_raw = &html[tag_start..tag_end.min(html.len())];
        let tag_low = &lower[tag_start..tag_end.min(lower.len())];
        i = tag_end + 1;
        let attrs = split_attrs(tag_raw, tag_low);
        // disabled 字段不会被提交
        if attrs.iter().any(|(k, _)| *k == "disabled") {
            continue;
        }
        let mut name = None;
        let mut value = None;
        for (k, v) in &attrs {
            match *k {
                "name" => name = Some(v.to_string()),
                "value" => value = Some(v.to_string()),
                _ => {}
            }
        }
        if let Some(n) = name {
            // 原始 HTML 里的 value 可能含实体,简单还原常见三种
            let raw = value.unwrap_or_default();
            let decoded = raw
                .replace("&amp;", "&")
                .replace("&quot;", "\"")
                .replace("&#39;", "'");
            fields.push((n, decoded));
        }
    }
    fields
}

/// 把 <input ...> 标签体切成 (小写key, 原始大小写value) 属性对
/// 在 tag_lower 上定位结构, 在 tag_raw 上切片(偏移 1:1)
fn split_attrs<'a>(tag_raw: &'a str, tag_lower: &'a str) -> Vec<(&'a str, &'a str)> {
    let mut out = Vec::new();
    let b = tag_lower.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        while i < b.len() && (b[i] as char).is_whitespace() {
            i += 1;
        }
        let start = i;
        while i < b.len() && b[i] != b'=' && !(b[i] as char).is_whitespace() {
            i += 1;
        }
        if i >= b.len() || b[i] != b'=' {
            // 无值属性(如 disabled)
            if i > start {
                out.push((&tag_lower[start..i], ""));
            }
            continue;
        }
        let key = &tag_lower[start..i];
        i += 1; // '='
        let vstart;
        if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
            let quote = b[i];
            i += 1;
            vstart = i;
            while i < b.len() && b[i] != quote {
                i += 1;
            }
        } else {
            vstart = i;
            while i < b.len() && !(b[i] as char).is_whitespace() {
                i += 1;
            }
        }
        // 值从原始文本切片(保留大小写); tag_raw 与 tag_lower 等长同偏移
        let val_end = i.min(tag_raw.len());
        let val = &tag_raw[vstart.min(tag_raw.len())..val_end];
        i += 1; // 跳过闭合引号
        out.push((key, val));
    }
    out
}

/// 按文档顺序解析登录页 <input>, 返回 (name, type, value)。
/// type 取不到按 "text" 处理, value 取不到为空串。
/// 用途: 账号/密码字段名各家门户不同(老板牌 userId/passwd, 别家 account/pwd...),
/// 需要按 type=password 与可见文本输入的先后顺序推断, 而不是写死字段名。
pub fn parse_form_inputs(html: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let lower = html.to_ascii_lowercase();
    let mut i = 0usize;
    while let Some(pos) = lower[i..].find("<input") {
        let tag_start = i + pos;
        let tag_end = match lower[tag_start..].find('>') {
            Some(p) => tag_start + p,
            None => break,
        };
        let tag_raw = &html[tag_start..tag_end.min(html.len())];
        let tag_low = &lower[tag_start..tag_end.min(lower.len())];
        i = tag_end + 1;
        let attrs = split_attrs(tag_raw, tag_low);
        if attrs.iter().any(|(k, _)| *k == "disabled") {
            continue;
        }
        let mut name = None;
        let mut value = String::new();
        let mut typ = "text".to_string();
        for (k, v) in &attrs {
            match *k {
                "name" => name = Some(v.to_string()),
                "value" => {
                    value = v
                        .replace("&amp;", "&")
                        .replace("&quot;", "\"")
                        .replace("&#39;", "'")
                }
                "type" => typ = v.to_ascii_lowercase(),
                _ => {}
            }
        }
        if let Some(n) = name {
            if !n.is_empty() {
                out.push((n, typ, value));
            }
        }
    }
    out
}

/// 从表单输入推断 (账号字段名, 密码字段名):
/// - 密码: 第一个 type=password 的输入
/// - 账号: 密码框之前最近的一个可见文本输入; 找不到再按名称特征(user/account/login/name/id)找
pub fn detect_credential_fields(
    inputs: &[(String, String, String)],
) -> (Option<String>, Option<String>) {
    let visible_text = |t: &str| {
        !matches!(
            t,
            "hidden" | "submit" | "button" | "reset" | "image" | "checkbox" | "radio" | "file"
        )
    };
    let pass_idx = inputs.iter().position(|(_, t, _)| t == "password");
    let pass = pass_idx.map(|i| inputs[i].0.clone());
    let user = match pass_idx {
        Some(pi) => inputs[..pi]
            .iter()
            .rev()
            .find(|(_, t, _)| visible_text(t))
            .map(|(n, _, _)| n.clone()),
        None => None,
    };
    let user = user.or_else(|| {
        inputs
            .iter()
            .filter(|(_, t, _)| visible_text(t))
            .find(|(n, _, _)| {
                let n = n.to_ascii_lowercase();
                ["user", "account", "login", "name", "id"]
                    .iter()
                    .any(|k| n.contains(k))
            })
            .map(|(n, _, _)| n.clone())
    });
    (user, pass)
}

/// 从响应页提取隐藏域 errMessage 的 value
pub fn extract_err_message(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let mut search = 0usize;
    while let Some(p) = lower[search..].find("<input") {
        let tag_start = search + p;
        let tag_end = match lower[tag_start..].find('>') {
            Some(e) => tag_start + e,
            None => break,
        };
        let tag_lower = &lower[tag_start..=tag_end];
        let tag_raw = &html[tag_start..=tag_end];
        search = tag_end + 1;
        if tag_lower.contains("id=\"errmessage\"") || tag_lower.contains("id='errmessage'") {
            // 找 value=
            if let Some(vpos) = tag_lower.find("value=") {
                let rest = &tag_raw[vpos + 6..];
                let bytes = rest.as_bytes();
                if !bytes.is_empty() && (bytes[0] == b'"' || bytes[0] == b'\'') {
                    let q = bytes[0];
                    if let Some(end) = rest[1..].find(q as char) {
                        return rest[1..1 + end]
                            .replace("&amp;", "&")
                            .replace("&quot;", "\"");
                    }
                }
            }
            return String::new();
        }
    }
    String::new()
}
