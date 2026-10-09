// -*- coding: utf-8 -*-
//! 自助后台接口(新版门户, 2026-10 起): `/api/portal/user/*`, Bearer 令牌鉴权。
//!
//! 与旧版(`/self/*.do` + SPA 登录 + 图片验证码)相比的变化:
//!   - **不再有独立的自助登录, 也没有图片验证码**: 令牌直接取自 Web 认证接口
//!     `POST /portal/webauth/auth` 响应里的 `result.token`(签名串, 有效期由服务端定);
//!   - 在线设备: `GET  /api/portal/user/onlineUsers?pageNum=1&pageSize=50`
//!     行字段: `accountBindIp`(IP) / `callerId`(MAC) / `terminalType`(a=电脑 b=手机) / `onlineTime` / `internetTacticsName`(套餐)
//!   - 强制下线: `POST /api/portal/user/onlineUser/forceOffline` JSON `{accountBindIp, callerId}` →「强制下线成功」
//!   - 清除 MAC 绑定: `DELETE /api/portal/user/accountMac?terminalMac=<MAC>`
//!     (无记录时返回「未找到可清除的MAC记录」, 视为无需清理)
//!
//! 响应统一 `{success, message, code, result, timestamp}`; 失败看 `message`。

use serde_json::Value;

use crate::common::{decode_body, UA_PC};
use crate::net::HttpClient;

/// 在线设备行(新后台字段 → 归一化命名)
// 字段由 CLI 列表打印使用; GUI 侧只取 ip/mac, 故允许未读
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DeviceRow {
    /// accountBindIp: 该在线设备的 IP
    pub ip: String,
    /// callerId: 该在线设备的 MAC(带冒号大写)
    pub mac: String,
    /// terminalType: a=电脑 / b=手机
    pub terminal_type: String,
    /// terminalTypeLabel: 中文标签
    pub terminal_label: String,
    /// onlineTime
    pub online_time: String,
    /// internetTacticsName: 套餐/策略名
    pub policy: String,
}

/// 新版自助后台 API 客户端(令牌鉴权)
pub struct PortalApi<'a> {
    client: HttpClient,
    /// 门户基地址, 如 http://10.255.2.249
    pub base: String,
    /// Web 认证拿到的令牌
    pub token: String,
    log: &'a (dyn Fn(&str) + Sync),
}

impl<'a> PortalApi<'a> {
    pub fn new(
        source: Option<std::net::Ipv4Addr>,
        base: &str,
        token: &str,
        log: &'a (dyn Fn(&str) + Sync),
    ) -> Self {
        PortalApi {
            client: HttpClient::new(source),
            base: base.trim_end_matches('/').to_string(),
            token: token.to_string(),
            log,
        }
    }

    /// 统一调用: 返回 result 字段; success=false 时返回 message
    fn call(&self, method: &str, path: &str, body: Option<&str>) -> Result<Value, String> {
        let url = format!("{}{}", self.base, path);
        let auth = format!("Bearer {}", self.token);
        let referer = format!("{}/portal/center", self.base);
        let mut headers: Vec<(&str, &str)> = vec![
            ("User-Agent", UA_PC),
            ("Accept", "application/json, text/plain, */*"),
            ("Authorization", auth.as_str()),
            ("Origin", self.base.as_str()),
            ("Referer", referer.as_str()),
        ];
        if body.is_some() {
            headers.push(("Content-Type", "application/json"));
        }
        let resp = self
            .client
            .request(method, &url, &headers, body)
            .map_err(|e| format!("{method} {path} 失败: {e}"))?;
        let text = decode_body(&resp.body);
        let v: Value = serde_json::from_str(text.trim()).map_err(|e| {
            format!(
                "{method} {path} 响应不是 JSON({e}): {}",
                text.chars().take(160).collect::<String>()
            )
        })?;
        if !v["success"].as_bool().unwrap_or(false) {
            let msg = v["message"].as_str().unwrap_or("").to_string();
            return Err(if msg.is_empty() {
                format!("{method} {path} 返回失败(code={})", v["code"])
            } else {
                msg
            });
        }
        Ok(v["result"].clone())
    }

    /// 在线设备列表
    pub fn online_users(&self) -> Result<Vec<DeviceRow>, String> {
        (self.log)("自助后台: 查询在线设备(onlineUsers)...");
        let r = self.call("GET", "/api/portal/user/onlineUsers?pageNum=1&pageSize=50", None)?;
        let mut out = Vec::new();
        if let Some(items) = r["items"].as_array() {
            for it in items {
                out.push(DeviceRow {
                    ip: it["accountBindIp"].as_str().unwrap_or("").to_string(),
                    mac: it["callerId"].as_str().unwrap_or("").to_string(),
                    terminal_type: it["terminalType"].as_str().unwrap_or("").to_string(),
                    terminal_label: it["terminalTypeLabel"].as_str().unwrap_or("").to_string(),
                    online_time: it["onlineTime"].as_str().unwrap_or("").to_string(),
                    policy: it["internetTacticsName"].as_str().unwrap_or("").to_string(),
                });
            }
        }
        Ok(out)
    }

    /// 强制下线指定在线设备(只操作本机那一行, 绝不顶号)
    pub fn force_offline(&self, ip: &str, mac: &str) -> Result<String, String> {
        let body = serde_json::json!({ "accountBindIp": ip, "callerId": mac }).to_string();
        (self.log)(&format!("自助后台: 强制下线 {ip} / {mac} ..."));
        let r = self.call("POST", "/api/portal/user/onlineUser/forceOffline", Some(&body))?;
        Ok(match r.as_str() {
            Some(s) => s.to_string(),
            None => "已提交下线".to_string(),
        })
    }

    /// 清除 MAC 绑定记录(换槽位前用); 没有记录时不算失败
    pub fn clear_mac(&self, mac_nosep: &str) -> Result<String, String> {
        (self.log)(&format!("自助后台: 清除 MAC 绑定 {mac_nosep} ..."));
        let path = format!("/api/portal/user/accountMac?terminalMac={mac_nosep}");
        match self.call("DELETE", &path, None) {
            Ok(r) => Ok(match r.as_str() {
                Some(s) => s.to_string(),
                None => "已清除".to_string(),
            }),
            Err(e) if e.contains("未找到可清除") => Ok("没有需要清除的绑定记录".to_string()),
            Err(e) => Err(e),
        }
    }
}

/// MAC 归一化: 只留十六进制数字并转大写(与门户 callerId 比较用)
pub fn norm_mac(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_uppercase()
}

/// 在设备行里找"本机": MAC 匹配优先, 其次 IP 匹配
pub fn find_own_row(rows: &[DeviceRow], mac_nosep: &str, ip: &str) -> Option<usize> {
    let want_mac = norm_mac(mac_nosep);
    if !want_mac.is_empty() {
        if let Some(i) = rows.iter().position(|r| norm_mac(&r.mac) == want_mac) {
            return Some(i);
        }
    }
    if !ip.is_empty() {
        if let Some(i) = rows.iter().position(|r| r.ip == ip) {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_norm_and_row_match() {
        assert_eq!(norm_mac("bc:6e:e2:34:4f:63"), "BC6EE2344F63");
        assert_eq!(norm_mac("BC-6E-E2-34-4F-63"), "BC6EE2344F63");
        let rows = vec![
            DeviceRow {
                ip: "10.200.0.9".into(),
                mac: "AA:BB:CC:DD:EE:FF".into(),
                terminal_type: "b".into(),
                terminal_label: "手机".into(),
                online_time: "2026-10-09 11:00:00".into(),
                policy: "默认".into(),
            },
            DeviceRow {
                ip: "10.200.0.8".into(),
                mac: "BC:6E:E2:34:4F:63".into(),
                terminal_type: "a".into(),
                terminal_label: "电脑".into(),
                online_time: "2026-10-09 11:01:00".into(),
                policy: "默认".into(),
            },
        ];
        assert_eq!(find_own_row(&rows, "bc6ee2344f63", "10.200.0.9"), Some(1)); // MAC 优先
        assert_eq!(find_own_row(&rows, "", "10.200.0.9"), Some(0)); // 退回按 IP
        assert_eq!(find_own_row(&rows, "112233445566", "10.9.9.9"), None);
    }
}