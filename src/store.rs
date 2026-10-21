//! 单一数据文件存储: 配置 + DPAPI 加密凭据 + 滚动日志
//!
//! 所有持久数据合并在 exe 同目录的 campus-auth.dat 一个文件里,
//! 与程序放在一起,不散落单独的日志/配置文件。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::common::{cutoff_str, now_str};

pub const DAT_FILE: &str = "campus-auth.dat";
const MAX_LOG_LINES: usize = 2000;
const LOG_KEEP_DAYS: u64 = 7;

#[derive(Serialize, Deserialize, Clone)]
pub struct StoreData {
    #[serde(default)]
    pub username: String,
    /// DPAPI 加密后的 base64 blob(非明文)
    #[serde(default)]
    pub password_dpapi: String,
    #[serde(default)]
    pub save_password: bool,
    /// "pc" | "mobile"
    #[serde(default = "default_ua")]
    pub ua: String,
    #[serde(default)]
    pub adapter: String,
    /// 门户地址(留空 = 靠 302 劫持自动发现)。
    /// 可填基地址(http://10.10.0.1)或从浏览器地址栏抄来的完整登录页地址;
    /// 自动发现成功时也会把门户基地址写回这里, 下次可直接用。
    #[serde(default)]
    pub portal_url: String,
    /// 新版门户认证接口要求的网关参数(从劫持 URL 学到, 设备在线时也用它);
    /// 值形如 wlanacip=10.255.2.250 / wlanacname=hzxy
    #[serde(default)]
    pub wlanacip: String,
    #[serde(default)]
    pub wlanacname: String,
    /// 开机自启: 写 HKCU Run 项, 开机带 --auto 启动即用已存凭据自动认证
    #[serde(default)]
    pub auto_start: bool,
    /// 掉线自动重连: 后台定时探测, 掉线后按策略自动重认证
    #[serde(default)]
    pub auto_reauth: bool,
    /// 自动重连: 两次尝试之间的间隔(秒)
    #[serde(default = "default_reauth_interval")]
    pub reauth_interval_secs: u32,
    /// 自动重连: 每次掉线最多尝试认证的次数(含立即重试的第 1 次)
    #[serde(default = "default_reauth_retries")]
    pub reauth_max_retries: u32,
    /// 统计: 检测到掉线的次数(在线 -> 未认证 的跳变)
    #[serde(default)]
    pub drop_count: u64,
    /// 统计: 自动重连成功次数
    #[serde(default)]
    pub reauth_count: u64,
    /// 滚动日志(与配置同文件,最多 MAX_LOG_LINES 行)
    #[serde(default)]
    pub log_lines: Vec<String>,
}

fn default_ua() -> String {
    "pc".into()
}

/// 自动重连默认参数(间隔 30 秒 / 最多 3 次)
fn default_reauth_interval() -> u32 {
    30
}

fn default_reauth_retries() -> u32 {
    3
}

impl Default for StoreData {
    fn default() -> Self {
        StoreData {
            username: String::new(),
            password_dpapi: String::new(),
            save_password: false,
            ua: default_ua(),
            adapter: String::new(),
            portal_url: String::new(),
            wlanacip: String::new(),
            wlanacname: String::new(),
            auto_start: false,
            auto_reauth: false,
            reauth_interval_secs: default_reauth_interval(),
            reauth_max_retries: default_reauth_retries(),
            drop_count: 0,
            reauth_count: 0,
            log_lines: Vec::new(),
        }
    }
}

pub struct Store {
    path: PathBuf,
    pub data: StoreData,
}

impl Store {
    /// 数据文件路径 = exe 同目录 / campus-auth.dat
    pub fn default_path() -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(|| Path::new(".").to_path_buf())
            .join(DAT_FILE)
    }

    pub fn load(path: PathBuf) -> Store {
        let data = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<StoreData>(&b).ok())
            .unwrap_or_default();
        Store {
            path,
            data,
        }
    }

    /// 原子落盘: 先写临时文件再替换, 避免写一半时崩溃损坏数据文件(内含加密凭据)
    pub fn save(&self) {
        if let Ok(json) = serde_json::to_vec_pretty(&self.data) {
            let tmp = self.path.with_extension("dat.tmp");
            if std::fs::write(&tmp, &json).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }

    /// 追加一条日志(带时间戳, 滚动裁剪 + 7 天过期清理, 立即落盘)
    pub fn append_log(&mut self, msg: &str) {
        let line = format!("[{}] {}", now_str(), msg);
        self.data.log_lines.push(line);
        if self.data.log_lines.len() > MAX_LOG_LINES {
            let excess = self.data.log_lines.len() - MAX_LOG_LINES;
            self.data.log_lines.drain(..excess);
        }
        self.drop_expired_logs();
        self.save();
    }

    /// 删除超过 LOG_KEEP_DAYS 天的日志行(默认 7 天)
    fn drop_expired_logs(&mut self) {
        let deadline = cutoff_str(LOG_KEEP_DAYS);
        // 行格式固定 "[YYYY-MM-DD HH:MM:SS] ...", 同格式 ISO 字典序即时间序
        self.data
            .log_lines
            .retain(|ln| ln.len() < 20 || &ln.as_bytes()[1..20] >= deadline.as_bytes());
    }

    /// 清空全部日志(历史日志窗口「清除日志」按钮)
    pub fn clear_logs(&mut self) {
        self.data.log_lines.clear();
        self.save();
    }

    /// 是否有可直接用于自动认证的已存凭据
    pub fn has_usable_credentials(&self) -> bool {
        self.data.save_password
            && !self.data.username.is_empty()
            && self.get_password().is_some()
    }

    /// 保存账号(勾选时密码 DPAPI 加密写入; 未勾选时账号密码一并清除)
    pub fn set_credentials(
        &mut self,
        username: &str,
        password: Option<&str>,
        save_password: bool,
        ua: &str,
        adapter: &str,
    ) -> Result<(), String> {
        if save_password {
            self.data.username = username.to_string();
            self.data.save_password = true;
            self.data.ua = ua.to_string();
            self.data.adapter = adapter.to_string();
            match password {
                Some(pw) if !pw.is_empty() => {
                    self.data.password_dpapi = crate::crypto::protect(pw)?;
                }
                _ => self.data.password_dpapi.clear(),
            }
        } else {
            // 未勾选保存: 账号密码一起清除
            self.clear_credentials();
        }
        self.save();
        Ok(())
    }

    /// 清除已保存的账号密码(全部)
    pub fn clear_credentials(&mut self) {
        self.data.username.clear();
        self.data.password_dpapi.clear();
        self.data.save_password = false;
        self.save();
    }

    /// 读取解密后的密码(未保存返回空)
    pub fn get_password(&self) -> Option<String> {
        if self.data.password_dpapi.is_empty() {
            return None;
        }
        crate::crypto::unprotect(&self.data.password_dpapi).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 旧版本(升级前)的 dat 文件没有自启/重连字段,
    /// 反序列化时必须走 serde default, 不能让老用户的数据文件读不出来
    #[test]
    fn old_dat_without_new_fields_still_loads() {
        let old_json = r#"{
            "username": "20260001",
            "password_dpapi": "",
            "save_password": false,
            "ua": "pc",
            "adapter": "WLAN",
            "portal_url": "http://10.255.2.249",
            "wlanacip": "10.255.2.250",
            "wlanacname": "hzxy",
            "log_lines": ["[2026-10-20 10:00:00] hello"]
        }"#;
        let data: StoreData = serde_json::from_str(old_json).unwrap();
        assert_eq!(data.username, "20260001");
        // 新字段全部落到默认值
        assert!(!data.auto_start);
        assert!(!data.auto_reauth);
        assert_eq!(data.reauth_interval_secs, 30);
        assert_eq!(data.reauth_max_retries, 3);
        assert_eq!(data.drop_count, 0);
        assert_eq!(data.reauth_count, 0);
        assert_eq!(data.log_lines.len(), 1);
    }

    #[test]
    fn defaults_match_documented_values() {
        let d = StoreData::default();
        assert_eq!(d.reauth_interval_secs, 30);
        assert_eq!(d.reauth_max_retries, 3);
        assert!(!d.auto_start);
        assert!(!d.auto_reauth);
    }
}
