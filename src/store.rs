//! 单一数据文件存储: 配置 + DPAPI 加密凭据 + 滚动日志
//!
//! 所有持久数据合并在 exe 同目录的 campus-auth.dat 一个文件里,
//! 与程序放在一起,不散落单独的日志/配置文件。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

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
    /// 滚动日志(与配置同文件,最多 MAX_LOG_LINES 行)
    #[serde(default)]
    pub log_lines: Vec<String>,
}

fn default_ua() -> String {
    "pc".into()
}

impl Default for StoreData {
    fn default() -> Self {
        StoreData {
            username: String::new(),
            password_dpapi: String::new(),
            save_password: false,
            ua: default_ua(),
            adapter: String::new(),
            log_lines: Vec::new(),
        }
    }
}

pub struct Store {
    path: PathBuf,
    pub data: StoreData,
    dirty: AtomicBool,
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
            dirty: AtomicBool::new(false),
        }
    }

    pub fn save(&self) {
        if let Ok(json) = serde_json::to_vec_pretty(&self.data) {
            if let Ok(mut f) = std::fs::File::create(&self.path) {
                let _ = f.write_all(&json);
            }
        }
        self.dirty.store(false, Ordering::Relaxed);
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
        self.dirty.store(true, Ordering::Relaxed);
        self.save_if_dirty();
    }

    /// 删除超过 LOG_KEEP_DAYS 天的日志行(默认 7 天)
    fn drop_expired_logs(&mut self) {
        let deadline = cutoff_str(LOG_KEEP_DAYS);
        // 行格式固定 "[YYYY-MM-DD HH:MM:SS] ...", 同格式 ISO 字典序即时间序
        self.data
            .log_lines
            .retain(|ln| ln.len() < 20 || ln[1..20].as_bytes() >= deadline.as_bytes());
    }

    /// 清空全部日志(历史日志窗口「清除日志」按钮)
    pub fn clear_logs(&mut self) {
        self.data.log_lines.clear();
        self.save();
    }

    fn save_if_dirty(&self) {
        if self.dirty.load(Ordering::Relaxed) {
            self.save();
        }
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
