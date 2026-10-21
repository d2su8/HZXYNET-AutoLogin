//! 开机自启: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
//!
//! 写入一条 Run 项, 值为 `"<exe 全路径>" --auto`。
//! 开机启动时程序带 `--auto` 参数, 主窗口最小化, 等网络就绪后用已保存
//! 凭据自动认证(见 main.rs 的开机自动认证流程)。
//!
//! 只写 HKCU(当前用户), 不需要管理员权限; 入口值为 REG_SZ(含结尾 NUL)。

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    KEY_READ, KEY_WRITE, REG_SZ,
};

/// Run 键(HKCU 下, 每用户生效, 免管理员)
const RUN_SUBKEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
/// 值名(与其它程序区分)
const RUN_VALUE_NAME: &str = "campus-auth";
/// HKCU 预定义句柄(windows-sys 亦导出, 本地定义以免 glob 冲突)
const HKEY_CURRENT_USER: HKEY = -2147483647i32 as _;

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// 开机启动项应写入的命令行(带 --auto)
pub fn command_line() -> String {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "campus-auth.exe".to_string());
    format!("\"{exe}\" --auto")
}

/// Run 项当前的值(不存在返回 None)
pub fn current_value() -> Option<String> {
    unsafe {
        let subkey = utf16(RUN_SUBKEY);
        let mut hkey: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        ) != ERROR_SUCCESS
        {
            return None;
        }
        let name = utf16(RUN_VALUE_NAME);
        // 第一遍查询拿长度(字节)
        let mut cbdata: u32 = 0;
        let rc = RegQueryValueExW(
            hkey,
            name.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut cbdata,
        );
        if rc != ERROR_SUCCESS || cbdata == 0 {
            RegCloseKey(hkey);
            return None;
        }
        let mut buf = vec![0u8; cbdata as usize];
        let rc = RegQueryValueExW(
            hkey,
            name.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            &mut cbdata,
        );
        RegCloseKey(hkey);
        if rc != ERROR_SUCCESS {
            return None;
        }
        // REG_SZ: UTF-16LE + 结尾 NUL
        let units = buf.len() / 2;
        let slice = std::slice::from_raw_parts(buf.as_ptr() as *const u16, units);
        let end = slice.iter().position(|&c| c == 0).unwrap_or(units);
        Some(String::from_utf16_lossy(&slice[..end]))
    }
}

/// 开机自启是否已开启(Run 项存在即视为开启)
pub fn is_enabled() -> bool {
    current_value().is_some()
}

/// 开启/关闭开机自启。返回 Err 时调用方应还原界面勾选状态。
pub fn set_enabled(enable: bool) -> Result<(), String> {
    unsafe {
        let subkey = utf16(RUN_SUBKEY);
        let mut hkey: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_WRITE,
            &mut hkey,
        ) != ERROR_SUCCESS
        {
            return Err("无法打开注册表 Run 键(写入被拒绝?)".to_string());
        }
        let name = utf16(RUN_VALUE_NAME);
        let rc = if enable {
            // REG_SZ 数据必须是 UTF-16LE 字节序列, 含结尾 NUL
            let cmd = command_line();
            let mut bytes: Vec<u8> = cmd
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect();
            bytes.extend_from_slice(&0u16.to_le_bytes());
            RegSetValueExW(
                hkey,
                name.as_ptr(),
                0,
                REG_SZ,
                bytes.as_ptr(),
                bytes.len() as u32,
            )
        } else {
            // 值不存在时返回 ERROR_FILE_NOT_FOUND(2), 视为已关闭
            RegDeleteValueW(hkey, name.as_ptr())
        };
        RegCloseKey(hkey);
        if rc == ERROR_SUCCESS || (rc == 2 /* ERROR_FILE_NOT_FOUND */ && !enable) {
            Ok(())
        } else {
            Err(format!("注册表操作失败(错误码 {rc})"))
        }
    }
}

/// 自愈: 已开启但入口命令与当前 exe 不一致(exe 被移动/改名/换版本)时重写。
/// 返回重写后的最新状态(true = 开启)。
pub fn sync_if_enabled() -> bool {
    if !is_enabled() {
        return false;
    }
    if current_value().as_deref() != Some(command_line().as_str()) {
        let _ = set_enabled(true);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_points_to_current_exe_with_auto_flag() {
        let cmd = command_line();
        let exe = std::env::current_exe().unwrap();
        let exe_s = exe.display().to_string();
        assert!(cmd.contains(&exe_s), "命令行应含当前 exe 路径: {cmd}");
        assert!(cmd.ends_with(" --auto"), "应带 --auto: {cmd}");
        assert!(cmd.starts_with('"'), "路径应加引号: {cmd}");
    }

    /// 真实注册表 round-trip(会写 HKCU Run 键, 故默认忽略):
    /// `cargo test -- --ignored` 手动验证 FFI 调用是否正确
    #[test]
    #[ignore = "会写入真实注册表 HKCU Run 键, 仅手动验证时运行"]
    fn registry_roundtrip() {
        assert!(!is_enabled(), "前置条件: 当前未开启");
        set_enabled(true).expect("开启应成功");
        assert!(is_enabled());
        assert_eq!(current_value().as_deref(), Some(command_line().as_str()));
        set_enabled(false).expect("关闭应成功");
        assert!(!is_enabled());
    }
}
