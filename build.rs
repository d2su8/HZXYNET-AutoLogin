//! 嵌入 comctl32 v6 manifest(现代视觉样式)与版本信息
//!
//! 用 embed-manifest(纯 Rust 实现): 不依赖 Windows SDK 的 rc.exe/mt.exe,
//! 任何机器上都能成功嵌入。此前用 winres, 在缺 SDK 工具链的机器上
//! `res.compile()` 静默失败(os error 3), exe 没有清单 → 所有控件
//! 退回 Win95 经典灰按钮样式, 界面观感极差。
fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        // System DPI 感知: 与 main.rs 里 SetProcessDpiAwarenessContext(SYSTEM_AWARE)
        // 及 dp() 的 GetDpiForSystem 缩放逻辑保持一致(不用默认的 PerMonitorV2,
        // 因为布局是按系统 DPI 一次性算好的, 未处理 WM_DPICHANGED)
        embed_manifest::embed_manifest(
            embed_manifest::new_manifest("HzxyCampusAuth")
                .dpi_awareness(embed_manifest::manifest::DpiAwareness::System),
        )
        .expect("unable to embed manifest");
    }
    check_bin_name_has_version();
    println!("cargo:rerun-if-changed=build.rs");
}

/// 一致性检查: [[bin]] name 必须含 package version, 否则编译产物
/// (campus-auth.exe) 区分不出版本。Cargo 不支持在 [[bin]] name 里
/// 插值 CARGO_PKG_VERSION, 只能手写; 这里在忘改时给出告警。
/// (bin 名不允许含 '.', 版本号的点要写成下划线, 如 1.4.0 -> 1_4_0)
fn check_bin_name_has_version() {
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    if version.is_empty() {
        return;
    }
    let expected = format!("campus-auth-{}", version.replace('.', "_"));
    let toml = std::fs::read_to_string("Cargo.toml").unwrap_or_default();
    if !toml.contains(&expected) {
        println!(
            "cargo:warning=[[bin]] name 未含版本号 {version}(应为 \"{expected}\"): \
             产物文件名将区分不出版本"
        );
    }
}
