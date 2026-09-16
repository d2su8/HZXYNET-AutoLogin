//! campus-auth-cli (console subsystem, stdout 原生可用)

mod auth;
mod cli_shared;
mod common;
mod crypto;
mod net;
mod store;

use windows_sys::Win32::System::Console::{GetConsoleWindow, SetConsoleOutputCP};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        cli_shared::print_help();
        std::process::exit(1);
    }
    // 中文输出: 切 UTF-8 代码页(仅在附着真实控制台时)
    unsafe {
        if GetConsoleWindow() != std::ptr::null_mut() {
            SetConsoleOutputCP(65001);
        }
    }
    let code = cli_shared::cli_main(&args);
    std::process::exit(code);
}
