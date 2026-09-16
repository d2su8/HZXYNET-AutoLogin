//! CLI 实现(供 campus-auth-cli.exe 使用, console 子系统 stdout 原生可用)

use crate::auth;
use crate::net;
use crate::store::Store;

pub fn print_help() {
    println!(
        "贺州学院校园网认证工具 (Rust 原生版)\n\
用法:\n\
  campus-auth-cli.exe --check                          探测认证状态(不登录)\n\
  campus-auth-cli.exe --list-adapters                  列出网卡\n\
  campus-auth-cli.exe --username U --password P        登录(默认电脑端)\n\
  campus-auth-cli.exe --ask-password                   交互输入密码\n\
选项:\n\
  --ua pc|mobile       设备类型(占 PC 槽还是手机槽), 默认 pc\n\
  --adapter NAME       网卡名(如 WLAN), 自动绑定其源 IP\n\
  --source IP          直接指定源 IP\n\
  --save               登录成功后保存账号(密码 DPAPI 加密)\n\
  --forget             清除已保存的账号密码\n\
退出码: 0=成功/已在线  1=失败  3=槽位冲突需手动下线"
    );
}

pub fn cli_main(args: &[String]) -> i32 {
    let mut username = String::new();
    let mut password = String::new();
    let mut ask_password = false;
    let mut ua = "pc".to_string();
    let mut adapter_name = String::new();
    let mut source_ip: Option<std::net::Ipv4Addr> = None;
    let mut check = false;
    let mut list = false;
    let mut save = false;
    let mut forget = false;

    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--check" => check = true,
            "--list-adapters" => list = true,
            "--save" => save = true,
            "--forget" => forget = true,
            "--ask-password" => ask_password = true,
            "--help" | "-h" => {
                print_help();
                return 0;
            }
            "--ua" => {
                i += 1;
                match args.get(i).map(|s| s.as_str()) {
                    Some("pc") | Some("mobile") => ua = args[i].clone(),
                    _ => {
                        eprintln!("--ua 需要 pc 或 mobile");
                        return 1;
                    }
                }
            }
            "--adapter" => {
                i += 1;
                adapter_name = args.get(i).cloned().unwrap_or_default();
            }
            "--source" => {
                i += 1;
                match args.get(i).and_then(|s| s.parse().ok()) {
                    Some(ip) => source_ip = Some(ip),
                    None => {
                        eprintln!("--source 需要合法 IPv4 地址");
                        return 1;
                    }
                }
            }
            "--username" => {
                i += 1;
                username = args.get(i).cloned().unwrap_or_default();
            }
            "--password" => {
                i += 1;
                password = args.get(i).cloned().unwrap_or_default();
            }
            other => {
                eprintln!("未知参数: {other}");
                print_help();
                return 1;
            }
        }
        i += 1;
    }

    if forget {
        let mut store = Store::load(Store::default_path());
        store.clear_credentials();
        println!("已清除保存的账号密码.");
        return 0;
    }

    if list {
        for a in net::list_adapters() {
            println!(
                "{:<14} {:<18} {:<20} {:<8} {}",
                a.name,
                a.ipv4
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                a.mac,
                a.status,
                a.desc
            );
        }
        return 0;
    }

    // 源地址解析
    let source = if let Some(ip) = source_ip {
        Some(ip)
    } else if !adapter_name.is_empty() {
        match net::resolve_adapter_ip(&adapter_name) {
            Some(ip) => Some(ip),
            None => {
                eprintln!("!! 网卡 \"{adapter_name}\" 未找到或没有 IPv4 地址");
                return 1;
            }
        }
    } else {
        match net::guess_campus_adapter() {
            Some(a) => {
                println!("自动选择网卡: {} ({})", a.name, a.ipv4[0]);
                Some(a.ipv4[0])
            }
            None => {
                eprintln!("警告: 未自动找到校园网段(10.200/10.202)网卡, 将使用系统默认路由");
                None
            }
        }
    };

    let store = Mutex::new(Store::load(Store::default_path()));
    let logger = |s: &str| {
        println!("{s}");
        if let Ok(mut st) = store.lock() {
            st.append_log(s);
        }
    };

    let a = auth::Auth::new(&ua, source, &logger);

    if check {
        let (conclusive, _) = a.connectivity_test();
        return match conclusive {
            Some(true) => {
                println!("结论: 已联网(已认证)");
                0
            }
            Some(false) => {
                println!("结论: 未认证(被门户劫持)");
                1
            }
            None => {
                println!("结论: 无法判定(网络不通?)");
                1
            }
        };
    }

    // 登录流程: 补齐凭据(已保存优先)
    if username.is_empty() {
        username = store.lock().map(|s| s.data.username.clone()).unwrap_or_default();
    }
    if password.is_empty() && !ask_password {
        if let Ok(s) = store.lock() {
            if s.data.save_password {
                if let Some(pw) = s.get_password() {
                    password = pw;
                }
            }
        }
    }
    if ask_password {
        print!("请输入校园网密码: ");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        password = line.trim().to_string();
    }
    if username.is_empty() || password.is_empty() {
        eprintln!("!! 缺少账号或密码: 用 --username/--password 或 --ask-password 提供");
        return 1;
    }

    let (ok, code, detail) = a.login(&username, &password);

    if ok && save {
        if let Ok(mut st) = store.lock() {
            match st.set_credentials(&username, Some(&password), true, &ua, &adapter_name) {
                Ok(()) => println!("账号信息已加密保存(DPAPI)"),
                Err(e) => println!("!! 保存账号失败: {e}"),
            }
        }
    }

    match code {
        auth::CODE_ALREADY => {
            println!("结论: 本机已在线, 无需操作");
            0
        }
        auth::CODE_OK => {
            println!("结论: 认证成功");
            0
        }
        auth::CODE_CONFLICT => {
            println!(
                "结论: 槽位被占用, 需到自助管理界面手动下线后重试 ({})",
                crate::common::SELF_SERVICE_URL
            );
            3
        }
        auth::CODE_BADPASS => {
            println!("结论: 密码错误");
            1
        }
        _ => {
            println!("结论: 认证失败 ({detail})");
            1
        }
    }
}

use std::sync::Mutex;
