//! CLI 实现(供 campus-auth-cli.exe 使用, console 子系统 stdout 原生可用)

use crate::auth;
use crate::net;
use crate::selfsvc;
use crate::store::Store;

pub fn print_help() {
    println!(
        "贺州学院校园网认证工具 (Rust 原生版)\n\
用法:\n\
  campus-auth-cli.exe --check                          探测认证状态(不登录)\n\
  campus-auth-cli.exe --list-adapters                  列出网卡\n\
  campus-auth-cli.exe --username U --password P        登录(默认电脑端)\n\
  campus-auth-cli.exe --ask-password                   交互输入密码\n\
  campus-auth-cli.exe --offline                        下线本设备并清 MAC 绑定(弹验证码图输入)\n\
  campus-auth-cli.exe --list-online                    查看本账号在线设备(需验证码)\n\
  --offline-code N --offline-session S                 (脚本)两段式提交验证码\n\
  campus-auth-cli.exe --detect-portal                  仅探测门户地址(排查用)\n\
选项:\n\
  --ua pc|mobile       设备类型(占 PC 槽还是手机槽), 默认 pc\n\
  --adapter NAME       网卡名(如 WLAN), 自动绑定其源 IP\n\
  --source IP          直接指定源 IP\n\
  --portal URL         手动指定门户地址(留空=靠 302 劫持自动发现)\n\
                       自动发现失败时: 浏览器打开任意 http 网站, 把跳转后的地址整条抄过来\n\
  --save               登录成功后保存账号(密码 DPAPI 加密)\n\
  --save-portal        把本次发现的门户地址写进数据文件\n\
  --forget             清除已保存的账号密码\n\
退出码: 0=成功/已在线  1=失败  2=未探测到门户(需手动填门户地址)  3=槽位冲突需手动下线"
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
    let mut offline = false;
    let mut offline_code: Option<String> = None;
    let mut offline_session: Option<String> = None;
    let mut list_online = false;
    let mut portal_url = String::new();
    let mut detect_portal = false;
    let mut save_portal = false;

    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--check" => check = true,
            "--list-adapters" => list = true,
            "--save" => save = true,
            "--forget" => forget = true,
            "--ask-password" => ask_password = true,
            "--offline" => offline = true,
            "--list-online" => list_online = true,
            "--offline-code" => {
                i += 1;
                offline_code = args.get(i).cloned();
            }
            "--offline-session" => {
                i += 1;
                offline_session = args.get(i).cloned();
            }
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
            "--portal" => {
                i += 1;
                portal_url = args.get(i).cloned().unwrap_or_default();
            }
            "--detect-portal" => detect_portal = true,
            "--save-portal" => save_portal = true,
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

    let mut a = auth::Auth::new(&ua, source, &logger);

    // 门户地址: --portal > 数据文件里保存的 > 自动发现
    if portal_url.trim().is_empty() {
        if let Ok(s) = store.lock() {
            portal_url = s.data.portal_url.clone();
        }
    }
    a.set_portal_url(if portal_url.trim().is_empty() {
        None
    } else {
        Some(portal_url.clone())
    });
    if !portal_url.trim().is_empty() {
        println!("使用门户地址: {portal_url}");
    }

    // 只探测门户地址(排查/提前获取用)
    if detect_portal {
        return match a.detect_portal() {
            Some(base) => {
                println!("发现门户: {base}");
                println!("(登录页 GET 正常, 可把它填进「门户地址」或加 --save-portal 保存)");
                if save_portal {
                    if let Ok(mut st) = store.lock() {
                        st.data.portal_url = base.clone();
                        st.save();
                        println!("已保存到数据文件: {base}");
                    }
                }
                0
            }
            None => {
                println!("未发现门户(没有劫持响应, 也可能本机已在线)");
                println!("手动获取: 浏览器打开 http://www.msftconnecttest.com/connecttest.txt,");
                println!("把地址栏跳转后的地址整条抄下来, 用 --portal '地址' 或填进界面「门户地址」框。");
                2
            }
        };
    }

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

    if list_online {
        return run_list_online(source, &username, &password, offline_code, offline_session, &logger);
    }

    if offline {
        let adapter = if !adapter_name.is_empty() {
            net::list_adapters()
                .into_iter()
                .find(|a| a.name.eq_ignore_ascii_case(&adapter_name))
        } else {
            net::guess_campus_adapter()
        };
        let mac_nosep = adapter
            .as_ref()
            .map(|a| selfsvc::norm_mac(&a.mac))
            .unwrap_or_default();
        let my_ip = source.map(|s| s.to_string()).unwrap_or_default();
        return run_offline(
            source,
            &username,
            &password,
            &mac_nosep,
            &my_ip,
            offline_code,
            offline_session,
            &logger,
        );
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
        auth::CODE_NO_PORTAL => {
            println!("结论: 未探测到门户——本机可能不在校园网, 或该校 AC 不用 302 劫持");
            println!("手动获取门户地址: 浏览器打开 http://www.msftconnecttest.com/connecttest.txt ,");
            println!("地址栏会跳到校园网认证页, 把整条地址复制下来, 然后:");
            println!("  campus-auth-cli.exe --portal '粘贴的地址' --username 账号 --ask-password");
            println!("(用 --save-portal 可写入数据文件, 以后自动使用)");
            2
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

/// 下线/查询公共前置: 取验证码(交互或两段式)并登录自助系统
fn spa_login_with_captcha(
    spa: &mut selfsvc::Spa,
    username: &str,
    password: &str,
    offline_code: Option<String>,
    offline_session: Option<String>,
) -> Result<(), String> {
    let code: String = match (offline_session, offline_code) {
        (Some(session), Some(c)) => {
            spa.cookie = session;
            c
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err("--offline-code 与 --offline-session 必须同时提供".into());
        }
        _ => {
            let cap = spa.tologin()?;
            let path = selfsvc::save_captcha_png(&cap.png)?;
            println!("验证码图片: {}", path.display());
            println!(
                "自助会话: {} (脚本可配合 --offline-session 复用)",
                cap.cookie
            );
            unsafe {
                let wp: Vec<u16> = path
                    .as_os_str()
                    .to_string_lossy()
                    .encode_utf16()
                    .chain([0])
                    .collect();
                let op: Vec<u16> = "open".encode_utf16().chain([0]).collect();
                windows_sys::Win32::UI::Shell::ShellExecuteW(
                    std::ptr::null_mut(),
                    op.as_ptr(),
                    wp.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    1, /* SW_SHOWNORMAL */
                );
            }
            print!("请输入图中 4 位验证码: ");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            let t = line.trim().to_string();
            if t.chars().count() < 4 {
                return Err("验证码不完整".into());
            }
            t
        }
    };
    spa.login(username, password, &code)
}

/// 查看本账号在线设备(只读, 不做任何下线)
fn run_list_online(
    source: Option<std::net::Ipv4Addr>,
    username: &str,
    password: &str,
    offline_code: Option<String>,
    offline_session: Option<String>,
    logger: &(dyn Fn(&str) + Sync),
) -> i32 {
    let mut spa = selfsvc::Spa::new(source, logger);
    if let Err(e) = spa_login_with_captcha(&mut spa, username, password, offline_code, offline_session) {
        eprintln!("!! {e}");
        return 1;
    }
    let rows = match spa.getonline(username) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("!! {e}");
            return 1;
        }
    };
    if rows.is_empty() {
        println!("当前没有在线会话");
        return 0;
    }
    println!("账号 {} 在线设备 {} 台:", username, rows.len());
    for r in &rows {
        println!(
            "  IP={}  槽位={}({})  MAC={}  上线时间={}",
            r.account_ip,
            if r.terminal_type == "b" { "手机" } else { "PC" },
            r.os_info,
            r.account_mac,
            r.online_time
        );
    }
    0
}

/// 下线本设备: tologin(验证码) → login → getonline → 匹配本机行 → kickonlineByMac(清绑定) → 复核断网
#[allow(clippy::too_many_arguments)]
fn run_offline(
    source: Option<std::net::Ipv4Addr>,
    username: &str,
    password: &str,
    mac_nosep: &str,
    my_ip: &str,
    offline_code: Option<String>,
    offline_session: Option<String>,
    logger: &(dyn Fn(&str) + Sync),
) -> i32 {
    let mut spa = selfsvc::Spa::new(source, logger);
    // ①② 会话+验证码+自助登录(交互或两段式)
    if let Err(e) = spa_login_with_captcha(&mut spa, username, password, offline_code, offline_session) {
        eprintln!("!! {e}");
        return 1;
    }
    // ③ 在线设备列表
    let rows = match spa.getonline(username) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("!! {e}");
            return 1;
        }
    };
    if rows.is_empty() {
        println!("当前没有在线会话(可能本机已下线)");
        return 0;
    }
    // ④ 只允许下线本机(MAC/IP 匹配), 绝不顶号
    let Some(i) = selfsvc::find_own_row(&rows, mac_nosep, my_ip) else {
        println!(
            "在线列表有 {} 台设备, 但没有本机(MAC/IP 均不匹配); 未做任何下线:",
            rows.len()
        );
        for r in &rows {
            println!(
                "  {}  [{}:{}]  {}",
                r.account_ip, r.terminal_type, r.os_info, r.account_mac
            );
        }
        println!("提示: 用 --adapter 指定本机网卡后重试");
        return 3;
    };
    let row = &rows[i];
    // ⑤ 按 MAC 下线并清绑定(槽位分类存在「绑定粘性」, 清绑定后下次认证按 UA 重新分类)
    match spa.kick_by_mac(username, row) {
        Ok(msg) => println!("下线结果: {msg} (本机 {})", row.account_ip),
        Err(e) => {
            eprintln!("!! 下线失败: {e}");
            return 1;
        }
    }
    spa.logout(); // 用完即弃自助会话
    // ⑥ 复核放行状态
    std::thread::sleep(std::time::Duration::from_secs(3));
    let auth = auth::Auth::new("pc", source, logger);
    let (conclusive, _) = auth.connectivity_test();
    match conclusive {
        Some(false) => {
            println!("复核: 已断网(回到未认证状态)");
            0
        }
        Some(true) => {
            println!("复核: 仍显示在线(?), 请到自助管理界面确认");
            1
        }
        _ => {
            println!("复核: 无结论");
            0
        }
    }
}

use std::sync::Mutex;
