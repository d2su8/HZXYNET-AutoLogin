//! CLI 实现(供 campus-auth-cli.exe 使用, console 子系统 stdout 原生可用)

use std::sync::Mutex;

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
  campus-auth-cli.exe --offline                        下线本设备并清 MAC 绑定\n\
  campus-auth-cli.exe --list-online                    查看本账号在线设备\n\
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
退出码: 0=成功/已在线  1=失败  2=未探测到门户(需手动填门户地址)  3=槽位冲突需手动下线
项目主页: {}"
    , crate::common::REPO_URL);
    println!("{}", crate::common::DISCLAIMER);
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
            // 抓包转储(门户换版本时用): 探测/登录页/POST 响应落盘, 见 cli_dump()
            "--dump" => {
                return cli_dump(&args[i + 1..]);
            }
            "--out" => {
                i += 1;
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
        let hint = if portal_url.trim().is_empty() { None } else { Some(portal_url.as_str()) };
        return run_list_online(source, &username, &password, hint, &store, &logger);
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
        let hint = if portal_url.trim().is_empty() { None } else { Some(portal_url.as_str()) };
        return run_offline(
            source, &username, &password, &mac_nosep, &my_ip, hint, &store, &logger,
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
    // 登录成功顺手记住门户地址与网关参数(设备在线时下线/查列表要用)
    if ok {
        if let Ok(mut st) = store.lock() {
            if let Some(b) = a.discovered_base.lock().ok().and_then(|g| g.clone()) {
                if st.data.portal_url.trim() != b {
                    st.data.portal_url = b;
                }
            }
            if let Some((i, n)) = a.discovered_ac.lock().ok().and_then(|g| g.clone()) {
                st.data.wlanacip = i;
                st.data.wlanacname = n;
            }
            st.save();
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
                crate::common::self_service_url(&portal_url)
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

/// 取令牌并构造新版自助后台客户端(令牌来自 Web 认证接口, 不再有独立的自助登录/验证码)
fn open_api<'a>(
    source: Option<std::net::Ipv4Addr>,
    portal_hint: Option<&str>,
    username: &str,
    password: &str,
    store: &Mutex<Store>,
    logger: &'a (dyn Fn(&str) + Sync),
) -> Result<selfsvc::PortalApi<'a>, String> {
    let (stored_portal, acip, acname) = store
        .lock()
        .map(|s| {
            (
                s.data.portal_url.clone(),
                s.data.wlanacip.clone(),
                s.data.wlanacname.clone(),
            )
        })
        .unwrap_or_default();
    let mut a = auth::Auth::new("pc", source, logger);
    a.set_portal_url(
        portal_hint
            .filter(|h| !h.trim().is_empty())
            .map(|h| h.to_string())
            .or_else(|| Some(stored_portal).filter(|h| !h.trim().is_empty())),
    );
    a.set_portal_ac(&acip, &acname);
    let token = a.obtain_portal_token(username, password)?;
    let base = a
        .discovered_base
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .or_else(|| portal_hint.map(|s| s.to_string()))
        .ok_or_else(|| "拿不到门户基地址".to_string())?;
    // 学到就记下来(下次设备在线时也能直接调接口)
    if let Ok(mut st) = store.lock() {
        if st.data.portal_url.trim() != base {
            st.data.portal_url = base.clone();
        }
        if let Ok(ac) = a.discovered_ac.lock() {
            if let Some((i, n)) = ac.clone() {
                st.data.wlanacip = i;
                st.data.wlanacname = n;
            }
        }
        st.save();
    }
    Ok(selfsvc::PortalApi::new(source, &base, &token, logger))
}

/// 查看本账号在线设备(只读, 不做任何下线)
fn run_list_online(
    source: Option<std::net::Ipv4Addr>,
    username: &str,
    password: &str,
    portal_hint: Option<&str>,
    store: &Mutex<Store>,
    logger: &(dyn Fn(&str) + Sync),
) -> i32 {
    let api = match open_api(source, portal_hint, username, password, store, logger) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("!! {e}");
            return 1;
        }
    };
    let rows = match api.online_users() {
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
            "  IP={}  槽位={}({})  MAC={}  上线时间={}  套餐={}",
            r.ip, r.terminal_label, r.terminal_type, r.mac, r.online_time, r.policy
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
    portal_hint: Option<&str>,
    store: &Mutex<Store>,
    logger: &(dyn Fn(&str) + Sync),
) -> i32 {
    // ① 拿令牌(设备在线时接口也会给令牌, 不会打扰在线会话)
    let api = match open_api(source, portal_hint, username, password, store, logger) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("!! {e}");
            return 1;
        }
    };
    // ② 在线设备列表
    let rows = match api.online_users() {
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
    // ③ 只允许下线本机(MAC/IP 匹配), 绝不顶号
    let Some(i) = selfsvc::find_own_row(&rows, mac_nosep, my_ip) else {
        println!(
            "在线列表有 {} 台设备, 但没有本机(MAC/IP 均不匹配); 未做任何下线:",
            rows.len()
        );
        for r in &rows {
            println!(
                "  {}  [{} {}]  {}",
                r.ip, r.terminal_label, r.terminal_type, r.mac
            );
        }
        println!("提示: 用 --adapter 指定本机网卡后重试");
        return 3;
    };
    let row = rows[i].clone();
    // ④ 强制下线
    match api.force_offline(&row.ip, &row.mac) {
        Ok(msg) => println!("下线结果: {msg} (本机 {})", row.ip),
        Err(e) => {
            eprintln!("!! 下线失败: {e}");
            return 1;
        }
    }
    // ⑤ 清除 MAC 绑定(换槽位前需要; 没有记录不算失败)
    match api.clear_mac(mac_nosep) {
        Ok(msg) => println!("清除绑定: {msg}"),
        Err(e) => println!("清除绑定失败(不影响下线): {e}"),
    }
    // ⑥ 复核放行状态
    std::thread::sleep(std::time::Duration::from_secs(3));
    let a = auth::Auth::new("pc", source, logger);
    let (conclusive, _) = a.connectivity_test();
    match conclusive {
        Some(false) => {
            println!("复核: 已断网(回到未认证状态)");
            0
        }
        Some(true) => {
            println!("复核: 仍在线(门户可能有延迟, 稍后重查)");
            1
        }
        None => {
            println!("复核: 无法判定");
            2
        }
    }
}


fn arg_of(rest: &[String], key: &str) -> Option<String> {
    rest.iter().position(|a| a == key).and_then(|i| rest.get(i + 1)).cloned()
}

fn adapter_source(rest: &[String]) -> Option<std::net::Ipv4Addr> {
    if let Some(ip) = arg_of(rest, "--source").and_then(|s| s.parse().ok()) {
        return Some(ip);
    }
    if let Some(name) = arg_of(rest, "--adapter") {
        if let Some(ip) = net::resolve_adapter_ip(&name) {
            return Some(ip);
        }
    }
    net::guess_campus_adapter().map(|a| a.ipv4[0])
}

// ---------------------------------------------------------------------------
// 抓包转储(门户换版本时用): 探测 / 登录页 / 认证接口响应全部落盘
// ---------------------------------------------------------------------------

/// `--dump` 实现: 把探测、登录页、认证接口的原始响应存到 --out 目录(默认 target/portal-dump)
pub fn cli_dump(rest: &[String]) -> i32 {
    let out_dir = arg_of(rest, "--out").unwrap_or_else(|| "target/portal-dump".to_string());
    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        eprintln!("!! 无法创建目录 {out_dir}: {e}");
        return 1;
    }
    let source = adapter_source(rest);
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    let client = net::HttpClient::new(source);
    let dump = |name: &str, text: &str| {
        let p = format!("{out_dir}/{name}");
        let _ = std::fs::write(&p, text);
        println!("  已写入 {p}");
    };
    println!("=== 抓包转储(源 IP {source:?}) ===");

    let mut report = String::new();
    let mut loc_url: Option<String> = None;
    for (host, path) in auth::probe_targets() {
        match client.request("GET", &format!("http://{host}{path}"), &[("Accept", "*/*")], None) {
            Ok(resp) => {
                let l = resp.header("Location").unwrap_or("").to_string();
                report.push_str(&format!("GET http://{host}{path}\n  -> {} Location: {l}\n", resp.status));
                if loc_url.is_none() {
                    if let Some(u) = auth::captive_target(&host, &l) {
                        loc_url = Some(u);
                    }
                }
            }
            Err(e) => report.push_str(&format!("GET http://{host}{path}\n  -> 失败: {e}\n")),
        }
    }
    println!("--- 探测 ---\n{report}");
    dump("01-probe.txt", &report);
    let loc = loc_url.or_else(|| arg_of(rest, "--portal"));
    let Some(loc) = loc else {
        println!("没有劫持响应(已在线? 不在校园网?) — 用 --portal 指定门户地址再试");
        return 2;
    };

    // 抓登录页(自己跟随跳转)
    let mut url = loc.clone();
    for hop in 0..4 {
        let resp = match client.request(
            "GET",
            &url,
            &[("User-Agent", ua), ("Accept", "*/*"), ("Accept-Language", "zh-CN,zh;q=0.9")],
            None,
        ) {
            Ok(r) => r,
            Err(e) => {
                println!("!! GET {url} 失败: {e}");
                return 1;
            }
        };
        let hdrs: String = resp.headers.iter().map(|(k, v)| format!("{k}: {v}\n")).collect();
        if let Some(next) = resp.header("Location") {
            let next = next.trim();
            url = if next.starts_with('/') {
                format!("{}{next}", auth::url_base(&url))
            } else {
                next.to_string()
            };
            println!("--- GET {url} -> {} (跳转) ---", resp.status);
            continue;
        }
        let body = crate::common::decode_body(&resp.body);
        println!("--- GET {url} -> {} ({} 字节) ---", resp.status, resp.body.len());
        dump(&format!("02-login-hop{hop}.html"), &body);
        dump(&format!("02-login-hop{hop}.headers.txt"), &format!("GET {url}\n{hdrs}"));
        let inputs = crate::common::parse_form_inputs(&body);
        let mut list = String::new();
        for (n, t, v) in &inputs {
            list.push_str(&format!("  name={n:<22} type={t:<10} value={}\n", &v[..v.len().min(80)]));
        }
        println!("--- 登录页 input({} 个) ---\n{list}", inputs.len());
        dump(&format!("02-login-hop{hop}.inputs.txt"), &list);
        let (uf, pf) = crate::common::detect_credential_fields(&inputs);
        println!("  推断身份字段: 账号={uf:?} 密码={pf:?}   → {}",
                 if pf.is_some() { "旧版表单式门户" } else { "新版 SPA 门户(走 /portal/webauth/auth)" });

        // 可选: 用账号密码走一次认证接口, 看响应形状
        let (Some(user), Some(pass)) = (arg_of(rest, "--username"), arg_of(rest, "--password")) else {
            println!("(未提供 --username/--password, 跳过提交)");
            return 0;
        };
        if pf.is_some() {
            println!("(旧版表单式门户: 请用 --username/--password 直接跑正常认证流程)");
            return 0;
        }
        let base = auth::url_base(&url);
        let get = |k: &str| {
            crate::common::parse_form_fields(&body)
                .into_iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v)
                .filter(|v| !v.is_empty())
                .or_else(|| auth::query_param(&loc, k))
                .unwrap_or_default()
        };
        let form = format!(
            "userId={}&passwd={}&loginMode=password&wlanuserip={}&wlanacip={}&wlanacname={}",
            crate::common::urlencode(&user),
            crate::common::urlencode(&pass),
            crate::common::urlencode(&get("wlanuserip")),
            crate::common::urlencode(&get("wlanacip")),
            crate::common::urlencode(&get("wlanacname")),
        );
        let auth_url = format!("{base}/portal/webauth/auth");
        let resp2 = match client.request(
            "POST",
            &auth_url,
            &[
                ("User-Agent", ua),
                ("Accept", "application/json, text/plain, */*"),
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Referer", url.as_str()),
                ("Origin", base.as_str()),
            ],
            Some(&form),
        ) {
            Ok(r) => r,
            Err(e) => {
                println!("!! POST {auth_url} 失败: {e}");
                return 1;
            }
        };
        let body2 = crate::common::decode_body(&resp2.body);
        println!("--- POST {auth_url} -> {} ({} 字节) ---", resp2.status, resp2.body.len());
        println!("  body: {}", body2.chars().take(400).collect::<String>());
        dump("03-auth.body.txt", &body2);
        dump("03-auth.form.txt", &form.replace(&pass, "***"));
        return 0;
    }
    println!("!! 跳转过多, 未拿到登录页");
    1
}
