//! 网络层: 网卡枚举(GetAdaptersAddresses) + 绑定源 IP 的极简 HTTP/1.1 客户端
//!
//! 门户是纯明文 HTTP(80),无需 TLS,因此手写 HTTP 协议,零重依赖。

use std::net::{Ipv4Addr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR};

// ---------------------------------------------------------------------------
// 网卡枚举
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Adapter {
    pub name: String,
    pub desc: String,
    pub mac: String,
    pub status: String,
    pub ipv4: Vec<Ipv4Addr>,
}

impl Adapter {
    pub fn is_campus(&self) -> bool {
        self.ipv4
            .iter()
            .any(|ip| ip.octets()[0] == 10 && (ip.octets()[1] == 200 || ip.octets()[1] == 202))
    }
}

fn pwstr_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

fn sockaddr_to_ipv4(sa: &SOCKADDR) -> Option<Ipv4Addr> {
    if sa.sa_family != AF_INET as u16 {
        return None;
    }
    // SOCKADDR 布局: family(2) + sin_port(2) + in_addr(4) + zero(8), sa_data 是 i8
    let d = sa.sa_data;
    Some(Ipv4Addr::new(d[2] as u8, d[3] as u8, d[4] as u8, d[5] as u8))
}

const GAA_FLAGS: u32 = 0x2 | 0x4 | 0x8; // SKIP_ANYCAST | SKIP_MULTICAST | SKIP_DNS_SERVER

/// 枚举所有有 IPv4 的网卡
pub fn list_adapters() -> Vec<Adapter> {
    unsafe {
        let mut size: u32 = 16 * 1024;
        let mut buf = vec![0u8; size as usize];
        let mut ret;
        // 两次调用模式: 先探测缓冲区大小
        loop {
            ret = GetAdaptersAddresses(
                AF_INET as u32,
                GAA_FLAGS,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            );
            if ret == 111 /* ERROR_BUFFER_OVERFLOW */ {
                buf = vec![0u8; size as usize];
                continue;
            }
            break;
        }
        if ret != 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            let a = &*cur;
            let name = pwstr_to_string(a.FriendlyName);
            if !name.is_empty() {
                let desc = pwstr_to_string(a.Description);
                let mac = a.PhysicalAddress[..a.PhysicalAddressLength as usize]
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join("-");
                let status = match a.OperStatus {
                    1 => "Up",
                    2 => "Down",
                    3 => "Testing",
                    4 => "Unknown",
                    5 => "Dormant",
                    6 => "NotPresent",
                    7 => "LowerLayerDown",
                    _ => "Unknown",
                }
                .to_string();
                let mut ipv4 = Vec::new();
                let mut ua = a.FirstUnicastAddress;
                while !ua.is_null() {
                    let u = &*ua;
                    // Address 是 SOCKET_ADDRESS(包着裸指针 SOCKADDR)
                    let sa = &*u.Address.lpSockaddr;
                    if let Some(ip) = sockaddr_to_ipv4(sa) {
                        // 过滤 APIPA 链路本地地址
                        if !ip.is_link_local() && !ip.is_loopback() {
                            ipv4.push(ip);
                        }
                    }
                    ua = u.Next;
                }
                if !ipv4.is_empty() {
                    out.push(Adapter {
                        name,
                        desc,
                        mac,
                        status,
                        ipv4,
                    });
                }
            }
            cur = a.Next;
        }
        out
    }
}

/// 网卡名 -> 第一个 IPv4 (仅 CLI 使用)
#[allow(dead_code)]
pub fn resolve_adapter_ip(name: &str) -> Option<Ipv4Addr> {
    list_adapters()
        .into_iter()
        .find(|a| a.name.eq_ignore_ascii_case(name))
        .and_then(|a| a.ipv4.into_iter().next())
}

/// 自动猜测校园网网卡: 10.200/10.202 段优先,其次名字含 WLAN/WiFi/无线 (仅 CLI 使用)
#[allow(dead_code)]
pub fn guess_campus_adapter() -> Option<Adapter> {
    let adapters = list_adapters();
    for a in &adapters {
        if a.is_campus() {
            return Some(a.clone());
        }
    }
    adapters
        .into_iter()
        .find(|a| {
            (a.name.to_ascii_lowercase().contains("wlan")
                || a.name.to_ascii_lowercase().contains("wifi")
                || a.name.contains("无线"))
                && !a.ipv4.is_empty()
        })
}

// ---------------------------------------------------------------------------
// 极简 HTTP/1.1 客户端(支持绑定源 IP)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>, // name 全小写
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }
}

pub struct HttpClient {
    pub source: Option<Ipv4Addr>,
    pub timeout: Duration,
}

impl HttpClient {
    pub fn new(source: Option<Ipv4Addr>) -> Self {
        HttpClient {
            source,
            timeout: Duration::from_secs(8),
        }
    }

    /// GET/POST 一个 http:// URL。url 形如 http://host[:port]/path?query
    pub fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> Result<HttpResponse, String> {
        // 解析 URL
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| format!("仅支持 http URL: {url}"))?;
        let (hostport, path) = match rest.find('/') {
            Some(p) => (&rest[..p], &rest[p..]),
            None => (rest, "/"),
        };
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
                (h, p.parse::<u16>().unwrap_or(80))
            }
            _ => (hostport, 80),
        };

        // DNS 解析 + 建连(绑定源 IP)
        let target = (host, port)
            .to_socket_addrs()
            .map_err(|e| format!("DNS 解析失败 {host}: {e}"))?
            .find(|a| a.is_ipv4())
            .ok_or_else(|| format!("DNS 未返回 IPv4 地址: {host}"))?;

        let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .map_err(|e| format!("创建 socket 失败: {e}"))?;
        if let Some(src) = self.source {
            sock.bind(&std::net::SocketAddr::from((src, 0)).into())
                .map_err(|e| format!("绑定源 IP {src} 失败: {e}"))?;
        }
        sock.connect_timeout(&target.into(), self.timeout)
            .map_err(|e| format!("连接 {target} 失败: {e}"))?;
        sock.set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("set_read_timeout 失败: {e}"))?;
        sock.set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("set_write_timeout 失败: {e}"))?;
        let mut stream: TcpStream = sock.into();

        // 构造请求
        let host_hdr = if port == 80 {
            host.to_string()
        } else {
            format!("{host}:{port}")
        };
        // 请求里 User-Agent 只能出现一次: 门户按【首个】UA 头判定设备类型(实测),
        // 若先固定写默认 UA 再把调用方 UA 追加其后, 门户永远读到默认 UA,
        // 手机端认证会被误判为电脑。因此仅在调用方未提供 UA 时补默认值。
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host_hdr}\r\nConnection: close\r\n"
        );
        let mut has_ua = false;
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("user-agent") {
                has_ua = true;
            }
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        if !has_ua {
            req.push_str("User-Agent: rust-auth/1.0\r\n");
        }
        match body {
            Some(b) => {
                req.push_str(&format!("Content-Length: {}\r\n", b.len()));
                req.push_str("\r\n");
                req.push_str(b);
            }
            None => req.push_str("\r\n"),
        }
        use std::io::{Read, Write};
        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("发送请求失败: {e}"))?;

        // 读响应(直到 EOF / 超时),手动循环以保留超时前已收到的数据
        let mut raw = Vec::with_capacity(16 * 1024);
        let mut chunk = [0u8; 8192];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => raw.extend_from_slice(&chunk[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(e) => return Err(format!("读取响应失败: {e}")),
            }
        }

        parse_response(&raw)
    }
}

/// 解析 HTTP 响应(状态行 + 头 + body,支持 chunked)
fn parse_response(raw: &[u8]) -> Result<HttpResponse, String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "响应缺少头部分隔符".to_string())?;
    let head = String::from_utf8_lossy(&raw[..sep]).into_owned();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.split_whitespace();
    let _ver = parts.next().unwrap_or("HTTP/1.1");
    let status: u16 = parts
        .next()
        .unwrap_or("0")
        .parse()
        .map_err(|_| format!("无法解析状态行: {status_line}"))?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let mut body = raw[sep + 4..].to_vec();
    let chunked = headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        body = decode_chunked(&body);
    }
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

/// RFC7230 chunked 解码
fn decode_chunked(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0usize;
    loop {
        // 读一行 chunk size
        let line_end = match data[i..].windows(2).position(|w| w == b"\r\n") {
            Some(p) => i + p,
            None => break,
        };
        let size_str = String::from_utf8_lossy(&data[i..line_end]);
        let size_str = size_str.split(';').next().unwrap_or("").trim();
        let size = match usize::from_str_radix(size_str, 16) {
            Ok(s) => s,
            Err(_) => break,
        };
        i = line_end + 2;
        if size == 0 {
            break;
        }
        if i + size > data.len() {
            out.extend_from_slice(&data[i..]);
            break;
        }
        out.extend_from_slice(&data[i..i + size]);
        i += size + 2; // 跳过 chunk 数据 + \r\n
    }
    out
}
