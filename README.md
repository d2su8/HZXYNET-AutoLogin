# HZXYNET-AutoLogin（贺州学院校园网自动认证项目）

[![AI Assisted](https://img.shields.io/badge/AI-Assisted%20Project-blue)](AI-NOTES.md)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-lightgrey)]()
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

贺州学院校园网（bossWeb 门户）自动认证工具 —— Rust + Win32 API 编写的原生 Windows 应用，单文件可执行、零运行时依赖。

> **同一套认证协议的路由器版**：[PortalKeeper](https://github.com/d2su8/PortalKeeper) —— OpenWrt 插件（Rust 静态单二进制 + LuCI 中文界面，opkg 安装），
> 开机自动认证、掉线自动重连、多线多拨、逐线路联通测试，日志只写 /tmp 不磨损 NAND。

> 本项目由 **AI 辅助完成**（AI-Assisted），详见 [AI-NOTES.md](AI-NOTES.md)。

## 功能特性

- **一键 Web 认证**：完整复刻 bossWeb 门户浏览器认证流程（探测劫持 → 会话 Cookie → 表单提交 → 复核放行），全程自动
- **双设备槽位**：按 User-Agent 区分设备类型，可选「电脑端」或「手机端」登录（账号限 1 台电脑 + 1 部手机/平板同时在线）
- **网卡选择与源地址绑定**：枚举本机网卡并绑定源 IP 发包，适配「有线接普通网络 + Wi-Fi 接校园网」的双网卡环境
- **加密保存凭据**：密码经 Windows DPAPI（当前用户绑定 + 应用熵）加密后存储，文件中无明文
- **内嵌日志**：认证过程逐条显示在程序界面，并随配置合并写入单一数据文件
- **幂等保活**：已在线时只探测不重复登录；DHCP 换 IP 后重新认证即可恢复
- **槽位冲突保护**：检测到设备槽位被占用时绝不自动顶号，只提示到自助管理界面手动下线
- **一键下线本设备**：走门户自助管理接口（在线设备列表 → 踢下线 → 复核断网），门户强制验证码，弹图输入 4 位即可

## 环境要求

- Windows 10 / 11 x64
- 无需安装任何运行库（原生编译，无 .NET / Python / VC Redist 依赖）
- 从源码构建需要 Rust 1.75+（MSVC 工具链）

## 预编译版本

在 [Releases](../../releases) 下载预编译的 Windows x64 可执行文件：

| 文件 | 说明 |
|---|---|
| `campus-auth.exe` | 图形界面版（主程序，双击即用） |
| `campus-auth-cli.exe` | 命令行版（可选，供脚本/计划任务使用） |

运行时数据（加密凭据 + 日志）保存在 exe 同目录的 `campus-auth.dat`，该文件含个人凭据密文，**请勿分享**。

## 使用方法

1. 下载或构建 `campus-auth.exe`，双击运行
2. 在「网卡选择」下拉框中选择校园网网卡（程序会自动识别校园网段 10.200/10.202 并绑定源 IP）
3. 输入账号密码，选择设备类型（电脑端 / 手机端）
4. 点击「一键认证登录」，在确认弹窗中同意后开始认证
5. 认证成功后即可上网；可勾选「保存账号密码(加密存储)」实现下次自动填充

> 提示：若提示槽位冲突（该设备类型已被占用），请到门户自助管理界面手动下线旧设备后再试，程序不会自动顶号。

## 命令行（可选）

仓库同时提供 `campus-auth-cli.exe`（与 GUI 共享认证引擎），便于脚本化：

```text
campus-auth-cli.exe --check                 # 仅探测认证状态
campus-auth-cli.exe --list-adapters         # 列出网卡
campus-auth-cli.exe --ask-password          # 交互登录（默认电脑端）
campus-auth-cli.exe --offline               # 下线本设备并清 MAC 绑定（弹验证码图，输入 4 位后自动下线）
  --ua pc|mobile      设备类型
  --adapter NAME      网卡名
  --source IP         直接指定源 IP
  --save              登录成功后加密保存凭据
  --forget            清除已保存凭据
  --offline-code N --offline-session S   # 脚本两段式提交验证码
退出码: 0=成功/已在线  1=失败  3=槽位冲突需手动下线
```

## 从源码构建

```bash
cargo build --release
# 产物: target/release/campus-auth.exe (GUI) 与 campus-auth-cli.exe (CLI)
```

## 换学校 / 换门户（自动发现 + 手动填写）

**认证服务器不是写死的**：程序先用内置探测地址探一次，被 AC 302 劫持时直接跟着跳转地址走，
表单字段和账号/密码字段名也都从登录页现解析。所以换到别的同类门户（web 门户 + 表单提交）通常不用改代码。

探测不到时（该校 AC 不用 302 劫持，或本机不在校园网），程序会提示手动填写「门户地址」：

1. 用浏览器打开任意一个 http 网站，例如 `http://www.msftconnecttest.com/connecttest.txt`
2. 浏览器会自动跳到校园网认证页 —— 把地址栏里那条地址**整个复制**下来
3. 粘贴到界面的「门户地址」框（或命令行 `--portal '地址'`），再点「一键认证登录」

填过一次就会自动记进数据文件（`campus-auth.dat` 里的 `portal_url`），以后直接用。
界面上的「检测门户」按钮 / 命令行 `--detect-portal` 只做探测，不登录、不占槽位。

其他相关开关：`--save-portal` 把发现的门户地址写进数据文件；环境变量
`CAMPUS_AUTH_PROBE` 可以覆盖探测地址（逗号分隔，如 `10.0.0.1/portal,example.com/generate_204`），
用于测试或换用自己的探测网站。

## 认证协议概要

未认证时，网关（AC）会将任意 HTTP 出网请求 302 重定向到门户登录页，URL 查询串中携带会话绑定参数（`wlanuserip` / `mac` 等）；登录即向同一 URL POST 配置字段 + 账号密码。是否上线以「复核探测」为准（响应头无 `Location` = 已放行）。设备类型由 User-Agent 判定（**单 UA 头**，门户取首个）。完整协议见 [docs/PROTOCOL.md](docs/PROTOCOL.md)。

## 项目结构

```text
Hzunet-autologin/
├─ .github/workflows/   # CI（构建 + 测试）
├─ docs/
│  └─ PROTOCOL.md       # 认证协议文档
├─ src/
│  ├─ main.rs           # Win32 原生 GUI(窗口/控件/消息循环/后台线程)
│  ├─ cli_main.rs       # CLI 入口(console 子系统)
│  ├─ cli_shared.rs     # CLI 逻辑(与 GUI 共享引擎)
│  ├─ auth.rs           # 认证引擎(探测/登录/复核)
│  ├─ selfsvc.rs        # 自助管理接口(设备列表/下线本设备/验证码解码)
│  ├─ net.rs            # 网卡枚举 + 绑定源 IP 的 HTTP 客户端
│  ├─ crypto.rs         # DPAPI 加密存储
│  ├─ store.rs          # 单一数据文件(配置+加密凭据+滚动日志)
│  └─ common.rs         # 常量与工具
├─ build.rs             # winres 嵌入 comctl32 v6 清单
├─ Cargo.toml / Cargo.lock
├─ AI-NOTES.md          # AI 编辑项目说明
└─ LICENSE
```

## 相关项目

同一套「探测劫持 → 表单提交 → 复核放行」认证协议，两种运行形态：

| 项目 | 形态 | 适用场景 |
|---|---|---|
| **本项目** | Windows 10 / 11 x64 | Rust + Win32 原生 GUI，单文件零运行时依赖；适合单机——例如网线接普通网络、Wi-Fi 接校园网的双网卡环境，按网卡绑定源 IP 发包 |
| [PortalKeeper](https://github.com/d2su8/PortalKeeper) | OpenWrt / LuCI | 路由器插件：Rust 静态单二进制 + LuCI 中文 Web 界面，opkg 安装；procd 开机自启、掉线自动重试、多线多拨、逐线路联通测试、自定义探测网站；日志只写 /tmp（不磨损 NAND）；路由器认证一次，全屋设备共享在线 |

两者的协议细节同源，协议文档见 [docs/PROTOCOL.md](docs/PROTOCOL.md)。

## 安全说明

- 凭据使用 Windows DPAPI 加密（绑定当前用户，换用户/换机器无法解密），并叠加应用熵
- 门户本身为明文 HTTP，属于校园网现状；本工具不改变传输方式，仅保护本地存储
- 日志不含密码；「历史日志」仅内存与本机数据文件
- 请勿在公用电脑勾选保存密码

## 免责声明

- 本项目仅供个人学习交流使用，请遵守所在学校/机构的网络使用规定。使用本项目产生的一切后果由使用者自行承担。
- 本脚本并非破解软件，不提供破解功能，无任何入侵和破解行为。
- 本软件免费发布并无任何盈利行为，请勿商用。

## 许可证

[MIT License](LICENSE)
