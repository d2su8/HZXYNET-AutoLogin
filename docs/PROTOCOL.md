# 认证协议文档 (bossWeb Portal)

> 本文描述校园网 bossWeb 门户的 Web 认证协议，全部要点均来自实机抓包与回归验证。
>
> **⚠️ 2026-10 门户大改版**：学校已把门户换成新版 SPA（IP `10.255.2.252` → `10.255.2.249`，
> 登录路径 `/webauth.do` → `/portal/webauth`，自助后台 `/self/index.html` → `/self/` SPA + `/api/portal/user/*` 令牌 API，
> **图片验证码取消、下线改走令牌接口**）。**以 §8「新版门户（v3）」为准**；
> 旧版协议（§1–§7）保留作历史参考，工具会按登录页是否有 password 输入框自动识别两种门户。

## 1. 探测：判断认证状态

未认证时，AC（接入控制器）将任意 HTTP 出网请求 302 重定向到门户登录页：

```text
GET http://www.msftconnecttest.com/connecttest.txt
→ HTTP/1.1 302 Found
→ Location: http://<PORTAL>/webauth.do?wlanacip=<AC_IP>&wlanacname=<NAME>
            &wlanuserip=<本机IP>&mac=<本机MAC>&vlan=0&url=<原始目标>
```

判定规则（幂等关键）：

- 响应头存在 `Location` 且指向门户 → **未认证**（该 URL 即登录入口，查询串为会话绑定参数）
- 响应头无 `Location` 且状态 200/204 → **已放行（已认证）**
- 302 到其他位置（如 baidu 的 http→https 跳转）→ **无结论**，换下一个探测地址
- 门户为明文 HTTP（80 端口），无 TLS

建议探测地址（任一给出结论即可，可并发）：

```text
http://www.msftconnecttest.com/connecttest.txt
http://connect.rom.miui.com/generate_204
http://www.baidu.com/
```

## 2. 获取登录页

GET 重定向得到的登录页 URL：

- 取得会话 Cookie（如 `JSESSIONID-BOSS-1=...`），后续 POST 需带上
- 登录页包含大量隐藏表单字段，其中配置类字段的值**应动态解析**（不同网段的值可能不同，例如 `hostIp` 在无线段为 `http://127.0.0.1:8081/`、有线段为 `:8082/`）

## 3. 提交认证

向与登录页相同的 URL（含查询串）POST 表单：

```text
Content-Type: application/x-www-form-urlencoded
Referer: <登录页URL>
Cookie: <第2步取得的会话Cookie>
User-Agent: <按设备类型选择 PC 或手机 UA>

scheme=http&serverIp=tomcat_server%3A80&hostIp=http%3A%2F%2F127.0.0.1%3A8081%2F
&auth_type=0&isBindMac1=0&pageid=-1&templatetype=1&listbindmac=0&recordmac=0
&userId=<账号>&passwd=<密码>
```

- **设备类型**由 User-Agent 决定：PC UA 占「电脑槽」，手机 UA 占「手机槽」；账号限 1 台电脑 + 1 部手机/平板同时在线
- **User-Agent 头只能出现一次**：门户按【首个】User-Agent 头判定设备类型（实测：两个 UA 头时取第一个）。若请求带重复 UA 头，设备 UA 会被排到第二位导致误判为电脑
- 响应页中的隐藏域 `<input id="errMessage" value="...">` 为人类可读结果（如「密码错误」「认证成功」）

## 4. 复核放行（唯一的可靠判定）

不依赖 `errMessage` 文案。等待 2–4 秒后重复第 1 步探测：

- 无 `Location` 且 200/204 → **已上线**
- 仍被劫持 → 再等 3 秒复核一次；仍未放行则失败

## 5. 槽位冲突处理

`errMessage` 含「已在线 / 重复 / 超限 / 终端 / 绑定」等关键词时判定为槽位冲突：

- **绝不自动顶号**（该门户无可靠的程序化下线接口）
- 引导用户到门户自助管理界面（`http://<PORTAL>/self/index.html#/Login`）手动下线后重试

## 6. 其他要点

- **源地址绑定**：双网卡机器必须绑定校园网网卡的源 IP 发包，否则认证流量走默认路由（普通网络）探测不到劫持
- **单 UA 头**：请求中 User-Agent 只能有一个；门户按首个 UA 判定设备类型（`Linux/Android` 判手机、`Windows NT` 判电脑，与机型或 `Mobile` 标记无关——无机型名、无 Mobile 标记的 Linux UA 也实测判为手机）
- **DHCP 换 IP**：认证按 IP+MAC 放行，租约更新换 IP 后需重新认证
- **编码**：门户响应以 UTF-8 为主，个别流程页为 GBK，建议 UTF-8 → GBK 顺序容错解码
- **幂等**：已在线时只探测不提交表单，探测请求应保持轻量（单请求、短超时）

## 7. 自助管理下线接口（/self，旧版，历史参考）

下线走门户自助管理 JSON API（与 web 认证同主机 `10.255.2.252` 但**独立会话**，门户登录不贯通）。全链路：

1. `POST /self/tologin.do {}` → `Set-Cookie: JSESSIONID-BOSS-1=<SPA会话>`，`data.verifyCode` 为 base64 PNG 验证码（130×40，与该会话绑定）
2. `POST /self/login.do {"accountId","password","verifyCode"}`（带同一 Cookie）→ `errcode=0`；缺 Cookie 一律「验证码为空」
3. `POST /self/getonline.do {"accountId"}` → `rows[]`，行字段：`accountId/accountMac/billingId/accountIp/serverIp/onlineTime/port/nasId/vlanId/terminalType('a'=PC,'b'=手机)/osInfo/broswerType/externalFlag/authType/binded`
4. `POST /self/kickonline.do {"accountId","accountIp","billingId","serverIp"}`（必须用本机行的 live 值）→「下线成功」，3–4 秒内设备回 captive；`kickonlineByMac.do {"accountId","accountMac"}` 按 MAC 批下线并**清除绑定**；`clearusermac.do {"accountId"}` 仅清绑定

要点：

- **调用规约**：全部 POST + `Content-Type: application/json`（表单编码→415，空/畸形 JSON→400），响应统一 `{"errcode","errmsg","success"}`，未登录业务接口 `errcode=-1「请重新登录」`
- **单 IP 单会话**：同 IP 在线时换 UA 再登录 →「此IP已在线请勿重复认证」
- **设备分类是 MAC 绑定粘性**：计费行分类在建绑定的那次登录按 UA 确定，之后同 MAC 换 UA 不变（门户模板仍随 UA）；换槽 = 清绑定（kick ByMac）→ 目标 UA 重登
- **清绑定注意**：`kickonline`（按行下线）**不**清除 MAC 绑定；`clearusermac.do` 虽返回「操作成功」但实测不总能实际清掉绑定（次日登录仍沿用旧分类）。修正/切换槽位请用 `kickonlineByMac`
- **限流**：连续登录间隔 <15s 会「认证请求太频繁」，重试间隔建议 ≥30s
- **策略**：仅下线本机（行匹配本机 MAC/IP），绝不顶号；死路：`webdisconn.do`（恒拒绝）、`appoffline.do`（404）、在线态 `1.1.1.1/userlogout.massrv`（直通公网）

## 8. 新版门户（v3，2026-10 起，当前生效）

门户换成 Vite 打包的 SPA + JSON/表单接口。旧版（§1–§7）仅作历史参考，判据天然兼容：**登录页没有 `password` 输入框 → 新版 SPA 门户**。

### 8.1 变化一览

| 项 | 旧（≤2026-09） | 新（2026-10 起） |
|---|---|---|
| 门户 IP | `10.255.2.252` | `10.255.2.249` |
| 登录页路径 | `/webauth.do?<绑定query>` | `/portal/webauth?<绑定query>` |
| 登录页内容 | 74KB 服务端渲染 HTML（带表单） | 2.2KB SPA 外壳，只有隐藏参数 `#portalLegacyParams` |
| 提交方式 | 向同一 URL 表单 POST（B 组 9 字段 + userId/passwd） | `POST /portal/webauth/auth`（表单编码），响应 JSON |
| 自助后台 | `/self/index.html` + `/self/*.do`（独立 SPA 登录 + 图片验证码） | `/self/` SPA + `/api/portal/user/*`（`Authorization: Bearer <令牌>`），无验证码 |
| 令牌来源 | 自助 SPA 自己登录（tologin/login.do） | Web 认证响应 `result.token` |
| 网关参数 | 会话参数只在校验里 | 接口必填 `wlanacip` / `wlanacname` |

### 8.2 认证流程（实测）

```
1) 探测(未认证时任意 HTTP) → 302 Location:
   http://10.255.2.249/portal/webauth?wlanacip=10.255.2.250&wlanacname=hzxy&wlanuserip=<本机IP>&mac=<本机MAC>&vlan=0&url=<原始目标>
2) GET 该 Location → SPA 外壳; 页面无 password 输入框(这是"新版 SPA 门户"的判据)
3) POST http://10.255.2.249/portal/webauth/auth
   Content-Type: application/x-www-form-urlencoded
   userId=<账号>&passwd=<密码>&loginMode=password
   &wlanuserip=<本机IP>&wlanacip=10.255.2.250&wlanacname=hzxy
4) 响应(JSON): {"success":true,"message":"","code":200,
    "result":{"redirect":"/portal/center?pageid=...&terminalType=a&distoken=...&token=<签名令牌>",
              "accountId":"<账号>","distoken":"...","token":"<签名令牌>"},
    "timestamp":...}
5) 放行判定: 仍用探测(等 3 秒, 200/204 无 Location = 已上线) —— 不解析 JSON 文案
```

关键细节：

- **密码明文**，无 RSA/SM2/JSEncrypt；`loginMode` 可选 `password` / `sms` / `twoFactor`（本校未启用短信/二次验证）。
- **设备已在线时接口照样返回 `success:true` + 新令牌**，提示放在 `redirect` 的 `errorMsg` 参数（`此IP已在线请勿重复认证`）——在线状态下也能拿令牌查列表/下线。
- 失败响应：`{"success":false,"message":"账号或密码错误","code":500}`；缺少 `wlanacip`/`wlanacname` 时报「认证失败: 网关配置不存在」。
- `token` 形如 `base64url({"accountId","timestamp"}) + "." + <hex 签名>`，实测同一令牌 10 分钟内可用。

### 8.3 自助后台 API（令牌鉴权，实测）

基地址 `http://10.255.2.249`，前缀 `/api`，鉴权头 `Authorization: Bearer <token>`。

| 用途 | 调用 | 备注 |
|---|---|---|
| 在线设备 | `GET /api/portal/user/onlineUsers?pageNum=1&pageSize=50` | `result.items[]`：`accountBindIp` / `callerId`(MAC) / `terminalType`(a/b) / `terminalTypeLabel` / `onlineTime` / `internetTacticsName` |
| 强制下线 | `POST /api/portal/user/onlineUser/forceOffline` JSON `{"accountBindIp":"<IP>","callerId":"<MAC>"}` | 实测「强制下线成功」；3~4 秒内探测回 302 |
| 清除 MAC 绑定 | `DELETE /api/portal/user/accountMac?terminalMac=<MAC>` | 无记录时回「未找到可清除的MAC记录」（视为无需清理） |

响应统一 `{success, message, code, result, timestamp}`；失败看 `message`。

### 8.4 对工具的影响

1. **登录**：登录页无 password 输入框 → 走 `/portal/webauth/auth`（JSON 响应），否则走旧表单式逻辑（§3）。
2. **门户地址与网关参数要"记住"**：在线时无劫持响应，而新接口必须带 `wlanacip`/`wlanacname`，因此首次登录时把门户基地址 + 网关参数写进 `campus-auth.dat`（`portal_url` / `wlanacip` / `wlanacname`）。
3. **下线流程**：拿令牌（Web 认证接口）→ `onlineUsers` → 按 MAC/IP 匹配本机 → `forceOffline` → `accountMac` 清绑定 → 探测复核。GUI 验证码弹窗、GDI+ PNG 解码、CLI `--offline-code/--offline-session` 全部删除。
4. **槽位分类仍由 UA 决定**（`terminalType` a=电脑/b=手机），选「电脑端/手机端」继续有效。
