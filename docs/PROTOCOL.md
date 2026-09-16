# 认证协议文档 (bossWeb Portal)

> 本文描述校园网 bossWeb 门户的 Web 认证协议，全部要点均来自实机抓包与回归验证。

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
