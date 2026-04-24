# 卡密系统 → 纯 Shadowsocks 架构改造方案

> 目标：用户在网页上输入**账号 + 密码 + 卡密**完成注册/续期后，
> 客户端一键导入 `ss://` 链接或扫码即可上网。
>
> ⚠️ **协议选型说明**：
> 原计划用 SOCKS5，但 3x-ui 面板协议下拉里没有 `socks` 选项（官方隐藏了，因为 SOCKS5 明文）。
> 改用 **Shadowsocks**，好处更多：
> - **流量加密**（AES-256-GCM），SOCKS5 做不到
> - 3x-ui 原生支持，代码改动小（复用现有 `addClient` API）
> - 小火箭/Clash/V2rayN 全部原生支持一键导入
> - 每用户独立密码，鉴权方式与 SOCKS5 等价

---

## 一、现状 vs 目标

### 1.1 你现在的样子（Trojan 架构）

```
[浏览器]               [main.py]               [3x-ui 面板]           [Xray 内核]
   │  注册/卡密      │                     │                     │
   ├──────────────▶│  写 user 表         │                     │
   │                │  调 /panel/api      │                     │
   │                ├────────────────────▶│  addClient          │
   │                │                     │  (Trojan, 18888)    │
   │                │                     ├────────────────────▶│
   │                │                     │                     │  监听 18888
   │                │                     │                     │  协议=Trojan
   │  返回订阅链接   │                     │                     │  security=none ❌
   │◀───────────────┤                     │                     │
   │
   │  sub://user:pass@host/sub_auth
   ▼
[小火箭] ── 拉订阅 ──▶ 得到 trojan://UUID@IP:18888?security=none
                       ↑
            问题：Trojan 无 TLS 几乎没有客户端支持，
                 所以你朋友才说"要 socks5 / 要搞隧道 / ssh 加密"
```

### 1.2 改造后的样子（Shadowsocks 架构）

```
[浏览器]               [main.py]               [3x-ui 面板]           [Xray 内核]
   │  注册/卡密      │                     │                     │
   ├──────────────▶│  写 user 表         │                     │
   │                │  调 /panel/api      │                     │
   │                ├────────────────────▶│  addClient          │
   │                │                     │  (Shadowsocks, 1080)│
   │                │                     ├────────────────────▶│
   │                │                     │                     │  监听 1080
   │                │                     │                     │  协议=shadowsocks
   │                │                     │                     │  加密=AES-256-GCM
   │                │                     │                     │  clients=[邮箱/密码]
   │  返回 ss:// URI │                     │                     │
   │◀───────────────┤                     │                     │
   │
   │  ss://BASE64(aes-256-gcm:密码)@IP:1080#名称
   ▼
[小火箭] ── 点击一键导入 / 扫码 ──▶ 自动识别 Shadowsocks 节点
                                    加密已自动配置
                                    密码已自动填入
```

**关键变化**：
- 入站协议：`Trojan(18888, no TLS)` → **`Shadowsocks(1080, AES-256-GCM)`**
- 下发内容：`trojan://` URI → **`ss://` URI**（标准 SS 一键导入链接 + 二维码）
- 客户端操作：**一键导入**（点 `ss://` 链接）或**扫码**

---

## 二、为什么选 Shadowsocks 是对的

| 对比项 | Trojan-无TLS（现在） | Shadowsocks-AEAD（目标） |
|---|---|---|
| 小火箭兼容性 | ❌ 必须带 TLS 才能识别 | ✅ 原生支持 `ss://` 一键导入 |
| 客户端配置复杂度 | 需导入订阅 + 证书 | **点链接/扫码即可** |
| 是否需要域名 | 配合 TLS 时需要 | **不需要** |
| 流量加密 | 有（如果开 TLS） | ✅ **AES-256-GCM（AEAD）** |
| 抗封锁能力 | 强（有 TLS 时） | 中（比裸 SOCKS5 强） |
| 3x-ui 原生支持 | ✅ | ✅ |

> ✅ **Shadowsocks 自带 AEAD 加密**，运营商看不到流量内容。
> 如果后续遇到强封锁，可以再叠加 `plugin=v2ray-plugin` 走 WebSocket+TLS 混淆（到时需要域名）。

---

## 三、3x-ui 面板侧改造（手动操作，一次性）

你现在面板里已经有一个 18888 的 Trojan 入站。改造思路：**保留旧入站不动（兼容老用户）**，**新增一个 Shadowsocks 入站**，然后让 `main.py` 之后的新注册都写到这个新入站里。

### 3.1 新增 Shadowsocks 入站

打开 3x-ui → 入站列表 → **添加入站**，按下表填（对应你截图 5 的那个弹窗）：

| 字段 | 值 | 说明 |
|---|---|---|
| 启用 | **开** | |
| 备注 | `FengDu-SS` | 任意 |
| 协议 | **`shadowsocks`** | 下拉选它 |
| 监听 | 空 | 监听全部网卡 |
| 端口 | `1080`（或任意未占用端口） | ⚠️ 记下来 |
| 总流量 | `0` | 不限量 |
| 流量重置 | 从不 | |
| 到期时间 | 空 | |
| **加密** | **`AES_256_GCM`** | 保持默认即可（也可选 `CHACHA20_POLY1305`） |
| 网络 | `TCP,UDP` | 保持默认 |
| 传输 | `TCP (RAW)` | 保持默认 |
| 安全 | **`无`** | SS 自己加密，不需要 TLS |
| **客户 (Clients)** | 先留一个占位客户即可（面板要求至少 1 个） | 后续由程序自动增删 |
| Sniffing | 可开 `http,tls` | 让 Xray 能看到目的域名，方便排查 |

保存后，**记下这个入站的 ID**（列表左侧那个数字，假设是 `2`）。

### 3.2 防火墙 / 安全组放行

- 云服务器（阿里云/腾讯云/AWS）：去控制台安全组给 TCP+UDP **1080** 放行入站。
- 本机防火墙（ufw/firewalld）：
  ```bash
  sudo ufw allow 1080/tcp
  sudo ufw allow 1080/udp
  ```

### 3.3 验证面板侧通了

从任意一台带 SS 客户端的机器（也可以直接用小火箭），用"占位客户"的账号密码连一下 `106.14.137.59:1080` + `AES-256-GCM` + 那个占位密码，能上网就说明入站 OK。

或者服务器上装个 `sslocal` 命令行也能测，但不必须。

---

## 四、代码侧改造（`main.py`）

> 这一节只说**改哪里、改成什么**，不贴完整代码。你下次让我动手时直接按这个清单改。
> **好消息**：因为 3x-ui 对 SS 和 Trojan 的客户端管理用**同一套 API**（`/panel/api/inbounds/addClient` / `updateClient` / `delClient`），现有 `XUIClient` 类 90% 可以直接复用，只需要微调 `client_obj` 字段。

### 4.1 新增配置项（文件顶部）

```
XUI_SS_INBOUND_ID = int(os.getenv("XUI_SS_INBOUND_ID", "2"))   # 第 3.1 步记下的 ID
SS_SERVER_HOST    = os.getenv("SS_SERVER_HOST", "106.14.137.59")
SS_SERVER_PORT    = int(os.getenv("SS_SERVER_PORT", "1080"))
SS_METHOD         = os.getenv("SS_METHOD", "aes-256-gcm")   # 与面板加密方式保持一致
```

旧的 `UNIFIED_PROXY_*` / `XUI_INBOUND_ID` 变量**保留**（老的 Trojan 订阅还要用），不动。

### 4.2 改造 `XUIClient.add_client` 的 `client_obj` 字段

Trojan 的 client 是：
```python
{"id": UUID, "password": UUID, "flow": "", "email": ..., "limitIp": 0, ...}
```

SS 的 client 是（3x-ui 内部要求）：
```python
{
    "method": "",          # 为空 = 继承入站的加密方式（推荐）
    "password": 用户密码,   # ⚠️ SS 只靠密码区分用户，全入站唯一
    "email": 用户名,       # 面板展示用
    "limitIp": 0,
    "totalGB": 0,
    "expiryTime": 到期毫秒,
    "enable": True,
    "tgId": "",
    "subId": "随机16位",
    "reset": 0,
}
```

两个协议共用 `XUIClient`，建议把 `add_client / update_client` 改成能接收 `protocol: Literal["trojan","ss"]` 参数，内部分叉构造 `client_obj`。

### 4.3 新增 `_sync_ss_upsert` / `_sync_ss_remove`

和现有 `_sync_xui_upsert` / `_sync_xui_remove` 并列，只是传入的 `inbound_id` 和 `client_obj` 结构不同。

### 4.4 在 `api_register` / `api_recharge` / 管理员调时长接口里**切换调用**

把对 `_sync_xui_upsert(user)` 的调用改为 `_sync_ss_upsert(user)`（如果决定全切到 SS）；
或者同时调用两个（双轨期），新老客户端都能连。

### 4.5 注册/续期接口的返回值改造

现在返回：
```json
{"sub_url": "...", "sub_url_with_auth": "...", "sub_import_url": "sub://..."}
```

改为追加（或替换）为：
```json
{
  "proxy": {
    "type": "shadowsocks",
    "host": "106.14.137.59",
    "port": 1080,
    "method": "aes-256-gcm",
    "password": "用户的SS密码（建议 = 用户 UUID）"
  },
  "ss_uri": "ss://YWVzLTI1Ni1nY206VVVJRA==@106.14.137.59:1080#风度防封专线"
}
```

**`ss://` URI 的标准格式**：
```
ss://BASE64(method:password)@host:port#name
```
例如 `method=aes-256-gcm`, `password=abc123`, `host=1.2.3.4`, `port=1080`：
```
ss://YWVzLTI1Ni1nY206YWJjMTIz@1.2.3.4:1080#风度防封专线
```
BASE64 部分是 `aes-256-gcm:abc123` 的 URL-safe Base64 编码。

这个链接：
- 点击：小火箭 / Clash 直接弹出导入
- 扫码：生成二维码后手机扫一下就导入
- 复制：粘贴到客户端"从剪贴板导入"也可

### 4.5 可以删掉/保留的东西

| 接口 | 处理 |
|---|---|
| `GET /sub_auth`（订阅入口） | **保留**，老用户小火箭里的订阅还要刷新用。新用户可以不引导走这个 |
| `GET /sub/{device_id}`（规则分发） | **保留**，跟代理协议无关，是 Shadowrocket 的分流规则 |
| 证书下载 `/download/certificate` | SOCKS5 不需要证书，可以**从前端注册完成页移除按钮**，后端路由保留无妨 |

### 4.6 前端注册成功页要改（`templates/index.html` 等）

改成三段式：

```
方式一（推荐，一键导入）：
   [按钮] 点此一键导入小火箭   → href="ss://BASE64@host:port#名称"

方式二（扫码导入）：
   [二维码]  内容就是上面的 ss:// URI

方式三（手动添加）：
   类型：Shadowsocks
   地址：106.14.137.59
   端口：1080
   加密：aes-256-gcm
   密码：xxxxxxxx              (复制按钮)
```

我可以在代码改造阶段帮你把 HTML 一起改掉，现在先不动。

---

## 五、客户端教程（给你的客户看的）

### 5.1 小火箭 iOS

1. 打开 Shadowrocket → 右上角 `+`
2. 类型选 **`Socks5`**
3. 地址：`106.14.137.59`
4. 端口：`1080`
5. 用户名：网站上注册的账号
6. 密码：网站上注册的密码
7. 保存 → 选中该节点 → 首页顶部拨杆打开

### 5.2 Clash（Mac/Win/Android）

配置片段：
```yaml
proxies:
  - name: "FengDu-Socks5"
    type: socks5
    server: 106.14.137.59
    port: 1080
    username: 你的账号
    password: 你的密码
    udp: true
```

### 5.3 Windows / Mac 系统直连

Windows → 设置 → 网络 → 代理 → 手动设置代理 → 填 `106.14.137.59:1080`（但这个是 HTTP 代理框，不能用，**SOCKS5 要靠软件**，不推荐）。
推荐用 Proxifier 或 Clash for Windows 全局。

---

## 六、域名这事儿（你选了"可以买一个"）

### 6.1 纯 SOCKS5 架构**短期内不需要域名**

按本方案跑起来，客户填 IP:端口就行。

### 6.2 什么时候需要买域名？

出现以下任一情况时考虑：
- 服务器 IP 被墙（国内运营商封) → 换 IP 后域名不用改，客户不用重新配置
- 客户抱怨"明文鉴权不安全，能不能加密" → 需要 TLS，TLS 需要域名
- 想上 CDN 隐藏真实 IP → 必须有域名

### 6.3 买什么样的域名

- 注册商：Cloudflare Registrar / Namecheap / 国内阿里云均可
- 后缀：`.com / .net / .xyz / .top` 都行，`.xyz` 最便宜（10元/年左右）
- 要求：无需备案（如果用**海外服务器 / 境外 CDN**）；如果你这台是阿里云国内服务器，用 IP 就行**不要**绑域名（备案麻烦，且和这个业务冲突）

### 6.4 域名到位后怎么升级（未来事）

DNS → A 记录指向 `106.14.137.59` → 在 3x-ui 里新增一个 **Trojan/VLESS + TLS + 域名** 入站，同时保留 SOCKS5 入站，给愿意"要加密"的高端客户用。

---

## 七、改造落地的执行顺序（推荐）

1. **先手工** 在 3x-ui 加 SOCKS5 入站（第三章），用 curl 确认通（第 3.3）。
2. **再改代码**（第四章），先只实现"新注册 → 写 SOCKS5 入站"，老用户不动。
3. **前端先加一个新段落**展示 SOCKS5 参数，老的订阅段落暂时保留。
4. 找**两三个内测客户**按第五章教程连一下，全部 OK 再广播给所有客户。
5. 等 2-3 周没问题后，把 Trojan 入站和相关订阅路由**下线**，完成迁移。

---

## 八、我需要你确认的几个事

下次开始改代码前，请你告诉我：

1. SOCKS5 入站的**端口**你准备用哪个？（`1080` / `2080` / 其他）
2. 在 3x-ui 里加完 SOCKS5 入站后，把那个**入站 ID** 告诉我（类似现在的 `XUI_INBOUND_ID=1`）。
3. 要不要**完全抛弃 Trojan**（更简单），还是**双轨并行**一段时间（兼容老用户）？
4. 前端注册成功页，你希望默认展示哪种引导？一键导入链接优先，还是手动参数表格优先？

确认好这 4 件事，我再一次性把 `main.py` 和模板改完。
