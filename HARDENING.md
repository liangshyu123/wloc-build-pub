# wloc 加固版：卡密闸门 + 防移除

本目录 = 原 wloc 源码 + 服务端卡密（`https://km.47.254.47.138.nip.io`）+ 防移除/防调试/防注入。
**编译必须在 macOS + Xcode 上做**（本机是 iOS，没有 swiftc/xcodebuild，出不了 IPA）。出包命令见第四节。

---

## 一、防护设计（写进代码的，不是口头承诺）

| # | 机制 | 位置 | 触发后的行为 |
|---|---|---|---|
| 1 | 未解锁时卡密窗必须存在 | `CardKeyGate.checkpoint()` | 窗口被隐藏/删掉 → `raise(SIGKILL)` |
| 2 | 启动埋点哨兵 | `GateSentinel` + `AppDelegate` | 关键埋点缺失（被删）→ 终止 |
| 3 | 服务端签名租约 | `Lease` + `verifyStoredLease()` | 本地改 `isUnlocked` 也过不了 `checkpoint` → 终止 |
| 4 | 验签逻辑自检 | `CardKeyGate.selfTest()` | `verifyLease` 被改成恒真 → 终止 |
| 5 | HMAC 实现自检 | 同上 | `CCHmac`/签名链被劫持 → 终止 |
| 6 | 反调试 | `denyDebugger()` | `PT_DENY_ATTACH` + `sysctl(P_TRACED)` 命中 → 终止 |
| 7 | 注入检测 | `checkInjection()` | `DYLD_INSERT_LIBRARIES`、frida/substrate/cycript 等 → 终止 |
| 8 | 心跳续租 | `heartbeat()` 每 30s | 封禁/到期/换设备/会话失效 → 重新上锁 |
| 9 | 密钥不落明文 | `Secret.reveal()` 异或还原 | `strings` 搜不到 `SK_` / 域名 |
| 10 | 深链也要过闸门 | `AppDelegate.open url` | 未授权时深链直接丢弃 |

`checkpoint()` 埋点位置（删掉任意一处不影响，全部删掉才算"移除"，而删光要改 3 个文件 4 处 ≥ 且第 3 条兜底）：

- `AppDelegate.application(_:didFinishLaunchingWithOptions:)` —— 启动
- `WLocMapViewController.viewDidAppear` —— 首屏（同时打 `appear` 点）
- `WLocMapViewController.applyCoordinateInput` —— 每次选点/输入坐标
- `WLocMapViewController.handleDeepLink` —— 深链导入
- `WLocTutorialViewController.startCertificateServer` —— 证书/描述文件下载

关键点：**授权真假不由布尔值决定，由 `HMAC(session_key, lease|device|expireAt|token)` 决定**。
`session_key` 只有服务端 `/api/activate` 成功才会下发，所以把 `isUnlocked` 改成 `true` 也没用——
下一次 `checkpoint` 验租约失败就 `SIGKILL`。

---

## 二、和服务端的契约（已对齐你现在的服务端）

- AppKey：`AK_0fcf4063e8755a56`（源码内，异或存放）
- AppSecret：`SK_...`（源码内，异或存放）
- 激活：`POST /api/activate`
  `sig = HMAC_SHA256(appSecret, canonical({key, appKey, deviceId, ts, nonce}))`
- 心跳：`POST /api/heartbeat`
  `sig = HMAC_SHA256(session_key, canonical({token, deviceId, ts, nonce}))`，间隔 30s
- 失败码处理：`KEY_EXPIRED` / `KEY_BANNED` / `SESSION_INVALID` / `SESSION_EXPIRED` / `DEVICE_MISMATCH` → 立刻上锁
- 服务端默认宽限 `hb_grace=90s`，超时不上报即判离线

`canonical()` 规则与 `km-verify/server/lib/core.js` 一致：键名升序、`k=v` 用 `&` 拼接、排除 `sig`、空值跳过。

---

## 三、后台生成卡密

面板地址：`https://km.47.254.47.138.nip.io`（默认 `admin / admin888`，先改密码）

1. 「应用」里确认存在 AppKey = `AK_0fcf4063e8755a56` 的应用（Bundle 填 `com.hrtt.apploc`）。
   不存在就新建一个，把它的 AppKey/AppSecret 填回源码 `Secret.appKeyBytes / appSecretBytes`（异或 0x5A）。
2. 「卡密管理 → 生成卡密」，选应用、时长、数量，生成后导出。
3. 想让改包必然失效：保持 `enforceSign = true`（默认）、`hbGraceSec` 别调太大、卡密绑定设备。

---

## 四、出包（先看这台机器行不行）

| 你的电脑 | 能不能本地编 | 怎么办 |
|---|---|---|
| **Mac**（Intel / Apple Silicon，Xcode 15+） | ✅ 能 | `bash build-ipa.sh`，约 3~8 分钟 |
| **Windows** | ❌ 不能 | Swift/iOS SDK 只有 macOS 有。用 GitHub Actions（免费 macOS runner）出包，5~12 分钟 |
| **Linux** | ❌ 不能 | 同上，走 Actions 或租云 Mac |
| 云 Mac（MacinCloud / Scaleway M1） | ✅ 能 | 装 Xcode 后同上 |

### 方式 A：Mac 本机

```bash
cd wloc
brew install cocoapods ldid        # 只需要一次
bash build-ipa.sh                  # -> wloc-hardened.ipa（TrollStore：已打 entitlements）
MODE=unsigned bash build-ipa.sh    # -> 纯未签名（Sideloadly 自签）
TEAM=你的TeamID bash build-ipa.sh   # -> 开发者证书签名
```

脚本会自己 `pod install`、跑证书脚本、Release 编译、给主程序和 Tunnel 扩展用 ldid 打
entitlements，最后打包成 IPA。日志里应看到两行 `ldid ✓`。

### 方式 B：Windows / 没有 Mac —— GitHub Actions

1. github.com 新建一个 **private** 仓库（public 也行，但源码别公开）。
2. 把 `wloc-hardened-src-20261127.zip` 解压后的所有文件拖进仓库根目录（网页版直接拖拽上传即可，
   `.github` 目录要一起传）。
3. 仓库 → Actions → 左侧 `build-ipa` → `Run workflow`。
4. 等 8~12 分钟，进这次运行 → 底部 Artifacts → 下载 `wloc-unsigned-ipa`。
5. Windows 上装：TrollStore（设备支持的话）、Sideloadly / AltStore（用 Apple ID 自签）。

私有仓库的 macOS runner 每月免费 2000 分钟，够跑 200 次以上。

### ⚠️ 签名与权限：这一步决定装完能不能用

wloc 靠 NetworkExtension 隧道 + App Group 工作，**这两样写在 entitlements 里，不是写进代码就行**：

- **TrollStore**：用 `MODE=trollstore`（默认）出的包，ldid 已把 entitlements 写进主程序和
  `WLocTunnel-iOS.appex`，装完隧道可用。
- **Sideloadly / AltStore + 免费 Apple ID**：装得上，但免费账号不支持 App Group 和
  NetworkExtension，**VPN/隧道会失效**，只剩地图界面。
- **付费开发者账号（$99/年）**：Xcode 里勾好 App Group + Network Extension 权限，
  `TEAM=xxx bash build-ipa.sh` 出正式签名包，功能完整。

```bash
# TrollStore 包（默认）
bash build-ipa.sh
# 只要个能装的未签名包
MODE=unsigned bash build-ipa.sh
```

## 五、装完怎么验

1. 首启出现卡密窗，不输卡密 → 点地图任何按钮都应无反应（`checkpoint` 在跑）。
2. 输错卡密 → 服务端返回 `KEY_NOT_FOUND`，界面显示原因，不进主界面。
3. 正确卡密 → 进主界面，服务端「会话」里能看到该设备在线，30s 一次心跳。
4. 面板把这张卡封禁 → 30s 内 App 自动回到卡密窗，提示「卡密已被封禁」。
5. 面板停用应用（runControl 停）→ 同样被踢。
6. 越狱机用 Frida 附加 → 进程直接被 `PT_DENY_ATTACH` / 注入检测干掉。
7. 把卡密窗 `isHidden = true`（越狱插件试）→ 下一次点地图/深链即 `SIGKILL`。
8. 改 `isUnlocked` 返回 true（静态改包）→ 心跳 90s 内失败，`checkpoint` 验租约失败 → 终止。

---

## 六、说清楚的部分

- 这套防护是**客户端 + 服务端租约**双绑：删弹窗、改布尔、去掉 `checkpoint` 都会被服务端会话和租约兜住，
  但只要攻击者有足够时间做完整静态分析，客户端代码终究能被改。真正的锁在服务端：**设备绑定 + 心跳 + 封禁**，
  这三样在面板上按一下就能让旧包失效，比任何本地混淆都硬。
- 想再上一层（可选，需要改服务端）：激活时下发一次性 `nonce` 挑战、心跳带 `attestation`，
  以及把关键功能数据改成服务端下发（无有效会话 = 没有数据可显示），这样"过了 UI 也没东西用"。
