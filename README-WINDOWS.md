# 这个目录 = 可直接拖进 GitHub 仓库根目录的完整工程

解压后 **全选**（含 `.github` 隐藏目录）拖进仓库根目录，覆盖同名文件即可。
里面已经修好了原包里会导致构建失败的三个问题，不需要再改任何东西。

---

## 零、一条命令全自动出包（推荐）

```powershell
powershell -ExecutionPolicy Bypass -File .\make-ipa.ps1 -Token ghp_你的token
```

token 在 https://github.com/settings/tokens 生成（classic 勾 `repo` + `workflow`；
fine-grained 给 Contents R/W + Actions R/W + Workflows W）。它会自动：

1. 校验 token、定位账号
2. 仓库不存在就建私有仓库 `wloc-build`，存在就直接用
3. 把本目录全部文件推到 `main`（会强制把 `Podfile.lock` 一起推，锁住 pod 版本）
4. 触发 `build-ipa` 工作流
5. 轮询构建，实时打印「跑到哪一步」
6. 成功后下载 artifact、解出 `wloc-ipa.ipa` 放桌面，并打印 ipa 结构自检
7. 失败则下载日志、挑出 `error:` / `cannot be found` / `BUILD FAILED` 行和日志尾部

也可以先 `setx GITHUB_TOKEN ghp_xxx` 再开新窗口，脚本会自己读环境变量。

---

## 一、我在包里改了什么

| 文件 | 问题 | 处理 |
|---|---|---|
| `generate_apple_wloc_p12.sh` | 写死 `openssl pkcs12 -legacy`。macOS 自带的 LibreSSL **不认这个开关**，装了 OpenSSL 3 之前它直接报 `unknown option -legacy` 退出；老 LibreSSL 也没有 `-macalg` | 改成能力探测 + 三级降级：有 `-legacy` 才传 → 去掉 `-macalg` 再试 → 用当前 openssl 默认算法兜底。任何一套 openssl 都能出 legacy(3DES/SHA1) p12 |
| `.github/workflows/build-ipa.yml` | 旧 `build.yml` 没跑证书脚本。`project.pbxproj` 引用了 `Resources/iOS/AppWLocRootCA.cer`、`Resources/iOS/AppWLocProxy.p12`、`Resources/Tunnel/AppWLocProxy.p12`，这三个文件在源码里**不存在**（脚本生成），不先生成 → `Build input file cannot be found` 直接失败。旧版还少了 ldid 打 entitlements 那步 | 新建 `build-ipa.yml`：环境自检 → 生成证书 → pod install → Release 编译 → `ldid -S` 写 entitlements（主程序 + 隧道扩展）→ 打 IPA → 上传 Artifacts。旧的 `build.yml` 已从本包移除，避免 push 时被误触发 |
| `codemagic.yaml` | 默认镜像不保证有 `openssl@3`，脚本直接 exit 1 | 先探测 `/opt/homebrew/opt/openssl@3/bin`，没有就 `brew install openssl@3`，再不行退回系统 LibreSSL（靠上面那套降级） |

其余源码原样保留，没有动 `appKey/appSecret`（`AppDelegate.swift` 里 `Secret` 枚举，异或 0x5A），
卡密服务端、品牌名、版本号（`MARKETING_VERSION = 1.3`）、域名 `gs-loc.apple.com` 白名单全部不变。

---

## 二、出包（Windows 只负责浏览器操作）

### 路线 1：GitHub Actions（仓库已有，推荐）

1. 仓库根目录拖进本包全部文件（`.github` 一定要一起传）。
2. Actions → 左侧 `build-ipa` → `Run workflow`。
3. 等 8~12 分钟（`macos-13` 排队慢是常态，挂着）。
4. 这次运行页底部 Artifacts → `wloc-ipa` → 下载 zip → 解压得 `wloc-ipa.ipa`。

> `macos-14` / `macos-15` 在你的账号上会被映射成付费大机型，报 `configuration not supported`，
> 所以工作流固定 `macos-13`。

### 路线 2：Codemagic（队列快，1~2 分钟开编）

1. `https://codemagic.io` → Sign up with GitHub（仓库所有者的号）。
2. Add application → 选仓库 → Finish。
3. 工作流选 `wloc unsigned IPA`（根目录的 `codemagic.yaml` 已被本包换成修好的版本）。
4. Start new build → 8~12 分钟 → Artifacts 下载 `wloc-ipa.ipa`。
5. 免费额度 500 分钟/月，M2 机器。

---

## 三、拿到 ipa 之后（Windows 侧）

| 装法 | 结果 |
|---|---|
| **TrollStore**（设备支持才可用） | 完整功能。`ldid` 已把 App Group + NetworkExtension 写进 Mach-O，VPN 隧道能用 |
| **Sideloadly / AltStore + 免费 Apple ID** | 装得上，**但拿不到 App Group / NetworkExtension**，VPN 隧道失效，只剩地图界面，7 天到期 |
| **付费开发者账号（$99/年）** | 功能完整，走 `build-ipa.sh` 的 `TEAM=xxx` 路线 |

---

## 四、验包清单（装之前先看，装之后对一遍）

1. ipa 大小 1.8~2.5 MB；解压结构是 `Payload/WLocApp-iOS.app/`。
2. `WLocApp-iOS.app/PlugIns/WLocTunnel-iOS.appex` 存在。
3. `Payload/WLocApp-iOS.app/Info.plist` 里 `CFBundleDisplayName = 软件`、`CFBundleShortVersionString = 1.3`。
4. `Resources/iOS/AppWLocProxy.p12` 是 **legacy 3DES/SHA1**（密码 `1`，见 `AppWLocConfig.proxyIdentityPassword`）。
   如果不是 legacy，iOS 16 的 `SecPKCS12Import` 会返回 `-25293`，代理 TLS 握手会失败。
5. 首启弹「软件 · 卡密验证」，不输卡密点地图无反应；输错提示服务端原因；输对进主界面。
6. 面板后台封卡 → 30 秒内回到卡密窗（心跳续租）。
