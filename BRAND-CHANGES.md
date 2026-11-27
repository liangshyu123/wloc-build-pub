# 品牌替换记录：wloc → 软件

## 已替换（用户能看到的地方）

| 位置 | 原文 | 现在 |
|---|---|---|
| 桌面图标名 / 系统里的应用名 | WLoc8.com | **软件** |
| 卡密窗标题 | WLOC 卡密验证 | **软件 卡密验证** |
| 教程第 1–3 步 | WLoc8.com iOS App Root CA | **软件 iOS App Root CA** |
| 教程说明 | 影响 WLoc 定位 / WLoc 方式 | **影响 软件定位 / 软件方式** |
| 描述文件名称（设置里看到的） | Apple定位屏蔽增强-TG：wloc88 | **Apple定位屏蔽增强-TG：软件** |
| 下载的根证书文件名 | WLoc8.com-iOS-App-RootCA.cer | **软件-iOS-App-RootCA.cer** |
| 证书 CN（构建时生成） | WLoc8.com iOS App | **Software iOS App**（见下方说明） |
| macOS 提示 | 再开启 WLoc / 允许 WLoc8.com 后台项目 / 将完整的 WLoc8.com 安装到 | 全部改为 **软件** |
| 深链错误提示 | 链接协议不是 wlocapp / 来自 wlocapp 链接 | **链接协议不正确 / 来自外部链接** |

共 24 处，涉及 9 个文件。

## 证书名为什么用英文 Software

证书 CN 走 openssl `-subj`，macOS 自带的是 LibreSSL，中文 subj 在部分版本会直接报错或写成乱码；
为了保证你到 Mac 上一条命令就能出包，CN 用 ASCII 的 `Software iOS App`，
界面其余文案仍然是「软件」。iOS「证书信任设置」里显示的就是 `Software iOS App Root CA`。
如果要中文 CN：在 `generate_apple_wloc_p12.sh` 的 openssl req 那几行加 `-utf8`，并把 `CERTIFICATE_BRAND` 换回中文，
先跑一次脚本确认不报错再出包。

## 故意保留的（改了会坏）

| 保留项 | 原因 |
|---|---|
| `wlocapp://` URL Scheme | 深链协议标识，改了导入链接全失效 |
| `group.com.wlocapp.shared` App Group | 主 App 与隧道扩展共享数据用，改了隧道拿不到数据 |
| Bundle ID `com.hrtt.apploc` | 与卡密后台的应用绑定、签名配置相关 |
| Telegram / GitHub 链接 | 外链地址，不是界面文案（按钮上显示的是 Telegram / GitHub） |
| `AppWLocProxy.p12` 等资源名 | 证书链内部文件名 |

## 改名后必须做的一步

证书 CN 从 `WLoc8.com iOS App` 改成了 `软件 iOS App`，所以：

1. 删掉旧的 `app_wloc_certs/` 目录，重新跑 `./generate_apple_wloc_p12.sh`（`build-ipa.sh` 会自动跑）。
2. 手机上去「设置 → 通用 → VPN 与设备管理」删掉旧的证书和描述文件，装新的。
3. 旧的根证书不删也能用，但教程里写的名字会对不上。
