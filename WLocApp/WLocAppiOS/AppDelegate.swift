import CommonCrypto
import Darwin
import IQKeyboardManagerSwift
import UIKit

// MARK: - 启动

@UIApplicationMain
final class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    private weak var mapController: WLocMapViewController?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        IQKeyboardManager.shared.enable = true

        // 防护链：反调试 → 注入检测 → 函数自检，任何一项不过直接终止进程
        GateSentinel.mark(.launch)
        CardKeyGate.shared.bootstrap()

        AppWLocUtils.debugLog("\(AppWLocConfig.displayName) App 启动签名信息 \(AppWLocConfig.signingDiagnostics)")

        let window = UIWindow(frame: UIScreen.main.bounds)
        let controller = WLocMapViewController()
        mapController = controller
        window.rootViewController = UINavigationController(rootViewController: controller)
        window.makeKeyAndVisible()
        self.window = window

        CardKeyGate.shared.start()

        if let url = launchOptions?[.url] as? URL {
            controller.handleDeepLink(url)
        }
        return true
    }

    func application(
        _ app: UIApplication,
        open url: URL,
        options: [UIApplication.OpenURLOptionsKey: Any] = [:]
    ) -> Bool {
        // 深链导入位置同样要过闸门，否则可以绕过弹窗直接下指令
        guard CardKeyGate.shared.isUnlocked else { return false }
        return mapController?.handleDeepLink(url) ?? false
    }

    func applicationDidEnterBackground(_ application: UIApplication) {
        CardKeyGate.shared.verifyIntegrityNow("background")
    }

    func applicationWillTerminate(_ application: UIApplication) {
//        mapController?.disconnectVPNForAppTermination()
    }
}

// MARK: - 埋点哨兵

/// 关键路径打点。少一个点 = 闸门被摘，直接终止。
enum GateSentinel {
    enum Bit: UInt32 {
        case launch = 1
        case appear = 2
        case unlocked = 4
        case heartbeat = 8
    }

    private static var mask: UInt32 = 0
    private static let queue = DispatchQueue(label: "wloc.gate.sentinel")

    static func mark(_ bit: Bit) {
        queue.sync { mask |= bit.rawValue }
    }

    static func missing(_ required: UInt32) -> UInt32 {
        queue.sync { required & ~mask }
    }

    static func verify(orDie required: UInt32, _ tag: String) {
        let m = missing(required)
        if m != 0 { CardKeyGate.panic("sentinel.\(tag).\(m)") }
    }
}

// MARK: - 卡密闸门

/// 启动全屏遮罩，激活后放行；心跳续租，到期/封禁/换设备重新上锁。
/// 授权状态同时以"服务端会话签名租约"落盘，删弹窗、改布尔值都拿不到有效租约。
final class CardKeyGate {
    static let shared = CardKeyGate()

    // MARK: 配置（异或还原，二进制里不留明文）

    private enum Secret {
        static let appKeyBytes: [UInt8] = [0x1b, 0x11, 0x05, 0x6a, 0x3c, 0x39, 0x3c, 0x6e, 0x6a, 0x6c, 0x69, 0x3f, 0x62, 0x6d, 0x6f, 0x6f, 0x3b, 0x6f, 0x6c]
        static let appSecretBytes: [UInt8] = [0x09, 0x11, 0x05, 0x3b, 0x68, 0x6b, 0x68, 0x69, 0x68, 0x6f, 0x68, 0x68, 0x63, 0x63, 0x39, 0x3b, 0x3f, 0x6c, 0x6f, 0x3f, 0x38, 0x6f, 0x6f, 0x6d, 0x38, 0x6d, 0x39, 0x3b, 0x3c, 0x38, 0x68, 0x69, 0x6a, 0x69, 0x3f, 0x62, 0x3c, 0x38, 0x6a, 0x6a, 0x63, 0x3b, 0x6c, 0x6e, 0x6a, 0x3b, 0x6a, 0x69, 0x6c, 0x3f, 0x38]
        static let baseURLBytes: [UInt8] = [0x32, 0x2e, 0x2e, 0x2a, 0x29, 0x60, 0x75, 0x75, 0x31, 0x37, 0x74, 0x6e, 0x6d, 0x74, 0x68, 0x6f, 0x6e, 0x74, 0x6e, 0x6d, 0x74, 0x6b, 0x69, 0x62, 0x74, 0x34, 0x33, 0x2a, 0x74, 0x33, 0x35]

        static func reveal(_ bytes: [UInt8]) -> String {
            String(bytes: bytes.map { $0 ^ 0x5A }, encoding: .utf8) ?? ""
        }
    }

    private enum Conf {
        static let appKey = Secret.reveal(Secret.appKeyBytes)
        static let appSecret = Secret.reveal(Secret.appSecretBytes)
        static let baseURL = Secret.reveal(Secret.baseURLBytes)
        static let siteName = "软件 卡密验证"
    }

    /// 服务端会话签发的本地租约：sig = HMAC(session_key, lease|device|expireAt|token)
    private struct Lease: Codable {
        let device: String
        let expireAt: Double
        let token: String
        let sig: String
    }

    // MARK: 存储键

    private let tokenKey = "ck_token"
    private let sessionKey = "ck_session"
    private let deviceKey = "ck_device"
    private let leaseKey = "ck_lease"

    // MARK: 状态

    private let stateQueue = DispatchQueue(label: "wloc.gate.state")
    private var _unlocked = false
    private var _expireAt: Date?
    private var startedAt: Date?

    private var gateWindow: UIWindow?
    private var statusLabel: UILabel?
    private var heartbeatTimer: Timer?

    private init() {}

    var isUnlocked: Bool { stateQueue.sync { _unlocked } }
    var expireAt: Date? { stateQueue.sync { _expireAt } }

    // MARK: - 防护链

    func bootstrap() {
        #if !DEBUG
        Self.denyDebugger()
        Self.checkInjection()
        Self.selfTest()
        #endif
    }

    func verifyIntegrityNow(_ tag: String) {
        #if !DEBUG
        Self.checkInjection()
        #endif
        checkpoint(tag)
    }

    /// 未解锁时只要卡密窗没了，就判定闸门被摘 → 直接终止
    func checkpoint(_ tag: String) {
        guard let startedAt = self.startedAt, Date().timeIntervalSince(startedAt) > 3 else { return }

        if isUnlocked {
            if !verifyStoredLease() { Self.panic("lease.\(tag)") }
            return
        }
        if gateWindow == nil || gateWindow?.isHidden == true {
            Self.panic("gate.removed.\(tag)")
        }
    }

    /// 终止进程：清本地授权痕迹 + SIGKILL（不走 atexit，避免被 hook 兜住）
    static func panic(_ reason: String) -> Never {
        let ud = UserDefaults.standard
        ["ck_token", "ck_session", "ck_lease"].forEach { ud.removeObject(forKey: $0) }
        ud.synchronize()
        raise(SIGKILL)
        exit(0)
    }

    private static func denyDebugger() {
        _ = ptrace(PT_DENY_ATTACH, 0, nil, nil)

        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        if sysctl(&mib, 4, &info, &size, nil, 0) == 0, (info.kp_proc.p_flag & P_TRACED) != 0 {
            panic("debugger")
        }
    }

    private static func checkInjection() {
        if let raw = getenv("DYLD_INSERT_LIBRARIES"), String(cString: raw).isEmpty == false {
            panic("dyld-insert")
        }
        let blacklist = ["frida", "substrate", "substitute", "libhooker", "cycript",
                         "sslkillswitch", "revealserver", "cydiainject", "flexloader", "tweakbox"]
        let count = _dyld_image_count()
        for index in 0..<Int(count) {
            guard let name = _dyld_get_image_name(UInt32(index)) else { continue }
            let path = String(cString: name).lowercased()
            if blacklist.contains(where: { path.contains($0) }) {
                panic("injected.\(path)")
            }
        }
    }

    private static func selfTest() {
        // HMAC 实现自检：被替换/劫持会与常量不符
        if hmac("k", "a=1") != "310f57de49873563b85599a4aaa688883c5c6ebc7d3925020d99379d1a4d0af8" {
            panic("hmac")
        }
        // 验签逻辑自检：伪造租约必须判假，恒真说明被改成了 return true
        let forged = Lease(device: "x", expireAt: 0, token: "y", sig: "deadbeef")
        if shared.verifyLease(forged, session: "s") { panic("selftest") }
    }

    // MARK: - 入口

    func start() {
        startedAt = Date()
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            if self.restoreSession() {
                self.unlockUI()
                self.startHeartbeat()
            } else {
                self.showGate(message: "请输入卡密后进入")
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in
                guard let self = self else { return }
                guard self.isUnlocked else { return }
                let required = GateSentinel.Bit.launch.rawValue
                    | GateSentinel.Bit.appear.rawValue
                    | GateSentinel.Bit.unlocked.rawValue
                    | GateSentinel.Bit.heartbeat.rawValue
                GateSentinel.verify(orDie: required, "boot")
            }
        }
    }

    private func unlockUI() {
        stateQueue.sync { _unlocked = true }
        GateSentinel.mark(.unlocked)
        gateWindow?.isHidden = true
        gateWindow = nil
    }

    private func lock(reason: String, clear: Bool) {
        stateQueue.sync { _unlocked = false; _expireAt = nil }
        if clear { clearSession() }
        DispatchQueue.main.async { [weak self] in
            self?.showGate(message: reason)
        }
    }

    // MARK: - UI

    private func showGate(message: String?) {
        guard gateWindow == nil else {
            gateWindow?.isHidden = false
            statusLabel?.text = message ?? statusLabel?.text
            return
        }
        guard let scene = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene })
            .first(where: { $0.activationState == .foregroundActive })
            ?? UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene }).first
        else { return }

        let win = UIWindow(windowScene: scene)
        win.windowLevel = .alert + 100
        win.backgroundColor = UIColor(white: 0.06, alpha: 1)

        let vc = UIViewController()
        vc.view.backgroundColor = win.backgroundColor

        let title = UILabel()
        title.text = "\(Conf.siteName)"
        title.textColor = .white
        title.font = .boldSystemFont(ofSize: 22)
        title.textAlignment = .center
        title.translatesAutoresizingMaskIntoConstraints = false

        let field = UITextField()
        field.placeholder = "请输入卡密"
        field.textColor = .white
        field.backgroundColor = UIColor(white: 1, alpha: 0.12)
        field.layer.cornerRadius = 10
        field.autocapitalizationType = .allCharacters
        field.autocorrectionType = .no
        field.textAlignment = .center
        field.translatesAutoresizingMaskIntoConstraints = false

        let button = UIButton(type: .system)
        button.setTitle("激活并进入", for: .normal)
        button.setTitleColor(.white, for: .normal)
        button.titleLabel?.font = .boldSystemFont(ofSize: 17)
        button.backgroundColor = UIColor(red: 0.15, green: 0.39, blue: 0.92, alpha: 1)
        button.layer.cornerRadius = 10
        button.translatesAutoresizingMaskIntoConstraints = false

        let status = UILabel()
        status.text = message ?? ""
        status.textColor = UIColor(red: 1, green: 0.45, blue: 0.45, alpha: 1)
        status.font = .systemFont(ofSize: 13)
        status.textAlignment = .center
        status.numberOfLines = 0
        status.translatesAutoresizingMaskIntoConstraints = false
        statusLabel = status

        [title, field, button, status].forEach { vc.view.addSubview($0) }
        NSLayoutConstraint.activate([
            title.centerXAnchor.constraint(equalTo: vc.view.centerXAnchor),
            title.topAnchor.constraint(equalTo: vc.view.safeAreaLayoutGuide.topAnchor, constant: 120),
            field.centerXAnchor.constraint(equalTo: vc.view.centerXAnchor),
            field.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 28),
            field.widthAnchor.constraint(equalToConstant: 260),
            field.heightAnchor.constraint(equalToConstant: 46),
            button.centerXAnchor.constraint(equalTo: vc.view.centerXAnchor),
            button.topAnchor.constraint(equalTo: field.bottomAnchor, constant: 16),
            button.widthAnchor.constraint(equalToConstant: 260),
            button.heightAnchor.constraint(equalToConstant: 46),
            status.leadingAnchor.constraint(equalTo: vc.view.leadingAnchor, constant: 24),
            status.trailingAnchor.constraint(equalTo: vc.view.trailingAnchor, constant: -24),
            status.topAnchor.constraint(equalTo: button.bottomAnchor, constant: 16),
        ])

        button.addAction(UIAction { [weak self, weak field, weak button, weak status] _ in
            guard let self = self else { return }
            let code = (field?.text ?? "").trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
            if code.count < 6 {
                status?.text = "请输入有效卡密"
                return
            }
            button?.isEnabled = false
            button?.alpha = 0.6
            status?.textColor = UIColor(white: 0.85, alpha: 1)
            status?.text = "验证中…"
            self.activate(code: code) { ok, msg in
                DispatchQueue.main.async {
                    if ok {
                        self.unlockUI()
                        self.startHeartbeat()
                    } else {
                        button?.isEnabled = true
                        button?.alpha = 1
                        status?.textColor = UIColor(red: 1, green: 0.45, blue: 0.45, alpha: 1)
                        status?.text = msg
                    }
                }
            }
        }, for: .touchUpInside)

        win.rootViewController = vc
        win.makeKeyAndVisible()
        gateWindow = win
    }

    // MARK: - 网络

    private func activate(code: String, completion: @escaping (Bool, String) -> Void) {
        let deviceId = self.deviceId()
        let ts = String(Int(Date().timeIntervalSince1970 * 1000))
        let nonce = Self.nonce()
        let signDict: [String: String] = ["key": code, "appKey": Conf.appKey, "deviceId": deviceId, "ts": ts, "nonce": nonce]
        var body: [String: Any] = signDict
        body["deviceName"] = UIDevice.current.name
        body["deviceModel"] = UIDevice.current.model
        body["hostVer"] = (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? "1.0"
        body["bundleId"] = Bundle.main.bundleIdentifier ?? ""
        body["sig"] = Self.hmac(Conf.appSecret, Self.canonical(signDict))

        postJSON(path: "/api/activate", body: body) { [weak self] json in
            guard let self = self else { return }
            guard let json = json, (json["ok"] as? Bool) == true else {
                let msg = (json?["error"] as? [String: Any])?["message"] as? String
                completion(false, msg ?? "验证失败，请检查网络或卡密")
                return
            }
            let data = json["data"] as? [String: Any]
            guard let token = data?["token"] as? String,
                  let session = data?["session_key"] as? String, !token.isEmpty, !session.isEmpty else {
                completion(false, "服务端返回异常")
                return
            }
            self.persist(token: token, session: session, expiresAt: self.parseDate(data?["expires_at"]))
            completion(true, "")
        }
    }

    private func startHeartbeat() {
        heartbeatTimer?.invalidate()
        heartbeatTimer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            self?.heartbeat()
        }
        heartbeat()
    }

    private func heartbeat() {
        guard isUnlocked else { return }
        let ud = UserDefaults.standard
        guard let token = ud.string(forKey: tokenKey),
              let session = ud.string(forKey: sessionKey) else {
            lock(reason: "登录状态失效，请重新激活", clear: true)
            return
        }
        let deviceId = self.deviceId()
        let ts = String(Int(Date().timeIntervalSince1970 * 1000))
        let nonce = Self.nonce()
        let signDict: [String: String] = ["token": token, "deviceId": deviceId, "ts": ts, "nonce": nonce]
        var body: [String: Any] = signDict
        body["sig"] = Self.hmac(session, Self.canonical(signDict))
        body["deviceName"] = UIDevice.current.name
        body["hostVer"] = (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? "1.0"

        postJSON(path: "/api/heartbeat", body: body) { [weak self] json in
            guard let self = self else { return }
            if let json = json, (json["ok"] as? Bool) == true {
                let data = json["data"] as? [String: Any]
                self.persist(token: token, session: session, expiresAt: self.parseDate(data?["expires_at"]))
                GateSentinel.mark(.heartbeat)
                let required = GateSentinel.Bit.launch.rawValue
                    | GateSentinel.Bit.appear.rawValue
                    | GateSentinel.Bit.unlocked.rawValue
                    | GateSentinel.Bit.heartbeat.rawValue
                GateSentinel.verify(orDie: required, "heartbeat")
                return
            }

            let code = ((json?["error"] as? [String: Any])?["code"] as? String) ?? ""
            if ["KEY_EXPIRED", "KEY_BANNED", "SESSION_INVALID", "SESSION_EXPIRED", "DEVICE_MISMATCH"].contains(code) {
                let msg: String
                switch code {
                case "KEY_BANNED": msg = "卡密已被封禁"
                case "DEVICE_MISMATCH": msg = "卡密已在其它设备使用"
                default: msg = "卡密已到期，请续费"
                }
                self.lock(reason: msg, clear: true)
                return
            }

            // 网络异常：租约还在有效期就不打扰，超时才上锁
            if let exp = self.expireAt, exp.timeIntervalSinceNow < -180 {
                self.lock(reason: "网络异常，授权已过期", clear: false)
            }
        }
    }

    private func postJSON(path: String, body: [String: Any], completion: @escaping ([String: Any]?) -> Void) {
        guard let url = URL(string: Conf.baseURL + path) else { completion(nil); return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = 12
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        URLSession.shared.dataTask(with: req) { data, _, _ in
            guard let data = data,
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                completion(nil)
                return
            }
            completion(obj)
        }.resume()
    }

    // MARK: - 租约

    private func persist(token: String, session: String, expiresAt: Date?) {
        let ud = UserDefaults.standard
        ud.set(token, forKey: tokenKey)
        ud.set(session, forKey: sessionKey)

        let device = deviceId()
        let exp = expiresAt?.timeIntervalSince1970 ?? 0
        let lease = Lease(device: device, expireAt: exp, token: token,
                          sig: Self.hmac(session, "lease|\(device)|\(Int64(exp))|\(token)"))
        if let data = try? JSONEncoder().encode(lease) {
            ud.set(data, forKey: leaseKey)
        }
        ud.synchronize()
        stateQueue.sync { _expireAt = expiresAt }
    }

    private func restoreSession() -> Bool {
        let ud = UserDefaults.standard
        guard let session = ud.string(forKey: sessionKey), !session.isEmpty,
              let data = ud.data(forKey: leaseKey),
              let lease = try? JSONDecoder().decode(Lease.self, from: data) else { return false }
        guard verifyLease(lease, session: session) else { return false }
        if lease.expireAt > 0, Date().timeIntervalSince1970 > lease.expireAt + 60 { return false }
        stateQueue.sync {
            _unlocked = true
            _expireAt = lease.expireAt > 0 ? Date(timeIntervalSince1970: lease.expireAt) : nil
        }
        return true
    }

    private func verifyStoredLease() -> Bool {
        let ud = UserDefaults.standard
        guard let session = ud.string(forKey: sessionKey), !session.isEmpty,
              let data = ud.data(forKey: leaseKey),
              let lease = try? JSONDecoder().decode(Lease.self, from: data) else { return false }
        guard verifyLease(lease, session: session) else { return false }
        if lease.expireAt > 0, Date().timeIntervalSince1970 > lease.expireAt + 180 { return false }
        return true
    }

    private func verifyLease(_ lease: Lease, session: String) -> Bool {
        guard lease.device == deviceId() else { return false }
        let payload = "lease|\(lease.device)|\(Int64(lease.expireAt))|\(lease.token)"
        return Self.hmac(session, payload) == lease.sig
    }

    private func clearSession() {
        let ud = UserDefaults.standard
        [tokenKey, sessionKey, leaseKey].forEach { ud.removeObject(forKey: $0) }
        ud.synchronize()
    }

    // MARK: - 工具

    private func parseDate(_ value: Any?) -> Date? {
        guard let s = value as? String, !s.isEmpty else { return nil }
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: s) { return d }
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: s)
    }

    private func deviceId() -> String {
        let ud = UserDefaults.standard
        if let d = ud.string(forKey: deviceKey), !d.isEmpty { return d }
        let d = (UIDevice.current.identifierForVendor?.uuidString ?? Self.nonce())
            .replacingOccurrences(of: "-", with: "")
        ud.set(d, forKey: deviceKey)
        ud.synchronize()
        return d
    }

    private static func nonce() -> String {
        var r: UInt64 = 0
        arc4random_buf(&r, MemoryLayout<UInt64>.size)
        return String(format: "%016llx", r)
    }

    private static func canonical(_ d: [String: String]) -> String {
        d.keys.sorted().compactMap { k in
            guard k != "sig", let v = d[k], !v.isEmpty else { return nil }
            return "\(k)=\(v)"
        }.joined(separator: "&")
    }

    private static func hmac(_ secret: String, _ text: String) -> String {
        let key = Array(secret.utf8)
        let data = Array(text.utf8)
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), key, key.count, data, data.count, &digest)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
