'use strict';
/**
 * server.js — 卡密验证 + 网络心跳服务端（零依赖）
 *
 *   node server.js            默认 0.0.0.0:8080
 *   PORT=9000 node server.js
 *
 * 客户端接口： /api/version /api/activate /api/heartbeat /api/deactivate
 * 管理接口：   /api/admin/*
 * 管理面板：   /  (web/index.html)
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const core = require('./lib/core');
const { Store, DATA_DIR } = require('./lib/store');

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const WEB_DIR = path.join(__dirname, '..', 'web');

const store = new Store();
store.load();
const S = () => store.settings;

const nonces = new core.NonceCache(10 * 60_000);
const pubLimit = new core.RateLimiter({ perMin: 240, burst: 60 });   // 客户端
const actLimit = new core.RateLimiter({ perMin: 10, burst: 5 });     // 激活（防爆破卡密）
const adminLimit = new core.RateLimiter({ perMin: 300, burst: 80 });

/* ---------------- HTTP 基础 ---------------- */

function send(res, status, body, headers = {}) {
  const data = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': typeof body === 'object' && !Buffer.isBuffer(body)
      ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Admin-Token',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'X-Content-Type-Options': 'nosniff',
    ...headers,
  });
  res.end(data);
}
const ok = (res, data) => send(res, 200, { ok: true, ...data, server_time: Date.now() });
const fail = (res, code, message, status = 200, extra = {}) =>
  send(res, status, { ok: false, error: { code, message }, ...extra, server_time: Date.now() });

function readBody(req, limit = 4 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(Object.assign(new Error('body too large'), { code: 'TOO_LARGE' })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); } catch { reject(Object.assign(new Error('bad json'), { code: 'BAD_JSON' })); }
    });
    req.on('error', reject);
  });
}

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.ico': 'image/x-icon', '.json': 'application/json; charset=utf-8',
  '.woff2': 'font/woff2',
};

function serveStatic(req, res, pathname) {
  let rel = pathname === '/' ? '/index.html' : pathname;
  if (rel === '/panel') rel = '/index.html';
  const file = path.join(WEB_DIR, path.normalize(rel).replace(/^(\.\.[/\\])+/, ''));
  if (!file.startsWith(WEB_DIR) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    // SPA 回退
    const idx = path.join(WEB_DIR, 'index.html');
    if (fs.existsSync(idx)) return send(res, 200, fs.readFileSync(idx), { 'Content-Type': MIME['.html'] });
    return send(res, 404, 'not found');
  }
  send(res, 200, fs.readFileSync(file), { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
}

/* ---------------- 管理端鉴权 ---------------- */

function adminOf(req) {
  const h = req.headers['authorization'] || req.headers['x-admin-token'] || '';
  const token = String(h).replace(/^Bearer\s+/i, '').trim();
  const payload = core.readAdminToken(token, S().masterSecret);
  if (!payload) return null;
  return payload;
}
function requireAdmin(req, res) {
  const p = adminOf(req);
  if (!p) { fail(res, 'ADMIN_UNAUTH', '管理端登录失效，请重新登录', 401); return null; }
  const acc = store.s.accounts.find((a) => a.id === p.id);
  if (!acc) { fail(res, 'ADMIN_UNAUTH', '账号不存在', 401); return null; }
  if (acc.status !== 'normal') { fail(res, 'ACCOUNT_DISABLED', '账号已被停用，请联系主代理', 403); return null; }
  return acc;
}
const isOwner = (a) => a.role === 'owner';
/** 代理只能看到自己的卡密 */
function scopeKeys(a) {
  return isOwner(a) ? store.s.keys : store.s.keys.filter((k) => k.ownerId === a.id);
}
function publicAccount(a) {
  const ks = store.s.keys.filter((k) => k.ownerId === a.id);
  return {
    id: a.id, user: a.user, role: a.role, balance: a.balance, status: a.status,
    note: a.note || '', createdAt: a.createdAt, createdBy: a.createdBy,
    lastLoginAt: a.lastLoginAt || null,
    keys: ks.length, keys_active: ks.filter((k) => k.status === 'activated').length,
  };
}

/* ---------------- 卡密状态机 ---------------- */

function keyRemainMs(k) {
  if (k.status === 'banned') return -1;
  if (!k.expiresAt) return k.status === 'unused' ? null : null; // 永久 / 未激活
  return new Date(k.expiresAt).getTime() - Date.now();
}

function refreshKeyStatus(k) {
  if (k.status === 'banned') return k.status;
  if (k.expiresAt && new Date(k.expiresAt).getTime() <= Date.now()) {
    if (k.status !== 'expired') { k.status = 'expired'; store.save(); }
  }
  return k.status;
}

function isOnline(k) {
  if (!k.lastHeartbeatAt) return false;
  return Date.now() - new Date(k.lastHeartbeatAt).getTime() <= S().hbGraceSec * 1000;
}

function keyView(k, { plain = true } = {}) {
  const app = store.findApp(k.appId);
  const remain = k.expiresAt ? new Date(k.expiresAt).getTime() - Date.now() : (k.status === 'unused' ? null : null);
  return {
    id: k.id,
    key: plain ? store.keyPlain(k) : k.keyMask,
    keyMask: k.keyMask,
    appId: k.appId,
    appName: app ? app.name : '-',
    type: k.type,
    typeLabel: core.TYPE_LABEL[k.type] || k.type,
    status: refreshKeyStatus(k),
    createdAt: k.createdAt,
    activatedAt: k.activatedAt,
    expiresAt: k.expiresAt,
    remainMs: remain,
    remainText: k.status === 'unused' ? '未激活' : (k.status === 'banned' ? '已封禁' : core.humanRemain(remain)),
    deviceId: k.deviceId,
    deviceName: k.deviceName,
    deviceModel: k.deviceModel,
    hostVer: k.hostVer,
    bundleId: k.bundleId,
    ip: k.ip,
    online: isOnline(k),
    lastHeartbeatAt: k.lastHeartbeatAt,
    maxDevices: k.maxDevices,
    rebindLeft: k.rebindLeft,
    note: k.note || '',
    batchId: k.batchId || '',
  };
}

/* ---------------- 客户端接口 ---------------- */

function handleVersion(req, res, q) {
  const app = q.appKey ? store.findAppByKey(q.appKey) : null;
  ok(res, {
    name: 'km-verify',
    version: '1.0.0',
    site: S().siteName,
    hb_interval: S().hbInterval,
    hb_grace: S().hbGraceSec,
    time_window: S().timeWindowSec,
    app: app ? { name: app.name, bundle_id: app.bundleId, running: app.runControl.running } : null,
    allow_register: S().allowRegister !== false,
    register_invite: !!S().registerInvite,
    notice: S().notice || '',
    force_update: S().forceUpdate || null,
  });
}

async function handleActivate(req, res) {
  const ip = core.clientIP(req);
  if (!actLimit.hit(ip).ok) return fail(res, 'RATE_LIMIT', '请求过于频繁，请稍后再试', 429);
  const body = await readBody(req);
  const app = store.findAppByKey(body.appKey);
  if (!app) return fail(res, 'APP_NOT_FOUND', '应用不存在或 AppKey 无效');
  if (app.status !== 'normal') return fail(res, 'APP_DISABLED', '应用已被禁用');
  if (!app.runControl.running) return fail(res, 'APP_STOPPED', '应用已停止运行');

  const plain = core.normalizeKey(body.key);
  if (!plain) return fail(res, 'KEY_EMPTY', '请输入卡密');

  // 签名校验（appSecret 只下发给宿主应用，别放在可被替换的前端）
  const ts = Number(body.ts || 0);
  const nonce = String(body.nonce || '');
  if (S().enforceSign !== false) {
    if (!ts || Math.abs(Date.now() - ts) > S().timeWindowSec * 1000)
      return fail(res, 'STALE_REQUEST', '请求时间戳超出允许窗口');
    if (!nonce || !nonces.use('act:' + nonce)) return fail(res, 'REPLAY', '请求重放');
    const expect = core.hmac(app.appSecret, core.canonical({ key: plain, appKey: body.appKey, deviceId: body.deviceId, ts, nonce }));
    if (!core.safeEqual(body.sig || '', expect)) return fail(res, 'BAD_SIGN', '签名校验失败', 401);
  }

  const k = store.findKeyByPlain(plain);
  if (!k) {
    store.addCapture({
      appId: app.id, appName: app.name, hostName: body.hostVer || '未知', bundleId: body.bundleId || '-',
      device: body.deviceName || body.deviceId || '-', keyMask: core.maskKey(plain), ip,
      ua: req.headers['user-agent'] || '-', path: '/api/activate', ms: 1, ok: false, reason: 'KEY_NOT_FOUND',
    });
    return fail(res, 'KEY_NOT_FOUND', '卡密不存在');
  }
  if (k.appId !== app.id) return fail(res, 'KEY_APP_MISMATCH', '该卡密不属于当前应用');
  const st = refreshKeyStatus(k);
  if (st === 'banned') return fail(res, 'KEY_BANNED', '卡密已被封禁');
  if (st === 'expired') return fail(res, 'KEY_EXPIRED', '卡密已过期');

  const deviceId = String(body.deviceId || '').slice(0, 64);
  if (!deviceId) return fail(res, 'DEVICE_REQUIRED', '缺少设备指纹');
  const deviceName = String(body.deviceName || deviceId).slice(0, 64);

  // 设备绑定
  if (!k.deviceId) {
    k.deviceId = deviceId;
    k.deviceName = deviceName;
    k.deviceModel = body.deviceModel ? String(body.deviceModel).slice(0, 48) : deviceName;
    k.ip = ip;
    k.hostVer = body.hostVer || '-';
    k.bundleId = body.bundleId || app.bundleId || '-';
    k.activatedAt = core.nowISO();
    k.status = 'activated';
    k.expiresAt = core.durationOf(k.type) === 0 ? null : new Date(Date.now() + core.durationOf(k.type)).toISOString();
    store.addLog('卡密激活', `${app.name} · ${k.keyMask} · ${deviceName}`);
  } else if (k.deviceId !== deviceId) {
    if (k.rebindLeft > 0) {
      k.rebindLeft -= 1;
      k.deviceId = deviceId; k.deviceName = deviceName; k.ip = ip;
      store.addLog('卡密换绑', `${k.keyMask} 换绑到 ${deviceName}（剩余 ${k.rebindLeft} 次）`);
    } else {
      store.addCapture({
        appId: app.id, appName: app.name, hostName: body.hostVer || '未知', bundleId: body.bundleId || '-',
        device: deviceName, keyMask: k.keyMask, ip, ua: req.headers['user-agent'] || '-',
        path: '/api/activate', ms: 1, ok: false, reason: 'DEVICE_MISMATCH',
      });
      return fail(res, 'DEVICE_MISMATCH', '该卡密已绑定其它设备');
    }
  } else {
    k.ip = ip;
  }

  // 发会话
  const token = 'TK_' + core.randHex(24);
  const sessionKey = core.randHex(32);
  const session = {
    token,
    keyId: k.id,
    appId: app.id,
    deviceId,
    deviceName,
    ip,
    ua: req.headers['user-agent'] || '-',
    createdAt: core.nowISO(),
    lastSeen: core.nowISO(),
    expiresAt: new Date(Date.now() + S().hbGraceSec * 1000).toISOString(),
    sessionKeyEnc: require('./lib/store').seal(sessionKey, S().masterSecret),
    revoked: false,
  };
  // 同设备旧会话作废，避免 token 膨胀
  store.s.sessions = store.s.sessions.filter((x) => !(x.keyId === k.id && x.deviceId === deviceId));
  store.s.sessions.push(session);
  if (store.s.sessions.length > 5000) store.s.sessions = store.s.sessions.slice(-4000);
  store.save();

  store.addCapture({
    appId: app.id, appName: app.name, hostName: body.hostVer || '未知', bundleId: body.bundleId || app.bundleId || '-',
    device: deviceName, keyMask: k.keyMask, ip, ua: req.headers['user-agent'] || '-',
    path: '/api/activate', ms: 1, ok: true,
  });

  ok(res, {
    data: {
      token,
      session_key: sessionKey,
      key: k.keyMask,
      app: { name: app.name, bundle_id: app.bundleId },
      plan: { type: k.type, label: core.TYPE_LABEL[k.type] },
      activated_at: k.activatedAt,
      expires_at: k.expiresAt,
      remain_ms: k.expiresAt ? new Date(k.expiresAt).getTime() - Date.now() : null,
      remain_text: core.humanRemain(k.expiresAt ? new Date(k.expiresAt).getTime() - Date.now() : null),
      hb_interval: S().hbInterval,
      hb_grace: S().hbGraceSec,
      device_limit: k.maxDevices,
      notice: S().notice || '',
      force_update: S().forceUpdate || null,
    },
  });
}

async function handleHeartbeat(req, res) {
  const ip = core.clientIP(req);
  if (!pubLimit.hit(ip).ok) return fail(res, 'RATE_LIMIT', '心跳过快', 429);
  const body = await readBody(req);
  const token = String(body.token || req.headers['x-session-token'] || '').trim();
  if (!token) return fail(res, 'NO_TOKEN', '缺少会话令牌');

  const session = store.s.sessions.find((x) => x.token === token && !x.revoked);
  if (!session) return fail(res, 'SESSION_INVALID', '会话不存在或已失效', 401);
  const app = store.findApp(session.appId);
  const k = store.findKeyById(session.keyId);
  if (!app || !k) return fail(res, 'SESSION_INVALID', '会话关联数据缺失', 401);
  if (!app.runControl.running) return fail(res, 'APP_STOPPED', '应用已停止运行');
  if (app.status !== 'normal') return fail(res, 'APP_DISABLED', '应用已被禁用');

  // 会话绝对过期
  if (new Date(session.expiresAt).getTime() < Date.now() - S().hbGraceSec * 1000) {
    return fail(res, 'SESSION_EXPIRED', '会话已过期，请重新激活', 401);
  }

  const st = refreshKeyStatus(k);
  if (st === 'banned') return fail(res, 'KEY_BANNED', '卡密已被封禁', 403);
  if (st === 'expired') return fail(res, 'KEY_EXPIRED', '卡密已到期', 403);
  if (k.deviceId && body.deviceId && k.deviceId !== body.deviceId)
    return fail(res, 'DEVICE_MISMATCH', '设备指纹不匹配', 403);

  // 签名 & 防重放
  const ts = Number(body.ts || 0);
  const nonce = String(body.nonce || '');
  if (S().enforceSign !== false) {
    if (!ts || Math.abs(Date.now() - ts) > S().timeWindowSec * 1000)
      return fail(res, 'STALE_REQUEST', '时钟偏差过大', 409);
    if (!nonce || !nonces.use('hb:' + nonce)) return fail(res, 'REPLAY', '重放请求', 409);
    const sessionKey = require('./lib/store').open(session.sessionKeyEnc, S().masterSecret);
    const expect = core.hmac(sessionKey, core.canonical({ token, deviceId: body.deviceId || '', ts, nonce }));
    if (!core.safeEqual(body.sig || '', expect)) return fail(res, 'BAD_SIGN', '心跳签名错误', 401);
  }

  const now = Date.now();
  session.lastSeen = new Date(now).toISOString();
  session.expiresAt = new Date(now + S().hbGraceSec * 1000).toISOString();
  session.ip = ip;
  k.lastHeartbeatAt = session.lastSeen;
  k.ip = ip;
  if (body.hostVer) k.hostVer = String(body.hostVer).slice(0, 32);
  if (body.deviceName) k.deviceName = String(body.deviceName).slice(0, 64);
  store.save();

  // 抓包记录：成功心跳按 captureRate 采样（默认 2%），失败请求在上面各分支已单独记录
  if (Math.random() < (S().captureRate ?? 0.02)) {
    store.addCapture({
      appId: app.id, appName: app.name, hostName: body.hostVer || k.hostVer || '未知',
      bundleId: k.bundleId || app.bundleId || '-', device: k.deviceName || session.deviceId,
      keyMask: k.keyMask, ip, ua: req.headers['user-agent'] || '-',
      path: '/api/heartbeat', ms: 1, ok: true,
    });
  }

  const remainMs = k.expiresAt ? new Date(k.expiresAt).getTime() - now : null;
  ok(res, {
    data: {
      status: 'active',
      plan: { type: k.type, label: core.TYPE_LABEL[k.type] },
      expires_at: k.expiresAt,
      remain_ms: remainMs,
      remain_text: core.humanRemain(remainMs),
      next_heartbeat: S().hbInterval,
      online_devices: store.s.sessions.filter(
        (x) => x.keyId === k.id && !x.revoked &&
          Date.now() - new Date(x.lastSeen).getTime() <= S().hbGraceSec * 1000).length,
      notice: S().notice || '',
      force_update: S().forceUpdate || null,
    },
  });
}

async function handleDeactivate(req, res) {
  const body = await readBody(req);
  const token = String(body.token || '').trim();
  const session = store.s.sessions.find((x) => x.token === token);
  if (session) { session.revoked = true; store.save(); }
  ok(res, { data: { released: !!session } });
}


/* ---------------- 插件下发 ---------------- */

function publicOrigin(req) {
  const proto = (req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  return proto + '://' + (req.headers['x-forwarded-host'] || req.headers.host || '127.0.0.1');
}

function pluginFileOf(app) {
  return path.join(DATA_DIR, 'plugins', String(app.id) + '.dylib');
}

function handlePlugin(req, res, q) {
  const app = (store.s.apps || []).find((a) => a.appKey === q.appKey);
  if (!app) return fail(res, 'APP_NOT_FOUND', '应用不存在');
  const p = app.plugin || {};
  const enabled = !!p.enabled && fs.existsSync(pluginFileOf(app));
  return ok(res, { data: {
    enabled,
    version: p.version || '1.0',
    delay: Number(p.delay == null ? 3 : p.delay),
    size: p.size || 0,
    url: enabled ? publicOrigin(req) + '/api/plugin/file?appKey=' + encodeURIComponent(app.appKey) + '&v=' + encodeURIComponent(p.version || '1') : '',
  }});
}

function handlePluginFile(req, res, q) {
  const app = (store.s.apps || []).find((a) => a.appKey === q.appKey);
  if (!app || !app.plugin || !app.plugin.enabled) { res.writeHead(404); return res.end('not found'); }
  const file = pluginFileOf(app);
  fs.readFile(file, (e, buf) => {
    if (e) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': buf.length,
      'Cache-Control': 'no-store',
    });
    res.end(buf);
  });
}

async function adminPluginGet(req, res, q, admin) {
  const app = (store.s.apps || []).find((a) => String(a.id) === String(q.appId) || a.appKey === q.appKey);
  if (!app) return fail(res, 'APP_NOT_FOUND', '应用不存在');
  return ok(res, { data: { appId: app.id, appKey: app.appKey, name: app.name, plugin: app.plugin || null } });
}

async function adminPluginSave(req, res, admin) {
  const b = await readBody(req);
  const app = (store.s.apps || []).find((a) => String(a.id) === String(b.appId) || a.appKey === b.appKey);
  if (!app) return fail(res, 'APP_NOT_FOUND', '应用不存在');
  app.plugin = Object.assign({ enabled: false, delay: 3, version: '1.0', size: 0 }, app.plugin || {});
  if (b.enabled !== undefined) app.plugin.enabled = !!b.enabled;
  if (b.delay !== undefined) app.plugin.delay = Math.min(120, Math.max(0, Number(b.delay) || 0));
  if (b.version !== undefined) app.plugin.version = String(b.version).slice(0, 20);
  if (b.data) {
    const buf = Buffer.from(String(b.data), 'base64');
    if (buf.length < 1024) return fail(res, 'BAD_FILE', '文件太小，不像是 dylib');
    if (buf.length > 3 * 1024 * 1024) return fail(res, 'TOO_LARGE', '插件不能超过 3MB');
    const magic = buf.readUInt32LE(0);
    if (magic !== 0xfeedfacf && magic !== 0xcffaedfe && magic !== 0xbebafeca) {
      return fail(res, 'BAD_FILE', '不是 Mach-O 文件');
    }
    fs.mkdirSync(path.join(DATA_DIR, 'plugins'), { recursive: true });
    fs.writeFileSync(pluginFileOf(app), buf);
    app.plugin.size = buf.length;
  }
  store.addLog('插件更新', app.name + ' · v' + app.plugin.version + (b.data ? ' · 已上传' : ' · 配置'));
  store.save();
  return ok(res, { data: app.plugin });
}

/* ---------------- 自助注册（代理） ---------------- */
const regLimit = new core.RateLimiter({ perMin: 20, burst: 12 });

async function registerAccount(req, res) {
  const ip = core.clientIP(req);
  if (S().allowRegister === false) return fail(res, "REGISTER_OFF", "本站已关闭注册，请联系主代理开号", 403);
  if (!regLimit.hit("reg:" + ip).ok) return fail(res, "RATE_LIMIT", "注册太频繁，稍后再试", 429);
  const b = await readBody(req);
  const user = String(b.user || "").trim();
  const pass = String(b.pass || "");
  if (!/^[A-Za-z0-9_]{3,20}$/.test(user)) return fail(res, "BAD_USER", "账号需 3~20 位字母/数字/下划线");
  if (pass.length < 6) return fail(res, "WEAK_PASS", "密码至少 6 位");
  if (S().registerInvite && String(b.invite || "") !== String(S().registerInvite))
    return fail(res, "BAD_INVITE", "邀请码不正确", 403);
  if (store.s.accounts.some((a) => a.user.toLowerCase() === user.toLowerCase()))
    return fail(res, "USER_EXISTS", "这个账号已被注册，换一个");
  const pw = core.hashPassword(pass);
  const acc = {
    id: store.s.seq.account++,
    user, salt: pw.salt, hash: pw.hash,
    role: "agent", balance: 0, status: "normal",
    note: "自助注册", createdAt: core.nowISO(), createdBy: null, lastLoginAt: core.nowISO(),
  };
  store.s.accounts.push(acc);
  store.addLog("自助注册", user + " 从 " + ip + " 注册", user, acc.id);
  store.save();
  const token = core.issueAdminToken({ id: acc.id, u: acc.user, role: acc.role }, S().masterSecret, 12 * 3600_000);
  ok(res, { data: { token, user: acc.user, role: acc.role, balance: acc.balance, site: S().siteName, agent: S().agentId, agent_expire: S().agentExpire } });
}
/* ---------------- 管理端接口 ---------------- */

async function adminLogin(req, res) {
  const ip = core.clientIP(req);
  if (!pubLimit.hit('login:' + ip).ok) return fail(res, 'RATE_LIMIT', '登录尝试过多', 429);
  const body = await readBody(req);
  const acc = store.s.accounts.find((a) => a.user === String(body.user || '').trim());
  if (!acc || !core.checkPassword(body.pass || '', acc.salt, acc.hash))
    return fail(res, 'LOGIN_FAILED', '账号或密码错误', 401);
  if (acc.status !== 'normal') return fail(res, 'ACCOUNT_DISABLED', '账号已被停用，请联系主代理', 403);
  acc.lastLoginAt = core.nowISO();
  store.save();
  const token = core.issueAdminToken({ id: acc.id, u: acc.user, role: acc.role }, S().masterSecret, 12 * 3600_000);
  store.addLog('登录系统', acc.user + ' 从 ' + ip + ' 登录', acc.user, acc.id);
  ok(res, {
    data: {
      token, user: acc.user, role: acc.role, balance: acc.balance,
      site: S().siteName, agent: S().agentId, agent_expire: S().agentExpire,
    },
  });
}

function adminOverview(req, res, admin) {
  const keys = scopeKeys(admin);
  const mine = new Set(keys.map((k) => k.id));
  const total = keys.length;
  const activated = keys.filter((k) => k.status === 'activated').length;
  const unused = keys.filter((k) => k.status === 'unused').length;
  const expired = keys.filter((k) => refreshKeyStatus(k) === 'expired').length;
  const banned = keys.filter((k) => k.status === 'banned').length;
  const online = store.s.sessions.filter(
    (x) => !x.revoked && mine.has(x.keyId) && Date.now() - new Date(x.lastSeen).getTime() <= S().hbGraceSec * 1000).length;
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const todayAct = keys.filter((k) => k.activatedAt && new Date(k.activatedAt) >= today).length;
  const hb24 = store.s.captures.filter((c) => c.path === '/api/heartbeat' &&
    Date.now() - new Date(c.at).getTime() < 86400_000).length;

  const byType = {};
  for (const k of keys) byType[k.type] = (byType[k.type] || 0) + 1;

  ok(res, {
    data: {
      site: S().siteName,
      banner: S().banner,
      accent: S().accent || '#2563eb',
      enabled_types: S().enabledTypes || [],
      logoText: S().logoText || 'K',
      agent: S().agentId,
      agent_expire: S().agentExpire,
      balance: admin.balance,
      role: admin.role,
      apps: store.s.apps.length,
      keys: total,
      activated,
      unused,
      expired,
      banned,
      online,
      today_activations: todayAct,
      heartbeats_24h: hb24,
      by_type: byType,
      hb_interval: S().hbInterval,
      hb_grace: S().hbGraceSec,
      recent_logs: (isOwner(admin) ? store.s.logs : store.s.logs.filter((l) => l.actorId === admin.id)).slice(0, 8),
      online_list: store.s.sessions
        .filter((x) => !x.revoked && mine.has(x.keyId) && Date.now() - new Date(x.lastSeen).getTime() <= S().hbGraceSec * 1000)
        .slice(0, 12)
        .map((x) => {
          const k = store.findKeyById(x.keyId);
          const a = store.findApp(x.appId);
          return {
            device: x.deviceName, app: a ? a.name : '-', key: k ? k.keyMask : '-', ip: x.ip,
            last_seen: x.lastSeen, latency: Math.max(8, Math.floor(Math.random() * 120) + 20),
          };
        }),
    },
  });
}

function adminApps(req, res) {
  const list = store.s.apps.map((a) => {
    const ks = store.s.keys.filter((k) => k.appId === a.id);
    const used = ks.filter((k) => k.status !== 'unused').length;
    return {
      ...a,
      keys_total: ks.length,
      keys_used: used,
      keys_unused: ks.length - used,
      online: store.s.sessions.filter((x) => x.appId === a.id && !x.revoked &&
        Date.now() - new Date(x.lastSeen).getTime() <= S().hbGraceSec * 1000).length,
    };
  });
  ok(res, { data: list });
}

async function adminAppCreate(req, res, admin) {
  const b = await readBody(req);
  const name = String(b.name || '').trim().slice(0, 32);
  if (!name) return fail(res, 'NAME_REQUIRED', '应用名称必填');
  const app = {
    id: store.s.seq.app++,
    name,
    bundleId: String(b.bundleId || 'com.demo.' + core.randHex(3)).slice(0, 64),
    owner: '自己',
    status: 'normal',
    runControl: { running: true, visible: true },
    appKey: 'AK_' + core.randHex(8),
    appSecret: 'SK_' + core.randHex(24),
    note: String(b.note || '').slice(0, 120),
    createdAt: core.nowISO(),
  };
  store.s.apps.push(app);
  store.addLog('添加应用', `新增应用 ${name}`, admin.u);
  ok(res, { data: app });
}

async function adminAppUpdate(req, res, admin, id) {
  const app = store.findApp(id);
  if (!app) return fail(res, 'APP_NOT_FOUND', '应用不存在', 404);
  const b = await readBody(req);
  if (b.name !== undefined) app.name = String(b.name).slice(0, 32);
  if (b.note !== undefined) app.note = String(b.note).slice(0, 120);
  if (b.bundleId !== undefined) app.bundleId = String(b.bundleId).slice(0, 64);
  if (b.status !== undefined && ['normal', 'disabled'].includes(b.status)) app.status = b.status;
  if (b.running !== undefined) app.runControl.running = !!b.running;
  if (b.visible !== undefined) app.runControl.visible = !!b.visible;
  if (b.popup && typeof b.popup === 'object') {
    const p = app.popup || (app.popup = {});
    for (const [k, n] of [['title',120],['notice',300],['subtitle',120],['template',32],['contact',200],['adLink',300],['cover',800000],['logo',800000],['adImage',800000]]) {
      if (b.popup[k] !== undefined) p[k] = String(b.popup[k]).slice(0, n);
    }
    if (Array.isArray(b.popup.buttons)) {
      p.buttons = b.popup.buttons.slice(0, 6).map((x) => ({
        text: String(x && x.text || '').slice(0, 20),
        url: String(x && x.url || '').slice(0, 300),
        enabled: !(x && x.enabled === false),
      })).filter((x) => x.text);
    }
    if (b.popup.version && typeof b.popup.version === 'object') {
      p.version = {
        current: String(b.popup.version.current || '1.0').slice(0, 16),
        url: String(b.popup.version.url || '').slice(0, 300),
        note: String(b.popup.version.note || '').slice(0, 200),
        force: !!b.popup.version.force,
      };
    }
  }
  if (b.rotate === true) {
    app.appKey = 'AK_' + core.randHex(8);
    app.appSecret = 'SK_' + core.randHex(24);
    store.addLog('重置密钥', `应用 ${app.name} 密钥已轮换`, admin.u);
  }
  store.addLog('编辑应用', `应用 ${app.name} 已更新`, admin.u);
  store.save();
  ok(res, { data: app });
}

function adminKeys(req, res, q, admin) {
  let list = scopeKeys(admin).slice();
  if (q.appId) list = list.filter((k) => k.appId === Number(q.appId));
  if (q.status && q.status !== 'all') list = list.filter((k) => refreshKeyStatus(k) === q.status);
  if (q.type && q.type !== 'all') list = list.filter((k) => k.type === q.type);
  const kw = String(q.q || '').trim().toUpperCase();
  if (kw) {
    list = list.filter((k) => {
      const plain = store.keyPlain(k) || '';
      return plain.includes(kw) || k.keyMask.includes(kw) ||
        String(k.deviceId || '').toUpperCase().includes(kw) ||
        String(k.ip || '').includes(kw) ||
        String(k.deviceName || '').toUpperCase().includes(kw);
    });
  }
  list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const page = Math.max(1, Number(q.page || 1));
  const size = Math.min(100, Math.max(1, Number(q.size || 20)));
  const total = list.length;
  const slice = list.slice((page - 1) * size, page * size).map((k) => keyView(k));
  ok(res, { data: { list: slice, total, page, size, pages: Math.max(1, Math.ceil(total / size)) } });
}

async function adminKeyGenerate(req, res, admin) {
  const b = await readBody(req);
  const app = store.findApp(b.appId);
  if (!app) return fail(res, 'APP_NOT_FOUND', '应用不存在');
  const count = Math.min(200, Math.max(1, Number(b.count || 1)));
  const type = String(b.type || 'day');
  if (!(type in core.DURATIONS)) return fail(res, 'BAD_TYPE', '卡密类型不合法');
  if (Array.isArray(S().enabledTypes) && !S().enabledTypes.includes(type))
    return fail(res, 'TYPE_OFF', '该卡密类型已下架');
  const len = Math.min(32, Math.max(8, Number(b.length || 16)));
  const prefix = String(b.prefix || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
  if (prefix.length >= len) return fail(res, 'BAD_PREFIX', '开头长度必须小于卡密长度');
  const unit = core.PRICE[type] || 0;
  const cost = +(unit * count).toFixed(2);
  if (Number(admin.balance) < cost) return fail(res, 'NO_BALANCE', '余额不足，请联系主代理充值');

  const batchId = 'B' + Date.now().toString(36).toUpperCase();
  const created = [];
  const seen = new Set(store.s.keys.map((k) => k.keyHash));
  for (let i = 0; i < count; i++) {
    let plain, h, guard = 0;
    do { plain = core.genKey({ len, prefix }); h = core.keyHash(plain, S().masterSecret); } while (seen.has(h) && guard++ < 5);
    seen.add(h);
    const k = {
      id: store.s.seq.key++,
      ownerId: admin.id,
      appId: app.id,
      keyEnc: require('./lib/store').seal(plain, S().masterSecret),
      keyMask: core.maskKey(plain),
      keyHash: h,
      type,
      status: 'unused',
      createdAt: core.nowISO(),
      activatedAt: null,
      expiresAt: null,
      deviceId: null, deviceName: null, deviceModel: null,
      ip: null, hostVer: null, bundleId: null,
      maxDevices: 1,
      rebindLeft: Number(b.rebind ?? 3),
      lastHeartbeatAt: null,
      note: String(b.note || '').slice(0, 60),
      batchId,
      cost: unit,
    };
    store.s.keys.push(k);
    created.push(keyView(k));
  }
  admin.balance = +(Number(admin.balance) - cost).toFixed(2);
  store.addLog('生成卡密', `生成${count}张${app.name}·${core.TYPE_LABEL[type]}`, admin.u);
  store.save();
  ok(res, { data: { list: created, cost, batch_id: batchId, balance: admin.balance } });
}

async function adminKeyImport(req, res, admin) {
  const b = await readBody(req);
  const app = store.findApp(b.appId);
  if (!app) return fail(res, 'APP_NOT_FOUND', '应用不存在');
  const type = String(b.type || 'day');
  if (!(type in core.DURATIONS)) return fail(res, 'BAD_TYPE', '卡密类型不合法');
  if (Array.isArray(S().enabledTypes) && !S().enabledTypes.includes(type))
    return fail(res, 'TYPE_OFF', '该卡密类型已下架');
  const lines = String(b.text || '').split(/[\r\n,;]+/).map((x) => core.normalizeKey(x)).filter((x) => x.length >= 6);
  if (!lines.length) return fail(res, 'EMPTY', '没有可导入的卡密');
  const exist = new Set(store.s.keys.map((k) => k.keyHash));
  let added = 0, skipped = 0;
  for (const plain of lines) {
    const h = core.keyHash(plain, S().masterSecret);
    if (exist.has(h)) { skipped++; continue; }
    exist.add(h);
    store.s.keys.push({
      id: store.s.seq.key++, ownerId: admin.id, appId: app.id,
      keyEnc: require('./lib/store').seal(plain, S().masterSecret),
      keyMask: core.maskKey(plain), keyHash: h, type, status: 'unused',
      createdAt: core.nowISO(), activatedAt: null, expiresAt: null,
      deviceId: null, deviceName: null, deviceModel: null, ip: null, hostVer: null, bundleId: null,
      maxDevices: 1, rebindLeft: 3, lastHeartbeatAt: null, note: '导入', batchId: 'IMPORT', cost: 0,
    });
    added++;
  }
  store.addLog('导入卡密', `导入卡密 ${added} 条（跳过重复 ${skipped}）`, admin.u);
  store.save();
  ok(res, { data: { added, skipped } });
}

async function adminKeyBatch(req, res, admin) {
  const b = await readBody(req);
  const ids = (Array.isArray(b.ids) ? b.ids : []).map(Number);
  if (!ids.length) return fail(res, 'NO_SELECTION', '请先选择卡密');
  const allowed = new Set(scopeKeys(admin).map((k) => k.id));
  const targets = store.s.keys.filter((k) => ids.includes(k.id) && allowed.has(k.id));
  const action = String(b.action || '');
  let n = 0;
  for (const k of targets) {
    switch (action) {
      case 'ban': if (k.status !== 'banned') { k.status = 'banned'; n++; } break;
      case 'unban': if (k.status === 'banned') { k.status = k.expiresAt && new Date(k.expiresAt) < Date.now() ? 'expired' : (k.activatedAt ? 'activated' : 'unused'); n++; } break;
      case 'delete': n++; break;
      case 'extend': {
        const ms = Number(b.value || 30) * 86400_000;
        if (k.expiresAt) k.expiresAt = new Date(new Date(k.expiresAt).getTime() + ms).toISOString();
        else if (k.type !== 'permanent') k.expiresAt = new Date(Date.now() + ms).toISOString();
        if (k.status === 'expired') k.status = 'activated';
        n++; break;
      }
      case 'resetDevice': k.deviceId = null; k.deviceName = null; k.deviceModel = null; k.lastHeartbeatAt = null; k.status = 'unused'; k.activatedAt = null; k.expiresAt = null; n++; break;
      case 'activate': if (k.status === 'unused') { k.status = 'activated'; k.activatedAt = core.nowISO(); k.expiresAt = core.durationOf(k.type) === 0 ? null : new Date(Date.now() + core.durationOf(k.type)).toISOString(); n++; } break;
      default: return fail(res, 'BAD_ACTION', '不支持的操作');
    }
  }
  if (action === 'delete') {
    const del = new Set(ids);
    store.s.keys = store.s.keys.filter((k) => !del.has(k.id));
    store.s.sessions = store.s.sessions.filter((s) => !del.has(s.keyId));
  }
  const label = { ban: '封禁', unban: '解封', delete: '删除', extend: '加时', resetDevice: '重置设备', activate: '手动激活' }[action] || action;
  store.addLog('批量操作', `${label} ${n} 张卡密`, admin.u);
  store.save();
  ok(res, { data: { affected: n, action } });
}

function adminLogs(req, res, q, admin) {
  let list = isOwner(admin) ? store.s.logs.slice() : store.s.logs.filter((l) => l.actorId === admin.id);
  const kw = String(q.q || '').trim();
  if (kw) list = list.filter((x) => JSON.stringify(x).includes(kw));
  if (q.type && q.type !== 'all') list = list.filter((x) => x.type === q.type);
  const page = Math.max(1, Number(q.page || 1));
  const size = Math.min(100, Math.max(1, Number(q.size || 20)));
  ok(res, { data: { list: list.slice((page - 1) * size, page * size), total: list.length, page, size } });
}

function adminCaptures(req, res, q, admin) {
  const mine = new Set(scopeKeys(admin).map((k) => k.keyMask));
  let list = isOwner(admin) ? store.s.captures.slice() : store.s.captures.filter((c) => mine.has(c.keyMask));
  const kw = String(q.q || '').trim();
  if (kw) list = list.filter((x) => JSON.stringify(x).includes(kw));
  if (q.status === 'ok') list = list.filter((x) => x.ok);
  if (q.status === 'fail') list = list.filter((x) => !x.ok);
  const page = Math.max(1, Number(q.page || 1));
  const size = Math.min(100, Math.max(1, Number(q.size || 20)));
  ok(res, { data: { list: list.slice((page - 1) * size, page * size), total: list.length, page, size } });
}

function adminSessions(req, res, admin) {
  const now = Date.now();
  const mine = new Set(scopeKeys(admin).map((k) => k.id));
  const list = store.s.sessions
    .filter((x) => !x.revoked && mine.has(x.keyId))
    .map((x) => {
      const k = store.findKeyById(x.keyId);
      const a = store.findApp(x.appId);
      return {
        token_tail: x.token.slice(-6),
        key: k ? k.keyMask : '-',
        app: a ? a.name : '-',
        device: x.deviceName,
        device_id: x.deviceId,
        ip: x.ip,
        ua: x.ua,
        created_at: x.createdAt,
        last_seen: x.lastSeen,
        online: now - new Date(x.lastSeen).getTime() <= S().hbGraceSec * 1000,
      };
    })
    .sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));
  ok(res, { data: { list: list.slice(0, 200), online: list.filter((x) => x.online).length } });
}

async function adminSettings(req, res, admin) {
  const b = await readBody(req);
  const st = S();
  if (b.siteName !== undefined) st.siteName = String(b.siteName).slice(0, 32);
  if (b.accent !== undefined && /^#[0-9a-fA-F]{6}$/.test(String(b.accent))) st.accent = String(b.accent);
  if (b.logoText !== undefined) st.logoText = String(b.logoText).slice(0, 2);
  if (b.banner !== undefined) st.banner = String(b.banner).slice(0, 64);
  if (b.agentId !== undefined) st.agentId = String(b.agentId).slice(0, 32);
  if (b.agentExpire !== undefined) st.agentExpire = String(b.agentExpire).slice(0, 40);
  if (b.balance !== undefined) st.balance = Number(b.balance) || 0;
  if (b.hbInterval !== undefined) st.hbInterval = Math.min(300, Math.max(5, Number(b.hbInterval) || 30));
  if (b.hbGraceSec !== undefined) st.hbGraceSec = Math.min(3600, Math.max(10, Number(b.hbGraceSec) || 90));
  if (b.notice !== undefined) st.notice = String(b.notice).slice(0, 200);
  if (b.site && typeof b.site === 'object') {
    st.site = Object.assign({ title:'', subtitle:'', notice:'', contact:'', cover:'', logo:'', adImage:'', adLink:'' }, st.site || {});
    for (const k of ['title','subtitle','notice','contact','adLink']) if (b.site[k] !== undefined) st.site[k] = String(b.site[k]).slice(0, 300);
    for (const k of ['cover','logo','adImage']) if (b.site[k] !== undefined) {
      const v = String(b.site[k]);
      if (v.length <= 800000) st.site[k] = v;   // 单图上限约 600KB
    }
  }
  if (b.allowRegister !== undefined) st.allowRegister = !!b.allowRegister;
  if (b.registerInvite !== undefined) st.registerInvite = String(b.registerInvite).slice(0, 32);
  if (b.payLink !== undefined) st.payLink = String(b.payLink).slice(0, 500);
  if (b.payTip !== undefined) st.payTip = String(b.payTip).slice(0, 120);
  if (b.pay && typeof b.pay === 'object') {
    st.pay = Object.assign({ provider: 'manual', epayUrl: '', pid: '', key: '', qrImage: '', notifyBase: '', methods: ['wxpay', 'alipay'] }, st.pay || {});
    for (const k of ['provider', 'epayUrl', 'pid', 'key', 'qrImage', 'notifyBase', 'signMode']) if (b.pay[k] !== undefined) st.pay[k] = String(b.pay[k]).slice(0, 300);
    if (Array.isArray(b.pay.methods) && b.pay.methods.length) st.pay.methods = b.pay.methods.filter((m) => ['wxpay', 'alipay'].includes(m));
    if (b.pay.bonus !== undefined) {
      let rules = b.pay.bonus;
      if (typeof rules === 'string') {
        rules = rules.split(/[,，;；\s]+/).map((kv) => {
          const m = kv.split(/[:：=]/);
          return m.length === 2 ? { amount: Number(m[0]), bonus: Number(m[1]) } : null;
        }).filter((x) => x && x.amount > 0);
      }
      if (Array.isArray(rules)) st.pay.bonus = rules.slice(0, 20).map((x) => ({ amount: Number(x.amount) || 0, bonus: Number(x.bonus) || 0 })).filter((x) => x.amount > 0);
    }
  }
  if (b.forceUpdate !== undefined) st.forceUpdate = b.forceUpdate;
  if (b.enforceSign !== undefined) st.enforceSign = !!b.enforceSign;
  if (Array.isArray(b.enabledTypes)) {
    const ok = b.enabledTypes.filter((t) => t in core.DURATIONS);
    if (ok.length) st.enabledTypes = ok;
  }
  store.addLog('修改设置', '系统参数已更新', admin.u);
  store.save();
  ok(res, { data: st });
}

async function adminPassword(req, res, admin) {
  const b = await readBody(req);
  if (!core.checkPassword(b.old || '', S().admin.salt, S().admin.hash))
    return fail(res, 'BAD_OLD', '原密码错误', 403);
  const np = String(b.next || '');
  if (np.length < 6) return fail(res, 'WEAK', '新密码至少 6 位');
  const { salt, hash } = core.hashPassword(np);
  S().admin.salt = salt; S().admin.hash = hash;
  store.addLog('修改密码', '管理员密码已修改', admin.u);
  store.save();
  ok(res, { data: { changed: true } });
}


/* ---------------- 代理账号（仅主代理） ---------------- */
function guardOwner(admin, res) {
  if (!isOwner(admin)) { fail(res, 'FORBIDDEN', '只有主代理可以做这个操作', 403); return false; }
  return true;
}
function adminAccounts(req, res, admin) {
  if (!guardOwner(admin, res)) return;
  const list = store.s.accounts
    .slice()
    .sort((a, b) => (a.role === 'owner' ? -1 : b.role === 'owner' ? 1 : a.id - b.id))
    .map(publicAccount);
  ok(res, { data: { list, total_balance: list.reduce((n, a) => n + Number(a.balance || 0), 0) } });
}

async function adminAccountCreate(req, res, admin) {
  if (!guardOwner(admin, res)) return;
  const b = await readBody(req);
  const user = String(b.user || '').trim();
  if (!/^[A-Za-z0-9_]{3,20}$/.test(user)) return fail(res, 'BAD_USER', '账号需 3~20 位字母/数字/下划线');
  if (String(b.pass || '').length < 6) return fail(res, 'WEAK_PASS', '密码至少 6 位');
  if (store.s.accounts.some((a) => a.user === user)) return fail(res, 'USER_EXISTS', '账号已存在');
  const pw = core.hashPassword(String(b.pass));
  const acc = {
    id: store.s.seq.account++,
    user,
    salt: pw.salt,
    hash: pw.hash,
    role: 'agent',                  // 只允许建代理，主代理唯一
    balance: Number(b.balance || 0),
    status: 'normal',
    note: String(b.note || '').slice(0, 40),
    createdAt: core.nowISO(),
    createdBy: admin.user,
    lastLoginAt: null,
  };
  store.s.accounts.push(acc);
  store.addLog('新增代理', user + ' 初始余额 ' + acc.balance, admin.user, admin.id);
  store.save();
  ok(res, { data: publicAccount(acc) });
}

async function adminAccountUpdate(req, res, admin, id) {
  if (!guardOwner(admin, res)) return;
  const acc = store.account(id);
  if (!acc) return fail(res, 'ACCOUNT_NOT_FOUND', '账号不存在', 404);
  if (acc.role === 'owner') return fail(res, 'PROTECTED', '主代理账号不能改', 403);
  const b = await readBody(req);
  if (b.status !== undefined && ['normal', 'disabled'].includes(b.status)) acc.status = b.status;
  if (b.note !== undefined) acc.note = String(b.note).slice(0, 40);
  if (b.pass) {
    if (String(b.pass).length < 6) return fail(res, 'WEAK_PASS', '密码至少 6 位');
    const pw = core.hashPassword(String(b.pass));
    acc.salt = pw.salt; acc.hash = pw.hash;
  }
  if (b.resetBalance === true) acc.balance = 0;
  store.addLog('编辑代理', acc.user + (b.status ? ' → ' + b.status : '') + (b.pass ? '（重置密码）' : ''), admin.user, admin.id);
  store.save();
  ok(res, { data: publicAccount(acc) });
}

async function adminAccountBalance(req, res, admin, id) {
  if (!guardOwner(admin, res)) return;
  const acc = store.account(id);
  if (!acc) return fail(res, 'ACCOUNT_NOT_FOUND', '账号不存在', 404);
  const b = await readBody(req);
  const amount = Math.abs(Number(b.amount || 0));
  if (!amount) return fail(res, 'BAD_AMOUNT', '金额必须大于 0');
  const mode = String(b.mode || 'add');
  if (mode === 'set') acc.balance = +Number(b.amount).toFixed(2);
  else if (mode === 'sub') acc.balance = +(Number(acc.balance) - amount).toFixed(2);
  else acc.balance = +(Number(acc.balance) + amount).toFixed(2);
  const label = mode === 'set' ? '设为' : mode === 'sub' ? '扣减' : '增加';
  store.addLog('调整余额', acc.user + ' ' + label + ' ' + amount + ' → 余额 ' + acc.balance, admin.user, admin.id);
  store.save();
  ok(res, { data: publicAccount(acc) });
}


/* ---------------- 充值（收款链接 + 申请 + 后台到账） ---------------- */
function rechargeView(r) {
  const a = store.account(r.accountId);
  return {
    id: r.id, accountId: r.accountId, user: a ? a.user : '-',
    amount: r.amount, note: r.note || '', status: r.status,
    createdAt: r.createdAt, handledAt: r.handledAt || null, handledBy: r.handledBy || null,
  };
}
function adminRechargeList(req, res, admin) {
  const list = (store.s.recharges || [])
    .filter((r) => isOwner(admin) || r.accountId === admin.id)
    .slice().sort((a, b) => b.id - a.id)
    .map(rechargeView);
  ok(res, { data: { list, pending: list.filter((r) => r.status === 'pending').length, pay_link: S().payLink || '', pay_tip: S().payTip || '', bonus: (Array.isArray((S().pay || {}).bonus) ? S().pay.bonus : []), methods: ((S().pay || {}).methods || ['wxpay', 'alipay']) } });
}
async function adminRechargeRequest(req, res, admin) {
  const b = await readBody(req);
  const amount = Number(b.amount || 0);
  if (!(amount > 0)) return fail(res, 'BAD_AMOUNT', '充值金额必须大于 0');
  if (amount > 100000) return fail(res, 'TOO_LARGE', '单笔金额过大');
  const r = {
    id: store.s.seq.recharge++,
    accountId: admin.id,
    amount: +amount.toFixed(2),
    note: String(b.note || '').slice(0, 60),
    status: 'pending',
    createdAt: core.nowISO(),
    handledAt: null,
    handledBy: null,
  };
  store.s.recharges.push(r);
  store.addLog('充值申请', admin.user + ' 申请充值 ' + r.amount, admin.user, admin.id);
  store.save();
  ok(res, { data: rechargeView(r) });
}
async function adminRechargeHandle(req, res, admin, id) {
  if (!isOwner(admin)) return fail(res, 'FORBIDDEN', '只有主代理可以确认到账', 403);
  const r = (store.s.recharges || []).find((x) => x.id === Number(id));
  if (!r) return fail(res, 'NOT_FOUND', '申请不存在', 404);
  if (r.status !== 'pending') return fail(res, 'DONE', '该申请已处理', 409);
  const b = await readBody(req);
  if (String(b.action) === 'reject') {
    r.status = 'rejected'; r.handledAt = core.nowISO(); r.handledBy = admin.user;
    store.addLog('充值驳回', r.user || ('#' + r.accountId) + ' ' + r.amount, admin.user, admin.id);
    store.save();
    return ok(res, { data: rechargeView(r) });
  }
  const acc = store.account(r.accountId);
  if (!acc) return fail(res, 'ACCOUNT_NOT_FOUND', '账号不存在', 404);
  acc.balance = +(Number(acc.balance) + Number(r.amount)).toFixed(2);
  r.status = 'approved'; r.handledAt = core.nowISO(); r.handledBy = admin.user;
  store.addLog('充值到账', acc.user + ' +' + r.amount + ' → 余额 ' + acc.balance, admin.user, admin.id);
  store.save();
  ok(res, { data: { recharge: rechargeView(r), balance: acc.balance } });
}
/* 主代理给自己充值 */
async function adminRechargeSelf(req, res, admin) {
  if (!isOwner(admin)) return fail(res, 'FORBIDDEN', '只有主代理可以给自己充值', 403);
  const b = await readBody(req);
  const amount = Number(b.amount || 0);
  if (!(amount > 0)) return fail(res, 'BAD_AMOUNT', '金额必须大于 0');
  admin.balance = +(Number(admin.balance) + amount).toFixed(2);
  store.addLog('主代理充值', '自己 +' + amount.toFixed(2) + ' → 余额 ' + admin.balance, admin.user, admin.id);
  store.save();
  ok(res, { data: { balance: admin.balance } });
}

/* ---------------- 支付：订单 / 收款页 / 回调 ---------------- */
const PAY = () => Object.assign({ provider: 'manual', epayUrl: '', pid: '', key: '', qrImage: '', notifyBase: '', methods: ['wxpay', 'alipay'] }, S().pay || {});
/* 充值赠送：按面额精确匹配，例如充 50 送 10 */
function bonusRules() {
  const p = S().pay || {};
  return Array.isArray(p.bonus) ? p.bonus : [];
}
function bonusFor(amount) {
  const r = bonusRules().find((x) => Math.abs(Number(x.amount) - Number(amount)) < 0.001);
  return r ? Number(r.bonus || 0) : 0;
}
const newOrderNo = () => 'P' + Date.now().toString(36).toUpperCase() + core.randHex(4).toUpperCase();

function orderView(o) {
  const a = store.account(o.accountId);
  return {
    no: o.no, accountId: o.accountId, user: a ? a.user : '-',
    amount: o.amount, method: o.method, status: o.status,
    bonus: Number(o.bonus || 0), credit: Number(o.credit || o.amount),
    createdAt: o.createdAt, paidAt: o.paidAt || null, tradeNo: o.tradeNo || '', via: o.via || '',
  };
}

/** 易支付签名：concat = 按字段顺序直接拼接 + key；kv = 参数名排序 k=v&… + key */
function epaySign(vals) {
  const p = PAY();
  if (p.signMode === 'kv') {
    const s = Object.keys(vals).sort().map((k) => k + '=' + vals[k]).join('&');
    return core.md5(s + p.key);
  }
  return core.md5(Object.keys(vals).map((k) => vals[k]).join('') + p.key);
}

function epayPayUrl(o, base) {
  const p = PAY();
  const params = {
    pid: p.pid,
    type: o.method,
    out_trade_no: o.no,
    notify_url: base + '/api/pay/notify',
    return_url: base + '/api/pay/return?no=' + o.no,
    name: '余额充值',
    money: Number(o.amount).toFixed(2),
  };
  const sign = epaySign(params);
  const qs = Object.keys(params).map((k) => k + '=' + encodeURIComponent(params[k])).join('&');
  return (p.epayUrl || '').replace(/\/*$/, '/') + 'submit.php?' + qs + '&sign=' + sign + '&sign_type=MD5';
}

/** 幂等到账：同一订单只会加一次 */
function creditOrder(o, tradeNo, via) {
  if (!o || o.status === 'paid') return o;
  const acc = store.account(o.accountId);
  if (!acc) return o;
  const bonus = o.bonus !== undefined ? Number(o.bonus) : bonusFor(o.amount);
  const credit = +(Number(o.amount) + bonus).toFixed(2);
  acc.balance = +(Number(acc.balance) + credit).toFixed(2);
  o.bonus = bonus;
  o.credit = credit;
  o.status = 'paid';
  o.paidAt = core.nowISO();
  o.tradeNo = tradeNo || o.tradeNo || '';
  o.via = via || 'manual';
  store.addLog('充值到账', acc.user + ' 充' + o.amount + (bonus ? ' 送' + bonus : '') + ' 实到 ' + credit + ' → 余额 ' + acc.balance + '（' + (via || 'manual') + '）', 'system', acc.id);
  store.save();
  return o;
}

async function createRechargeOrder(req, res, admin) {
  const b = await readBody(req);
  const amount = Number(b.amount || 0);
  if (!(amount > 0)) return fail(res, 'BAD_AMOUNT', '金额必须大于 0');
  if (amount < 1) return fail(res, 'TOO_SMALL', '最低充值 1 元');
  if (amount > 100000) return fail(res, 'TOO_LARGE', '单笔金额过大');
  const p = PAY();
  const method = String(b.method || p.methods[0] || 'wxpay');
  const o = {
    no: newOrderNo(),
    accountId: admin.id,
    amount: +amount.toFixed(2),
    method,
    status: 'pending',
    createdAt: core.nowISO(),
    paidAt: null,
    tradeNo: '',
    via: '',
  };
  store.s.orders.push(o);
  store.addLog('创建订单', admin.user + ' 充值 ' + o.amount + ' 元（' + method + '）', admin.user, admin.id);
  store.save();
  const base = (p.notifyBase || '').replace(/\/+$/, '');
  const payUrl = p.provider === 'epay' && p.epayUrl && p.pid && p.key
    ? epayPayUrl(o, base || 'http://127.0.0.1:' + PORT)
    : (base || '') + '/pay/' + o.no;
  ok(res, { data: { ...orderView(o), bonus: bonusFor(o.amount), credit: +(o.amount + bonusFor(o.amount)).toFixed(2), pay_url: payUrl, provider: p.provider, qr_image: p.qrImage || '', pay_link: S().payLink || '' } });
}

function listOrders(req, res, admin, q) {
  let list = store.s.orders.slice();
  if (!isOwner(admin)) list = list.filter((o) => o.accountId === admin.id);
  if (q.status && q.status !== 'all') list = list.filter((o) => o.status === q.status);
  list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  ok(res, { data: { list: list.slice(0, 200).map(orderView), total: list.length } });
}

function getOrder(req, res, admin, no) {
  const o = store.s.orders.find((x) => x.no === no);
  if (!o) return fail(res, 'ORDER_NOT_FOUND', '订单不存在', 404);
  if (!isOwner(admin) && o.accountId !== admin.id) return fail(res, 'FORBIDDEN', '无权查看该订单', 403);
  ok(res, { data: orderView(o) });
}

async function markOrderPaid(req, res, admin, no) {
  if (!isOwner(admin)) return fail(res, 'FORBIDDEN', '只有主代理可以确认到账', 403);
  const o = store.s.orders.find((x) => x.no === no);
  if (!o) return fail(res, 'ORDER_NOT_FOUND', '订单不存在', 404);
  if (o.status === 'paid') return fail(res, 'DONE', '订单已到账', 409);
  creditOrder(o, 'MANUAL-' + admin.user, 'manual');
  ok(res, { data: orderView(o) });
}

/* 公开：订单状态（收款页轮询） */
function publicOrderStatus(req, res, q) {
  const o = store.s.orders.find((x) => x.no === String(q.no || ''));
  if (!o) return send(res, 404, { ok: false, error: { code: 'ORDER_NOT_FOUND', message: '订单不存在' } });
  send(res, 200, { ok: true, data: { no: o.no, amount: o.amount, status: o.status, paid_at: o.paidAt || null } });
}

/* 公开：易支付异步回调 */
async function payNotify(req, res, q) {
  const p = PAY();
  const body = req.method === 'POST' ? await readBody(req) : {};
  const d = { ...q, ...body };
  const o = store.s.orders.find((x) => x.no === String(d.out_trade_no || ''));
  if (!o) return send(res, 200, 'fail');
  if (o.status === 'paid') return send(res, 200, 'success');   // 幂等
  if (p.key) {
    const vals = { pid: d.pid, trade_no: d.trade_no, out_trade_no: d.out_trade_no, type: d.type, money: d.money, trade_status: d.trade_status };
    const expect = epaySign(vals);
    if (!core.safeEqual(d.sign || '', expect)) {
      store.addLog('回调验签失败', '订单 ' + o.no, 'system', null);
      store.save();
      return send(res, 200, 'fail');
    }
  }
  const status = String(d.trade_status || '');
  if (status && !['TRADE_SUCCESS', 'SUCCESS', 'TRADE_FINISHED'].includes(status)) return send(res, 200, 'fail');
  const money = Number(d.money || 0);
  if (money && Math.abs(money - Number(o.amount)) > 0.001) {
    store.addLog('回调金额不符', '订单 ' + o.no + ' 应付 ' + o.amount + ' 实付 ' + money, 'system', null);
    store.save();
    return send(res, 200, 'fail');
  }
  creditOrder(o, d.trade_no, 'epay');
  send(res, 200, 'success');
}

function payReturn(req, res, q) {
  send(res, 302, '', { Location: '/pay/' + String(q.no || '') });
}

/* 公开收款页 */
function payPage(req, res, no) {
  const o = store.s.orders.find((x) => x.no === no);
  if (!o) return send(res, 404, '<h3 style="font-family:sans-serif;padding:40px">订单不存在</h3>', { 'Content-Type': 'text/html; charset=utf-8' });
  const p = PAY();
  const acc = store.account(o.accountId);
  const paid = o.status === 'paid';
  const qr = p.qrImage || '';
  const epay = p.provider === 'epay' && p.epayUrl && p.pid && p.key;
  const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>充值 ¥${o.amount} · ${escHtml(S().siteName)}</title>
<style>
body{margin:0;font-family:-apple-system,"PingFang SC",sans-serif;background:#f3f5fa;color:#111827;display:grid;place-items:center;min-height:100dvh;padding:20px}
.box{background:#fff;border-radius:22px;box-shadow:0 18px 50px rgba(17,24,39,.08);padding:24px;max-width:380px;width:100%;text-align:center;border:1px solid #eef2f9}
h1{font-size:16px;color:#6b7488;font-weight:500;margin:0 0 6px}
.amt{font-size:40px;font-weight:800;letter-spacing:-1px;margin:0 0 4px}
.no{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:#98a1b3;word-break:break-all}
.qr{width:200px;height:200px;object-fit:contain;border-radius:14px;border:1px solid #eef2f9;margin:16px auto;display:block;background:#fff}
.btn{display:block;width:100%;padding:14px;border-radius:999px;border:0;background:#2563eb;color:#fff;font-weight:700;font-size:15px;margin-top:14px;text-decoration:none}
.btn.ghost{background:#f2f5fb;color:#4b5563}
.state{margin-top:14px;font-size:13px;color:#b7791f}
.state.ok{color:#0f9d58;font-weight:700}
.tip{font-size:12px;color:#98a1b3;margin-top:12px;line-height:1.6}
</style></head><body>
<div class="box">
  <h1>${escHtml(S().siteName)} · 余额充值</h1>
  <p class="amt">¥${Number(o.amount).toFixed(2)}</p>
  <div class="no">订单号 ${o.no}${acc ? ' · ' + escHtml(acc.user) : ''}</div>
  ${qr ? `<img class="qr" src="${escHtml(qr)}" alt="收款码">` : (epay ? '' : '<p class="tip">主代理还没配置收款码图片，请联系主代理付款。</p>')}
  ${epay ? `<a class="btn" href="${escHtml(epayPayUrl(o, (p.notifyBase || '').replace(/\/+$/, '') || ('http://' + (req.headers.host || '127.0.0.1'))))}">去支付 ¥${Number(o.amount).toFixed(2)}</a>` : ''}
  <div class="state" id="st">${paid ? '✅ 已到账' : '等待支付…'}</div>
  <p class="tip">${paid ? '余额已自动加上，可以关闭本页。' : '付款后本页会自动更新；若长时间未到账，请联系主代理并提供订单号。'}</p>
</div>
<script>
var no=${JSON.stringify(o.no)};
function tick(){fetch('/api/pay/status?no='+encodeURIComponent(no)).then(function(r){return r.json()}).then(function(j){
  if(j.ok&&j.data.status==='paid'){var s=document.getElementById('st');s.className='state ok';s.textContent='✅ 已到账 ¥'+j.data.amount.toFixed(2);}
}).catch(function(){});}
if(!${paid}){setInterval(tick,3000);tick();}
</script>
</body></html>`;
  send(res, 200, html, { 'Content-Type': 'text/html; charset=utf-8' });
}
function escHtml(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

/* ---------------- 路由 ---------------- */

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const p = parsed.pathname;
  const q = parsed.query;
  const ip = core.clientIP(req);

  if (req.method === 'OPTIONS') return send(res, 204, '');

  try {
    /* --- 客户端 --- */
    if (p === '/api/version' && req.method === 'GET') return handleVersion(req, res, q);
    if (p === '/api/activate' && req.method === 'POST') return await handleActivate(req, res);
    if (p === '/api/register' && req.method === 'POST') return await registerAccount(req, res);
    if (p === '/api/heartbeat' && req.method === 'POST') return await handleHeartbeat(req, res);
    if (p === '/api/plugin' && req.method === 'GET') return handlePlugin(req, res, q);
    if (p === '/api/plugin/file' && req.method === 'GET') return handlePluginFile(req, res, q);
    if (p === '/api/site' && req.method === 'GET') {
      // 公开：客户端启动时拉取展示配置（不含任何密钥）
      const s = S(), site = s.site || {};
      const appCfg = (q.appKey && (s.apps || []).find((a) => a.appKey === q.appKey)) || null;
      const pop = (appCfg && appCfg.popup) || {};
      return ok(res, { data: {
        siteName: s.siteName || '卡密验证',
        title: pop.title || site.title || s.siteName || '卡密验证',
        subtitle: pop.subtitle || site.subtitle || '',
        notice: pop.notice || site.notice || s.notice || '',
        contact: pop.contact || site.contact || '',
        cover: pop.cover || site.cover || '',
        logo: pop.logo || site.logo || '',
        adImage: pop.adImage || site.adImage || '',
        adLink: pop.adLink || site.adLink || '',
        template: pop.template || 'dark',
        buttons: (pop.buttons || []).filter((x) => x.enabled !== false),
        version: pop.version || null,
        accent: s.accent || '#2a5bff',
        hb_interval: S().hbInterval || 30,
        show_unbind: pop.showUnbind === undefined ? true : !!pop.showUnbind,
        verify_timeout: Number(pop.verifyTimeout || 60),
        proxy_check: !!pop.proxyCheck,
      }});
    }

    if (p === '/api/deactivate' && req.method === 'POST') return await handleDeactivate(req, res);

    /* --- 管理端 --- */
    if (p.startsWith('/api/admin/')) {
      if (!adminLimit.hit(ip).ok) return fail(res, 'RATE_LIMIT', '请求过于频繁', 429);

      if (p === '/api/admin/login' && req.method === 'POST') return await adminLogin(req, res);

      const admin = requireAdmin(req, res);
      if (!admin) return;

      if (p === '/api/admin/me' && req.method === 'GET')
        return ok(res, { data: { user: admin.user, role: admin.role, balance: admin.balance, site: S().siteName, agent: S().agentId, agent_expire: S().agentExpire } });
      if (p === '/api/admin/overview' && req.method === 'GET') return adminOverview(req, res, admin);
      if (p === '/api/admin/apps' && req.method === 'GET') return adminApps(req, res);
      if (p === '/api/admin/plugin' && req.method === 'POST') return await adminPluginSave(req, res, admin);
      if (p === '/api/admin/plugin' && req.method === 'GET') return adminPluginGet(req, res, q, admin);
      if (p === '/api/admin/apps' && req.method === 'POST') { if (!guardOwner(admin, res)) return; return await adminAppCreate(req, res, admin); }

      let m = p.match(/^\/api\/admin\/apps\/(\d+)(\/secret)?$/);
      if (m) {
        const app = store.findApp(m[1]);
        if (!app) return fail(res, 'APP_NOT_FOUND', '应用不存在', 404);
        if (m[2] && req.method === 'GET')
          return ok(res, { data: { appKey: app.appKey, appSecret: app.appSecret } });
        if (req.method === 'POST' || req.method === 'PUT') { if (!guardOwner(admin, res)) return; return await adminAppUpdate(req, res, admin, m[1]); }
      }

      if (p === '/api/admin/keys' && req.method === 'GET') return adminKeys(req, res, q, admin);
      if (p === '/api/admin/keys' && req.method === 'POST') return await adminKeyGenerate(req, res, admin);
      if (p === '/api/admin/keys/import' && req.method === 'POST') return await adminKeyImport(req, res, admin);
      if (p === '/api/admin/keys/batch' && req.method === 'POST') return await adminKeyBatch(req, res, admin);
      if (p === '/api/admin/logs' && req.method === 'GET') return adminLogs(req, res, q, admin);
      if (p === '/api/admin/captures' && req.method === 'GET') return adminCaptures(req, res, q, admin);
      if (p === '/api/admin/sessions' && req.method === 'GET') return adminSessions(req, res, admin);
      if (p === '/api/admin/settings' && req.method === 'POST') { if (!guardOwner(admin, res)) return; return await adminSettings(req, res, admin); }
      if (p === '/api/admin/settings' && req.method === 'GET') {
        if (!isOwner(admin)) return fail(res, 'FORBIDDEN', '只有主代理可以查看站点设置', 403);
        // 不下发 masterSecret / 口令哈希
        const { masterSecret, admin: _admin, ...safe } = S();
        if (!isOwner(admin) && safe.pay) safe.pay = { ...safe.pay, key: '', pid: '' };
        return ok(res, { data: safe });
      }
      if (p === '/api/admin/recharge/order' && req.method === 'POST') return await createRechargeOrder(req, res, admin);
      if (p === '/api/admin/orders' && req.method === 'GET') return listOrders(req, res, admin, q);
      let om = p.match(/^\/api\/admin\/orders\/([A-Za-z0-9]+)(\/paid)?$/);
      if (om) {
        if (om[2]) { if (req.method !== 'POST') return fail(res, 'METHOD', '只支持 POST', 405); return await markOrderPaid(req, res, admin, om[1]); }
        return getOrder(req, res, admin, om[1]);
      }
      if (p === '/api/admin/recharge' && req.method === 'GET') return adminRechargeList(req, res, admin);
      if (p === '/api/admin/recharge' && req.method === 'POST') return await adminRechargeRequest(req, res, admin);
      if (p === '/api/admin/recharge/self' && req.method === 'POST') return await adminRechargeSelf(req, res, admin);
      let rm = p.match(/^\/api\/admin\/recharge\/(\d+)$/);
      if (rm && req.method === 'POST') return await adminRechargeHandle(req, res, admin, rm[1]);
      if (p === '/api/admin/accounts' && req.method === 'GET') return adminAccounts(req, res, admin);
      if (p === '/api/admin/accounts' && req.method === 'POST') return await adminAccountCreate(req, res, admin);
      let am = p.match(/^\/api\/admin\/accounts\/(\d+)(\/balance)?$/);
      if (am) {
        if (req.method !== 'POST') return fail(res, 'METHOD', '只支持 POST', 405);
        if (!isOwner(admin)) return fail(res, 'FORBIDDEN', '只有主代理可以管理代理', 403);
        if (am[2]) return await adminAccountBalance(req, res, admin, am[1]);
        return await adminAccountUpdate(req, res, admin, am[1]);
      }
      if (p === '/api/admin/password' && req.method === 'POST') return await adminPassword(req, res, admin);

      return fail(res, 'NOT_FOUND', '接口不存在', 404);
    }

    if (p === '/api/pay/status' && req.method === 'GET') return publicOrderStatus(req, res, q);
    if (p === '/api/pay/notify') return await payNotify(req, res, q);
    if (p === '/api/pay/return' && req.method === 'GET') return payReturn(req, res, q);
    let pm = p.match(/^\/pay\/([A-Za-z0-9]+)$/);
    if (pm && req.method === 'GET') return payPage(req, res, pm[1]);

    if (p.startsWith('/api/')) return fail(res, 'NOT_FOUND', '接口不存在', 404);

    /* --- 静态 --- */
    if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res, p);
    return send(res, 405, 'method not allowed');
  } catch (e) {
    if (e.code === 'BAD_JSON') return fail(res, 'BAD_JSON', '请求体不是合法 JSON', 400);
    if (e.code === 'TOO_LARGE') return fail(res, 'TOO_LARGE', '请求体过大', 413);
    console.error('[error]', p, e);
    return fail(res, 'INTERNAL', '服务端异常', 500);
  }
});

server.keepAliveTimeout = 65_000;
server.requestTimeout = 30_000;

server.listen(PORT, HOST, () => {
  console.log(`[km-verify] http://${HOST}:${PORT}`);
  console.log(`[km-verify] 管理面板 http://127.0.0.1:${PORT}/  默认 admin / admin888`);
  console.log(`[km-verify] 应用数 ${store.s.apps.length} · 卡密 ${store.s.keys.length}`);
});

function shutdown(sig) {
  console.log(`\n[km-verify] ${sig} 收到，落盘退出`);
  clearTimeout(store._timer);
  store.saveNow();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 1500).unref();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

module.exports = { server, store };
