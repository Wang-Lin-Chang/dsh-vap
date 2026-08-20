// phase1/transport-spi.mjs —— VAP Phase 1 传输 SPI（零第三方依赖）
//
// 把传输抽象为统一形状：name / capabilities / send / recv / peers / close。
// 本模块只「包装与复用」 ../vap-transport.mjs 的既有 FileTransport / HttpGateway /
// HttpClient，不复制其信封构造、验签、验证门、防重放、防环等任何逻辑：
//   - createFileTransport  包装 FileTransport → SPI 形状（现 v0 行为不变）；
//   - createHttpTransport  包装 HttpGateway（服务器）+ HttpClient（拨号客户端）→ SPI 形状；
//   - transportConformance  对任意实现做 SPI 一致性诊断（缺能力 / 缺方法清单）。
// 契约依据：同目录 brief.md / DESIGN.md、项目根 vap-spec.md。
//
// 身份绑定（DESIGN §二 / IDENTITY.md）：传输层密钥只是握手密钥，协议身份永远 = 信封
// from.pubKey 的 VAP Ed25519 密钥。本模块不裁决身份（裁决在 vap-core 验证门三道闸内），
// 只负责搬运；任何「协议身份 ≠ 信封签名者」的消息由验证门必拒（由测试与实验钉死）。

import fs from 'node:fs';
import path from 'node:path';

import {
  createFileTransport as createFileTransportImpl,
  createHttpGateway as createHttpGatewayImpl,
  createHttpClient as createHttpClientImpl,
} from '../vap-transport.mjs';

// SPI 能力位全集（dial = 可拨号连接对端；send/recv/peers 分别对应方法）。
const KNOWN_CAPABILITIES = ['dial', 'send', 'recv', 'peers'];
// SPI 必含的方法形状。
const REQUIRED_METHODS = ['send', 'recv', 'peers', 'close'];

// 入站拉取的传输层文件 IO：HttpGateway 的 POST 已把校验通过的信封原子写入
// root/inbox-http/evt-<id>.json，这里只按序读出（等价 FileTransport.read 的读目录行为），
// 不涉及任何信封判定或验证门逻辑。
function readInboxHttp(root) {
  const dir = path.join(root, 'inbox-http');
  const envelopes = [];
  let names;
  try {
    names = fs.readdirSync(dir);
  } catch {
    return envelopes;
  }
  for (const name of names.sort()) {
    if (!/^evt-.*\.json$/.test(name)) continue;
    try {
      const envelope = JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
      if (envelope) envelopes.push(envelope);
    } catch {
      // 读不出来的信封跳过（传输层尽力，不裁决）。
    }
  }
  return envelopes;
}

// ---------------------------------------------------------------------------
// createFileTransport —— 包装 FileTransport 为 SPI 形状
//
//   send(envelope)   写 outbox/evt-<id>.json（复用 FileTransport.send，行为零变化）；
//   recv({ after })  读未投递信封（复用 FileTransport.read，支持游标）；
//   peers()          文件传输无已知对端 → 恒空数组；
//   close()          无句柄可释放 → no-op。
// ---------------------------------------------------------------------------

export function createFileTransport({ root } = {}) {
  if (!root) throw new Error('createFileTransport: root is required');
  const file = createFileTransportImpl({ root });

  return {
    name: 'file',
    capabilities: ['send', 'recv'],
    send(envelope) {
      return file.send(envelope);
    },
    recv(options) {
      return file.read(options);
    },
    peers() {
      return [];
    },
    close() {
      // 文件传输无网络句柄，无资源需要释放。
    },
    fileTransport: file,
    root,
  };
}

// ---------------------------------------------------------------------------
// createHttpTransport —— 包装 HttpGateway + HttpClient 为 SPI 形状
//
//   start()            启动本地网关（返回实际端口；port=0 自动分配）；
//   send(envelope)     拨号出站：POST /envelopes 到 baseUrl（复用 HttpClient.post，
//                      返回 { status, ok, envelopeId?, error? }，202/409/400 语义不变）；
//   recv()             入站拉取：读 root/inbox-http 已落盘信封；
//   peers()            已知对端（创建时传入的 peers 列表快照）；
//   health()           透传网关健康计数（复用 HttpGateway.health）；
//   close()            停网关（复用 HttpGateway.stop）。
//
// 网关/客户端内部逻辑一行不改，HttpTransport 只是壳。
// ---------------------------------------------------------------------------

export function createHttpTransport({
  port = 0,
  host = '127.0.0.1',
  root,
  peers = [],
  baseUrl,
  laws,
  strictEnvelopeId = true,
  requireInboundSignature = true,
} = {}) {
  if (!root) throw new Error('createHttpTransport: root is required');
  const peersList = (Array.isArray(peers) ? peers : [])
    .filter((u) => typeof u === 'string' && u.length > 0);
  // F2/M1/M7：host 与入站白名单/验签策略原样透传给网关（本壳不自作裁决）。
  const gateway = createHttpGatewayImpl({
    port,
    host,
    root,
    peers: peersList,
    laws,
    strictEnvelopeId,
    requireInboundSignature,
  });
  const client = baseUrl ? createHttpClientImpl({ baseUrl }) : null;

  return {
    name: 'http',
    capabilities: ['dial', 'send', 'recv', 'peers'],
    async start() {
      return gateway.start();
    },
    async send(envelope) {
      if (!client) {
        throw new Error('createHttpTransport.send: baseUrl is required to dial a peer');
      }
      return client.post(envelope);
    },
    recv() {
      return readInboxHttp(root);
    },
    peers() {
      return peersList.slice();
    },
    health() {
      return gateway.health();
    },
    async close() {
      await gateway.stop();
    },
    gateway,
    client,
    get port() {
      return gateway.port;
    },
    host,
    get baseUrl() {
      return gateway.baseUrl;
    },
    root,
  };
}

// ---------------------------------------------------------------------------
// transportConformance —— SPI 一致性检查
//
// 检查必需形状：name（非空字符串）、capabilities（数组、位合法）、
// send/recv/peers/close（函数）。返回 { ok, missing, diagnostics }：
//   - missing      缺的字段/方法名；
//   - diagnostics  逐条诊断（含未知能力位、声明能力却缺方法等）。
// ok = missing 为空（未知能力位计入 diagnostics 但需单独看）。
// ---------------------------------------------------------------------------

export function transportConformance(t) {
  const diagnostics = [];
  const missing = [];

  if (!t || typeof t !== 'object' || Array.isArray(t)) {
    return {
      ok: false,
      missing: ['transport'],
      diagnostics: ['transport must be a plain object'],
    };
  }

  if (typeof t.name !== 'string' || t.name.length === 0) {
    missing.push('name');
    diagnostics.push("missing 'name' (non-empty string)");
  }

  if (!Array.isArray(t.capabilities)) {
    missing.push('capabilities');
    diagnostics.push("missing 'capabilities' (array)");
  } else {
    for (const cap of t.capabilities) {
      if (!KNOWN_CAPABILITIES.includes(cap)) {
        diagnostics.push(`unknown capability '${cap}' (expected one of ${KNOWN_CAPABILITIES.join(', ')})`);
      }
    }
  }

  for (const method of REQUIRED_METHODS) {
    if (typeof t[method] !== 'function') {
      missing.push(method);
      diagnostics.push(`missing method '${method}()'`);
    }
  }

  // 已声明能力却没有对应方法：额外诊断。
  if (Array.isArray(t.capabilities)) {
    const capMethod = { send: 'send', recv: 'recv', peers: 'peers' };
    for (const [cap, method] of Object.entries(capMethod)) {
      if (t.capabilities.includes(cap) && typeof t[method] !== 'function' && !missing.includes(method)) {
        missing.push(method);
        diagnostics.push(`capability '${cap}' declared but method '${method}()' is missing`);
      }
    }
  }

  return {
    ok: missing.length === 0,
    missing,
    diagnostics,
  };
}
