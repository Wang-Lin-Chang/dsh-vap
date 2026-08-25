// phase4/relay-client.mjs —— VAP Phase 4 中继客户端（零第三方依赖，node:net）
//
// 连接中继、注册、收发信封、断线指数退避重连（1s→2s→4s…上限 30s）。
//   行协议：4 字节大端长度前缀 + JSON 正文（与 relay-server.mjs 一致）。
//
//   createRelayClient({ host, port, nodeId, pubKey })
//     → { connect(), send(to, envelope), onEnvelope(cb), close(), connected(),
//         onStatus(cb), ready, stats() }
//
// 复用 ../vap-core.mjs 的三闸在接收方（实验装置内调用 verify），
// 本模块只「搬运与收发」，不复制信封构造/验签/军法/诚实边界等任何判定逻辑。

import net from 'node:net';
import tls from 'node:tls';

import { encodeFrame, createFrameDecoder } from './relay-server.mjs';

export const BACKOFF_BASE_MS = 1000;  // 首次退避 1s
export const BACKOFF_MAX_MS = 30000;  // 退避上限 30s

// 指数退避：attempt 0→1s, 1→2s, 2→4s, 3→8s, 4→16s, ≥5→上限 30s。
export function backoffDelayMs(attempt) {
  const n = Math.max(0, Math.floor(attempt));
  return Math.min(BACKOFF_BASE_MS * (2 ** Math.min(n, 20)), BACKOFF_MAX_MS);
}

export function createRelayClient({
  host = '127.0.0.1',
  port,
  nodeId,
  pubKey,
  tlsOptions = null, // S6：{ ca }（自签 CA PEM 路径/内容）——设置则走 TLS 并校验服务器证书
} = {}) {
  if (!nodeId) throw new Error('createRelayClient: nodeId is required');
  if (!Number.isInteger(port)) throw new Error('createRelayClient: port is required');
  const pub = typeof pubKey === 'string' ? pubKey : '';

  let socket = null;
  let reconnectTimer = null;
  let reconnectAttempt = 0;
  let closed = false;
  let everConnected = false;
  let lastStatus = { type: 'idle' };

  const envelopeListeners = new Set();
  const statusListeners = new Set();

  let resolveReady;
  const ready = new Promise((resolve) => { resolveReady = resolve; });

  function emitStatus(status) {
    lastStatus = status;
    for (const cb of statusListeners) {
      try { cb(status); } catch { /* 回调异常不阻断客户端 */ }
    }
  }

  function isConnected() {
    return !!socket && !socket.destroyed && socket.readyState === 'open';
  }

  function scheduleReconnect() {
    if (closed || reconnectTimer) return;
    const delayMs = backoffDelayMs(reconnectAttempt);
    reconnectAttempt += 1;
    emitStatus({ type: 'reconnecting', delayMs, attempt: reconnectAttempt });
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      if (closed) return;
      connectInternal();
    }, delayMs);
  }

  function connectInternal() {
    if (closed) return;
    // S6：tlsOptions 提供 ca 时走 TLS（校验服务器证书）；否则明文 TCP。
    const sock = tlsOptions
      ? tls.connect({ host, port, ...tlsOptions })
      : net.createConnection({ host, port });
    const decoder = createFrameDecoder({
      onFrame: (msg) => {
        if (msg && msg.type === 'relay') {
          for (const cb of envelopeListeners) {
            try { cb(msg.envelope, { from: msg.from, to: msg.to }); } catch { /* 尽力 */ }
          }
        }
      },
      onError: () => {
        try { sock.destroy(); } catch { /* 尽力 */ }
      },
    });

    sock.on('data', (chunk) => decoder.push(chunk));
    sock.on('error', () => { /* 连接失败/传输错误：close 后走退避重连 */ });
    sock.on('connect', () => {
      // 上线即注册：{ type:'register', nodeId, pubKey }
      sock.write(encodeFrame({ type: 'register', nodeId, pubKey: pub }));
      reconnectAttempt = 0; // 重连成功后重置退避
      everConnected = true;
      emitStatus({ type: 'connected' });
      resolveReady();
    });
    sock.on('close', () => {
      if (socket === sock) socket = null;
      if (closed) return;
      emitStatus({ type: 'disconnected' });
      scheduleReconnect();
    });

    socket = sock;
  }

  const client = {
    connect() {
      if (closed) throw new Error('createRelayClient: client is closed');
      if (socket && !socket.destroyed) return client; // 已连接/连接中
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      connectInternal();
      return client;
    },

    // 发送信封到 nodeId=to；返回是否已写入 socket（false = 未连接，消息丢弃）。
    send(to, envelope) {
      if (typeof to !== 'string' || to.length === 0) throw new Error('send: to is required');
      if (!envelope || typeof envelope !== 'object') throw new Error('send: envelope is required');
      if (!isConnected()) return false;
      try {
        // from=nodeId：让中继能识别发件方（日志/度量），并让接收方 onEnvelope 的 meta.from 正确。
        socket.write(encodeFrame({ type: 'relay', from: nodeId, to, envelope }));
        return true;
      } catch {
        return false;
      }
    },

    onEnvelope(cb) {
      if (typeof cb === 'function') envelopeListeners.add(cb);
      return client;
    },

    onStatus(cb) {
      if (typeof cb === 'function') statusListeners.add(cb);
      return client;
    },

    close() {
      closed = true;
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      if (socket) {
        try { socket.destroy(); } catch { /* 尽力 */ }
        socket = null;
      }
      emitStatus({ type: 'closed' });
      return client;
    },

    connected() {
      return isConnected();
    },

    stats() {
      return {
        nodeId,
        connected: isConnected(),
        everConnected,
        reconnectAttempt,
        lastStatus,
      };
    },

    ready,
  };

  return client;
}
