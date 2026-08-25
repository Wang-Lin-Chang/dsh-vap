// tests/security-s6-tls.test.mjs —— S6 中继 TLS 回归测试（生产级加固批次）
//
// 运行：node --test tests/security-s6-tls.test.mjs（需系统 openssl；无 openssl 则跳过）
// 覆盖：① TLS 中继 + 带 CA 的客户端正常注册转发
//       ② 明文客户端连 TLS 端口 → 注册不生效（transport 层被拒）
//       ③ 错误 CA 客户端 → 握手失败（不建立注册）
//
// 零第三方依赖：node: 内置 + 系统 openssl（生成临时证书）。

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { createRelayServer, encodeFrame } from '../phase4/relay-server.mjs';
import { createRelayClient } from '../phase4/relay-client.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

function opensslAvailable() {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function genCerts(dir) {
  execFileSync('bash', [path.join(HERE, '..', 'bin', 'vap-gencert.sh'), dir, 'localhost'], { stdio: 'ignore' });
  return {
    ca: fs.readFileSync(path.join(dir, 'vap-ca.pem')),
    cert: fs.readFileSync(path.join(dir, 'vap-server.crt')),
    key: fs.readFileSync(path.join(dir, 'vap-server.key')),
  };
}

const waitFor = (cond, timeoutMs = 3000) => new Promise((resolve) => {
  const start = Date.now();
  (function tick() {
    if (cond()) return resolve(true);
    if (Date.now() - start >= timeoutMs) return resolve(cond());
    setTimeout(tick, 20);
  })();
});

test('S6: TLS 中继——带 CA 客户端注册转发正常', { skip: !opensslAvailable() }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-s6-'));
  const certs = genCerts(dir);
  const server = createRelayServer({ port: 0, tlsOptions: { cert: certs.cert, key: certs.key } });
  const port = await server.start();
  const clientA = createRelayClient({ host: '127.0.0.1', port, nodeId: 'A', pubKey: 'pk-a', tlsOptions: { ca: certs.ca } });
  const clientB = createRelayClient({ host: '127.0.0.1', port, nodeId: 'B', pubKey: 'pk-b', tlsOptions: { ca: certs.ca } });
  const received = [];
  try {
    clientA.connect();
    clientB.connect();
    await waitFor(() => server.stats().connections === 2);
    clientB.onEnvelope((env) => received.push(env));
    clientA.send('B', { id: 'evt-s6' });
    await waitFor(() => received.length > 0);
    assert.equal(received[0].id, 'evt-s6', 'TLS 中继正常转发');
    assert.equal(server.stats().forwarded, 1);
  } finally {
    clientA.close();
    clientB.close();
    await server.stop();
  }
});

test('S6: 明文客户端连 TLS 端口——注册不生效', { skip: !opensslAvailable() }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-s6b-'));
  const certs = genCerts(dir);
  const server = createRelayServer({ port: 0, tlsOptions: { cert: certs.cert, key: certs.key } });
  const port = await server.start();
  try {
    // 明文 socket 发注册帧：TLS 握手失败，服务器侧注册表必须为空。
    const sock = net.connect(port, '127.0.0.1');
    await new Promise((r) => sock.on('connect', r));
    sock.write(encodeFrame({ type: 'register', nodeId: 'plain', pubKey: 'pk' }));
    await new Promise((r) => setTimeout(r, 800));
    assert.equal(server.stats().connections, 0, '明文注册不得进表');
    assert.equal(server.stats().registered, 0);
    sock.destroy();
  } finally {
    await server.stop();
  }
});

test('S6: 错误 CA 客户端——握手失败不建立注册', { skip: !opensslAvailable() }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vap-s6c-'));
  const certs = genCerts(dir);
  const server = createRelayServer({ port: 0, tlsOptions: { cert: certs.cert, key: certs.key } });
  const port = await server.start();
  const badClient = createRelayClient({ host: '127.0.0.1', port, nodeId: 'evil', pubKey: 'pk-evil', tlsOptions: { ca: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n' } });
  try {
    badClient.connect();
    await new Promise((r) => setTimeout(r, 1200));
    assert.equal(server.stats().connections, 0, '错误 CA 不得完成注册');
  } finally {
    badClient.close();
    await server.stop();
  }
});
