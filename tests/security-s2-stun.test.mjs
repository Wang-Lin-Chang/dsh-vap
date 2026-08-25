// tests/security-s2-stun.test.mjs —— S2 STUN 反射防护回归测试（生产级加固批次）
//
// 运行：node --test tests/security-s2-stun.test.mjs
// 覆盖：① 带合法 FINGERPRINT 请求 → 响应且响应指纹校验通过
//       ② 裸请求限速桶（容量 16）：突发 20 个最多 16 个得到响应（防伪造源反射放大）
//       ③ 坏指纹请求 → 静默丢弃
//       ④ createHolePuncher.discover 端到端（客户端已带指纹）→ 拿到映射
//
// 零第三方依赖：node: 内置 + 仓库相对 import。

import test from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { appendFingerprint, verifyFingerprint } from '../phase7/stun-fingerprint.mjs';
import { createHolePuncher } from '../phase7/hole-punch.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

// 杀掉服务器并释放 stdio 管道——否则挂起的子进程 stdout 会拖住 node --test 进程退出
function killServer(child) {
  try { child.kill(); } catch {}
  try { child.stdout.destroy(); } catch {}
  try { child.stderr.destroy(); } catch {}
}

function startStunServer() {
  return new Promise((resolve, reject) => {
    // 用相对路径 + cwd 启动（Windows 下 spawn 中文绝对路径参数有编码风险），stdio 用管道抓启动行
    const child = spawn(process.execPath, ['phase7/stun-server.mjs', '0', '127.0.0.1'], {
      cwd: path.join(HERE, '..'),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    const to = setTimeout(() => {
      killServer(child);
      reject(new Error('STUN server 启动超时'));
    }, 5000);
    child.stdout.on('data', (d) => {
      out += d.toString();
      const m = out.match(/STUN-UP host=127\.0\.0\.1 port=(\d+)/);
      if (m) {
        clearTimeout(to);
        resolve({ child, port: Number(m[1]) });
      }
    });
    child.on('error', (e) => {
      clearTimeout(to);
      reject(e);
    });
  });
}

function udpRequest(port, payload, timeoutMs = 1000) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket('udp4');
    const got = [];
    sock.on('message', (m) => got.push(m));
    sock.bind(0, '127.0.0.1', () => {
      sock.send(payload, port, '127.0.0.1');
      setTimeout(() => { sock.close(); resolve(got); }, timeoutMs);
    });
  });
}

function bareBindingRequest() {
  const txId = crypto.randomBytes(12);
  const req = Buffer.alloc(20);
  req.writeUInt16BE(0x0001, 0);
  req.writeUInt16BE(0, 2);
  Buffer.from([0x21, 0x12, 0xa4, 0x42]).copy(req, 4);
  txId.copy(req, 8);
  return req;
}

test('S2: 带合法 FINGERPRINT 的请求得到响应且响应指纹校验通过', async () => {
  const { child, port } = await startStunServer();
  try {
    const req = appendFingerprint(bareBindingRequest());
    const got = await udpRequest(port, req);
    assert.equal(got.length, 1, '应收到一个响应');
    assert.equal(got[0].readUInt16BE(0), 0x0101, 'Binding Success');
    assert.equal(verifyFingerprint(got[0]), true, '响应 FINGERPRINT 必须校验通过');
  } finally { killServer(child); }
});

test('S2: 裸请求限速桶——突发 20 个裸请求，响应数不超过桶容量 16', async () => {
  const { child, port } = await startStunServer();
  try {
    // 同一源（本机）快速发 20 个裸请求，统计收到响应的数量
    const sock = dgram.createSocket('udp4');
    let responses = 0;
    sock.on('message', () => { responses += 1; });
    await new Promise((r) => sock.bind(0, '127.0.0.1', r));
    for (let i = 0; i < 20; i += 1) sock.send(bareBindingRequest(), port, '127.0.0.1');
    await new Promise((r) => setTimeout(r, 1500));
    sock.close();
    assert.ok(responses <= 16, `裸请求响应数 ${responses} 必须不超过桶容量 16`);
    assert.ok(responses >= 1, '至少第一个请求应被响应');
  } finally { killServer(child); }
});

test('S2: 坏 FINGERPRINT 请求被静默丢弃', async () => {
  const { child, port } = await startStunServer();
  try {
    const req = appendFingerprint(bareBindingRequest());
    req[req.length - 1] ^= 0xFF; // 破坏指纹最后字节
    const got = await udpRequest(port, req);
    assert.equal(got.length, 0, '坏指纹请求不得得到响应');
  } finally { killServer(child); }
});

test('S2: createHolePuncher.discover 端到端（客户端带指纹）拿到映射', async () => {
  const { child, port } = await startStunServer();
  try {
    const p = createHolePuncher({ localPort: 0, stunHost: '127.0.0.1', stunPort: port, nodeId: 'T' });
    await p.bind();
    const mapping = await p.discover();
    assert.ok(mapping && mapping.ip && typeof mapping.port === 'number', 'discover 应拿到映射');
    p.close();
  } finally { killServer(child); }
});

test('S2: 畸形头长度字段被丢弃（fuzz 实证的反射放大面收口）', async () => {
  const { child, port } = await startStunServer();
  try {
    const sock = dgram.createSocket('udp4');
    let responses = 0;
    sock.on('message', () => { responses += 1; });
    await new Promise((r) => sock.bind(0, '127.0.0.1', r));
    // 声明长度与实际不符：28B 实长但声明 0 / 20B 实长但声明 8 / 声明 0xFFFF
    const cases = [
      { declared: 0, base: appendFingerprint(bareBindingRequest()) },
      { declared: 8, base: bareBindingRequest() },
      { declared: 0xFFFF, base: bareBindingRequest() },
    ];
    for (const c of cases) {
      const req = Buffer.from(c.base);
      req.writeUInt16BE(c.declared, 2);
      sock.send(req, port, '127.0.0.1');
    }
    await new Promise((r) => setTimeout(r, 1000));
    sock.close();
    assert.equal(responses, 0, '畸形长度请求一律不得被响应');
  } finally { killServer(child); }
});
