// tests/console-adapter.test.mjs —— 控制台乱码消弭适配器回归测试
//
// 覆盖（对照 enc-brief.md 交付物）：
//   ① detectConsoleLang 裁决表全覆盖（65001→zh、936→zh+自愈标记、54936→zh、
//     437→en、850→en、VAP_LANG 覆盖、非 TTY 短路、chcp 失败→en）；
//   ② parseCodePage 对 "Active code page: 936" / "活动代码页: 65001" /
//     乱码标签+数字 三种输入正确取数；
//   ③ createT 缺 key 抛错；
//   ④ 四个 bin 的字典 zh/en key 集合对等（同 key 两边都有非空值）。
//
// 零第三方依赖：仅 node: 内置模块 + 本仓库相对 import。

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  parseCodePage,
  detectConsoleLang,
  createT,
  DICT,
} from '../console-adapter.mjs';

// ---------------------------------------------------------------------------
// ② parseCodePage：行尾 ASCII 数字解析（忽略可能本地化/乱码的标签文本）
// ---------------------------------------------------------------------------

test('parseCodePage：Active code page: 936 → 936', () => {
  assert.equal(parseCodePage('Active code page: 936'), 936);
  assert.equal(parseCodePage('Active code page: 936\r\n'), 936);
});

test('parseCodePage：活动代码页: 65001 → 65001', () => {
  assert.equal(parseCodePage('活动代码页: 65001'), 65001);
  assert.equal(parseCodePage('活动代码页: 65001\r\n'), 65001);
});

test('parseCodePage：乱码标签 + 行尾数字 → 数字', () => {
  // 模拟 GBK 字节被当 UTF-8 解出的乱码标签（数字是纯 ASCII，必然存活）。
  assert.equal(parseCodePage('锟斤拷: 936'), 936);
  assert.equal(parseCodePage('\uFFFD\uFFFD: 437'), 437);
});

test('parseCodePage：无数字 / 空串 → null', () => {
  assert.equal(parseCodePage('no digits here'), null);
  assert.equal(parseCodePage(''), null);
  assert.equal(parseCodePage(null), null);
});

// ---------------------------------------------------------------------------
// ① detectConsoleLang 裁决表
// ---------------------------------------------------------------------------

function detect({ isTTY = true, platform = 'win32', env = {}, execChcp = () => 'Active code page: 437' } = {}) {
  return detectConsoleLang({ isTTY, platform, env, execChcp });
}

test('detectConsoleLang：65001 → zh', () => {
  const r = detect({ execChcp: () => 'Active code page: 65001' });
  assert.deepEqual(r, { lang: 'zh', reason: 'utf8' });
});

test('detectConsoleLang：936 → zh 且带自愈标记', () => {
  const r = detect({ execChcp: () => 'Active code page: 936' });
  assert.equal(r.lang, 'zh');
  assert.equal(r.reason, 'chcp-936');
});

test('detectConsoleLang：54936 → zh 且带自愈标记', () => {
  const r = detect({ execChcp: () => 'Active code page: 54936' });
  assert.equal(r.lang, 'zh');
  assert.equal(r.reason, 'chcp-54936');
});

test('detectConsoleLang：437 / 850 非 CJK → en', () => {
  assert.deepEqual(detect({ execChcp: () => 'Active code page: 437' }), { lang: 'en', reason: 'chcp-437' });
  assert.deepEqual(detect({ execChcp: () => 'Active code page: 850' }), { lang: 'en', reason: 'chcp-850' });
});

test('detectConsoleLang：VAP_LANG=zh 逃生舱胜过任何码页', () => {
  const r = detect({ env: { VAP_LANG: 'zh' }, execChcp: () => 'Active code page: 437' });
  assert.deepEqual(r, { lang: 'zh', reason: 'VAP_LANG=zh' });
});

test('detectConsoleLang：VAP_LANG=en 逃生舱胜过 65001', () => {
  const r = detect({ env: { VAP_LANG: 'en' }, execChcp: () => 'Active code page: 65001' });
  assert.deepEqual(r, { lang: 'en', reason: 'VAP_LANG=en' });
});

test('detectConsoleLang：非 TTY 短路 → zh 且不跑 chcp', () => {
  let called = false;
  const r = detect({ isTTY: false, execChcp: () => { called = true; return 'Active code page: 437'; } });
  assert.deepEqual(r, { lang: 'zh', reason: 'non-tty' });
  assert.equal(called, false, '非 TTY 必须短路，不调用 execChcp');
});

test('detectConsoleLang：非 win32 TTY → zh', () => {
  const r = detect({ platform: 'darwin', execChcp: () => { throw new Error('must not call'); } });
  assert.deepEqual(r, { lang: 'zh', reason: 'non-win32' });
});

test('detectConsoleLang：chcp 抛错 → en', () => {
  const r = detect({ execChcp: () => { throw new Error('boom'); } });
  assert.deepEqual(r, { lang: 'en', reason: 'chcp-failed' });
});

test('detectConsoleLang：chcp 输出无法解析 → en', () => {
  const r = detect({ execChcp: () => 'no code page in this output' });
  assert.deepEqual(r, { lang: 'en', reason: 'chcp-failed' });
});

// ---------------------------------------------------------------------------
// ③ createT 缺 key 抛错 + 取值/插值
// ---------------------------------------------------------------------------

test('createT：缺 key 抛错', () => {
  const t = createT(DICT, 'zh');
  assert.throws(() => t('no.such.key'), /missing i18n key/);
});

test('createT：缺当前语言的值也抛错（强制 zh/en 对等）', () => {
  const bad = { 'x.onlyZh': { zh: '中文' } };
  const t = createT(bad, 'en');
  assert.throws(() => t('x.onlyZh'), /missing i18n value/);
});

test('createT：zh/en 取值与 {var} 插值', () => {
  const zh = createT(DICT, 'zh');
  const en = createT(DICT, 'en');
  assert.equal(zh('pg.usage'), '用法 / Usage');
  assert.equal(en('pg.usage'), 'Usage');
  assert.equal(zh('gw.listening', { host: '127.0.0.1', port: 3081 }), '✓ vap-gateway listening http=127.0.0.1:3081');
  assert.equal(en('gw.listening', { host: '127.0.0.1', port: 3081 }), 'vap-gateway listening http=127.0.0.1:3081');
  assert.equal(zh('send.summaryTooLong', { count: 101, bound: 100 }), '--summary 有 101 字，超过验证门上限 100 字（军法 SUMMARY_BOUND 会 reject），请精简');
});

// ---------------------------------------------------------------------------
// ④ 四 bin 字典 zh/en key 集合对等
// ---------------------------------------------------------------------------

test('四 bin + process-guard 字典：同 key 两边都有非空值（zh/en 对等）', () => {
  assert.ok(DICT && typeof DICT === 'object', 'DICT 已导出');
  const keys = Object.keys(DICT);
  assert.ok(keys.length > 0, 'DICT 非空');

  for (const ns of ['pg', 'gw', 'relay', 'node', 'send']) {
    const nsKeys = keys.filter((k) => k.startsWith(`${ns}.`));
    assert.ok(nsKeys.length > 0, `命名空间 ${ns}.* 至少有一个 key`);
  }

  for (const [key, entry] of Object.entries(DICT)) {
    assert.ok(entry && typeof entry === 'object', `key ${key} 是 { zh, en } 对象`);
    assert.ok(typeof entry.zh === 'string' && entry.zh.length > 0, `key ${key} 的 zh 非空`);
    assert.ok(typeof entry.en === 'string' && entry.en.length > 0, `key ${key} 的 en 非空`);
  }
});

test('四 bin 字典 en 侧为纯 ASCII（非 CJK 码页降英文时任何码页安全）', () => {
  for (const [key, entry] of Object.entries(DICT)) {
    assert.ok(/^[\x00-\x7F]*$/.test(entry.en), `key ${key} 的 en 必须是纯 ASCII，实际: ${entry.en}`);
  }
});
