# VAP — Verifiable Agent Protocol

> A verifiable agent-interaction protocol — a **tested trust machine**. Any Node.js agent that
> installs this plugin and joins the same trust domain (a shared workspace) can claim tasks, submit
> ≤100-char reports, be adjudicated by a three-gate verification gate, and be adopted on crash.
> Zero third-party dependencies (only `node:` built-ins).

中文版见 [README.zh-CN.md](./README.zh-CN.md)。Specification: [vap-spec.md](./vap-spec.md).

## Capability overview

Every capability ships with an experiment device number and a control group.

| Layer | Capability | Device(s) |
|---|---|---|
| **Identity** | Ed25519 envelope + nonce replay protection + behavior-history scarcity | E01/E02/E03, P0-1..P0-4, P05 |
| **Trust** | Three-gate verification + credential-chain bootstrap + distributed 2/3 QC | E02, P3, D1-D5 |
| **Ordering** | Lockstep QC-chain consensus (total order / fork & double-spend prevention) | T1-T6 |
| **Transport** | File / HTTP gateway / UDP P2P / relay NAT traversal | P2-1..P2-4, R1-R4 |
| **Governance** | Dynamic membership + laws-on-chain + slash auto-expulsion | D1-D5 |

## Quick start — end-to-end in about two minutes

Requirement: **Node.js 22+** (`package.json` declares `engines.node >= 22`). No third-party
dependencies, nothing to install.

```bash
# 1. Get the code
git clone https://github.com/Wang-Lin-Chang/dsh-vap.git   # or download the ZIP and unpack it
cd dsh-vap

# 2. Check your Node.js version (22 or newer)
node --version

# 3. Terminal A — start the HTTP gateway on a fixed port
node bin/vap-gateway.mjs --port 3081

# 4. Terminal B — send your first verifiable envelope
node bin/vap-send.mjs --to brain --summary "hello vap" --gateway http://127.0.0.1:3081

# 5. Read the verdict — vap-send prints it; the gateway counter confirms it
curl http://127.0.0.1:3081/health

# 6. Run the tests
node --test
```

Step 3 tells you what to do next instead of leaving you at a bare prompt:

```text
✓ vap-gateway listening http=127.0.0.1:3081
  health    : http://127.0.0.1:3081/health
  envelopes : POST http://127.0.0.1:3081/envelopes （GET 同址拉取未投递信封）
  next      : send envelopes via POST /envelopes — node bin/vap-send.mjs --to brain --summary "hello vap" --gateway http://127.0.0.1:3081
```

Step 4 prints the verdict in plain words (exit code `0`):

```text
✓ 已投递 envelopeId=evt-a2d6aa6ab72547f3 网关已接收（HTTP 202 Accepted）
  boundary : L0（未给 --evidence，按诚实边界降级；加 --evidence '{"devices":["E01"]}' 才能声明 L2a）
  本地三闸 : pass（身份 ✓ / 军法 ✓ / 诚实边界 ✓）
  裁决     : 网关验签通过并落盘 inbox-http/（军法与诚实边界由下游裁决）
  next     : 看网关计数 → curl http://127.0.0.1:3081/health   （envelopesIn 会 +1）
```

Step 5 shows the gateway's own count: `{"ok":true,"envelopesIn":1,"envelopesOut":0,"peers":0,"relayed":0}`.

### Reading a verdict

| `vap-send` says | HTTP | What it means | Exit code |
|---|---|---|---|
| `✓ 已投递 … 网关已接收` | 202 | Signature verified, envelope stored in `inbox-http/` | 0 |
| `✗ 拒绝: 签名无效` | 403 | `sig` does not match `from.pubKey`, or the envelope was edited after signing | 1 |
| `✗ 拒绝: 格式错` | 400 | Missing / malformed `nonce` or `envelope.id`, or invalid JSON | 1 |
| `✗ 拒绝: 重放拦截` | 409 | That `nonce` was already spent — replay protection | 1 |
| `✗ 连不上网关 … ECONNREFUSED` | — | No gateway is listening on that port (start it first) | 1 |
| `✗ vap-send: unknown option …` | — | Usage error (unknown flag, missing value, bad `--boundary`) | 2 |

Every rejection also prints a `为什么`(why) and `怎么办`(fix) line, so a failure tells you what to do
next instead of only what went wrong.

## CLI commands

All four entries share one argument parser: `--help` prints usage to stdout and exits `0`, an unknown
flag (or a missing / non-numeric value) prints the error to stderr and exits `2`. Errors go to
stderr, help and results go to stdout.

| Command | What it does | Example |
|---|---|---|
| `bin/vap-send.mjs` | Build, sign and POST one envelope, then explain the verdict | `node bin/vap-send.mjs --to brain --summary "hello vap" --gateway http://127.0.0.1:3081` |
| `bin/vap-gateway.mjs` | HTTP gateway: `POST/GET /envelopes` + `/health` | `node bin/vap-gateway.mjs --port 3081` |
| `bin/vap-node.mjs` | Consensus node (lockstep QC chain + membership) with `/health` | `node bin/vap-node.mjs --node-id brain --port 3083` |
| `bin/vap-relay.mjs` | Relay: TCP registration + NAT-traversal forwarding | `node bin/vap-relay.mjs --port 3082` |

`vap-send` options: `--to <nodeId>`, `--summary <text>` (≤ 100 chars), `--gateway <url>`,
`--from <nodeId>`, `--claim-type <type>`, `--boundary <L2a|L1|L0>`, `--evidence <json>`,
`--request <text>`, `--key <keyFile>`, `--root <dir>`, `--from-file <json>`, `--timeout <ms>`,
`--dry-run`. Two shapes worth knowing:

```bash
# Claim the highest boundary L2a — it requires non-empty evidence.devices
node bin/vap-send.mjs --to brain --summary "巡检完成" --boundary L2a \
  --evidence '{"devices":["E01"]}' --gateway http://127.0.0.1:3081

# Inspect the envelope without sending it, or replay a stored one from a script
node bin/vap-send.mjs --to brain --summary "hello" --dry-run
node bin/vap-send.mjs --from-file ./evt-a2d6aa6ab72547f3.json --gateway http://127.0.0.1:3081
```

The three service entries accept `--host <ip>`, `--port <n>`, `--config <path>` (JSON config, see
`config.mjs`), `--log-file`, `--log-level`, plus `VAP_*` environment overrides; `vap-node` also takes
`--node-id <id>` and `--ledger-dir <dir>`. **Default ports are 0 (OS-assigned)** — the examples above
always pass an explicit `--port` so you never have to hunt for a random port. Logs go through the
structured logger (`logger.mjs`); SIGINT/SIGTERM (and the Windows `stdin shutdown` line) trigger
graceful exit with code 0. Set `VAP_LANG=zh` or `VAP_LANG=en` to force the CLI output language —
an escape hatch that overrides console codepage auto-detection (on Windows consoles the CLIs
self-heal `cp936` to UTF-8).

## Testing

```bash
node --test
```

The suite covers the inner ring (envelope / three gates / lease / adoption), the middle ring
(HTTP gateway / nonce replay 409-400 / relaying / anti-loop), the CLI experience
(`tests/cli.test.mjs`: help exit 0, unknown flag exit 2, `vap-send` 202/403/400/409 and
gateway-down paths), and every outer-ring phase. `node --test` must be all green.

## Directory structure

```
vap-core.mjs          # inner ring: envelope, three gates, lease, adoption, five-function contract
vap-transport.mjs     # middle ring: file/HTTP transport, gateway, nonce replay protection
vap-spec.md           # protocol spec (bilingual, v0.2)
config.mjs            # JSON + VAP_* env configuration layer
logger.mjs            # structured JSON-line logger + rotation
key-store.mjs         # PKCS8 private-key persistence (chmod 600)
bin/                  # vap-send (envelope CLI) / vap-relay / vap-gateway / vap-node + process guards
bridges/              # MCP server (mcp-server.mjs) + A2A card/spec (a2a-*.mjs/.md)
tests/                # regression suites (core / transport / security / deploy / bridge / cli)
phase0/ … phase6/     # outer-ring phases: DESIGN + REPORT + experiments
phase7/               # transport (paper 4): NAT-traversal decision state machine + STUN server + smokes
asmfs/                # ASM-FS bounded model checker (spec-driven, 6/6) + E-1..E-6 theorem specs
tlaplus/              # TLA+ consensus model + TLC results (paper 5): VAPConsensus, MC configs, TLC-RESULTS.md
experiments/          # v0 / http / ring2 experiment devices
```

## Honest boundaries

- **Small trust domain**: designed for a single-machine shared filesystem (extensible to a shared
  disk / HTTP gateway). The relay path is now exercised across the public internet (Tailscale-
  encrypted tunnel): cross-NAT 18/18 delivered-and-verified (see `phase6/DEPLOYMENT.md`) and
  502.5 envelopes/sec relay throughput (see `phase7/vap-punch-routes.md`); the bare-IP direct
  path is still untested.
- **Not Byzantine consensus at internet scale**: Ed25519 only proves "whoever holds the private
  key". The outer-ring consensus (Phase 5/6) tolerates `f` Byzantine nodes under `n = 3f+1`; a
  collusion of **≥ f+1** nodes crosses the mathematical boundary.
- **`doWork` / `respondExpand` are stubs** (see `vap-spec.md` §2): the real executor is a later phase.
- **IPv4 multicast only**: LAN P2P (`phase2/lan-peer.mjs`) rejects IPv6 multicast literals.

## Papers & formal verification

The repository is the source artifact for two companion papers, both zero third-party
dependencies and reproducible end to end:

| Paper | Subject | Source | Verification |
|---|---|---|---|
| Paper 4 (cs.NI) | NAT-traversal decision state machine (transport layer) | `phase7/` (+ `phase4/` relay) | `punch-chain.smoke` 12/12, `punch-plan.smoke` 5/5 |
| Paper 5 (cs.DC) | Lockstep-QC consensus: TLC model-checked safety + liveness repair | `tlaplus/` | `tlaplus/TLC-RESULTS.md` (62,064-state liveness PASS) |

- `asmfs/` is a spec-driven ASM-FS bounded model checker: `node asmfs/bmc-checker.mjs`
  runs theorems E-1..E-6 (6/6 PASS, exit 0). Bounded exhaustive ≠ universal proof.
- `phase7/` is the production-hardened form of the transport layer: the 2026-08-25
  hardening pass added S2 STUN-reflection protection and S3 handshake-token
  authentication (`stun-fingerprint.mjs`); see `SECURITY.md` and `CHANGELOG.md`.

## Phase links

| Phase | Design | Report |
|---|---|---|
| Phase 0 (behavior-history scarcity) | [DESIGN](phase0/DESIGN.md) | [P0-REPORT](phase0/P0-REPORT.md) |
| Phase 0.5 (auditor bootstrap) | [DESIGN](phase0.5/DESIGN.md) | [P05-REPORT](phase0.5/P05-REPORT.md) |
| Phase 1 (transport SPI) | [DESIGN](phase1/DESIGN.md) | [report-phase1](phase1/report-phase1.md) |
| Phase 2 (LAN P2P) | [DESIGN](phase2/DESIGN.md) | [P2-REPORT](phase2/P2-REPORT.md) |
| Phase 3 (distributed 2/3 endorsement) | [DESIGN](phase3/DESIGN.md) | [P3-REPORT](phase3/P3-REPORT.md) |
| Phase 4 (NAT traversal + relay) | [DESIGN](phase4/DESIGN.md) | [P4-REPORT](phase4/P4-REPORT.md) |
| Phase 5 (lockstep QC consensus) | [DESIGN](phase5/DESIGN.md) | [P5-REPORT](phase5/P5-REPORT.md) |
| Phase 6 (dynamic membership + laws-on-chain) | [DESIGN](phase6/DESIGN.md) | [P6-REPORT](phase6/P6-REPORT.md) |

## License

[Apache-2.0](./LICENSE)
