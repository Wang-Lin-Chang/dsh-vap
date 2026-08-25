# Security Policy

## Supported Versions

| Version | Status |
|---|---|
| 0.2.x (current) | Supported |

## Reporting a Vulnerability

If you discover a security issue in dsh-vap (protocol logic, relay/STUN/gateway
services, consensus, or key handling), please report it privately:

- Email: `452713206@qq.com`
- Subject line: `[SECURITY] <short summary>`

Do not open a public issue for vulnerabilities. We respond within 7 days with
an acknowledgement and a triage result (confirmed / not-a-vulnerability /
needs-more-info), and aim to publish a fix + advisory within 30 days of
confirmation.

## What We Treat as a Vulnerability

- Remote code execution, crash (unhandled exception / OOM) reachable over the
  network (relay port, STUN port, HTTP gateway, punch socket).
- Authentication bypass: registration takeover, forged relay `from`,
  unauthenticated handshake acceptance in hole punching, outbound queue
  exfiltration via the gateway.
- Amplification: any protocol surface usable as a UDP/TCP reflector.
- Key material disclosure: private keys, credentials, or secret tokens leaked
  by the software itself (not by operator misconfiguration).

## What We Do NOT Treat as a Vulnerability

- Attacks that require the attacker to already hold a registered node identity
  with a valid private key (that is the threat model boundary; see
  THREAT-MODEL).
- Denial of service by a node that is already authorized and rate-limited.
- Compromise of the host operating system or physical access to the machine.
- Use of the software in a deployment that disabled the documented safety
  defaults (e.g. gateway bound to `0.0.0.0` without the outbound token).

## Key-Compromise Runbook (K4)

If a node private key or a server credential leaks:

1. Rotate the credential immediately (new keypair for the node, new token for
   the gateway, new sudo password for the host).
2. Revoke the compromised node identity through the membership protocol
   (rotate/exclude) so old keys cannot keep participating.
3. Record a dated incident note with: what leaked, how, impact scope, and the
   fix (this file's history is part of the audit trail).
4. Re-run the regression suite (`node --test`) and the phase7 smokes before
   restoring service.

## Known Limitations (Honest Boundaries)

- The relay is a byte-forwarder over plain TCP unless deployed with TLS
  (tlsOptions supported in relay-server/relay-client; certificate bootstrap:
  `bash bin/vap-gencert.sh <outDir> <CN>`). The CLI entry points do not yet
  wire TLS options.
- STUN FINGERPRINT is not authentication (CRC-32 is recomputable): a forged
  source can obtain the authed rate bucket. The bucket capacity is therefore
  kept small (32 requests, ~1.5KB amplification per source); the bare-request
  bucket is 16/2-per-sec.
- The punch handshake token is a bearer secret exchanged over the relay: an
  attacker who can observe or tamper the relay channel can replay a captured
  token (mitigated by relay TLS + the relay from-binding; not eliminated).
- Bounded exhaustive checks (N<=4) are not universal proofs; liveness under
  full asynchrony is not proven (see PROOFS.md).
- A single validator is a single point of trust for the behavior-history
  apparatus (see bh-e11/README.md).

## Disclosure Hall of Fame

- 2026-08-25 production-hardening pass: S1 credential exposure in workspace
  (self-found, rotated), S2 STUN reflection, S3 unauthenticated punch
  handshake, S4/S5 relay takeover/from-spoof/bandwidth, S7/S8 gateway
  outbound/inbound controls, S11 deep-nesting crash, R3 ledger corruption
  crash loop. All fixed with regression tests; see tests/security-regression.test.mjs
  and tests/security-s2-stun.test.mjs.
