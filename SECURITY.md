# Security Policy

ShadowDAG is a proof-of-work BlockDAG that handles real value. We take security
seriously and welcome responsible disclosure from the community.

## Supported versions

Until mainnet launch, only the tip of the active development branch is supported.
After mainnet, the latest tagged release and the immediately preceding minor
release receive security fixes.

| Version            | Supported |
| ------------------ | --------- |
| `main` (pre-mainnet) | ✅ |
| tagged releases    | latest + previous minor |
| older              | ❌ |

## Reporting a vulnerability

**Do NOT open a public GitHub issue for a security vulnerability.**

Report privately, one of:

- **Email:** security@shadowdag.network (PGP key published in `docs/security/`),
  or the maintainer at the address in the repository profile until that mailbox
  is provisioned.
- **GitHub private advisory:** repository → *Security* → *Report a vulnerability*.

Please include:

- A clear description and the impact (funds at risk, consensus split, DoS, info
  leak, etc.).
- Reproduction steps or a proof-of-concept.
- The commit hash / version affected.
- Any suggested remediation.

**Encrypt** anything sensitive with our PGP key. Do not include exploit details
in unencrypted channels.

### Our commitment

- **Acknowledgement** within **48 hours**.
- **Triage + severity assessment** within **5 business days**.
- **Status updates** at least every **7 days** until resolution.
- **Coordinated disclosure:** we agree a public-disclosure date with you, by
  default **90 days** after the fix ships (sooner if the fix is already public,
  later by mutual agreement for a complex fix or a needed network upgrade).
- **Credit:** we credit reporters in the advisory and release notes unless you
  prefer to remain anonymous.

Please give us reasonable time to fix before any public disclosure, and do not
exploit the issue beyond what is necessary to demonstrate it.

## Scope

**In scope** (this repository):

- Consensus and validation (GHOSTDAG, PoW/difficulty, coinbase/emission, reorg,
  UTXO/RingCT), the ShadowVM, the P2P layer, the wallet and SDKs, node/RPC.
- Anything that can: create or steal funds, exceed the supply cap, split the
  network, permanently freeze funds, or crash/DoS a node remotely.

**Out of scope:**

- The public testnet is best-effort; report testnet-only issues but they are
  lower priority.
- Denial of service that requires implausible resources or physical/host access.
- Vulnerabilities in third-party dependencies already tracked by RustSec (report
  upstream; we track them via `cargo audit` in CI).
- Social engineering, spam, and issues in unaffiliated forks or infrastructure.
- Best-practice/hardening suggestions with no concrete exploit (open a normal
  issue instead).

## Bug bounty

A funded bug-bounty program launches **with mainnet**. Until then, disclosures
are handled under this policy and eligible reports will be **retroactively
considered** for the launch bounty. Indicative reward tiers (final amounts set
at launch, paid in SDAG):

| Severity | Examples | Indicative reward |
| -------- | -------- | ----------------- |
| **Critical** | mint funds, exceed the 21B supply cap, remote consensus split, steal funds | highest tier |
| **High** | permanent fund freeze, remote node crash/OOM, key/seed leak | high tier |
| **Medium** | recoverable consensus divergence, local DoS, privacy leak in RingCT | medium tier |
| **Low** | non-exploitable panics, minor info leaks | low tier / swag |

Eligibility requires: a valid in-scope report, first to disclose, no public
disclosure before the fix, and no exploitation against real users or funds.

## Known pre-mainnet status

ShadowDAG has **not yet completed an external cryptography + consensus audit**,
which is a hard gate before mainnet. The current readiness status (done,
verified, and remaining work) is tracked in
[`docs/MAINNET_READINESS.md`](docs/MAINNET_READINESS.md); the audit surface is
described in [`docs/AUDIT_SCOPE.md`](docs/AUDIT_SCOPE.md). Do not run mainnet
value on this software until that audit and a sustained public testnet are
complete.
