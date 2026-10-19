# MailPolicyWitness

A small, standalone GenLayer Intelligent Contract that records what two public DNS resolvers reported for one domain's **direct root DMARC TXT record**. It separates a published `p=reject` request from `p=none`, testing mode, missing or invalid records, resolver disagreement, and a failed lookup. The result is an immutable observation, not an assurance that any email was authenticated or rejected.

**Status:** deployed on GenLayer Studionet (chain `61999`). The contract has three finalized, successfully executed transactions: deployment and two full-consensus observations, `OBSERVED_REJECT` for `example.com` and `OBSERVED_NONE` for `gmail.com`. GenVM lint, semantic validation and type checking passed; **43 Direct Mode tests** passed with HTTP responses mocked. Local tests are not distributed-network results; the two live receipts are linked below. This is hosted development-network evidence, not email-delivery or mainnet proof.

## Why this belongs on GenLayer

The caller supplies only an ASCII domain, not a URL or an answer. During `observe`, the leader and every validating node independently query **Google Public DNS** and **Cloudflare** over DNS-over-HTTPS for `_dmarc.<domain>` TXT. The contract normalizes single/multi-chunk TXT strings and tag order, then binds the complete recognized record (including tags it does not interpret) to a SHA-256 digest. A custom GenLayer validator re-queries **both** fixed endpoints and compares the complete per-resolver packet: DNS status, policy digest, requested `p` value, `t` testing flag and legacy-tag flag. Checking only the format or overall label would not prevent a dishonest leader from hiding a changed record.

Code, not an LLM, derives the stored outcome. This is GenLayer consensus over independently acquired live external data; no language-model call or agent decision is needed. The two resolvers are independent caching services **for the same underlying DNS records**, not two independent domain authorities. A publisher can change its own DNS; this contract does not verify its identity or intentions.

## Outcomes

| Status | What the observed direct record says |
| --- | --- |
| `OBSERVED_REJECT` | Both resolvers agree on a bounded `v=DMARC1; p=reject` record without `t=y` or legacy `pct`. It is a **requested handling preference**, not a guarantee that receivers rejected mail. |
| `OBSERVED_QUARANTINE` | Both report a direct `p=quarantine` record under the same conditions. |
| `OBSERVED_NONE` | Both report `p=none`, which does not request quarantine or rejection for a DMARC failure. |
| `TEST_MODE` | The record has `t=y`; the `requested_policy` field retains its published `p` value, but is not treated as normal `OBSERVED_REJECT`/`OBSERVED_QUARANTINE`. |
| `LEGACY_TAG` | The record has `pct`, removed by RFC 9989. Record the observed `p` and digest, but do not treat legacy sampling as full current-policy enforcement. |
| `MISSING` | Both direct lookups show no recognized DMARC record. This is **not** an inherited-policy check. |
| `INVALID` | Both show the same malformed or multiple DMARC-like records under this bounded parser. |
| `DISAGREE` | The two resolvers return different complete normalized observations. No positive policy is asserted. |
| `UNAVAILABLE` | At least one lookup failed or was not safely parseable. It is never silently converted to `MISSING`. |

Each call appends a numbered, immutable observation; `get_latest(domain)` points to the **last attempt, including an outage**. Previous observations stay readable by ID. A consumer should inspect the most recent finalized result and its transaction age. This contract supplies no time-to-live guarantee: DNS can change immediately after any snapshot. Do not use a stale `OBSERVED_REJECT` as ongoing permission or a general email-security rating.

## Public methods

| Method | Purpose |
| --- | --- |
| `observe(domain)` | Permissionlessly re-read the fixed DNS endpoints and append one consensus-backed snapshot. Returns its status. |
| `get_latest(domain)` | Return the last attempt for this normalized domain as JSON, or an empty string. |
| `get_observation(id)` | Return an immutable observation by numeric string ID, or an empty string. |
| `count()` | Return the total number of observations. |

Names must be ASCII DNS names with at least two labels. A single trailing dot is normalized; URLs, query strings, underscores and overly long labels are refused. No arbitrary domain-dependent URL is fetched: the two endpoint hosts are fixed in source. Inputs and observations are public.

## Reproduce local checks

From the repository root, with Python 3.12+:

1. `python3 -m venv .venv`
2. `source .venv/bin/activate` (PowerShell: `.venv\Scripts\Activate.ps1`)
3. `python -m pip install -r requirements-dev.txt`
4. `python scripts/prepare_test_sdk.py`
5. `genvm-lint check contracts/mail_policy_witness.py`
6. `genvm-lint typecheck contracts/mail_policy_witness.py`
7. `python -m pytest tests -q`

Keep the virtual environment activated. The helper script bridges an upstream GenVM release-asset naming mismatch; it does not patch the contract or installed packages. Tests cover normal and missing policies, new testing and removed legacy tags, reordered/chunked TXT, malformed/oversized responses, DNS outages, two-resolver disagreement, falsified leader packets, append-only history and last-attempt behavior. All web calls are mocked in Direct Mode; the tests alone are not evidence of live resolver or validator behavior. The actual full-consensus transactions are linked below.

## Live Studionet evidence

Observed 2026-10-19 on Studionet, chain `61999`. Contract: [`0x1aAcE138c5c2d1413d32A763fD9B45e32A84CCc1`](https://explorer-studio.genlayer.com/address/0x1aAcE138c5c2d1413d32A763fD9B45e32A84CCc1). Explorer reports all three transactions `FINALIZED`, GenVM `SUCCESS`, and consensus Accepted. Both observations ran in Normal (Full Consensus) mode with five initial validators and zero leader rotations. All calls sent `0 GEN`.

| Action | Transaction | Observed result |
| --- | --- | --- |
| Deploy | [`0x73f36a94...311a533f`](https://explorer-studio.genlayer.com/tx/0x73f36a94eac4b11427641c608e975c513bfc40c6ed7cb0bbe4c83158311a533f) | Contract deployed with no constructor inputs. |
| `observe("example.com")` | [`0x0745ada7...d2e9e21d`](https://explorer-studio.genlayer.com/tx/0x0745ada7937c5231f7b1752c6c0a019e2635b6a0ea5032b35aceba0fd2e9e21d) | `OBSERVED_REJECT`; both resolver packets reported direct `p=reject`, `t=n`, `legacy=false`. |
| `observe("gmail.com")` | [`0x8c057fac...0c7f1597`](https://explorer-studio.genlayer.com/tx/0x8c057fac115914b5926f54f5270e60ed3a9a08e46bdcee05d40c59910c7f1597) | `OBSERVED_NONE`; both resolver packets reported direct `p=none`, `t=n`, `legacy=false`. |

Studio **Finalized** reads of `get_latest` returned immutable observations `0` and `1` with the expected statuses and matching Google/Cloudflare digests. These are snapshots of DNS answers served during those consensus rounds, not evidence of email authentication, receiver enforcement, or future DNS state.

The deployed source differs from GitHub in **raw bytes**: Studio stored CRLF line endings without the repository file's final newline. After normalizing only those line endings, the source texts match exactly; **do not claim byte-for-byte source parity**. The complete record, digests and reproduction notes are in [docs/DEPLOY.md](docs/DEPLOY.md).

## Evidence and limitations

The [design boundary](docs/DESIGN.md) explains exact comparison fields, error states and cases outside v1. The [2026 DMARC standard, RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html), replaces RFC 7489 and introduces `t=` while retiring `pct=`. MailPolicyWitness is **not a complete RFC 9989 implementation**: it does not implement DNS tree walks, inherited or non-existent-subdomain policy resolution, SPF/DKIM checks, email authentication, deliverability checks, DNSSEC validation, or recipient behavior.

Related work: [Deed](https://github.com/2TheMoom/deed) uses two DNS resolvers to bind a domain-controlled TXT token to a wallet. MailPolicyWitness does **not** prove domain control; it records a separate, bounded question about the domain's published direct DMARC handling preference. No code is copied from Deed, and this repository makes no global-first claim.

License: MIT. See [LICENSE](LICENSE).
