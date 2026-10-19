# Studionet deployment and observation record

Observed 2026-10-19 on GenLayer Studionet (chain ID `61999`). This is a record of public DNS answers seen by one hosted development-network contract. It does not establish control of the domains, authenticate an email, demonstrate that mail receivers honor a policy, or certify ongoing DNS security.

- Contract: [`0x1aAcE138c5c2d1413d32A763fD9B45e32A84CCc1`](https://explorer-studio.genlayer.com/address/0x1aAcE138c5c2d1413d32A763fD9B45e32A84CCc1).
- RPC used for the read-only source check: `https://studio.genlayer.com/api`.
- Deployer/caller: `0x3d9E39265d74511065f88C987f898c1d02892f3e`.
- Runner pinned on the first source line: `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`.
- No constructor inputs; all three transactions transferred `0 GEN`.

## Three live transactions

All three transactions reached **FINALIZED**, GenVM **SUCCESS** and accepted consensus. Explorer reports Normal (Full Consensus) execution, five initial validators and zero leader rotations for both `observe` transactions.

| Action | Explorer transaction | Return / outcome |
| --- | --- | --- |
| Deploy | [`0x73f36a94...311a533f`](https://explorer-studio.genlayer.com/tx/0x73f36a94eac4b11427641c608e975c513bfc40c6ed7cb0bbe4c83158311a533f) | Contract created at the address above. |
| `observe("example.com")` | [`0x0745ada7...d2e9e21d`](https://explorer-studio.genlayer.com/tx/0x0745ada7937c5231f7b1752c6c0a019e2635b6a0ea5032b35aceba0fd2e9e21d) | `OBSERVED_REJECT`. Both Google and Cloudflare readings were `PRESENT`, `policy=reject`, `test=n`, `legacy=false`. |
| `observe("gmail.com")` | [`0x8c057fac...0c7f1597`](https://explorer-studio.genlayer.com/tx/0x8c057fac115914b5926f54f5270e60ed3a9a08e46bdcee05d40c59910c7f1597) | `OBSERVED_NONE`. Both readings were `PRESENT`, `policy=none`, `test=n`, `legacy=false`. |

The `example.com` record's consensus packet carried the same canonical whole-policy SHA-256 on both resolvers: `9d08b8662a83da2044b3548cac3beed29f0b19eaaee470af7ba7e5cef69172b9`. For `gmail.com`, both packets carried `f76c22452b7f06fa8b1f9f410892f7b5f000e0026b3d4b1c5c396baded4b8c95`. The digest covers sorted, normalized TXT tags, including fields not interpreted by the contract; it is **not** a DNSSEC signature or a receipt of mail delivery. DNS may change immediately after a snapshot.

## Finalized state reads

In Studio, the Read Methods state selector was set to **Finalized**:

| Call | Stored observation |
| --- | --- |
| `get_latest("example.com")` | `id="0"`, `domain="example.com"`, `status="OBSERVED_REJECT"`, `requested_policy="reject"`, `testing="n"`, matching two-resolver digest `9d08b8662a83da2044b3548cac3beed29f0b19eaaee470af7ba7e5cef69172b9`, and `legacy=false` on both readings. |
| `get_latest("gmail.com")` | `id="1"`, `domain="gmail.com"`, `status="OBSERVED_NONE"`, `requested_policy="none"`, `testing="n"`, matching two-resolver digest `f76c22452b7f06fa8b1f9f410892f7b5f000e0026b3d4b1c5c396baded4b8c95`, and `legacy=false` on both readings. |

These reads confirm that the two distinct verdicts were stored under separate observations. `get_observation("0")` and `get_observation("1")` can retrieve the immutable history; neither was separately read onchain in this run. `get_latest` always points to the **last attempt** for each domain, including a later failure. There is no built-in expiry or proof that the same DNS records still exist now.

## Consensus scope

The caller cannot submit an outcome or choose a URL. The code builds fixed Google Public DNS and Cloudflare DNS-over-HTTPS requests for a direct `_dmarc.<domain>` TXT answer. The leader and validators each obtain independent web responses. A custom validator checks the complete keyed pair of per-resolver observations: DNS availability state, canonical full-record digest, `p` preference, `t` test mode and retired-`pct` flag. Deterministic code derives the stored status. No LLM is used. The two resolvers cache the **same underlying DNS namespace**; their agreement is not independent publisher attestation.

Only `OBSERVED_REJECT` and `OBSERVED_NONE` were exercised in live reviews. Malformed/multiple TXT records, `TEST_MODE`, `LEGACY_TAG`, `MISSING`, `DISAGREE`, `UNAVAILABLE`, changed resolver digests, forged leader output and failed lookups have **local Direct Mode test coverage only**, not separate live receipts.

## Source identity and local tests

- GitHub repository file `contracts/mail_policy_witness.py`: **10,746 bytes**, LF with final newline; SHA-256 `00b3f50e7bda7a04e5547d86cc110e31623432a925123c632a80f9d051a571f3`.
- `gen_getContractCode` on Studionet: **11,012 bytes**, CRLF with no final newline; raw SHA-256 `5a06533a3a7526eb07a8192ebd537ed4c2f5c689c706f57a6980d02ac1b6fa48`.
- **Raw byte parity: false. Normalized text parity: true.** Replacing onchain CRLF with LF and adding one final LF produces the GitHub/workspace source exactly. No code-token changes were found. Do not claim byte-for-byte source equality.

For a read-only reproduction, POST JSON-RPC `gen_getContractCode` to `https://studio.genlayer.com/api` with `params` containing the contract address as a **string**. Base64-decode `result`, then compare after the two line-ending adjustments. The read-only `gen_getContractSchema` returned the four public methods `observe`, `get_latest`, `get_observation`, `count`.

Before deployment, `genvm-lint check contracts/mail_policy_witness.py`, `genvm-lint typecheck contracts/mail_policy_witness.py` and `python -m pytest tests -q` passed locally (**43 Direct Mode tests**). The tests use mocked HTTP responses against the real contract but do not reproduce distributed validator execution; the two linked `observe` transactions are the live consensus evidence. Use the pinned `requirements-dev.txt` and `scripts/prepare_test_sdk.py` for reproduction.

The contract does not implement the full [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html) DMARC lookup, inherited-subdomain rules, DNSSEC, SPF/DKIM, individual email authentication, or receiver behavior. Hosted Studionet state may reset; verify the address remains available before relying on an old Explorer link.
