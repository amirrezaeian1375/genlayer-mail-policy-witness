# MailPolicyWitness design boundary

Status: local lint, typecheck and 43 Direct Mode tests passed; two contrasting full-consensus Studionet observations and their Finalized state reads are documented in [DEPLOY.md](DEPLOY.md). These are direct-DNS policy snapshots, not email-security assessments.

## Exact question, not an email verdict

For an explicitly named ASCII domain, what *direct* `_dmarc.<domain>` TXT record did two public DNS-over-HTTPS resolvers serve in one GenLayer observation? If they agree on one bounded policy record, what root `p=` preference and `t=` testing flag does it publish? This does not evaluate a message, assert domain ownership, discover inherited policies, issue an authorization, or promise that recipients follow any published request.

Anyone may call `observe(domain)`. The call has no free-form URL or claimed answer. It constructs requests to two fixed HTTPS hosts. No deployer-only admin method, pause, payout or user-specific permission exists. The supplied domain is normalized to lowercase ASCII with at most one terminal dot; invalid DNS labels, numeric TLDs, Unicode, port numbers, IP address spellings and query separators are refused.

## Observation pipeline

1. The leader queries both fixed DNS-over-HTTPS endpoints for type TXT at exactly `_dmarc.<domain>`. It requires HTTP 200, a bounded UTF-8 JSON body, DNS response code 0 or 3, an untruncated reply, and at most 16 direct TXT answers for the asked name. DNS failures, malformed JSON, unexpected CNAME/alias answers and oversized responses are `UNAVAILABLE`, not `MISSING`.
2. DNS TXT data can appear unquoted (Google) or as quoted, possibly concatenated chunks (Cloudflare). Only complete bounded strings are accepted. Version-like candidates are identified by a `v=DMARC...` tag. Zero candidates yield `MISSING`; two or more are `INVALID`. A single candidate must contain a first `v=DMARC1` tag and exactly one supported `p` value; duplicate keys, malformed tags and invalid `t`, `sp`, `np` or legacy `pct` syntax are `INVALID`.
3. For a valid record, code sorts and binds **all** tags, including uninterpreted extension/reporting fields, to one SHA-256 digest. This normalizes DNS quotation, TXT chunking, tag order and insignificant spaces without trusting just the `p` field. Each resolver yields exactly five fields: `state`, `digest`, `policy`, `test`, `legacy`.
4. The custom validator independently repeats *both* network requests and normalization, checks the leader packet's complete shape, then compares the entire pair of per-resolver fields. It refuses a forged result, missing resolver, swapped policy, changed digest or leader error. If different validators see genuinely different DNS snapshots, consensus can fail and no observation is written; there is no forced positive answer.
5. Only after GenLayer accepts that packet does deterministic code combine the two resolvers' observations. An outage in either becomes `UNAVAILABLE`. Two available but different observations become `DISAGREE`. Agreement yields `MISSING`, `INVALID`, `LEGACY_TAG`, `TEST_MODE`, or one of `OBSERVED_NONE`, `OBSERVED_QUARANTINE`, `OBSERVED_REJECT`. The model never chooses a status because there is no model call.

The full record's digest is an application fingerprint of parsed TXT tags, **not** a DNSSEC proof or a verified publisher signature. A resolver's HTTP response is an observation from that caching resolver. Both resolvers ultimately observe the same DNS namespace; their agreement reduces reliance on a single caching path but cannot prove an authoritative record, continuous availability or recipient behavior.

## Storage, finality and replay

`observations` maps sequential string IDs to immutable JSON receipts (normalized domain, status, the decision packet and requested policy when present). `latest` maps a domain to the ID of its **last attempt**, even an unavailable one, so an outage cannot leave a prior positive receipt as the apparent latest. `observation_count` is a `u256`. There is no overwrite, revision or deletion of prior receipts. Calling again adds a new observation; an old receipt is history, not current authorization. Consumers must establish transaction finality and age outside the contract; a new DNS change can happen right after a finalized read. This version intentionally does not rely on an unavailable or simulated Studionet timestamp API.

`get_latest` and `get_observation` are non-failing read methods returning an empty string if no record can be found. No onchain action is performed on the basis of a returned `OBSERVED_REJECT`. Using it as an email-acceptance or blocking oracle would be outside the design boundary.

## Known exclusions and adversarial tests

- Only a direct record is assessed. The full RFC 9989 DNS tree walk, public suffix behavior, `sp` / `np` inheritance, SPF, DKIM, DNSSEC, DMARC reports and message sampling/receiver policy are **not implemented**. Presence of retired `pct` is flagged `LEGACY_TAG`, not silently interpreted as current enforcement. `t=y` is flagged `TEST_MODE` rather than presenting a normal reject/quarantine snapshot.
- JSON shape, text length, answer count, response status, record version, duplicated tags and both resolver results are bounded. If any cannot be read safely, the outcome is `UNAVAILABLE` or `INVALID`, not an invented successful policy.
- Direct Mode tests execute the actual contract with a mocked HTTP boundary; they include forged leader results, two distinct resolver readings with the same `p` but different full digests, NXDOMAIN vs NODATA, malformed/multiple records, record order/chunking, v1 test/legacy flags and an outage after a successful observation. They do not substitute for two real full-consensus Studionet observations.

Nearest known GenLayer primitive: [Deed](https://github.com/2TheMoom/deed) uses cross-resolver DNS TXT checks to establish a wallet-bound domain claim. MailPolicyWitness does not claim a new DNS transport mechanism: it uses independent web-reading consensus to store a separate direct-DMARC-policy snapshot. No global originality or operational email-security guarantee is claimed.
