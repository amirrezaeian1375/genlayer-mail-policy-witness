# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""Consensus-witnessed snapshots of a domain's published root DMARC preference.

A DNS policy snapshot is not proof of email authentication or delivery behavior.
"""

from genlayer import *
import hashlib
import json
import re


MAX_DOMAIN_CHARS = 128
MAX_BODY_BYTES = 12000
MAX_TXT_CHARS = 4096
GOOGLE = "https://dns.google/resolve?name=_dmarc."
CLOUDFLARE = "https://cloudflare-dns.com/dns-query?name=_dmarc."


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _domain(value: str) -> str:
    if not isinstance(value, str):
        raise gl.vm.UserError("Domain must be an ASCII DNS name.")
    if value.endswith(".."):
        raise gl.vm.UserError("Domain must be an ASCII DNS name.")
    name = value[:-1].lower() if value.endswith(".") else value.lower()
    if len(name) > MAX_DOMAIN_CHARS or len(name) < 4 or name.count(".") < 1:
        raise gl.vm.UserError("Domain must be an ASCII DNS name.")
    labels = name.split(".")
    for label in labels:
        if (re.fullmatch(r"[a-z0-9-]{1,63}", label) is None or
                label[0] == "-" or label[-1] == "-"):
            raise gl.vm.UserError("Domain must be an ASCII DNS name.")
    if re.fullmatch(r"[a-z][a-z0-9-]{1,62}", labels[-1]) is None:
        raise gl.vm.UserError("Domain must be an ASCII DNS name.")
    return name


def _empty(state: str, digest: str = "") -> dict:
    return {"state": state, "digest": digest, "policy": "", "test": "", "legacy": False}


def _txt(raw: str) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > MAX_TXT_CHARS + 100:
        raise ValueError("Malformed DNS TXT data")
    if raw[0] != '"':
        if '"' in raw or "\\" in raw:
            raise ValueError("Malformed DNS TXT data")
        result = raw
    else:
        parts = []
        index = 0
        decoder = json.JSONDecoder()
        while index < len(raw):
            if raw[index] != '"':
                raise ValueError("Malformed DNS TXT chunks")
            chunk, end = decoder.raw_decode(raw, index)
            if not isinstance(chunk, str):
                raise ValueError("Malformed DNS TXT chunk")
            parts.append(chunk)
            index = end
            while index < len(raw) and raw[index] in " \t":
                index += 1
        result = "".join(parts)
    if not result or len(result) > MAX_TXT_CHARS:
        raise ValueError("DNS TXT data out of bounds")
    return result


def _is_dmarcish(text: str) -> bool:
    for part in text.split(";"):
        if "=" in part:
            key, val = part.split("=", 1)
            if key.strip().lower() == "v" and val.strip().lower().startswith("dmarc"):
                return True
    return False


def _parse_record(text: str) -> dict:
    raw_digest = _sha(text)
    parts = [part.strip() for part in text.split(";") if part.strip()]
    tags = {}
    for part in parts:
        if "=" not in part:
            return _empty("INVALID", raw_digest)
        key, value = part.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if (re.fullmatch(r"[a-z0-9_-]{1,32}", key) is None or
                not value or key in tags):
            return _empty("INVALID", raw_digest)
        tags[key] = value
    if (not parts or parts[0].split("=", 1)[0].strip().lower() != "v" or
            tags.get("v", "").lower() != "dmarc1" or
            tags.get("p", "").lower() not in ("none", "quarantine", "reject")):
        return _empty("INVALID", raw_digest)
    test = tags.get("t", "n").lower()
    if test not in ("y", "n"):
        return _empty("INVALID", raw_digest)
    if "sp" in tags and tags["sp"].lower() not in ("none", "quarantine", "reject"):
        return _empty("INVALID", raw_digest)
    if "np" in tags and tags["np"].lower() not in ("none", "quarantine", "reject"):
        return _empty("INVALID", raw_digest)
    if "pct" in tags and (re.fullmatch(r"[0-9]{1,3}", tags["pct"]) is None or
                          int(tags["pct"]) > 100):
        return _empty("INVALID", raw_digest)
    # Bind every tag, including extensions and reporting destinations, without
    # claiming to interpret them. DNS TXT chunking, ordering and spaces vary.
    normalized = [[key, value.lower() if key in ("v", "p", "t", "sp", "np") else value]
                  for key, value in sorted(tags.items())]
    return {"state": "PRESENT", "digest": _sha(_canonical(normalized)),
            "policy": tags["p"].lower(), "test": test, "legacy": "pct" in tags}


def _parse_dns(payload, name: str) -> dict:
    if not isinstance(payload, dict) or type(payload.get("Status")) is not int:
        return _empty("UNAVAILABLE")
    code = payload["Status"]
    if code not in (0, 3) or type(payload.get("TC")) is not bool or payload["TC"]:
        return _empty("UNAVAILABLE")
    answers = payload.get("Answer", [])
    if not isinstance(answers, list) or len(answers) > 16:
        return _empty("UNAVAILABLE")
    if code == 3:
        return _empty("MISSING", _sha("NXDOMAIN")) if not answers else _empty("UNAVAILABLE")
    texts = []
    try:
        for entry in answers:
            if (not isinstance(entry, dict) or type(entry.get("type")) is not int or
                    not isinstance(entry.get("name"), str) or
                    entry["name"].lower().rstrip(".") != name or entry["type"] != 16):
                # In v1, CNAMEs, aliases and other non-direct answers are not resolved.
                return _empty("UNAVAILABLE")
            texts.append(_txt(entry.get("data")))
    except (ValueError, TypeError, json.JSONDecodeError):
        return _empty("UNAVAILABLE")
    candidates = [text for text in texts if _is_dmarcish(text)]
    if not candidates:
        return _empty("MISSING", _sha(_canonical(sorted(texts))))
    if len(candidates) != 1:
        return _empty("INVALID", _sha(_canonical(sorted(candidates))))
    return _parse_record(candidates[0])


def _fetch(url: str, name: str) -> dict:
    try:
        response = gl.nondet.web.get(url, headers={
            "Accept": "application/dns-json",
            "User-Agent": "MailPolicyWitness/0.1 (+https://github.com/amirrezaeian1375)",
        })
        if response.status != 200 or not isinstance(response.body, bytes):
            return _empty("UNAVAILABLE")
        if not response.body or len(response.body) > MAX_BODY_BYTES:
            return _empty("UNAVAILABLE")
        payload = json.loads(response.body.decode("utf-8"))
        return _parse_dns(payload, name)
    except Exception:
        # A missing TXT record is NOT the same thing as a failed web/DNS lookup.
        return _empty("UNAVAILABLE")


def _check_observation(row) -> bool:
    if not isinstance(row, dict) or set(row) != {"state", "digest", "policy", "test", "legacy"}:
        return False
    if row["state"] not in ("PRESENT", "MISSING", "INVALID", "UNAVAILABLE"):
        return False
    if (not isinstance(row["digest"], str) or
            (row["digest"] and re.fullmatch(r"[0-9a-f]{64}", row["digest"]) is None)):
        return False
    if type(row["legacy"]) is not bool:
        return False
    if row["state"] == "PRESENT":
        return (len(row["digest"]) == 64 and
                row["policy"] in ("none", "quarantine", "reject") and
                row["test"] in ("n", "y"))
    return row["policy"] == "" and row["test"] == "" and row["legacy"] is False and (
        (row["state"] == "UNAVAILABLE" and row["digest"] == "") or
        (row["state"] != "UNAVAILABLE" and len(row["digest"]) == 64))


def _outcome(rows: dict) -> dict:
    if not isinstance(rows, dict) or set(rows) != {"google", "cloudflare"}:
        raise gl.vm.UserError("Malformed DNS observation.")
    a, b = rows["google"], rows["cloudflare"]
    if not _check_observation(a) or not _check_observation(b):
        raise gl.vm.UserError("Malformed DNS observation.")
    if a["state"] == "UNAVAILABLE" or b["state"] == "UNAVAILABLE":
        status = "UNAVAILABLE"
    elif a != b:
        status = "DISAGREE"
    elif a["state"] == "MISSING":
        status = "MISSING"
    elif a["state"] == "INVALID":
        status = "INVALID"
    elif a["legacy"]:
        status = "LEGACY_TAG"
    elif a["test"] == "y":
        status = "TEST_MODE"
    else:
        status = "OBSERVED_" + a["policy"].upper()
    agreed = a["state"] == "PRESENT" and b == a
    return {"status": status, "requested_policy": a["policy"] if agreed else "",
            "testing": a["test"] if agreed else "",
            "policy_digest": a["digest"] if agreed else "",
            "google": a, "cloudflare": b}


class MailPolicyWitness(gl.Contract):
    observations: TreeMap[str, str]
    latest: TreeMap[str, str]
    observation_count: u256

    def __init__(self):
        self.observation_count = u256(0)

    @gl.public.write
    def observe(self, domain: str) -> str:
        name = _domain(domain)
        dns_name = "_dmarc." + name

        def collect() -> dict:
            return {"google": _fetch(GOOGLE + name + "&type=TXT", dns_name),
                    "cloudflare": _fetch(CLOUDFLARE + name + "&type=TXT", dns_name)}

        def validate(leader_result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            proposed = leader_result.calldata
            try:
                _outcome(proposed)
                independent = collect()
                return _canonical(proposed) == _canonical(independent)
            except Exception:
                return False

        received = gl.vm.run_nondet_unsafe(collect, validate)
        result = _outcome(received)
        obs_id = str(self.observation_count)
        self.observation_count += u256(1)
        self.observations[obs_id] = _canonical({"id": obs_id, "domain": name, **result})
        # The last *attempt* wins: an outage must not leave a stale success
        # presented as the latest observation. Old receipts remain queryable.
        self.latest[name] = obs_id
        return result["status"]

    @gl.public.view
    def get_latest(self, domain: str) -> str:
        try:
            name = _domain(domain)
        except Exception:
            return ""
        obs_id = self.latest.get(name, "")
        return self.observations.get(obs_id, "") if obs_id else ""

    @gl.public.view
    def get_observation(self, obs_id: str) -> str:
        return self.observations.get(obs_id, "") if isinstance(obs_id, str) else ""

    @gl.public.view
    def count(self) -> u256:
        return self.observation_count
