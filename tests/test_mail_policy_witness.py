"""Direct Mode tests run the actual contract; only DNS-over-HTTPS is mocked."""

import hashlib
import json

import pytest


CONTRACT = "contracts/mail_policy_witness.py"
GOOGLE = r"dns\.google/resolve\?name=_dmarc\."
CLOUDFLARE = r"cloudflare-dns\.com/dns-query\?name=_dmarc\."
REJECT = "v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s"
NONE = "v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com"


def query(name, texts=None, code=0, extra=None):
    payload = {"Status": code, "TC": False}
    if texts is not None:
        payload["Answer"] = [
            {"name": "_dmarc." + name + ".", "type": 16, "TTL": 3600, "data": t}
            for t in texts
        ]
    if extra is not None:
        payload.update(extra)
    return payload


def wire(vm, domain="example.com", google=REJECT, cloudflare=None, *,
         gstatus=200, cstatus=200, gcode=0, ccode=0, gtext=None, ctext=None):
    if cloudflare is None:
        cloudflare = google
    if gtext is None:
        gtext = [google]
    if ctext is None:
        ctext = [json.dumps(cloudflare)]
    vm.mock_web(GOOGLE, {"status": gstatus, "body": json.dumps(query(domain, gtext, gcode))})
    vm.mock_web(CLOUDFLARE, {"status": cstatus, "body": json.dumps(query(domain, ctext, ccode))})
    vm.strict_mocks = True


def latest(contract, domain="example.com"):
    return json.loads(contract.get_latest(domain))


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def test_reject_snapshot_has_full_policy_binding(direct_deploy, direct_vm):
    c = direct_deploy(CONTRACT)
    wire(direct_vm)
    assert c.observe("Example.COM.") == "OBSERVED_REJECT"
    assert c.count() == 1
    result = latest(c)
    assert result["id"] == "0" and result["domain"] == "example.com"
    assert result["requested_policy"] == "reject" and result["testing"] == "n"
    assert result["google"] == result["cloudflare"]
    assert result["google"]["state"] == "PRESENT"
    assert result["policy_digest"] == sha(json.dumps(
        [["adkim", "s"], ["aspf", "s"], ["p", "reject"], ["sp", "reject"], ["v", "dmarc1"]],
        sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ))
    assert json.loads(c.get_observation("0")) == result
    assert direct_vm.run_validator() is True


def test_none_snapshot_is_not_silent_approval(direct_deploy, direct_vm):
    c = direct_deploy(CONTRACT)
    wire(direct_vm, domain="gmail.com", google=NONE)
    assert c.observe("gmail.com") == "OBSERVED_NONE"
    assert latest(c, "gmail.com")["requested_policy"] == "none"
    assert latest(c, "gmail.com")["google"]["digest"]
    assert direct_vm.run_validator() is True


@pytest.mark.parametrize("domain", [
    "", "localhost", "bad..com", "-bad.com", "bad-.com", "a.\u03b2", "a_.com",
    "https://example.com", "sub/example.com", "example.com..x", "example.com..",
    "127.0.0.1", "x" * 64 + ".com", "very." * 35 + "example.com", 17, None,
])
def test_invalid_domain_never_fetches(direct_deploy, direct_vm, domain):
    c = direct_deploy(CONTRACT)
    direct_vm.strict_mocks = True
    with direct_vm.expect_revert("Domain must be an ASCII DNS name"):
        c.observe(domain)
    assert c.count() == 0
    assert c.get_latest(domain) == ""


def test_reordered_tags_and_dns_chunking_are_semantically_equal(direct_deploy, direct_vm):
    c = direct_deploy(CONTRACT)
    google = "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"
    cloudflare = '"v=DMARC1; adkim=s; " "aspf=s; sp=reject; p=reject"'
    vm_doh = query("example.com", [google])
    direct_vm.mock_web(GOOGLE, {"status": 200, "body": json.dumps(vm_doh)})
    direct_vm.mock_web(CLOUDFLARE, {"status": 200, "body": json.dumps(query("example.com", [cloudflare]))})
    direct_vm.strict_mocks = True
    assert c.observe("example.com") == "OBSERVED_REJECT"
    assert latest(c)["google"] == latest(c)["cloudflare"]
    assert direct_vm.run_validator() is True


@pytest.mark.parametrize("raw,expected", [
    ("v=DMARC1; p=reject; t=y", "TEST_MODE"),
    ("v=DMARC1; p=quarantine; t=n", "OBSERVED_QUARANTINE"),
    ("v=DMARC1; p=reject; pct=100", "LEGACY_TAG"),
    ("v=DMARC1; p=reject; pct=0", "LEGACY_TAG"),
    ("v=DMARC1; p=reject; t=unknown", "INVALID"),
    ("v=DMARC1; p=reject; pct=101", "INVALID"),
    ("v=DMARC1; p=reject; p=none", "INVALID"),
    ("v=DMARC1; sp=not-a-policy; p=reject", "INVALID"),
    ("p=reject; v=DMARC1", "INVALID"),
    ("v=DMARC1; rua=mailto:reports@example.com", "INVALID"),
])
def test_testing_legacy_and_malformed_policies(direct_deploy, direct_vm, raw, expected):
    c = direct_deploy(CONTRACT)
    wire(direct_vm, google=raw)
    assert c.observe("example.com") == expected
    row = latest(c)
    if expected == "LEGACY_TAG":
        assert row["requested_policy"] == "reject" and row["google"]["legacy"]
    if expected == "TEST_MODE":
        assert row["requested_policy"] == "reject" and row["testing"] == "y"
    if expected == "INVALID":
        assert row["requested_policy"] == "" and row["policy_digest"] == ""
    assert direct_vm.run_validator() is True


def test_multiple_policy_records_are_invalid_not_cherry_picked(direct_deploy, direct_vm):
    c = direct_deploy(CONTRACT)
    wire(direct_vm, gtext=[REJECT, NONE], ctext=[json.dumps(NONE), json.dumps(REJECT)])
    assert c.observe("example.com") == "INVALID"
    assert latest(c)["google"] == latest(c)["cloudflare"]
    assert direct_vm.run_validator() is True


@pytest.mark.parametrize("gtext,ctext,gcode,ccode,expected", [
    ([], [], 0, 0, "MISSING"),
    ([], [], 3, 3, "MISSING"),
    ([REJECT], [json.dumps(REJECT)], 3, 3, "UNAVAILABLE"),
    (["hello"], ['"hello"'], 0, 0, "MISSING"),
    ([REJECT], [], 0, 0, "DISAGREE"),
    ([REJECT], ['"' + NONE + '"'], 0, 0, "DISAGREE"),
    (["v=DMARC1; p=reject; rua=mailto:a@a.com"],
     ['"v=DMARC1; p=reject; rua=mailto:b@b.com"'], 0, 0, "DISAGREE"),
    (["v=DMARC1; p=reject"], ["v=DMARC1; p=reject"], 2, 0, "UNAVAILABLE"),
])
def test_missing_vs_inconsistent_vs_unavailable(direct_deploy, direct_vm,
                                                   gtext, ctext, gcode, ccode, expected):
    c = direct_deploy(CONTRACT)
    wire(direct_vm, gtext=gtext, ctext=ctext, gcode=gcode, ccode=ccode)
    assert c.observe("example.com") == expected
    assert latest(c)["status"] == expected
    assert latest(c)["requested_policy"] == ""
    assert direct_vm.run_validator() is True


def test_last_attempt_replaces_previous_success_even_if_transport_fails(direct_deploy, direct_vm):
    c = direct_deploy(CONTRACT)
    wire(direct_vm)
    c.observe("example.com")
    old = c.get_observation("0")
    direct_vm.clear_mocks()
    wire(direct_vm, gstatus=503, cstatus=500)
    assert c.observe("example.com") == "UNAVAILABLE"
    assert c.count() == 2
    assert latest(c)["status"] == "UNAVAILABLE"
    assert latest(c)["id"] == "1" and latest(c)["requested_policy"] == ""
    assert c.get_observation("0") == old
    assert direct_vm.run_validator() is True
    assert c.get_observation("2") == ""
    assert c.get_observation(None) == ""


def test_dns_format_failures_do_not_become_missing(direct_deploy, direct_vm):
    c = direct_deploy(CONTRACT)
    direct_vm.mock_web(GOOGLE, {"status": 200, "body": "not json"})
    direct_vm.mock_web(CLOUDFLARE, {"status": 200, "body": "A" * 12001})
    direct_vm.strict_mocks = True
    assert c.observe("example.com") == "UNAVAILABLE"
    assert latest(c)["google"]["state"] == "UNAVAILABLE"
    assert latest(c)["cloudflare"]["state"] == "UNAVAILABLE"
    assert direct_vm.run_validator() is True


def test_cname_and_wrong_question_are_unavailable_not_no_record(direct_deploy, direct_vm):
    c = direct_deploy(CONTRACT)
    bad = query("example.com", [REJECT])
    bad["Answer"][0]["type"] = 5
    direct_vm.mock_web(GOOGLE, {"status": 200, "body": json.dumps(bad)})
    wrong = query("wrong.com", [json.dumps(REJECT)])
    direct_vm.mock_web(CLOUDFLARE, {"status": 200, "body": json.dumps(wrong)})
    direct_vm.strict_mocks = True
    assert c.observe("example.com") == "UNAVAILABLE"
    assert direct_vm.run_validator() is True


def test_truncated_or_bad_dns_envelope_is_unavailable(direct_deploy, direct_vm):
    c = direct_deploy(CONTRACT)
    malformed = query("example.com", [REJECT], extra={"TC": "false"})
    truncated = query("example.com", [json.dumps(REJECT)], extra={"TC": True})
    direct_vm.mock_web(GOOGLE, {"status": 200, "body": json.dumps(malformed)})
    direct_vm.mock_web(CLOUDFLARE, {"status": 200, "body": json.dumps(truncated)})
    direct_vm.strict_mocks = True
    assert c.observe("example.com") == "UNAVAILABLE"
    assert latest(c)["google"]["state"] == "UNAVAILABLE"
    assert latest(c)["cloudflare"]["state"] == "UNAVAILABLE"
    assert direct_vm.run_validator() is True


def test_validator_checks_all_fields_and_independently_queries_both(direct_deploy, direct_vm):
    c = direct_deploy(CONTRACT)
    wire(direct_vm)
    assert c.observe("example.com") == "OBSERVED_REJECT"
    packet = {k: latest(c)[k] for k in ("google", "cloudflare")}
    assert direct_vm.run_validator(leader_result=packet) is True
    fake_policy = json.loads(json.dumps(packet))
    fake_policy["cloudflare"]["policy"] = "none"
    assert direct_vm.run_validator(leader_result=fake_policy) is False
    fake_hash = json.loads(json.dumps(packet))
    fake_hash["google"]["digest"] = "0" * 64
    assert direct_vm.run_validator(leader_result=fake_hash) is False
    fake_legacy = json.loads(json.dumps(packet))
    fake_legacy["google"]["legacy"] = True
    assert direct_vm.run_validator(leader_result=fake_legacy) is False
    assert direct_vm.run_validator(leader_result={"google": packet["google"]}) is False
    assert direct_vm.run_validator(leader_error=RuntimeError("leader DNS error")) is False
    direct_vm.clear_mocks()
    wire(direct_vm, google=NONE)
    assert direct_vm.run_validator(leader_result=packet) is False
    assert c.count() == 1  # Validator calls do not change storage.
