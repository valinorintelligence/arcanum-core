"""Unit tests for the adaptive campaign engine (Phase 2).

The engine is pure/dependency-injected, so the adaptive brain (step gating by
parsed context), the output parsers, the ROE pause and the HITL gate are all
exercised here WITHOUT a sandbox, DB or WebSocket — just fake callables.
"""
import json

import pytest

from arcanum.campaigns import CampaignRunner, get_campaign, CAMPAIGNS
from arcanum.campaigns.definitions import SMART_WEB


# --------------------------- pure helpers ---------------------------------

def test_render_host_base_url():
    r = CampaignRunner.render
    assert r("httpx -u {base}", "host.docker.internal:8080") == "httpx -u host.docker.internal:8080"
    assert r("nmap {host}", "host.docker.internal:8080") == "nmap host.docker.internal"
    assert r("nuclei -u {url}", "host.docker.internal:8080") == "nuclei -u http://host.docker.internal:8080"
    assert r("nuclei -u {url}", "https://example.com/app") == "nuclei -u https://example.com/app"
    assert r("x {host}", "https://api.example.com") == "x api.example.com"


def test_is_eligible():
    assert CampaignRunner.is_eligible({"id": "a"}, {}) is True
    assert CampaignRunner.is_eligible({"id": "a", "when": "has_web"}, {}) is False
    assert CampaignRunner.is_eligible({"id": "a", "when": "has_web"}, {"has_web": True}) is True


def test_parse_httpx_json_detects_wordpress():
    run = CampaignRunner()
    line = json.dumps({"url": "http://h:8080", "status_code": 200, "tech": ["WordPress", "PHP"], "title": "x"})
    ctx, findings = run.parse("httpx_json", line + "\n", "", "h:8080")
    assert ctx["has_web"] is True
    assert ctx["is_wordpress"] is True
    assert "WordPress" in ctx["tech"]
    assert findings == []


def test_parse_httpx_json_non_json_fallback():
    run = CampaignRunner()
    ctx, _ = run.parse("httpx_json", "http://h [WordPress]\n", "", "h")
    assert ctx["has_web"] is True and ctx["is_wordpress"] is True


def test_parse_httpx_empty_means_no_web():
    run = CampaignRunner()
    ctx, _ = run.parse("httpx_json", "", "", "h")
    assert ctx.get("has_web") is False


def test_parse_nuclei_jsonl_builds_findings():
    run = CampaignRunner()
    lines = "\n".join([
        json.dumps({"template-id": "git-config", "info": {"name": "Git Config Exposure",
                    "severity": "medium", "tags": ["exposure", "config"]},
                    "matched-at": "http://h/.git/config"}),
        json.dumps({"template-id": "CVE-2021-1234", "info": {"name": "Some CVE",
                    "severity": "high", "tags": ["cve"]}, "matched-at": "http://h/x"}),
        "not-json-line",
    ])
    ctx, findings = run.parse("nuclei_jsonl", lines, "", "h")
    assert ctx["nuclei_hits"] == 2
    assert len(findings) == 2
    f0 = findings[0]
    assert f0["severity"] == "medium" and f0["cvss_score"] == 5.5
    assert "git-config" in f0["title"]
    assert f0["affected"]["url"] == "http://h/.git/config"
    assert findings[1]["severity"] == "high" and findings[1]["cvss_score"] == 8.0


def test_parse_katana_detects_graphql():
    run = CampaignRunner()
    ctx, _ = run.parse("katana_urls", "http://h/a\nhttp://h/graphql\n", "", "h")
    assert ctx["has_graphql"] is True and ctx["endpoints"] == 2
    ctx2, _ = run.parse("katana_urls", "http://h/a\n", "", "h")
    assert "has_graphql" not in ctx2


# --------------------------- driver (fakes) -------------------------------

class _Driver:
    def __init__(self, exec_map, govern=None, approve=True):
        self.exec_map = exec_map
        self.events = []
        self.exec_calls = []
        self.findings = []
        self._govern = govern
        self._approve = approve

    async def exec_fn(self, cmd):
        self.exec_calls.append(cmd)
        for key, out in self.exec_map.items():
            if key in cmd:
                return out
        return {"stdout": "", "stderr": "", "exit_code": 0}

    async def govern_fn(self, cmd):
        if self._govern:
            return self._govern(cmd)
        return (True, None, "active")

    async def emit(self, ev):
        self.events.append(ev)

    async def approve_fn(self, step, cmd):
        return self._approve

    async def finding_fn(self, f):
        self.findings.append(f)
        return "fid-%d" % len(self.findings)


CAMP = {
    "key": "t", "title": "T", "steps": [
        {"id": "httpx", "title": "id web", "cmd": "httpx-toolkit -u {base} -j", "parse": "httpx_json"},
        {"id": "nuclei", "title": "nuclei", "cmd": "nuclei -u {url} -jsonl", "when": "has_web", "parse": "nuclei_jsonl"},
        {"id": "wpscan", "title": "wp", "cmd": "wpscan --url {url}", "when": "is_wordpress", "intrusive": True},
        {"id": "graphql", "title": "gql", "cmd": "graphqlmap -u {url}/graphql", "when": "has_graphql", "intrusive": True},
    ],
}


def _types(events):
    return [e["type"] for e in events]


@pytest.mark.asyncio
async def test_run_adapts_to_wordpress_and_skips_graphql():
    httpx_out = {"stdout": json.dumps({"url": "http://h:8080", "status_code": 200,
                 "tech": ["WordPress"]}) + "\n", "stderr": "", "exit_code": 0}
    nuclei_out = {"stdout": json.dumps({"template-id": "git", "info": {"name": "Git",
                  "severity": "high", "tags": ["exposure"]}, "matched-at": "http://h/.git"}) + "\n",
                  "stderr": "", "exit_code": 0}
    d = _Driver({"httpx-toolkit": httpx_out, "nuclei": nuclei_out, "wpscan": {"stdout": "users", "exit_code": 0}})

    runner = CampaignRunner()
    res = await runner.run(CAMP, "h:8080", exec_fn=d.exec_fn, govern_fn=d.govern_fn,
                           emit=d.emit, approve_fn=d.approve_fn, finding_fn=d.finding_fn, auto_approve=True)

    assert res["status"] == "completed"
    assert res["context"].get("is_wordpress") is True
    # wpscan ran (wordpress unlocked, auto_approve => no pause); graphql skipped (no /graphql).
    assert any("wpscan" in c for c in d.exec_calls)
    assert not any("graphqlmap" in c for c in d.exec_calls)
    skips = [e for e in d.events if e["type"] == "step_skip"]
    assert any(e["id"] == "graphql" for e in skips)
    # one finding created from nuclei
    assert len(d.findings) == 1 and d.findings[0]["severity"] == "high"
    assert _types(d.events)[0] == "campaign_start" and _types(d.events)[-1] == "campaign_end"


@pytest.mark.asyncio
async def test_run_pauses_on_roe_block():
    httpx_out = {"stdout": json.dumps({"url": "http://h", "tech": ["WordPress"]}) + "\n", "exit_code": 0}
    # block anything that is a nuclei scan
    def gov(cmd):
        if "nuclei" in cmd:
            return (False, "target out of scope", "active")
        return (True, None, "active")
    d = _Driver({"httpx-toolkit": httpx_out}, govern=gov)

    res = await CampaignRunner().run(CAMP, "h", exec_fn=d.exec_fn, govern_fn=d.govern_fn,
                                     emit=d.emit, approve_fn=d.approve_fn, finding_fn=d.finding_fn, auto_approve=True)
    assert res["status"] == "paused_roe"
    assert any(e["type"] == "step_blocked" and e["id"] == "nuclei" for e in d.events)
    # httpx ran, nuclei was blocked before exec, nothing after ran
    assert d.exec_calls == ["httpx-toolkit -u h -j"]
    assert any(e["type"] == "campaign_end" and e["status"] == "paused_roe" for e in d.events)


@pytest.mark.asyncio
async def test_intrusive_step_skipped_without_approval():
    httpx_out = {"stdout": json.dumps({"url": "http://h", "tech": ["WordPress"]}) + "\n", "exit_code": 0}
    d = _Driver({"httpx-toolkit": httpx_out}, approve=False)
    await CampaignRunner().run(CAMP, "h", exec_fn=d.exec_fn, govern_fn=d.govern_fn,
                               emit=d.emit, approve_fn=d.approve_fn, finding_fn=d.finding_fn, auto_approve=False)
    assert not any("wpscan" in c for c in d.exec_calls)
    assert any(e["type"] == "step_skip" and e["id"] == "wpscan" for e in d.events)


@pytest.mark.asyncio
async def test_intrusive_step_runs_when_approved():
    httpx_out = {"stdout": json.dumps({"url": "http://h", "tech": ["WordPress"]}) + "\n", "exit_code": 0}
    d = _Driver({"httpx-toolkit": httpx_out, "wpscan": {"stdout": "ok", "exit_code": 0}}, approve=True)
    await CampaignRunner().run(CAMP, "h", exec_fn=d.exec_fn, govern_fn=d.govern_fn,
                               emit=d.emit, approve_fn=d.approve_fn, finding_fn=d.finding_fn, auto_approve=False)
    assert any("wpscan" in c for c in d.exec_calls)


# --------------------------- definitions ----------------------------------

def test_definitions_consistent():
    assert get_campaign("smart_web") is SMART_WEB
    assert get_campaign("nope") is None
    ids = [s["id"] for s in SMART_WEB["steps"]]
    assert "wpscan" in ids and "graphql" in ids
    wp = next(s for s in SMART_WEB["steps"] if s["id"] == "wpscan")
    assert wp["when"] == "is_wordpress" and wp["intrusive"] is True
    # every campaign step must carry a command and an id/title
    for c in CAMPAIGNS:
        for s in c["steps"]:
            assert s["id"] and s["title"] and s["cmd"]
