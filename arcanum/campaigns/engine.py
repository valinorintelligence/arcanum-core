"""Adaptive campaign runner (Phase 2) — pure, dependency-injected brain.

``CampaignRunner`` decides which step runs next (adapting to parsed context),
renders the command for the target, parses tool output into context + findings,
and drives execution through injected callables so it is fully unit-testable
without a sandbox/DB/WebSocket:

* ``exec_fn(command) -> {stdout, stderr, exit_code, duration}``  (async) — governed sandbox exec
* ``govern_fn(command) -> (allowed: bool, reason: str|None, action_class: str)``  (async)
* ``approve_fn(step, command) -> bool``  (async) — operator HITL for intrusive steps
* ``emit(event: dict)``  (async) — stream progress to the client
* ``finding_fn(finding: dict) -> id``  (async) — persist a real finding

Nothing here runs a command by itself; it only orchestrates governed calls.
"""
from __future__ import annotations

import json
from typing import Awaitable, Callable, Optional


SEVERITY_CVSS = {
    "critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0,
    "info": 0.0, "informational": 0.0, "unknown": 0.0,
}


class CampaignRunner:
    """Pure adaptive planner + output parser + governed driver."""

    # ---- rendering -------------------------------------------------------
    @staticmethod
    def render(cmd: str, target: str) -> str:
        """Substitute {host}/{base}/{url} for a raw target.

        {base} = host[:port] (scheme/path stripped) · {host} = {base} without the
        port · {url} = the target as an http(s) URL.
        """
        import re
        t = (target or "").strip()
        base = re.sub(r"^\w+://", "", t).split("/")[0]
        host = re.sub(r":\d+$", "", base)
        url = t if re.match(r"^\w+://", t) else ("http://" + base)
        return cmd.replace("{url}", url).replace("{host}", host).replace("{base}", base)

    # ---- adaptive gate ---------------------------------------------------
    @staticmethod
    def is_eligible(step: dict, context: dict) -> bool:
        cond = step.get("when")
        return True if not cond else bool(context.get(cond))

    # ---- output parsers (pure) ------------------------------------------
    def parse(self, key: str, stdout: str, stderr: str, target: str) -> tuple[dict, list[dict]]:
        """Return (context_update, findings) for a parser key."""
        fn = {
            "httpx_json": self._parse_httpx_json,
            "nuclei_jsonl": self._parse_nuclei_jsonl,
            "katana_urls": self._parse_katana_urls,
        }.get(key)
        if not fn:
            return {}, []
        try:
            return fn(stdout or "", target)
        except Exception:
            return {}, []

    @staticmethod
    def _parse_httpx_json(stdout: str, target: str) -> tuple[dict, list[dict]]:
        has_web = False
        is_wp = False
        techs: list[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            has_web = True  # httpx only emits a line for a live host
            try:
                obj = json.loads(line)
            except Exception:
                if "wordpress" in line.lower():
                    is_wp = True
                continue
            raw_tech = obj.get("tech") or obj.get("technologies") or []
            if isinstance(raw_tech, str):
                raw_tech = [raw_tech]
            for t in raw_tech:
                techs.append(str(t))
                if "wordpress" in str(t).lower():
                    is_wp = True
        ctx = {"has_web": has_web}
        if techs:
            ctx["tech"] = techs
        if is_wp:
            ctx["is_wordpress"] = True
        return ctx, []

    def _parse_nuclei_jsonl(self, stdout: str, target: str) -> tuple[dict, list[dict]]:
        findings: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            info = obj.get("info") or {}
            sev = str(info.get("severity", "info")).lower()
            # Skip pure-info noise unless it carries a CVE/exposure tag worth tracking.
            name = info.get("name") or obj.get("template-id") or "nuclei finding"
            tid = obj.get("template-id") or obj.get("templateID") or ""
            matched = obj.get("matched-at") or obj.get("host") or obj.get("url") or target
            tags = info.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]
            findings.append({
                "title": f"{name}" + (f" [{tid}]" if tid else ""),
                "type": (tags[0] if tags else "nuclei"),
                "severity": sev if sev in SEVERITY_CVSS else "info",
                "cvss_score": SEVERITY_CVSS.get(sev, 0.0),
                "affected": {"url": matched},
                "evidence": {"template": tid, "matched_at": matched, "tags": tags, "source": "nuclei"},
                "poc": {},
                "remediation": "Revise e corrija conforme o template do Nuclei; valide o impacto antes de reportar.",
                "source": "campaign:nuclei",
            })
        return {"nuclei_hits": len(findings)}, findings

    @staticmethod
    def _parse_katana_urls(stdout: str, target: str) -> tuple[dict, list[dict]]:
        low = stdout.lower()
        n = len([ln for ln in stdout.splitlines() if ln.strip()])
        ctx = {"endpoints": n}
        if "/graphql" in low:
            ctx["has_graphql"] = True
        return ctx, []

    # ---- governed driver -------------------------------------------------
    async def run(
        self,
        campaign: dict,
        target: str,
        *,
        exec_fn: Callable[[str], Awaitable[dict]],
        govern_fn: Callable[[str], Awaitable[tuple]],
        emit: Callable[[dict], Awaitable[None]],
        approve_fn: Optional[Callable[[dict, str], Awaitable[bool]]] = None,
        finding_fn: Optional[Callable[[dict], Awaitable[object]]] = None,
        auto_approve: bool = False,
    ) -> dict:
        """Drive the campaign. Each step is governed (``govern_fn``) before it runs;
        an out-of-policy step PAUSES the whole campaign (never silently skipped).
        Intrusive steps need ``approve_fn`` unless ``auto_approve`` (lab preset)."""
        ctx: dict = {}
        steps = campaign.get("steps", [])
        await emit({"type": "campaign_start", "campaign": campaign.get("key"),
                    "title": campaign.get("title"), "target": target, "steps": len(steps)})
        results: list[dict] = []

        for idx, step in enumerate(steps):
            if not self.is_eligible(step, ctx):
                await emit({"type": "step_skip", "id": step["id"], "title": step["title"],
                            "reason": f"condição '{step.get('when')}' não satisfeita ainda"})
                continue

            command = self.render(step["cmd"], target)

            allowed, reason, cls = await govern_fn(command)
            if not allowed:
                await emit({"type": "step_blocked", "id": step["id"], "title": step["title"],
                            "command": command, "reason": reason, "action_class": cls})
                await emit({"type": "campaign_end", "status": "paused_roe", "reason": reason,
                            "context": ctx, "done": idx})
                return {"status": "paused_roe", "reason": reason, "context": ctx, "results": results}

            if step.get("intrusive") and not auto_approve:
                ok = bool(await approve_fn(step, command)) if approve_fn else False
                if not ok:
                    await emit({"type": "step_skip", "id": step["id"], "title": step["title"],
                                "reason": "passo intrusivo não confirmado — pulado"})
                    continue

            await emit({"type": "step_start", "id": step["id"], "title": step["title"],
                        "why": step.get("why", ""), "command": command,
                        "action_class": cls, "intrusive": bool(step.get("intrusive")), "index": idx})

            out = await exec_fn(command)
            out = out if isinstance(out, dict) else {}
            stdout = out.get("stdout", "") or ""
            stderr = out.get("stderr", "") or ""
            exit_code = out.get("exit_code")

            parsed: dict = {}
            findings: list[dict] = []
            if step.get("parse"):
                parsed, findings = self.parse(step["parse"], stdout, stderr, target)
                ctx.update(parsed)

            created = 0
            for f in findings:
                if not finding_fn:
                    break
                try:
                    fid = await finding_fn(f)
                    created += 1
                    await emit({"type": "finding", "finding": {**f, "id": fid}})
                except Exception:
                    pass

            await emit({"type": "step_end", "id": step["id"], "exit_code": exit_code,
                        "duration": out.get("duration"), "context": parsed, "findings": created})
            results.append({"id": step["id"], "exit_code": exit_code, "findings": created, "parsed": parsed})

        await emit({"type": "campaign_end", "status": "completed", "context": ctx, "done": len(steps)})
        return {"status": "completed", "context": ctx, "results": results}
