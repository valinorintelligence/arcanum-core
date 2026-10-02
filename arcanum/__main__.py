"""Arcanum Core - Autonomous AI-Powered Security Reconnaissance Platform."""

import shutil
import subprocess
import sys

import click


@click.group(invoke_without_command=True)
@click.version_option(version="3.0.0", prog_name="arcanum-core")
@click.pass_context
def main(ctx):
    """Arcanum Core - Autonomous AI-Powered Security Reconnaissance Platform."""
    if ctx.invoked_subcommand is None:
        click.echo("Arcanum Core v3.0.0 - AI Security Recon Platform")
        click.echo("Use --help for available commands, or try: arcanum autopilot <target>")


@main.command()
@click.argument("target")
def autopilot(target: str):
    """Run fully autonomous reconnaissance against a target."""
    from .cli.app import ArcanumApp

    click.echo(f"[AUTOPILOT] Starting full engagement on {target}")
    app = ArcanumApp(mode="autopilot", target=target, op_name=f"auto-{target.replace('.', '-')}")
    app.run()


@main.command()
@click.argument("target")
def copilot(target: str):
    """Run AI-assisted reconnaissance with human oversight."""
    from .cli.app import ArcanumApp

    click.echo(f"[COPILOT] Starting assisted engagement on {target}")
    app = ArcanumApp(mode="copilot", target=target, op_name=f"copilot-{target.replace('.', '-')}")
    app.run()


@main.command()
def manual():
    """Launch the interactive manual TUI."""
    from .cli.app import ArcanumApp

    app = ArcanumApp(mode="manual")
    app.run()


# --- ops group ---


@main.group()
def ops():
    """Manage reconnaissance operations."""


@ops.command("list")
def ops_list_cmd():
    """List all operations."""
    from .cli.commands import ops_list

    ops_list()


@ops.command("new")
@click.argument("name")
@click.option("--target", "-t", default=None, help="Target domain or IP")
@click.option("--mode", "-m", default="manual", type=click.Choice(["autopilot", "copilot", "manual"]))
def ops_new_cmd(name: str, target: str, mode: str):
    """Create a new operation."""
    from .cli.commands import ops_new

    ops_new(name, target, mode)


@ops.command("resume")
@click.argument("name")
def ops_resume_cmd(name: str):
    """Resume a paused operation."""
    from .cli.commands import ops_resume

    ops_resume(name)


@ops.command("delete")
@click.argument("name")
def ops_delete_cmd(name: str):
    """Delete an operation."""
    from .cli.commands import ops_delete

    ops_delete(name)


# --- stash group ---


@main.group()
def stash():
    """Manage cross-operation artifact stash."""


@stash.command("list")
@click.option("--type", "-t", "type_filter", default=None, help="Filter by type")
def stash_list_cmd(type_filter: str):
    """List stashed artifacts."""
    from .cli.commands import stash_list

    stash_list(type_filter)


@stash.command("add")
@click.argument("type")
@click.argument("value")
@click.option("--note", "-n", default=None, help="Note for the item")
def stash_add_cmd(type: str, value: str, note: str):
    """Add an artifact to the stash."""
    from .cli.commands import stash_add

    stash_add(type, value, note)


@stash.command("pull")
@click.argument("item_id")
def stash_pull_cmd(item_id: str):
    """Pull a stash item into current operation."""
    from .cli.commands import stash_pull

    stash_pull(item_id)


# --- cve group ---


def _parse_cve_item(item):
    """Parse one NVD API 2.0 vulnerability item into a CVEEntry (or None)."""
    from .core.cve_kb import CVEEntry
    cve_data = item.get("cve", {})
    cve_id = cve_data.get("id", "")
    if not cve_id:
        return None
    desc = ""
    for d in cve_data.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    cvss_score = cvss_vector = None
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            cd = metrics[key][0].get("cvssData", {})
            cvss_score = cd.get("baseScore")
            cvss_vector = cd.get("vectorString")
            break
    cwe_ids = []
    for wp in cve_data.get("weaknesses", []):
        for d in wp.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-"):
                cwe_ids.append(v)
    published = cve_data.get("published", "")[:10] or None
    return CVEEntry(id=cve_id, description=desc, cvss_score=cvss_score,
                    cvss_vector=cvss_vector, cwe_ids=cwe_ids or None,
                    exploit_available=False, published_at=published)


async def _nvd_import_window(kb, w_start, w_end, date_param, ctx, echo):
    """Page one <=120-day NVD window and import it. ``date_param`` is 'pub' or
    'lastMod'. ``ctx`` is a mutable {'headers','delay'} dict so an invalid API
    key can transparently fall back to keyless mode. Returns #CVEs imported."""
    import httpx
    import time
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    sp, ep = (("pubStartDate", "pubEndDate") if date_param == "pub"
              else ("lastModStartDate", "lastModEndDate"))
    count = 0
    start_idx = 0
    while True:
        url = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
               f"?{sp}={w_start.strftime(fmt)}&{ep}={w_end.strftime(fmt)}"
               f"&startIndex={start_idx}&resultsPerPage=2000")
        try:
            async with httpx.AsyncClient(timeout=90) as client:
                resp = await client.get(url, headers=ctx["headers"])
                nvd_msg = (resp.headers.get("message") or "").lower()
                if resp.status_code == 404 and "apikey" in nvd_msg:
                    if ctx["headers"]:
                        echo("  NVD rejeitou a NVD_API_KEY (Invalid apiKey). Continuando SEM chave...")
                        ctx["headers"] = {}
                        ctx["delay"] = 6.5
                        continue
                    echo("  NVD: Invalid apiKey. Pulando janela.")
                    break
                if resp.status_code in (403, 429, 503):
                    echo("  Rate limited. Waiting 15s...")
                    time.sleep(15)
                    continue
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            echo(f"  Error fetching {w_start:%Y-%m-%d}..{w_end:%Y-%m-%d}: {e}")
            break
        vulns = data.get("vulnerabilities", [])
        entries = [e for e in (_parse_cve_item(it) for it in vulns) if e]
        if entries:
            await kb.bulk_import(entries)
            count += len(entries)
        total_results = data.get("totalResults", 0)
        start_idx += len(vulns)
        time.sleep(ctx["delay"])
        if not vulns or start_idx >= total_results:
            break
    return count


def _nvd_ctx():
    """Build the request context (headers + rate-limit delay) from NVD_API_KEY."""
    import os
    key = os.environ.get("NVD_API_KEY", "").strip()
    return {"headers": ({"apiKey": key} if key else {}), "delay": (0.8 if key else 6.5)}


@main.group()
def cve():
    """CVE knowledge base operations."""


@cve.command("search")
@click.argument("query")
def cve_search_cmd(query: str):
    """Search the CVE knowledge base."""
    from .cli.commands import cve_search

    cve_search(query)


@cve.command("update")
@click.option("--year", "-y", default=None, type=int, help="Specific year to fetch (default: current + previous)")
@click.option("--from-year", "from_year", default=None, type=int,
              help="Backfill every year from this one up to now (e.g. --from-year 2015 for history).")
def cve_update_cmd(year: int, from_year: int):
    """Update the local CVE database from NVD API 2.0."""
    import asyncio

    from .core.config import get_config
    from .core.cve_kb import CVEKnowledgeBase, CVEEntry

    async def _run():
        import json
        import os
        import time
        import httpx
        from datetime import datetime, timedelta

        config = get_config()
        kb = CVEKnowledgeBase(config.cve_db)
        await kb.connect()

        # NVD API 2.0 limits each query to a 120-day publish window, so we must
        # page the year in <=120-day slices (asking for a full year returns 404).
        api_key = os.environ.get("NVD_API_KEY", "").strip()
        headers = {"apiKey": api_key} if api_key else {}
        # Rate limits: 50 req / 30s with a key, 5 req / 30s without.
        delay = 0.8 if api_key else 6.5
        fmt = "%Y-%m-%dT%H:%M:%S.000"

        def _windows(y: int):
            start = datetime(y, 1, 1, 0, 0, 0)
            end = datetime(y, 12, 31, 23, 59, 59)
            now = datetime.now()
            if end > now:
                end = now
            cur = start
            while cur < end:
                w_end = min(cur + timedelta(days=119), end)
                yield cur, w_end
                cur = w_end + timedelta(seconds=1)

        try:
            if year:
                years = [year]
            elif from_year:
                years = list(range(from_year, datetime.now().year + 1))
            else:
                years = [datetime.now().year, datetime.now().year - 1]
            total = 0
            if not api_key:
                click.echo("  (Sem NVD_API_KEY — limite de 5 req/30s; defina NVD_API_KEY para acelerar.)")

            for y in years:
                click.echo(f"  Fetching CVEs for {y}...")
                year_count = 0

                for w_start, w_end in _windows(y):
                    start_idx = 0
                    while True:
                        url = (
                            "https://services.nvd.nist.gov/rest/json/cves/2.0"
                            f"?pubStartDate={w_start.strftime(fmt)}"
                            f"&pubEndDate={w_end.strftime(fmt)}"
                            f"&startIndex={start_idx}&resultsPerPage=2000"
                        )
                        try:
                            async with httpx.AsyncClient(timeout=90) as client:
                                resp = await client.get(url, headers=headers)
                                nvd_msg = (resp.headers.get("message") or "").lower()
                                # NVD returns 404 "Invalid apiKey" when the key is
                                # wrong or not activated yet. Fall back to keyless
                                # mode (works, just slower) instead of failing.
                                if resp.status_code == 404 and "apikey" in nvd_msg:
                                    if headers:
                                        click.echo("  NVD rejeitou a NVD_API_KEY (Invalid apiKey). "
                                                   "Ative a chave pelo link do e-mail do NVD ou remova-a. "
                                                   "Continuando SEM chave (mais lento)...")
                                        headers = {}
                                        delay = 6.5
                                        continue
                                    click.echo("  NVD: Invalid apiKey. Pulando janela.")
                                    break
                                if resp.status_code in (403, 429, 503):
                                    click.echo("  Rate limited. Waiting 15s...")
                                    time.sleep(15)
                                    continue
                                resp.raise_for_status()
                                data = resp.json()
                        except Exception as e:
                            click.echo(f"  Error fetching {w_start:%Y-%m-%d}..{w_end:%Y-%m-%d}: {e}")
                            break

                        vulns = data.get("vulnerabilities", [])
                        entries = []
                        for item in vulns:
                            cve_data = item.get("cve", {})
                            cve_id = cve_data.get("id", "")
                            if not cve_id:
                                continue

                            desc = ""
                            for d in cve_data.get("descriptions", []):
                                if d.get("lang") == "en":
                                    desc = d.get("value", "")
                                    break

                            cvss_score = None
                            cvss_vector = None
                            metrics = cve_data.get("metrics", {})
                            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                                if key in metrics and metrics[key]:
                                    cd = metrics[key][0].get("cvssData", {})
                                    cvss_score = cd.get("baseScore")
                                    cvss_vector = cd.get("vectorString")
                                    break

                            cwe_ids = []
                            for wp in cve_data.get("weaknesses", []):
                                for d in wp.get("description", []):
                                    v = d.get("value", "")
                                    if v.startswith("CWE-"):
                                        cwe_ids.append(v)

                            published = cve_data.get("published", "")[:10] or None
                            entries.append(CVEEntry(
                                id=cve_id, description=desc, cvss_score=cvss_score,
                                cvss_vector=cvss_vector, cwe_ids=cwe_ids or None,
                                exploit_available=False, published_at=published,
                            ))

                        if entries:
                            await kb.bulk_import(entries)
                            year_count += len(entries)

                        total_results = data.get("totalResults", 0)
                        start_idx += len(vulns)
                        time.sleep(delay)  # respect NVD rate limit
                        if not vulns or start_idx >= total_results:
                            break

                click.echo(f"  {y}: {year_count} CVEs imported")
                total += year_count

            final_count = await kb.count()
            # Mark the moment we synced up to, so 'cve sync' can fetch only
            # what changed afterwards (incremental daily updates).
            await kb.set_meta("last_sync", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000"))
            click.echo(f"[OK] CVE database updated. Total: {final_count} CVEs ({total} new)")
        finally:
            await kb.close()

    click.echo("Updating CVE database from NVD API 2.0...")
    click.echo("(Rate-limited to ~50 requests/30s — large imports may take minutes)")
    asyncio.run(_run())


@cve.command("sync")
@click.option("--days", "-d", default=None, type=int,
              help="Force re-pulling the last N days (default: since last sync).")
def cve_sync_cmd(days: int):
    """Incrementally sync only CVEs created/modified since the last update.

    Uses the NVD lastModStartDate feed, so a daily run fetches just the few
    hundred CVEs that changed — ideal for a scheduled job."""
    import asyncio
    from datetime import datetime, timedelta
    from .core.config import get_config
    from .core.cve_kb import CVEKnowledgeBase

    async def _run():
        kb = CVEKnowledgeBase(get_config().cve_db)
        await kb.connect()
        try:
            now = datetime.utcnow()
            if days:
                start = now - timedelta(days=days)
            else:
                last = await kb.get_meta("last_sync")
                if last:
                    try:
                        start = datetime.strptime(last, "%Y-%m-%dT%H:%M:%S.000")
                    except ValueError:
                        start = now - timedelta(days=1)
                    # small overlap to catch late enrichment at the boundary
                    start = start - timedelta(minutes=30)
                else:
                    click.echo("  Sem marcador de sync — puxando as últimas 24h "
                               "(rode 'arcanum cve update' para a carga inicial completa).")
                    start = now - timedelta(days=1)

            ctx = _nvd_ctx()
            if not ctx["headers"]:
                click.echo("  (Sem NVD_API_KEY — 5 req/30s.)")

            # lastMod windows also cap at 120 days; chunk if the gap is larger.
            total = 0
            cur = start
            while cur < now:
                w_end = min(cur + timedelta(days=119), now)
                total += await _nvd_import_window(kb, cur, w_end, "lastMod", ctx, click.echo)
                cur = w_end + timedelta(seconds=1)

            await kb.set_meta("last_sync", now.strftime("%Y-%m-%dT%H:%M:%S.000"))
            final = await kb.count()
            click.echo(f"[OK] Sync incremental concluído. {total} CVE(s) novos/atualizados. Total na base: {final}.")
        finally:
            await kb.close()

    click.echo("Sincronizando CVEs (incremental via lastModStartDate)...")
    asyncio.run(_run())


# --- demo ---


@main.command("demo")
def demo_seed_cmd():
    """Seed demo/mock data for testing without real targets."""
    import asyncio
    from .core.config import get_config
    from .core.database import Database
    from .core.cve_kb import CVEKnowledgeBase
    from .core.demo_data import seed_all_demo_data

    async def _run():
        config = get_config()
        db = Database(config.data_dir / "arcanum.db")
        await db.connect()
        await db.init_db()
        cve_kb = CVEKnowledgeBase(config.cve_db)
        await cve_kb.connect()
        try:
            result = await seed_all_demo_data(db, cve_kb)
            return result
        finally:
            await db.close()
            await cve_kb.close()

    result = asyncio.run(_run())
    if any(v > 0 for v in result.values()):
        click.echo(f"[OK] Demo data seeded:")
        click.echo(f"  Sessions: {result['sessions']}")
        click.echo(f"  Findings: {result['findings']}")
        click.echo(f"  Stash items: {result['stash_items']}")
        click.echo(f"  CVEs: {result['cves']}")
    else:
        click.echo("[INFO] Demo data already exists. Delete ~/.arcanum/arcanum.db to re-seed.")


# --- serve ---


@main.command()
@click.option("--port", "-p", default=8000, help="Port to serve on")
@click.option("--host", "-h", default="127.0.0.1",
              help="Host to bind to (default loopback; use 0.0.0.0 only behind a proxy)")
def serve(port: int, host: str):
    """Start the web UI server."""
    import uvicorn

    if host not in ("127.0.0.1", "localhost", "::1"):
        click.echo(
            "[WARN] Binding to a non-loopback address exposes the API. "
            "Ensure ARCANUM_API_TOKEN is set and a TLS proxy is in front."
        )
    click.echo(f"Starting Arcanum Core Web UI on http://{host}:{port}")
    # Keep WebSockets alive during long local-model inferences (the 32B tier can
    # take minutes on exploit/report). Without server pings the idle socket was
    # being closed (code 1006) mid-reasoning. ping_timeout generous for slow GPUs.
    uvicorn.run(
        "arcanum.api.main:app", host=host, port=port, reload=False,
        ws_ping_interval=20, ws_ping_timeout=300,
    )


# --- doctor ---


@main.command()
def doctor():
    """Check system dependencies and environment."""
    from .cli.commands import doctor as run_doctor

    run_doctor()


# --- sandbox group ---


@main.group()
def sandbox():
    """Manage the isolated sandbox environment."""


@sandbox.command("build")
def sandbox_build_cmd():
    """Build the sandbox Docker image."""
    import os

    dockerfile = os.path.join(os.path.dirname(__file__), "..", "docker", "Dockerfile")
    if not os.path.exists(dockerfile):
        click.echo("[ERROR] Dockerfile not found. Run from project root.")
        return
    click.echo("Building Arcanum sandbox image (this may take 10-20 minutes)...")
    result = subprocess.run(
        ["docker", "build", "-t", "arcanum-sandbox:latest", "-f", dockerfile, "."],
        capture_output=False,
    )
    if result.returncode == 0:
        click.echo("[OK] Sandbox image built successfully!")
    else:
        click.echo("[FAIL] Build failed. Check Docker output above.")


if __name__ == "__main__":
    main()
