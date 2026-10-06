"""CISA Known Exploited Vulnerabilities (KEV) Catalog Engine.

Ingests, caches and correlates vulnerabilities actively exploited in the wild,
enforcing CISA BOD 22-01 mandates and threat intelligence risk multiplier.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional
import httpx

from arcanum.core.database import Database

logger = logging.getLogger(__name__)

CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Curated bootstrap catalog for offline operation, unit testing, and immediate threat defense
BOOTSTRAP_KEV_DATA = [
    {
        "cveID": "CVE-2021-44228",
        "vendorProject": "Apache",
        "product": "Log4j",
        "vulnerabilityName": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "dateAdded": "2021-12-10",
        "shortDescription": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints.",
        "requiredAction": "Apply vendor mitigation or upgrade to log4j 2.15.0 or later.",
        "dueDate": "2021-12-24",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    },
    {
        "cveID": "CVE-2023-34362",
        "vendorProject": "Progress",
        "product": "MOVEit Transfer",
        "vulnerabilityName": "Progress MOVEit Transfer SQL Injection Vulnerability",
        "dateAdded": "2023-06-02",
        "shortDescription": "SQL injection vulnerability in Progress MOVEit Transfer web application allowing unauthenticated remote access.",
        "requiredAction": "Apply vendor patches immediately.",
        "dueDate": "2023-06-16",
        "knownRansomwareCampaignUse": "Known",
        "notes": "CL0P Ransomware widely exploited.",
    },
    {
        "cveID": "CVE-2024-21887",
        "vendorProject": "Ivanti",
        "product": "Connect Secure",
        "vulnerabilityName": "Ivanti Connect Secure Command Injection Vulnerability",
        "dateAdded": "2024-01-10",
        "shortDescription": "Command injection vulnerability in web components of Ivanti Connect Secure allowing authenticated admins to execute arbitrary commands.",
        "requiredAction": "Apply vendor mitigation and patch.",
        "dueDate": "2024-01-22",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    },
    {
        "cveID": "CVE-2024-1709",
        "vendorProject": "ConnectWise",
        "product": "ScreenConnect",
        "vulnerabilityName": "ConnectWise ScreenConnect Authentication Bypass Vulnerability",
        "dateAdded": "2024-02-21",
        "shortDescription": "Authentication bypass using an alternate path or channel in ConnectWise ScreenConnect allows an attacker with network access to create an administrative user.",
        "requiredAction": "Apply vendor updates immediately.",
        "dueDate": "2024-02-29",
        "knownRansomwareCampaignUse": "Known",
        "notes": "Widely weaponized in the wild.",
    },
    {
        "cveID": "CVE-2024-3400",
        "vendorProject": "Palo Alto Networks",
        "product": "PAN-OS GlobalProtect",
        "vulnerabilityName": "Palo Alto Networks PAN-OS Command Injection Vulnerability",
        "dateAdded": "2024-04-12",
        "shortDescription": "A command injection vulnerability in the GlobalProtect feature of PAN-OS allows an unauthenticated attacker to execute arbitrary code with root privileges.",
        "requiredAction": "Apply vendor patch or disable device telemetry as mitigation.",
        "dueDate": "2024-04-19",
        "knownRansomwareCampaignUse": "Known",
        "notes": "Active zero-day exploitation recorded.",
    },
    {
        "cveID": "CVE-2024-4577",
        "vendorProject": "PHP Group",
        "product": "PHP",
        "vulnerabilityName": "PHP CGI Argument Injection Vulnerability",
        "dateAdded": "2024-06-12",
        "shortDescription": "Argument injection vulnerability in PHP-CGI when running in Windows Locale Best Fit mode allowing remote code execution.",
        "requiredAction": "Upgrade to PHP 8.1.29, 8.2.20, or 8.3.8 or modify Apache rewrite rules.",
        "dueDate": "2024-07-03",
        "knownRansomwareCampaignUse": "Known",
        "notes": "TellYouThePass ransomware exploitation.",
    },
]


class CISAKEVEngine:
    """Manages CISA Known Exploited Vulnerabilities catalog with local cache and enrichment."""

    def __init__(self, db: Database, mock_mode: bool = False) -> None:
        self.db = db
        self.mock_mode = mock_mode
        self._memory_cache: dict[str, dict[str, Any]] = {
            item["cveID"].upper(): item for item in BOOTSTRAP_KEV_DATA
        }

    async def init_tables(self) -> None:
        """Ensures KEV table exists in database."""
        await self.db.execute(
            """CREATE TABLE IF NOT EXISTS cisa_kev (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                date_added TEXT,
                short_description TEXT,
                required_action TEXT,
                due_date TEXT,
                known_ransomware_campaign_use TEXT,
                notes TEXT,
                synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )"""
        )
        await self.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_cisa_kev_cve ON cisa_kev(cve_id)"
        )

    async def sync_cisa_kev(self, force: bool = False) -> dict[str, Any]:
        """Synchronizes local database with CISA KEV catalog feed.

        Falls back cleanly to bootstrap dataset if network request fails or mock_mode is active.
        """
        await self.init_tables()
        entries: list[dict[str, Any]] = []
        source = "online_cisa_feed"

        if not self.mock_mode:
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.get(CISA_KEV_FEED_URL)
                    if resp.status_code == 200:
                        data = resp.json()
                        raw_vulns = data.get("vulnerabilities", [])
                        if raw_vulns:
                            entries = raw_vulns
            except Exception as e:
                logger.warning(f"Could not reach CISA KEV feed ({e}), using bootstrap catalog.")
                source = "offline_bootstrap"

        if not entries:
            entries = BOOTSTRAP_KEV_DATA
            source = "offline_bootstrap"

        now_iso = datetime.now(timezone.utc).isoformat()
        synced_count = 0

        for item in entries:
            cve_id = (item.get("cveID") or item.get("cve_id") or "").upper().strip()
            if not cve_id:
                continue

            await self.db.execute(
                """INSERT OR REPLACE INTO cisa_kev
                   (cve_id, vendor_project, product, vulnerability_name, date_added,
                    short_description, required_action, due_date, known_ransomware_campaign_use, notes, synced_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cve_id,
                    item.get("vendorProject") or item.get("vendor_project") or "",
                    item.get("product") or "",
                    item.get("vulnerabilityName") or item.get("vulnerability_name") or "",
                    item.get("dateAdded") or item.get("date_added") or "",
                    item.get("shortDescription") or item.get("short_description") or "",
                    item.get("requiredAction") or item.get("required_action") or "",
                    item.get("dueDate") or item.get("due_date") or "",
                    item.get("knownRansomwareCampaignUse") or item.get("known_ransomware_campaign_use") or "Unknown",
                    item.get("notes") or "",
                    now_iso,
                ),
            )
            # Update in-memory lookup cache
            self._memory_cache[cve_id] = {
                "cve_id": cve_id,
                "vendor_project": item.get("vendorProject") or item.get("vendor_project"),
                "product": item.get("product"),
                "vulnerability_name": item.get("vulnerabilityName") or item.get("vulnerability_name"),
                "date_added": item.get("dateAdded") or item.get("date_added"),
                "short_description": item.get("shortDescription") or item.get("short_description"),
                "required_action": item.get("requiredAction") or item.get("required_action"),
                "due_date": item.get("dueDate") or item.get("due_date"),
                "known_ransomware": item.get("knownRansomwareCampaignUse") or item.get("known_ransomware_campaign_use"),
            }
            synced_count += 1

        return {
            "success": True,
            "source": source,
            "total_synced": synced_count,
            "synced_at": now_iso,
        }

    async def is_cisa_kev(self, cve_id: str | None) -> bool:
        """Returns True if the given CVE is present in the CISA KEV catalog."""
        if not cve_id:
            return False
        clean_cve = cve_id.strip().upper()
        if clean_cve in self._memory_cache:
            return True

        # Query database
        try:
            cursor = await self.db.execute("SELECT 1 FROM cisa_kev WHERE cve_id = ?", (clean_cve,))
            row = await cursor.fetchone()
            return row is not None
        except Exception:
            return False

    async def get_cve_details(self, cve_id: str | None) -> dict[str, Any] | None:
        """Retrieves CISA KEV metadata for a specific CVE."""
        if not cve_id:
            return None
        clean_cve = cve_id.strip().upper()
        if clean_cve in self._memory_cache:
            return self._memory_cache[clean_cve]

        try:
            cursor = await self.db.execute(
                """SELECT cve_id, vendor_project, product, vulnerability_name, date_added,
                          short_description, required_action, due_date, known_ransomware_campaign_use, notes
                   FROM cisa_kev WHERE cve_id = ?""",
                (clean_cve,),
            )
            row = await cursor.fetchone()
            if not row:
                return None
            return dict(row)
        except Exception:
            return None

    async def enrich_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Correlates finding with CISA KEV.

        If CVE is in KEV:
        - Flags is_cisa_kev = True
        - Automatically escalates severity to 'critical'
        - Injects CISA BOD 22-01 federal/enterprise remediation mandate
        """
        cve_id = finding.get("cve_id") or finding.get("cve")
        if not cve_id:
            finding["is_cisa_kev"] = False
            return finding

        kev_details = await self.get_cve_details(cve_id)
        if kev_details:
            finding["is_cisa_kev"] = True
            finding["original_severity"] = finding.get("severity")
            finding["severity"] = "critical"  # KEV items are actively exploited: always maximum urgency
            finding["cisa_kev"] = {
                "date_added": kev_details.get("date_added") or kev_details.get("dateAdded"),
                "due_date": kev_details.get("due_date") or kev_details.get("dueDate"),
                "required_action": kev_details.get("required_action") or kev_details.get("requiredAction"),
                "ransomware_associated": (kev_details.get("known_ransomware_campaign_use") or "").lower() == "known"
                or (kev_details.get("known_ransomware") or "").lower() == "known",
            }
            # Append CISA mandate to remediation if not already present
            action = kev_details.get("required_action") or kev_details.get("requiredAction")
            if action and action not in (finding.get("remediation") or ""):
                orig_rem = finding.get("remediation") or ""
                mandate = f"\n[CISA BOD 22-01 MANDATE]: Esta falha está no catálogo KEV da CISA (em exploração ativa por cibercriminosos). Ação mandatória: {action} (Prazo regulatório CISA: {kev_details.get('due_date') or kev_details.get('dueDate')})."
                finding["remediation"] = (orig_rem + mandate).strip()
        else:
            finding["is_cisa_kev"] = False

        return finding

    async def get_statistics(self) -> dict[str, Any]:
        """Returns statistics on the local CISA KEV catalog."""
        try:
            cursor = await self.db.execute("SELECT COUNT(*) AS total FROM cisa_kev")
            row = await cursor.fetchone()
            total = row["total"] if row else 0

            cursor_rw = await self.db.execute(
                "SELECT COUNT(*) AS rw_count FROM cisa_kev WHERE LOWER(known_ransomware_campaign_use) = 'known'"
            )
            row_rw = await cursor_rw.fetchone()
            rw_total = row_rw["rw_count"] if row_rw else 0

            cursor_last = await self.db.execute("SELECT MAX(date_added) AS latest_date FROM cisa_kev")
            row_last = await cursor_last.fetchone()
            latest = row_last["latest_date"] if row_last else None

            return {
                "total_cves": total or len(self._memory_cache),
                "ransomware_linked_cves": rw_total,
                "latest_date_added": latest,
                "engine_status": "active",
            }
        except Exception:
            return {
                "total_cves": len(self._memory_cache),
                "ransomware_linked_cves": sum(
                    1 for v in self._memory_cache.values() if (v.get("knownRansomwareCampaignUse") or "").lower() == "known"
                ),
                "latest_date_added": "2024-06-12",
                "engine_status": "fallback_cache",
            }
