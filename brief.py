#!/usr/bin/env python3
"""
brief.py — Pre-engagement intelligence brief for external O365/Entra ID red team engagements.

Usage:
    python3 brief.py <domain> [--output-dir <path>] [--skip-bbot] [--paste-domains]

Examples:
    python3 brief.py example.com
    python3 brief.py example.com --skip-bbot
    python3 brief.py example.com --paste-domains   # interactive paste from osint.aadinternals.com
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import jinja2
import dns.resolver
import dns.exception


# ============================================================================
# Banner & Progress
# ============================================================================

VERSION = "1.2.7"
BUILD_DATE = "2026-04-23"

BANNER = r"""
  _____          _   ___      __      _____ _____
 / ____|   /\   | \ | \ \    / /\    / ____/ ____|
| |       /  \  |  \| |\ \  / /  \  | (___| (___
| |      / /\ \ | . ` | \ \/ / /\ \  \___ \\___ \
| |____ / ____ \| |\  |  \  / ____ \ ____) |___) |
 \_____/_/    \_\_| \_|   \/_/    \_\_____/_____/
   M365 / Entra ID Pre-Engagement Brief  v{ver}
"""

# Globally toggled by --quiet
QUIET = False
START_TIME = 0.0
LOG_FILE = None  # Optional file handle — if set, every log() line is also written here


def print_banner() -> None:
    if QUIET:
        return
    print(BANNER.format(ver=VERSION))


def log(prefix: str, msg: str, level: str = "info") -> None:
    """Print a timestamped progress line. Goes to stderr so stdout stays clean.
    Also tees to LOG_FILE if set (regardless of --quiet).

    Levels: info (·), run (→), ok (✓), warn (!), err (✗)
    """
    icons = {"info": "·", "run": "→", "ok": "✓", "warn": "!", "err": "✗"}
    icon = icons.get(level, "·")
    elapsed = time.time() - START_TIME if START_TIME else 0
    ts = f"{elapsed:6.1f}s"
    # Pad prefix to 4 chars so columns align
    line = f"  [{ts}] [{prefix:<4}] {icon} {msg}"

    if not QUIET:
        print(line, file=sys.stderr, flush=True)

    # Tee to log file — always, even under --quiet
    if LOG_FILE is not None:
        try:
            LOG_FILE.write(line + "\n")
            LOG_FILE.flush()
        except (OSError, ValueError):
            pass  # file closed or disk full — don't crash the run over logging


# ============================================================================
# Configuration
# ============================================================================

VERIFICATION_PATTERNS: dict[str, str] = {
    "google-site-verification=": "Google Workspace",
    "ms=": "Microsoft 365",
    "atlassian-domain-verification=": "Atlassian",
    "docusign=": "DocuSign",
    "zoom-verification=": "Zoom",
    "slack-domain-verification=": "Slack",
    "okta-verification=": "Okta IdP",
    "onelogin-domain-verification=": "OneLogin IdP",
    "apple-domain-verification=": "Apple Business",
    "facebook-domain-verification=": "Facebook/Meta",
    "adobe-idp-site-verification=": "Adobe IdP",
    "citrix-verification-code=": "Citrix",
    "dropbox-domain-verification=": "Dropbox",
    "notion-domain-verification=": "Notion",
    "figma-domain-verification=": "Figma",
    "intuit-hs-verification=": "Intuit/QuickBooks",
    "workplace-domain-verification=": "Workplace by Meta",
    "miro-verification=": "Miro",
    # HRIS / payroll (high value — often contain sensitive employee data)
    "workday-verification=": "Workday HRIS",
    "adp-verification=": "ADP Payroll",
    "bamboohr-verification=": "BambooHR",
    "gusto-verification=": "Gusto Payroll",
    "greenhouse-domain-verification=": "Greenhouse ATS",
    # CRM / sales
    "hubspot-verification=": "HubSpot",
    "salesforce-verification=": "Salesforce",
    "zoho-verification=": "Zoho",
    "pipedrive-verification=": "Pipedrive",
    # Email infra (separate from MX)
    "sendgrid=": "SendGrid",
    "mandrill_verify=": "Mailchimp/Mandrill",
    "mailgun-verification=": "Mailgun",
    "postmark-domainkey=": "Postmark",
    "amazonses=": "AWS SES",
    # Support / comms
    "zendesk-verification=": "Zendesk",
    "freshdesk-verification=": "Freshdesk",
    "intercom-domain-verification=": "Intercom",
    "statuspage-domain-verification=": "Statuspage",
    # Dev / infra
    "github-site-verification=": "GitHub",
    "gitlab-verification=": "GitLab",
    "cloudflare-verify=": "Cloudflare",
    "fastly-verification=": "Fastly",
    "vercel=": "Vercel",
    "netlify=": "Netlify",
    # Security
    "cloudsmith=": "Cloudsmith",
    "have-i-been-pwned-verification=": "HaveIBeenPwned",
    "proofpoint-verification=": "Proofpoint",
    "mimecast-verification=": "Mimecast",
}

MX_VENDORS: list[tuple[str, str]] = [
    ("pphosted", "Proofpoint"),
    ("proofpoint", "Proofpoint"),
    ("mimecast", "Mimecast"),
    ("barracudanetworks", "Barracuda"),
    ("barracuda", "Barracuda"),
    ("protection.outlook.com", "Microsoft 365"),
    ("googlemail", "Google Workspace"),
    ("google", "Google Workspace"),
    ("messagelabs", "Symantec Email Security"),
    ("trendmicro", "Trend Micro"),
    ("ironport", "Cisco Email Security"),
    ("cisco", "Cisco Email Security"),
    ("sophos", "Sophos Email Security"),
    ("trustwave", "Trustwave"),
    ("zscaler", "Zscaler"),
    ("forcepoint", "Forcepoint"),
    ("websense", "Forcepoint"),
    ("vadesecure", "Vade Secure"),
    ("avanan", "Avanan/Check Point"),
    ("fireeye", "FireEye/Trellix"),
    ("trellix", "FireEye/Trellix"),
    ("hornet", "Hornetsecurity"),
    ("bitdefender", "Bitdefender"),
    ("kaspersky", "Kaspersky"),
    ("abusix", "Abusix"),
    ("gmx", "GMX Mail"),
]

M365_CNAME_PROBES: dict[str, str] = {
    "autodiscover": "Exchange Online",
    "sip": "Teams/Skype",
    "lyncdiscover": "Teams Federation",
    "enterpriseregistration": "Hybrid AD Join",
    "enterpriseenrollment": "Intune MDM",
    "msoid": "Legacy SSO",
}

SECURITY_SUBDOMAIN_PROBES: list[str] = [
    "adfs", "sso", "vpn", "owa", "webmail", "portal", "remote",
    "citrix", "rdweb", "gateway", "mfa", "auth", "login", "mail",
]

DKIM_SELECTORS: list[str] = [
    "selector1", "selector2", "google", "k1", "k2", "s1", "s2",
    "mandrill", "sendgrid", "zendesk1", "default", "mail",
]

SRV_PROBES: list[str] = [
    "_sip._tls",
    "_sipfederationtls._tcp",
    "_autodiscover._tcp",
]

# ============================================================================
# Cloud Service Discovery Patterns
# ============================================================================
# Passive DNS resolution only. We resolve candidate hostnames against standard
# cloud provider DNS patterns to enumerate the target's cloud attack surface.
# No HTTP requests, no API calls, no auth attempts — canvass stays passive.
#
# Each category maps to different operator next-actions:
#   Storage  — tester runs cloud_enum for active access testing
#   Platform — tester identifies specific service (WorkDocs? Kudu? CloudFront?)
#   M365     — tester uses findings for post-auth scope if creds land
#
# Patterns are `<token>.<suffix>` where token comes from the target's domain
# label, tenant brand, and additional tenant_domains labels (see build_cloud_tokens).

CLOUD_STORAGE_PATTERNS: list[tuple[str, str]] = [
    # (suffix, provider_label)
    # Only patterns where DNS resolution is high-signal (target actually owns the resource).
    # Azure Blob/Files/Queue/Table return NXDOMAIN if the storage account doesn't exist.
    # AWS S3 wildcards DNS — dropped (cloud_enum handles S3 better anyway).
    # GCS/R2/DO/B2/Wasabi all wildcard — dropped.
    ("blob.core.windows.net", "Azure Blob"),
    ("file.core.windows.net", "Azure Files"),
    ("queue.core.windows.net", "Azure Queue"),
    ("table.core.windows.net", "Azure Table"),
]

CLOUD_PLATFORM_PATTERNS: list[tuple[str, str]] = [
    # Azure — all return NXDOMAIN when app/resource doesn't exist. High signal.
    ("scm.azurewebsites.net", "Azure Kudu/SCM"),
    ("azurewebsites.net", "Azure App Service"),
    ("azureedge.net", "Azure CDN"),
    # AWS — awsapps.com and elasticbeanstalk.com return NXDOMAIN if tenant doesn't exist.
    # CloudFront wildcards — dropped.
    ("awsapps.com", "AWS Apps (WorkDocs/Connect/SSO)"),
    ("elasticbeanstalk.com", "AWS Elastic Beanstalk"),
    # Dropped due to wildcard DNS (low signal, too many false positives):
    #   appspot.com (GCP), run.app, web.app, firebaseapp.com, vercel.app,
    #   netlify.app, pages.dev, fly.dev, onrender.com, herokuapp.com,
    #   railway.app, azurefd.net, cloudfront.net
    # These are all better enumerated in the active phase anyway.
]

CLOUD_M365_PATTERNS: list[tuple[str, str]] = [
    # SharePoint Online — NXDOMAIN if tenant doesn't exist. High signal.
    ("sharepoint.com", "SharePoint Online"),
    ("crm.dynamics.com", "Dynamics 365 CRM"),
]

# SharePoint OneDrive uses `<token>-my.sharepoint.com`, handled specially
# in the collector because it's a token suffix not a standalone pattern.

# Storage account mutations — curated list of common suffix/prefix patterns that
# real engagements reveal in Azure storage naming. Applied ONLY to Azure storage
# patterns (blob/file/queue/table), NOT to platform or M365 patterns.
#
# Rationale: Azure storage accounts are a top-value target (data access) and
# naming conventions are real. When a tenant brand doesn't align with storage
# naming, mutations like `{base}prod`, `{base}data`, `{base}01` catch the common
# enterprise naming patterns without becoming cloud_enum's 306-mutation wordlist.
# Platform/M365 don't get mutations because:
#   - M365 tenant names don't mutate (there's one SharePoint tenant per org)
#   - Azure App Service / Kudu naming is more application-specific and less predictable
#
# Targeting: each mutation becomes `{token}{mutation}` (suffix) or `{mutation}{token}` (prefix).
STORAGE_MUTATION_SUFFIXES: list[str] = [
    "prod", "dev", "stage", "staging", "test", "qa",
    "backup", "backups", "data", "logs", "archive",
    "01", "02",
]
STORAGE_MUTATION_PREFIXES: list[str] = [
    "prod", "data",
]


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class Recommendation:
    priority: str   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category: str   # spray / enum / phishing / opsec / scope / next
    text: str       # full text for brief.md
    short: str | None = None  # compact single-line version for summary.txt


@dataclass
class Brief:
    # Metadata
    domain: str
    generated_at: str

    # M365 (AADOutsider)
    tenant_id: str | None = None
    tenant_brand: str | None = None
    tenant_name: str | None = None                # e.g. "example.onmicrosoft.com" or "example.onmicrosoft.us"
    tenant_region: str | None = None              # e.g. "NA", "EU", "WW"
    tenant_subregion: str | None = None           # e.g. "GCC", "DOD", "DODCON" (US Gov clouds)
    federation_type: str | None = None
    sts_server: str | None = None
    desktop_sso: bool = False
    tenant_domains: list[dict] = field(default_factory=list)
    tenant_domains_source: str = "aadoutsider"

    # MDI / AAD Connect Cloud Sync — auto-detected by AADOutsider-py OR manually captured via paste mode
    mdi_detected: bool | None = None              # None = unknown, True/False = known
    mdi_instance: str | None = None               # e.g. "microsoft.atp.azure.com"
    aad_connect_cloud_sync: bool | None = None
    manual_signals_captured: bool = False         # True if MDI/Cloud Sync are known (any source)
    signals_source: str = "none"                  # "aadoutsider" | "manual_paste" | "none"

    # DNS Intelligence
    mx_raw: list[str] = field(default_factory=list)
    mx_provider: str = "unknown"
    spf_includes: list[str] = field(default_factory=list)
    spf_all_qualifier: str | None = None       # "+", "-", "~", "?" — how strict the -all is
    spf_lookup_count: int | None = None         # SPF has a hard limit of 10 DNS lookups
    spf_record_present: bool = False             # True only if we saw an actual v=spf1 record
    dmarc_policy: str | None = None             # p=none/quarantine/reject
    dmarc_subdomain_policy: str | None = None   # sp= (overrides p= for subdomains)
    dmarc_pct: int | None = None                # pct= enforcement percentage (default 100)
    dmarc_rua: list[str] = field(default_factory=list)  # reporting addresses
    dmarc_ruf: list[str] = field(default_factory=list)  # forensic reporting addresses
    mta_sts_present: bool = False
    mta_sts_mode: str | None = None             # enforce / testing / none
    tls_rpt_present: bool = False
    caa_records: list[str] = field(default_factory=list)  # e.g. ["0 issue letsencrypt.org"]
    txt_verifications: dict = field(default_factory=dict)
    m365_subdomains: dict = field(default_factory=dict)
    security_subdomains: dict = field(default_factory=dict)
    dkim_selectors: list[str] = field(default_factory=list)
    srv_records: dict = field(default_factory=dict)

    # Cloud attack surface (passive DNS resolution only)
    # Each dict maps hostname -> resolution result. See collect_cloud_services.
    cloud_storage: dict = field(default_factory=dict)   # blob/S3/GCS buckets
    cloud_services: dict = field(default_factory=dict)  # Kudu, Azure Apps, WorkDocs, etc.
    cloud_m365_services: dict = field(default_factory=dict)  # SharePoint, OneDrive, Dynamics
    cloud_tokens_tried: list[str] = field(default_factory=list)  # for debugging / brief transparency
    cloud_wildcard_suffixes: list[str] = field(default_factory=list)  # providers skipped due to wildcard DNS

    # BBOT
    subdomains: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    takeovers: list[dict] = field(default_factory=list)  # baddns findings

    # HTTP probes on auth surface
    http_fingerprints: list[dict] = field(default_factory=list)

    # Output
    recommendations: list[Recommendation] = field(default_factory=list)


# ============================================================================
# Collectors
# ============================================================================

async def collect_aad(domain: str) -> dict:
    """Run AADOutsider-py recon. Returns dict with normalized fields.

    AADOutsider-py outputs the per-domain table to STDOUT as JSON, but the tenant
    metadata (brand, id, region, DesktopSSO, MDI, Cloud Sync) is logged to STDERR.
    We capture both and merge.

    Looks for aadoutsider.py at AADOUTSIDER_PATH env var, then a few common locations.
    Install via: git clone https://github.com/synacktiv/AADOutsider-py ~/tools/AADOutsider-py
    """
    candidates = [
        os.environ.get("AADOUTSIDER_PATH"),
        str(Path.home() / "tools" / "AADOutsider-py" / "aadoutsider.py"),
        str(Path.home() / "AADOutsider-py" / "aadoutsider.py"),
        "/opt/AADOutsider-py/aadoutsider.py",
    ]
    aadoutsider_script = next(
        (p for p in candidates if p and Path(p).exists()),
        None
    )

    if not aadoutsider_script:
        log("AAD", "AADOutsider-py not found at any expected path", level="warn")
        for c in candidates:
            if c:
                log("AAD", f"  tried: {c}", level="info")
        log("AAD", "install: git clone https://github.com/synacktiv/AADOutsider-py ~/tools/AADOutsider-py",
            level="info")
        return {}

    log("AAD", f"running AADOutsider-py recon ({Path(aadoutsider_script).name})", level="run")
    aad_start = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            "python3", aadoutsider_script, "recon",
            "-d", domain,
            "-of", "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        # Large multi-brand tenants can return hundreds of domains and take longer; allow up to 5min
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
    except asyncio.TimeoutError:
        log("AAD", "timed out after 300s", level="err")
        return {}
    except FileNotFoundError as e:
        log("AAD", f"failed: {e}", level="err")
        return {}

    # Parse stdout: JSON array of domain dicts (or empty/whitespace if failed)
    stdout_text = stdout.decode("utf-8", errors="ignore").strip()
    raw_domains = []
    try:
        parsed = json.loads(stdout_text) if stdout_text else []
        if isinstance(parsed, list):
            raw_domains = parsed
    except json.JSONDecodeError:
        log("AAD", "stdout was not valid JSON, falling back to text parser", level="warn")

    # Surface any visible warnings from AADOutsider's stderr (throttling, errors, etc)
    stderr_text = stderr.decode("utf-8", errors="ignore")
    for line in stderr_text.splitlines():
        if line.startswith(("WARNING:", "ERROR:")):
            log("AAD", line.strip(), level="warn")

    # Normalize domains: AADOutsider uses keys 'Name', 'Type', 'STS', etc. (capitalized)
    domains = []
    for d in raw_domains:
        if not isinstance(d, dict):
            continue
        domains.append({
            "name": d.get("Name", ""),
            "type": d.get("Type", "Unknown"),
            "sts": d.get("STS", ""),
            "dns": d.get("DNS", False),
            "mx": d.get("MX", False),
            "spf": d.get("SPF", False),
            "dmarc": d.get("DMARC", False),
            "dkim": d.get("DKIM", False),
            "mta_sts": d.get("MTA-STS", False),
        })

    # Parse stderr: each line is "INFO: <key>: <value>" (logging format)
    stderr_text = stderr.decode("utf-8", errors="ignore")
    metadata = parse_aadoutsider_stderr(stderr_text)

    # Build unified result
    result = {
        "domains": domains,
        **metadata,  # merges tenant_brand, tenant_id, etc.
    }

    # Derive federation_type and primary STS from queried domain's row if present
    queried = next((d for d in domains if d["name"].lower() == domain.lower()), None)
    if queried:
        if queried.get("type"):
            result["federation_type"] = queried["type"]
        if queried.get("sts"):
            result["sts_server"] = queried["sts"]

    # Fallback: if stderr parsing failed but stdout had domains, ensure queried domain present
    if not domains:
        result["domains"] = [{"name": domain, "type": "Unknown"}]

    # Per-finding logs — show the actual values
    if result.get("tenant_brand"):
        log("AAD", f"tenant brand: {result['tenant_brand']}", level="ok")
    if result.get("tenant_id"):
        log("AAD", f"tenant id: {result['tenant_id']}", level="ok")
    if result.get("tenant_name"):
        log("AAD", f"tenant name: {result['tenant_name']}")
    if result.get("tenant_region"):
        sub = f" / {result['tenant_subregion']}" if result.get("tenant_subregion") else ""
        log("AAD", f"region: {result['tenant_region']}{sub}", level="ok")
    if result.get("federation_type"):
        sts = f" → {result['sts_server']}" if result.get("sts_server") else ""
        log("AAD", f"federation: {result['federation_type']}{sts}", level="ok")
    if result.get("desktop_sso"):
        log("AAD", "DesktopSSO: enabled", level="ok")
    if result.get("mdi_detected") is True:
        instance = f" ({result.get('mdi_instance')})" if result.get("mdi_instance") else ""
        log("AAD", f"MDI: detected{instance}", level="ok")
    if result.get("aad_connect_cloud_sync") is True:
        log("AAD", "AAD Connect Cloud Sync: detected", level="ok")
    # Per-domain
    for d in result.get("domains", []):
        ftype = d.get("type", "Unknown")
        sts = f" via {d['sts']}" if d.get("sts") else ""
        log("AAD", f"  domain → {d['name']} [{ftype}]{sts}")

    elapsed = time.time() - aad_start
    n_domains = len(result.get("domains", []))
    log("AAD", f"done ({elapsed:.1f}s) — {n_domains} domain{'s' if n_domains != 1 else ''} returned", level="ok")

    return result


def parse_aadoutsider_stderr(text: str) -> dict:
    """Parse AADOutsider-py stderr log lines for tenant metadata.

    Format is logging.basicConfig(format='%(levelname)s: %(message)s'), so lines look like:
        INFO: Found N domains!
        INFO: Tenant brand: <brand>
        INFO: Tenant name: <tenant>.onmicrosoft.com
        INFO: Tenant id: <tenant-uuid>
        INFO: Tenant region: WW
        INFO: Tenant sub region: <subscope>
        INFO: DesktopSSO enabled: True/False
        INFO: MDI instance: <tenant>.atp.azure.com    (only if MDI exists)
        INFO: Uses cloud sync: True                    (only if cloud sync detected)
        INFO: CBA enabled: True/False                  (only if checked)
    """
    result: dict = {}

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        # Strip log level prefix ("INFO: ", "WARNING: ", etc.)
        if ":" in line:
            level, _, payload = line.partition(":")
            level = level.strip().upper()
            payload = payload.strip()
            if level not in ("INFO", "WARNING", "DEBUG", "ERROR"):
                # No log prefix — treat whole line as payload
                payload = line
        else:
            continue

        if ":" not in payload:
            continue
        key, _, val = payload.partition(":")
        key = key.strip().lower()
        val = val.strip()
        val_lower = val.lower()

        if key == "tenant brand":
            result["tenant_brand"] = val
        elif key == "tenant name":
            result["tenant_name"] = val
        elif key == "tenant id":
            result["tenant_id"] = val
        elif key == "tenant region":
            result["tenant_region"] = val
        elif key == "tenant sub region":
            result["tenant_subregion"] = val
        elif key == "desktopsso enabled":
            result["desktop_sso"] = val_lower in ("true", "yes", "1")
        elif key == "mdi instance":
            result["mdi_detected"] = True
            result["mdi_instance"] = val
        elif key == "uses cloud sync":
            result["aad_connect_cloud_sync"] = val_lower in ("true", "yes", "1")
        elif key == "cba enabled":
            result["cba_enabled"] = val_lower in ("true", "yes", "1")

    # MDI / Cloud Sync auto-fill — but ONLY if tenant_name was successfully resolved.
    # AADOutsider needs tenant_name to construct the MDI hostname (<tenant>.atp.azure.com)
    # and the Cloud Sync probe (ADToAADSyncServiceAccount@<tenant>). If tenant_name is
    # missing or "None", the absence of MDI/CloudSync log lines means "not checked",
    # not "checked and absent" — leave the keys absent so merge_aad treats them as Unknown.
    tenant_name = result.get("tenant_name")
    tenant_name_resolved = bool(tenant_name) and tenant_name != "None"

    if "tenant_id" in result and tenant_name_resolved:
        if "mdi_detected" not in result:
            result["mdi_detected"] = False
        if "aad_connect_cloud_sync" not in result:
            result["aad_connect_cloud_sync"] = False

    return result


# Kept for backwards-compat with paste-mode-only usage; new flow uses parse_aadoutsider_stderr
def parse_aadoutsider_text(text: str, domain: str) -> dict:
    """Legacy fallback parser for human-readable output (rarely needed now)."""
    result: dict = {"domains": []}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith("tenant brand"):
            result["tenant_brand"] = line.split(":", 1)[-1].strip()
        elif lower.startswith("tenant id") or lower.startswith("tenant_id"):
            result["tenant_id"] = line.split(":", 1)[-1].strip()
        elif lower.startswith("tenant region"):
            result["tenant_region"] = line.split(":", 1)[-1].strip()
        elif lower.startswith("desktopsso"):
            val = line.split(":", 1)[-1].strip().lower()
            result["desktop_sso"] = val in ("true", "yes", "1", "enabled")

    if domain not in [d.get("name") for d in result.get("domains", [])]:
        result["domains"].append({"name": domain, "type": "Unknown"})
    return result


async def collect_dns(domain: str) -> dict:
    """DNS intelligence: MX, SPF, DMARC, TXT verifications, M365/security CNAMEs."""
    log("DNS", "starting DNS fingerprint", level="run")
    dns_start = time.time()
    loop = asyncio.get_event_loop()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    def query(name: str, rtype: str) -> list:
        try:
            return list(resolver.resolve(name, rtype))
        except dns.exception.DNSException:
            return []

    result: dict = {
        "mx_raw": [],
        "mx_provider": "unknown",
        "spf_includes": [],
        "spf_all_qualifier": None,
        "spf_lookup_count": None,
        "spf_record_present": False,   # True only if we saw an actual v=spf1 record
        "dmarc_policy": None,
        "dmarc_subdomain_policy": None,
        "dmarc_pct": None,
        "dmarc_rua": [],
        "dmarc_ruf": [],
        "mta_sts_present": False,
        "mta_sts_mode": None,
        "tls_rpt_present": False,
        "caa_records": [],
        "txt_verifications": {},
        "m365_subdomains": {},
        "security_subdomains": {},
        "dkim_selectors": [],
        "srv_records": {},
    }

    # MX records — vendor identification
    mx_answers = await loop.run_in_executor(None, query, domain, "MX")
    if mx_answers:
        hosts = [str(r.exchange).rstrip(".").lower() for r in mx_answers]
        result["mx_raw"] = hosts
        mx_str = " ".join(hosts)
        for keyword, vendor in MX_VENDORS:
            if keyword in mx_str:
                result["mx_provider"] = vendor
                break
        log("DNS", f"MX vendor: {result['mx_provider']}", level="ok")
        for host in hosts:
            log("DNS", f"  MX → {host}")
    else:
        log("DNS", "MX: no records")

    # TXT records — SPF + verification tokens
    txt_answers = await loop.run_in_executor(None, query, domain, "TXT")
    for r in txt_answers:
        if hasattr(r, "strings"):
            s = "".join(part.decode() if isinstance(part, bytes) else str(part)
                        for part in r.strings)
        else:
            s = str(r).strip('"')

        if s.startswith("v=spf1"):
            result["spf_record_present"] = True
            result["spf_includes"] = [
                p.replace("include:", "")
                for p in s.split()
                if p.startswith("include:")
            ]
            # Detect the -all / +all / ~all / ?all qualifier
            # +all = critical misconfiguration (anyone can send as you)
            # ?all = neutral (no policy)
            # ~all = softfail (common weak config)
            # -all = hardfail (recommended)
            for token in s.split():
                if token in ("+all", "-all", "~all", "?all"):
                    result["spf_all_qualifier"] = token[0]  # "+", "-", "~", "?"
                    break
            # Rough SPF lookup count (includes + a + mx + exists + redirect + ptr)
            # SPF spec caps at 10 DNS lookups. Exceeding = permerror, all SPF fails.
            lookup_mechanisms = ("include:", "a:", "mx:", "exists:", "redirect=", "ptr:")
            count = sum(1 for tok in s.split() for m in lookup_mechanisms if tok.startswith(m))
            # Unqualified "a" and "mx" also count as 1 lookup each
            count += sum(1 for tok in s.split() if tok in ("a", "mx"))
            result["spf_lookup_count"] = count

        s_lower = s.lower()
        for pattern, service in VERIFICATION_PATTERNS.items():
            if pattern.lower() in s_lower:
                result["txt_verifications"][service] = s[:100]

    for service in result["txt_verifications"]:
        log("DNS", f"SaaS verification: {service}", level="ok")
    for inc in result["spf_includes"]:
        log("DNS", f"  SPF include → {inc}")
    if result["spf_all_qualifier"]:
        q = result["spf_all_qualifier"]
        interp = {"+": "+all (CRITICAL — anyone can spoof)", "-": "-all (hardfail, recommended)",
                  "~": "~all (softfail, weak)", "?": "?all (neutral, no enforcement)"}[q]
        log("DNS", f"  SPF qualifier: {interp}",
            level="err" if q == "+" else ("warn" if q in ("~", "?") else "ok"))
    if result["spf_lookup_count"] and result["spf_lookup_count"] > 10:
        log("DNS", f"  SPF lookups: {result['spf_lookup_count']} (EXCEEDS 10 — permerror, all SPF fails)",
            level="err")

    # DMARC policy — full parsing (not just p=)
    dmarc_answers = await loop.run_in_executor(None, query, f"_dmarc.{domain}", "TXT")
    for r in dmarc_answers:
        s = str(r).strip('"')
        if not s.startswith("v=DMARC1"):
            continue
        # Parse semicolon-separated tags into a dict
        tags = {}
        for part in s.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        if "p" in tags:
            result["dmarc_policy"] = tags["p"]
        if "sp" in tags:
            result["dmarc_subdomain_policy"] = tags["sp"]
        if "pct" in tags:
            try:
                result["dmarc_pct"] = int(tags["pct"])
            except ValueError:
                pass
        if "rua" in tags:
            # rua=mailto:dmarc@domain.com,mailto:reports@other.com
            result["dmarc_rua"] = [
                addr.replace("mailto:", "").strip()
                for addr in tags["rua"].split(",")
                if addr.strip()
            ]
        if "ruf" in tags:
            result["dmarc_ruf"] = [
                addr.replace("mailto:", "").strip()
                for addr in tags["ruf"].split(",")
                if addr.strip()
            ]
        break
    if result["dmarc_policy"]:
        pct_note = ""
        if result["dmarc_pct"] is not None and result["dmarc_pct"] < 100:
            pct_note = f" (pct={result['dmarc_pct']} — PARTIAL enforcement)"
        log("DNS", f"DMARC policy: p={result['dmarc_policy']}{pct_note}",
            level="warn" if result["dmarc_pct"] and result["dmarc_pct"] < 100 else "ok")
        if result["dmarc_rua"]:
            log("DNS", f"  DMARC reports to: {', '.join(result['dmarc_rua'])}")
        if result["dmarc_subdomain_policy"] and result["dmarc_subdomain_policy"] != result["dmarc_policy"]:
            log("DNS", f"  DMARC sp={result['dmarc_subdomain_policy']} (subdomain policy differs)",
                level="warn")
    else:
        log("DNS", "DMARC: not configured")

    # MTA-STS — modern email security (RFC 8461)
    # Absence is itself a finding; presence without enforce mode is partial
    mta_sts_answers = await loop.run_in_executor(None, query, f"_mta-sts.{domain}", "TXT")
    for r in mta_sts_answers:
        s = str(r).strip('"')
        if s.startswith("v=STSv1"):
            result["mta_sts_present"] = True
            # Policy mode requires fetching the policy HTTPS URL; skip for now.
            # Just note that the TXT record exists.
            break
    if result["mta_sts_present"]:
        log("DNS", "MTA-STS: configured", level="ok")
    # Not configured is NOT an error for small orgs — skip logging to reduce noise

    # TLS-RPT — reporting for TLS failures (RFC 8460)
    tls_rpt_answers = await loop.run_in_executor(None, query, f"_smtp._tls.{domain}", "TXT")
    for r in tls_rpt_answers:
        s = str(r).strip('"')
        if s.startswith("v=TLSRPTv1"):
            result["tls_rpt_present"] = True
            break
    if result["tls_rpt_present"]:
        log("DNS", "TLS-RPT: configured", level="ok")

    # CAA records — who's authorized to issue certs for this domain
    # Absence = any CA can issue, presence = hardened
    caa_answers = await loop.run_in_executor(None, query, domain, "CAA")
    if caa_answers:
        for r in caa_answers:
            result["caa_records"].append(str(r).strip())
        log("DNS", f"CAA: {len(result['caa_records'])} record(s)", level="ok")
        for rec in result["caa_records"][:5]:  # show first 5
            log("DNS", f"  CAA → {rec}")

    # M365 integration CNAMEs
    for label in M365_CNAME_PROBES:
        fqdn = f"{label}.{domain}"
        cname_answers = await loop.run_in_executor(None, query, fqdn, "CNAME")
        if cname_answers:
            target = str(cname_answers[0]).rstrip(".")
            result["m365_subdomains"][label] = target
            log("DNS", f"M365 CNAME: {fqdn} → {target}", level="ok")

    # Auth/security subdomains (CNAME first, A as fallback)
    for label in SECURITY_SUBDOMAIN_PROBES:
        fqdn = f"{label}.{domain}"
        cname_answers = await loop.run_in_executor(None, query, fqdn, "CNAME")
        if cname_answers:
            target = str(cname_answers[0]).rstrip(".")
            result["security_subdomains"][label] = target
            log("DNS", f"auth surface: {fqdn} → {target}", level="ok")
        else:
            a_answers = await loop.run_in_executor(None, query, fqdn, "A")
            if a_answers:
                ip = str(a_answers[0])
                result["security_subdomains"][label] = f"A:{ip}"
                log("DNS", f"auth surface: {fqdn} → A:{ip}", level="ok")

    # DKIM selectors
    for sel in DKIM_SELECTORS:
        fqdn = f"{sel}._domainkey.{domain}"
        answers = await loop.run_in_executor(None, query, fqdn, "TXT")
        if answers:
            result["dkim_selectors"].append(sel)
            log("DNS", f"DKIM selector found: {sel}")

    # SRV records
    for srv in SRV_PROBES:
        fqdn = f"{srv}.{domain}"
        answers = await loop.run_in_executor(None, query, fqdn, "SRV")
        if answers:
            records = [
                f"{r.priority} {r.weight} {r.port} {str(r.target).rstrip('.')}"
                for r in answers
            ]
            result["srv_records"][srv] = records
            for rec in records:
                log("DNS", f"SRV {srv} → {rec}")

    elapsed = time.time() - dns_start
    log("DNS", f"done ({elapsed:.1f}s)", level="ok")
    return result


async def collect_bbot(domain: str, output_dir: Path) -> dict:
    """Run BBOT subdomain-enum. Returns parsed events.

    NOTE: The 'subdomain-enum' preset only enables 'subdomains.txt' output by default.
    We add '-om json' to also enable the JSON output module for richer event data
    (emails, technologies). If JSON isn't found, we fall back to subdomains.txt.
    """
    bbot_out = output_dir / "bbot-output"
    log("BBOT", "starting subdomain-enum scan (60-120s typical, up to 10min worst case)", level="run")
    bbot_start = time.time()

    try:
        proc = await asyncio.create_subprocess_exec(
            "bbot", "-t", domain,
            "-p", "subdomain-enum",
            "-m", "baddns", "baddns_zone",   # enable takeover + zone-transfer/NSEC detection
            "-c", "modules.baddns.only_high_confidence=true",  # suppress GENERIC/POSSIBLE false positives
            "-om", "json",
            "-o", str(bbot_out),
            "-y", "--silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as e:
        log("BBOT", f"binary not found: {e}", level="err")
        log("BBOT", "install: pipx install bbot   (or: pip install bbot inside venv)", level="info")
        return {}

    # Live tailer task — every 5s, check subdomains.txt for new findings and print them
    seen_subs: set[str] = set()

    async def tailer():
        nonlocal seen_subs
        last_heartbeat = time.time()
        while True:
            await asyncio.sleep(5)
            try:
                txt_files = list(bbot_out.rglob("subdomains.txt"))
                if txt_files:
                    current = set()
                    for line in txt_files[0].read_text().splitlines():
                        line = line.strip()
                        if line:
                            current.add(line)
                    new_subs = current - seen_subs
                    for sub in sorted(new_subs):
                        log("BBOT", f"  found → {sub}")
                    seen_subs = current
            except OSError:
                pass
            # Heartbeat every 30s even if no new finds
            elapsed = time.time() - bbot_start
            if time.time() - last_heartbeat >= 30:
                log("BBOT", f"still running ({elapsed:.0f}s elapsed, {len(seen_subs)} subdomains so far)")
                last_heartbeat = time.time()

    hb = asyncio.create_task(tailer())
    try:
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
    except asyncio.TimeoutError:
        hb.cancel()
        log("BBOT", "timed out after 600s", level="err")
        return parse_bbot_output(bbot_out)  # try to salvage partial results
    finally:
        hb.cancel()

    # Surface BBOT errors if any
    stderr_text = stderr.decode("utf-8", errors="ignore") if stderr else ""
    for line in stderr_text.splitlines():
        if "ERROR" in line or "CRITICAL" in line:
            log("BBOT", line.strip()[:200], level="err")

    parsed = parse_bbot_output(bbot_out)
    elapsed = time.time() - bbot_start

    # Show emails and tech (subdomains were already streamed via tailer)
    for email in parsed["emails"]:
        log("BBOT", f"  email → {email}", level="ok")
    for tech in parsed["technologies"]:
        log("BBOT", f"  tech → {tech}", level="ok")

    # Takeovers — HIGH-signal findings, surface loudly
    for t in parsed.get("takeovers", []):
        icon_level = "err" if t["type"] == "VULNERABILITY" else "warn"
        label = "TAKEOVER" if t["type"] == "VULNERABILITY" else "DANGLING"
        log("BBOT", f"  {label}: {t['host']} [{t['module']}] — {t['description'][:120]}",
            level=icon_level)

    takeover_count = len(parsed.get("takeovers", []))
    takeover_str = f", {takeover_count} takeover/dangling findings" if takeover_count else ""
    log("BBOT",
        f"done ({elapsed:.1f}s) — {len(parsed['subdomains'])} subdomains, "
        f"{len(parsed['emails'])} emails, {len(parsed['technologies'])} technologies{takeover_str}",
        level="ok")
    return parsed


def parse_bbot_output(bbot_out: Path) -> dict:
    """Parse BBOT output. Prefers output.json (NDJSON event stream); falls back
    to subdomains.txt if JSON output module wasn't enabled."""
    result: dict = {"subdomains": [], "emails": [], "technologies": [], "takeovers": []}

    if not bbot_out.exists():
        return result

    # Prefer output.json (richer: includes emails, technologies, VULNERABILITY/FINDING)
    json_files = list(bbot_out.rglob("output.json"))
    if json_files:
        output_file = max(json_files, key=lambda p: p.stat().st_mtime)
        try:
            for line in output_file.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    etype = event.get("type", "")
                    data = event.get("data", "")
                    tags = event.get("tags", []) or []

                    if etype == "DNS_NAME" and isinstance(data, str):
                        result["subdomains"].append(data)
                    elif etype == "EMAIL_ADDRESS" and isinstance(data, str):
                        result["emails"].append(data)
                    elif etype == "TECHNOLOGY":
                        if isinstance(data, dict):
                            result["technologies"].append(data.get("technology", str(data)))
                        else:
                            result["technologies"].append(str(data))
                    elif etype in ("VULNERABILITY", "FINDING"):
                        # baddns events are tagged "baddns-<module>" (cname, ns, mx, txt, nsec, etc)
                        baddns_tags = [t for t in tags if isinstance(t, str) and t.startswith("baddns-")]
                        if not baddns_tags:
                            continue  # skip non-baddns findings (other modules can also emit these)
                        if isinstance(data, dict):
                            desc = data.get("description", "")
                            # Skip generic/heuristic findings (no real signature match) —
                            # these are baddns's NXDOMAIN heuristic, high false-positive rate
                            if "Signature: [GENERIC]" in desc:
                                continue
                            result["takeovers"].append({
                                "type": etype,  # VULNERABILITY (confirmed/probable) or FINDING (unlikely/possible)
                                "severity": data.get("severity", "MEDIUM" if etype == "VULNERABILITY" else "INFO"),
                                "host": data.get("host", event.get("host", "")),
                                "description": desc,
                                "module": baddns_tags[0].replace("baddns-", ""),  # cname/ns/mx/txt/nsec/etc
                            })
                except json.JSONDecodeError:
                    continue
        except OSError:
            pass

    # Fallback / supplement: subdomains.txt (always present with subdomain-enum preset)
    if not result["subdomains"]:
        txt_files = list(bbot_out.rglob("subdomains.txt"))
        if txt_files:
            txt_file = max(txt_files, key=lambda p: p.stat().st_mtime)
            try:
                for line in txt_file.read_text().splitlines():
                    line = line.strip()
                    if line and "." in line:
                        result["subdomains"].append(line)
            except OSError:
                pass

    result["subdomains"] = sorted(set(result["subdomains"]))
    result["emails"] = sorted(set(result["emails"]))
    result["technologies"] = sorted(set(result["technologies"]))
    # takeovers are dicts, not hashable — dedupe by (host, module) tuple
    seen = set()
    unique_takeovers = []
    for t in result["takeovers"]:
        key = (t["host"], t["module"], t["type"])
        if key not in seen:
            seen.add(key)
            unique_takeovers.append(t)
    result["takeovers"] = unique_takeovers
    return result


# ============================================================================
# Tier 2 Collectors: crt.sh + HTTP fingerprinting
# ============================================================================

async def collect_crtsh(domain: str) -> dict:
    """Query crt.sh certificate transparency logs for subdomains.

    Passive: queries a third-party public CT log aggregator, not the target.
    Often catches internal-looking subdomains that BBOT misses (names that appeared
    in TLS certs but not in DNS brute-force dictionaries).
    """
    log("CRTSH", "querying certificate transparency logs", level="run")
    start = time.time()
    result: dict = {"subdomains": []}

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        # Use urllib from stdlib to avoid new dep
        import urllib.request
        loop = asyncio.get_event_loop()

        def _fetch():
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; canvass/0.2)"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read()

        raw = await asyncio.wait_for(loop.run_in_executor(None, _fetch), timeout=35)
        entries = json.loads(raw)
    except asyncio.TimeoutError:
        log("CRTSH", "timed out after 35s (crt.sh is often slow)", level="warn")
        return result
    except (OSError, json.JSONDecodeError, ValueError) as e:
        log("CRTSH", f"failed: {e}", level="warn")
        return result

    # Entries have 'common_name' and 'name_value' fields; name_value can contain \n-separated SANs
    names: set[str] = set()
    for e in entries:
        if not isinstance(e, dict):
            continue
        for field_name in ("common_name", "name_value"):
            v = e.get(field_name, "")
            if isinstance(v, str):
                for name in v.split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    # Only keep names that are subdomains of the target domain
                    if name and name != domain and (name.endswith(f".{domain}") or name == domain):
                        names.add(name)

    result["subdomains"] = sorted(names)
    elapsed = time.time() - start
    log("CRTSH", f"done ({elapsed:.1f}s) — {len(names)} subdomains from CT logs", level="ok")
    return result


async def collect_http_fingerprints(domain: str, auth_subdomains: dict) -> dict:
    """Probe the known auth-surface subdomains with a native async HTTPS GET each.
    Captures: status, Server header, X-Powered-By, page title, missing security headers,
    final URL (reveals redirects), TLS cert CN (if visible).

    Uses httpx for proper HTTP/2, redirect following, and modern TLS — urllib was
    failing instantly on WAF-protected hosts (Incapsula, Cloudflare) because it
    couldn't handle HTTP/2 negotiation or modern TLS ciphers.

    Only probes the small fixed set of exposed auth subdomains canvass already found
    (webmail, portal, vpn, adfs, etc.) — not the full BBOT subdomain list. Typically
    5-15 requests total, well-behaved, short timeout per host.
    """
    if not auth_subdomains:
        return {"fingerprints": []}

    log("HTTP", f"fingerprinting {len(auth_subdomains)} auth subdomain(s)", level="run")
    start = time.time()
    result: dict = {"fingerprints": []}

    try:
        import httpx
    except ImportError:
        log("HTTP", "httpx not installed — skipping HTTP fingerprinting. "
                    "Run: pip install httpx", level="warn")
        return result

    # HTTP/2 is optional — requires `h2` package. Falls back to HTTP/1.1 if unavailable.
    try:
        import h2  # noqa: F401
        HTTP2_ENABLED = True
    except ImportError:
        HTTP2_ENABLED = False

    import re

    SECURITY_HEADERS = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]

    # Realistic browser User-Agent — some WAFs (Incapsula) block unusual UAs
    UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

    async def _probe(host: str) -> dict | None:
        # Try HTTPS first, fall back to HTTP if HTTPS completely fails
        last_error = None
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            try:
                # Per-host timeout: 10s total (connect 5s, read 5s)
                # verify=False for self-signed / WAF certs — we only want headers
                # http2=True to negotiate modern protocols
                # follow_redirects=True — some auth hosts 302 → login.microsoftonline.com,
                # we want to see the final resolution
                async with httpx.AsyncClient(
                    verify=False,
                    http2=HTTP2_ENABLED,
                    follow_redirects=True,
                    timeout=httpx.Timeout(10.0, connect=5.0),
                    headers={"User-Agent": UA,
                             "Accept": "text/html,application/xhtml+xml,*/*",
                             "Accept-Language": "en-US,en;q=0.9"},
                ) as client:
                    resp = await client.get(url)

                    # httpx normalizes header names to lowercase via .get()
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    status = resp.status_code

                    # Body capped at 64KB for title extraction
                    body = resp.text[:65536] if resp.text else ""

                    # Extract title
                    title = ""
                    m = re.search(r"<title[^>]*>([^<]{1,200})</title>",
                                  body, re.IGNORECASE | re.DOTALL)
                    if m:
                        title = m.group(1).strip()[:200]

                    missing = [h for h in SECURITY_HEADERS if h not in headers]

                    # If we were redirected, capture the final URL — reveals auth proxies
                    final_url = str(resp.url) if str(resp.url) != url else ""

                    # Extract TLS cert Subject Alternative Names (HTTPS only).
                    # This reveals which vhosts a shared IP legitimately serves — more
                    # reliable than path-guessing when a reverse proxy returns 404 on /.
                    # Hosts sharing a cert SAN often share IP too (wildcard
                    # certs, ADFS/WAP farms). Extracting SANs surfaces this.
                    #
                    # Runs in executor so the sync TLS socket call doesn't block the
                    # async event loop when many concurrent probes are in flight.
                    cert_sans: list[str] = []
                    cert_error = ""
                    if scheme == "https":
                        def _fetch_sans(h: str) -> tuple[list[str], str]:
                            """Sync worker: connect, grab DER cert, extract SANs."""
                            try:
                                import socket
                                import ssl as _ssl
                                from cryptography import x509
                                from cryptography.x509.oid import ExtensionOID
                                ctx = _ssl.create_default_context()
                                ctx.check_hostname = False
                                ctx.verify_mode = _ssl.CERT_NONE
                                sock = socket.create_connection((h, 443), timeout=5)
                                try:
                                    ssock = ctx.wrap_socket(sock, server_hostname=h)
                                    try:
                                        der = ssock.getpeercert(binary_form=True)
                                    finally:
                                        ssock.close()
                                finally:
                                    sock.close()
                                if not der:
                                    return [], "no DER cert returned"
                                cert = x509.load_der_x509_certificate(der)
                                try:
                                    ext = cert.extensions.get_extension_for_oid(
                                        ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                                    sans = [n.value for n in ext.value
                                            if hasattr(n, "value") and isinstance(n.value, str)]
                                    return sans, ""
                                except x509.ExtensionNotFound:
                                    # Fall back to CN from subject
                                    for attr in cert.subject:
                                        if attr.oid._name == "commonName":
                                            return [attr.value], ""
                                    return [], "no SAN, no CN"
                            except Exception as e:
                                return [], f"{type(e).__name__}: {str(e)[:60]}"

                        try:
                            # Run in default thread pool executor with its own timeout
                            loop = asyncio.get_event_loop()
                            cert_sans, cert_error = await asyncio.wait_for(
                                loop.run_in_executor(None, _fetch_sans, host),
                                timeout=7.0,
                            )
                        except asyncio.TimeoutError:
                            cert_error = "cert fetch timed out (>7s)"
                        except Exception as e:
                            cert_error = f"cert fetch error: {type(e).__name__}"

                    # Honest note when the probe returns 404 — reverse proxy is
                    # routing by Host header but / has no default vhost. Common
                    # on ADFS/WAP farms. Fires on any 404, not just empty body —
                    # farm 404 pages often have boilerplate "Not Found" HTML.
                    probe_note = ""
                    if status == 404:
                        probe_note = ("Responding but no default vhost on /. "
                                      "Host-header routed; probe service-specific "
                                      "paths (e.g., /adfs/ls/, /owa/, /Citrix/StoreWeb/).")

                    return {
                        "host": host,
                        "scheme": scheme,
                        "status": status,
                        "server": headers.get("server", ""),
                        "powered_by": headers.get("x-powered-by", ""),
                        "title": title,
                        "final_url": final_url,
                        "missing_security_headers": missing,
                        "cert_sans": cert_sans,
                        "cert_error": cert_error,
                        "probe_note": probe_note,
                    }

            except httpx.TimeoutException as e:
                last_error = f"timeout ({type(e).__name__})"
                continue
            except httpx.ConnectError as e:
                last_error = f"connect failed ({str(e)[:80]})"
                continue
            except httpx.HTTPError as e:
                last_error = f"http error ({type(e).__name__}: {str(e)[:80]})"
                continue
            except (OSError, ValueError) as e:
                last_error = f"{type(e).__name__}: {str(e)[:80]}"
                continue

        # Both schemes failed — record why for the log
        return {"host": host, "error": last_error or "unknown failure"}

    # Probe all auth subdomains concurrently
    hosts = [f"{label}.{domain}" for label in auth_subdomains]
    probes = await asyncio.gather(*[_probe(h) for h in hosts], return_exceptions=True)

    for host, fp in zip(hosts, probes):
        if isinstance(fp, Exception):
            log("HTTP", f"  {host} — exception: {type(fp).__name__}", level="warn")
            continue
        if not isinstance(fp, dict):
            continue

        if "error" in fp:
            # Probe attempt failed on both HTTPS and HTTP
            log("HTTP", f"  {host} — {fp['error']}", level="warn")
            continue

        result["fingerprints"].append(fp)
        tech_bits = []
        if fp.get("server"):
            tech_bits.append(fp["server"])
        if fp.get("powered_by"):
            tech_bits.append(fp["powered_by"])
        tech_str = " / ".join(tech_bits) if tech_bits else "no server header"
        redirect_note = ""
        if fp.get("final_url"):
            # Show a short form of the redirect target for context
            redirect_note = f" → {fp['final_url'][:60]}"
        log("HTTP", f"  {host} [{fp['status']}] {tech_str}{redirect_note}", level="ok")

    elapsed = time.time() - start
    log("HTTP", f"done ({elapsed:.1f}s) — {len(result['fingerprints'])}/{len(hosts)} probed",
        level="ok")
    return result


# ============================================================================
# Cloud Service Discovery
# ============================================================================

def build_cloud_tokens(domain: str, tenant_brand: str | None,
                       tenant_domains: list[dict]) -> list[str]:
    """Generate candidate tokens for cloud service DNS probing.

    Token strategy (Option A — exact tokens only, no mutations):
      1. Domain's second-level label (e.g., example.com → 'example')
      2. Tenant brand from AADOutsider, normalized (lowercased, spaces stripped).
         SKIPPED when AADOutsider returned the domain itself as the brand
         (its fallback behavior for tenants with no configured branding).
      3. Second-level labels from other tenant_domains entries (catches
         subsidiary / multi-brand ownership patterns where a tenant owns
         additional domains beyond the queried one).

    Returns deduped list. Mutation scanning is intentionally excluded — that's
    cloud_enum's job, not canvass's.
    """
    tokens: set[str] = set()

    # 1. Domain's second-level label
    if domain and "." in domain:
        primary = domain.split(".")[0].lower()
        if primary and len(primary) > 1:
            tokens.add(primary)

    # 2. Tenant brand (normalized).
    # Two-layer defense against AADOutsider brand strings that aren't proper brands:
    #
    #   Layer 1: AADOutsider returns the domain itself when no brand is configured.
    #     e.g. `example.com` returned as brand when queried domain is `example.com`.
    #     Strip normalization would produce junk tokens like `examplecom`.
    #     Skip entirely — already covered by domain param.
    #
    #   Layer 2: Brand is some OTHER domain-shaped string (sibling domain,
    #     subdomain, etc.). Common in parent/subsidiary tenants where the brand
    #     might be the parent's domain. Extract the leftmost label rather than
    #     normalizing the whole thing — `parent.com` → `parent`, `corp.example.com`
    #     → `corp`, `example.co.uk` → `example`. Preserves signal, avoids TLD junk.
    #
    # Real brand names (no dots) fall through to the normalization path unchanged.
    if tenant_brand:
        brand_lower = tenant_brand.lower().strip().rstrip(".")
        domain_lower = domain.lower()
        domain_label = domain_lower.split(".")[0] if "." in domain_lower else domain_lower

        # Layer 1: brand == domain or domain label — AADOutsider fallback, no signal
        if brand_lower == domain_lower or brand_lower == domain_label:
            tenant_brand = None
        # Layer 2: brand is a different domain-shaped string — extract leftmost label
        elif "." in brand_lower:
            label = brand_lower.split(".")[0]
            # Must be at least 2 chars and not identical to the domain label
            # (if it's identical, it's really the same org, no new signal)
            if len(label) > 1 and label != domain_label:
                tenant_brand = label  # use the label directly — no further normalization needed
            else:
                tenant_brand = None

    if tenant_brand:
        import re as _re
        # Lowercase, strip non-alphanumeric. "Example Corporation" → "examplecorporation"
        normalized = _re.sub(r"[^a-z0-9]", "", tenant_brand.lower())
        # Also try stripping corporate suffixes for a shorter variant
        # "examplecorporation" → "example" if we strip common suffixes
        CORP_SUFFIXES = ["corporation", "holdings", "company", "limited", "incorporated",
                         "corp", "inc", "llc", "ltd"]
        if normalized and len(normalized) > 1:
            tokens.add(normalized)
            for suffix in CORP_SUFFIXES:
                if normalized.endswith(suffix) and len(normalized) > len(suffix) + 1:
                    tokens.add(normalized[:-len(suffix)])
                    break

    # 3. Labels from other tenant_domains
    if tenant_domains:
        for td in tenant_domains:
            name = td.get("name", "") if isinstance(td, dict) else str(td)
            if name and "." in name and name != domain:
                label = name.split(".")[0].lower()
                if label and len(label) > 1 and not label.startswith("emails"):
                    tokens.add(label)

    # Filter obvious non-useful tokens
    EXCLUDED = {"www", "mail", "email", "webmail", "m", "login", "auth",
                "portal", "remote", "vpn", "owa", "ftp", "ns", "mx",
                "smtp", "pop", "imap", "dev", "test", "stage", "staging",
                "prod", "production", "api", "app", "web"}
    tokens = {t for t in tokens if t not in EXCLUDED}

    return sorted(tokens)


async def collect_cloud_services(domain: str, tenant_brand: str | None,
                                 tenant_domains: list[dict]) -> dict:
    """Discover cloud attack surface via passive DNS resolution.

    For each token generated by build_cloud_tokens(), try each cloud service
    pattern and record which hostnames resolve. No HTTP, no API, no auth.

    STORAGE MUTATIONS: For Azure storage patterns (blob/file/queue/table),
    additionally probes curated name mutations (`{token}prod`, `{token}01`,
    `data{token}`, etc.) because real-world Azure storage naming often doesn't
    align with the tenant brand. Exact-match only catches storage accounts where
    the tenant brand aligns with storage naming; many orgs use `{base}prod`,
    `{base}data`, etc. instead. ~15 curated mutations catches the high-frequency
    patterns without growing into cloud_enum territory.

    This is how canvass catches things like:
      - `{token}.blob.core.windows.net` (Azure Blob storage accounts)
      - `{token}prod.blob.core.windows.net` (common prod-env naming)
      - `{token}.awsapps.com` (AWS WorkDocs / Connect / IAM Identity Center)
      - `{token}.scm.azurewebsites.net` (Azure Kudu / SCM deployment console)

    WILDCARD FILTERING: Many PaaS providers (Vercel, Netlify, Heroku, Fly, Render,
    Railway, Pages.dev, etc.) wildcard-resolve ANY hostname in their zone. A DNS
    hit on `<target>.vercel.app` tells us nothing about whether the target actually
    owns a Vercel deployment. To avoid false positives, we probe each suffix with
    a random sentinel token first — if the sentinel resolves, the whole suffix
    is a wildcard zone and we skip it entirely.

    RATE LIMITING: Concurrent DNS queries are capped via semaphore (20) to avoid
    hammering corporate resolvers or tripping rate-limit / detection alerts during
    live engagements. Storage mutations can push query count to 400+ per target,
    so the cap matters.

    Output informs the active cloud enumeration phase — tester knows which
    platforms/services to target with cloud_enum, MicroBurst, s3scanner, etc.
    """
    log("CLOUD", "enumerating cloud attack surface (passive DNS)", level="run")
    start = time.time()

    result: dict = {
        "cloud_storage": {},
        "cloud_services": {},
        "cloud_m365_services": {},
        "cloud_tokens_tried": [],
        "wildcard_suffixes": [],  # suffixes that wildcard-resolve (for transparency)
    }

    tokens = build_cloud_tokens(domain, tenant_brand, tenant_domains)
    result["cloud_tokens_tried"] = tokens

    if not tokens:
        log("CLOUD", "no usable tokens — skipping", level="warn")
        return result

    log("CLOUD", f"probing {len(tokens)} token(s): {', '.join(tokens)}", level="info")

    loop = asyncio.get_event_loop()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    def resolve_any(hostname: str) -> str | None:
        """Try CNAME first, then A. Return resolution indicator or None."""
        try:
            answers = list(resolver.resolve(hostname, "CNAME"))
            if answers:
                return f"CNAME:{str(answers[0]).rstrip('.')}"
        except dns.exception.DNSException:
            pass
        try:
            answers = list(resolver.resolve(hostname, "A"))
            if answers:
                return f"A:{str(answers[0])}"
        except dns.exception.DNSException:
            pass
        return None

    # Wildcard detection: probe each suffix with a sentinel random token.
    # If the sentinel resolves, the suffix is a wildcard zone — skip it.
    import secrets
    sentinel = f"canvass-nonexistent-{secrets.token_hex(8)}"
    all_suffixes: list[tuple[str, str, str]] = []
    for suffix, label in CLOUD_STORAGE_PATTERNS:
        all_suffixes.append((suffix, "storage", label))
    for suffix, label in CLOUD_PLATFORM_PATTERNS:
        all_suffixes.append((suffix, "platform", label))
    for suffix, label in CLOUD_M365_PATTERNS:
        all_suffixes.append((suffix, "m365", label))

    # Rate limit: cap concurrent DNS queries to avoid hammering corporate resolvers
    # or triggering rate limits during engagements. Sub-second even with 400+ queries
    # given the cap parallelism.
    sem = asyncio.Semaphore(20)

    async def _resolve_with_limit(hostname: str) -> str | None:
        async with sem:
            return await loop.run_in_executor(None, resolve_any, hostname)

    async def _check_wildcard(suffix: str):
        result_val = await _resolve_with_limit(f"{sentinel}.{suffix}")
        return (suffix, result_val is not None)

    wildcard_checks = await asyncio.gather(*[
        _check_wildcard(s) for s, _, _ in all_suffixes
    ])
    wildcard_suffixes = {s for s, is_wild in wildcard_checks if is_wild}
    if wildcard_suffixes:
        log("CLOUD", f"wildcard zones detected ({len(wildcard_suffixes)}): "
            f"{', '.join(sorted(wildcard_suffixes))}", level="info")
        result["wildcard_suffixes"] = sorted(wildcard_suffixes)

    # Build non-wildcard candidate hostnames.
    # Storage category gets mutation expansion (prod/dev/stage/01/etc.) to catch
    # accounts where tenant brand doesn't align with storage naming. Platform +
    # M365 categories get exact token only — their naming is less predictable
    # and cloud_enum handles deeper enumeration in the active phase.
    candidates: list[tuple[str, str, str]] = []
    for token in tokens:
        for suffix, category, label in all_suffixes:
            if suffix in wildcard_suffixes:
                continue
            # Always probe the exact token
            candidates.append((f"{token}.{suffix}", category, label))
            # For storage only: apply curated mutations
            if category == "storage":
                for mut in STORAGE_MUTATION_SUFFIXES:
                    candidates.append((f"{token}{mut}.{suffix}", category, label))
                for mut in STORAGE_MUTATION_PREFIXES:
                    candidates.append((f"{mut}{token}.{suffix}", category, label))
        # OneDrive for Business uses `<token>-my.sharepoint.com`
        # sharepoint.com wildcards for tenants — but -my suffix only resolves for real OneDrive
        if "sharepoint.com" not in wildcard_suffixes:
            candidates.append((f"{token}-my.sharepoint.com", "m365", "OneDrive for Business"))

    if not candidates:
        log("CLOUD", "all suffixes are wildcard zones — no useful probes possible", level="warn")
        elapsed = time.time() - start
        log("CLOUD", f"done ({elapsed:.1f}s) — 0 cloud services (all wildcards)", level="ok")
        return result

    log("CLOUD", f"probing {len(candidates)} candidate(s) "
        f"(tokens × patterns + storage mutations)", level="info")

    # Resolve all concurrently via thread pool executor (dnspython is sync).
    # Semaphore caps parallelism to avoid resolver rate-limit / detection issues.
    async def _probe(hostname: str, category: str, label: str):
        result_val = await _resolve_with_limit(hostname)
        return (hostname, category, label, result_val)

    probe_results = await asyncio.gather(*[
        _probe(h, c, l) for h, c, l in candidates
    ])

    for hostname, category, label, resolution in probe_results:
        if resolution is None:
            continue
        entry = {"label": label, "resolution": resolution}
        if category == "storage":
            result["cloud_storage"][hostname] = entry
        elif category == "platform":
            result["cloud_services"][hostname] = entry
        elif category == "m365":
            result["cloud_m365_services"][hostname] = entry
        log("CLOUD", f"{label}: {hostname} → {resolution}", level="ok")

    total_found = (len(result["cloud_storage"]) + len(result["cloud_services"])
                   + len(result["cloud_m365_services"]))
    elapsed = time.time() - start
    log("CLOUD", f"done ({elapsed:.1f}s) — {total_found} cloud service(s) discovered",
        level="ok")

    return result


# ============================================================================
# Mergers
# ============================================================================

def merge_aad(brief: Brief, data: dict) -> None:
    if not data:
        return
    brief.tenant_id = data.get("tenant_id")
    brief.tenant_brand = data.get("tenant_brand")
    brief.tenant_region = data.get("tenant_region")
    brief.tenant_subregion = data.get("tenant_subregion")
    brief.federation_type = data.get("federation_type")
    brief.sts_server = data.get("sts_server") or data.get("sts")
    brief.desktop_sso = bool(data.get("desktop_sso", False))
    brief.tenant_domains = data.get("domains", []) or []

    # Tenant name handling — AADOutsider emits the literal string "None" if it
    # couldn't resolve the <tenant>.onmicrosoft.{com,us} name. Treat that as None.
    raw_name = data.get("tenant_name")
    if raw_name and raw_name != "None":
        brief.tenant_name = raw_name

    # Track source of tenant domain list
    if data.get("domains_source") == "manual_paste_from_aadinternals":
        brief.tenant_domains_source = "manual_paste"
    elif brief.tenant_domains:
        brief.tenant_domains_source = "aadoutsider"

    # MDI / AAD Connect Cloud Sync handling — CRITICAL CORRECTNESS:
    # AADOutsider's auto-detection requires tenant_name (it constructs
    # <tenant>.atp.azure.com and ADToAADSyncServiceAccount@<tenant>).
    # If tenant_name was unresolved, MDI/CloudSync results are UNRELIABLE —
    # treat them as Unknown rather than asserting False.
    aad_autodetected = (data.get("domains_source") != "manual_paste_from_aadinternals"
                        and "tenant_id" in data)
    autodetect_unreliable = aad_autodetected and not brief.tenant_name

    if "mdi_detected" in data:
        if autodetect_unreliable and data["mdi_detected"] is False:
            # Don't trust the False — leave as None (Unknown) and remember why
            brief.mdi_detected = None
        else:
            brief.mdi_detected = data["mdi_detected"]
            brief.mdi_instance = data.get("mdi_instance")
        brief.manual_signals_captured = True

    if "aad_connect_cloud_sync" in data:
        if autodetect_unreliable and data["aad_connect_cloud_sync"] is False:
            brief.aad_connect_cloud_sync = None
        else:
            brief.aad_connect_cloud_sync = data["aad_connect_cloud_sync"]
        brief.manual_signals_captured = True

    # Track signal source for transparency
    if data.get("domains_source") == "manual_paste_from_aadinternals":
        brief.signals_source = "manual_paste"
    elif "tenant_id" in data:
        brief.signals_source = "aadoutsider"


def merge_dns(brief: Brief, data: dict) -> None:
    if not data:
        return
    for key in ("mx_raw", "mx_provider", "spf_includes", "spf_all_qualifier",
                "spf_lookup_count", "spf_record_present", "dmarc_policy",
                "dmarc_subdomain_policy", "dmarc_pct", "dmarc_rua", "dmarc_ruf",
                "mta_sts_present", "mta_sts_mode", "tls_rpt_present", "caa_records",
                "txt_verifications", "m365_subdomains", "security_subdomains",
                "dkim_selectors", "srv_records"):
        if key in data:
            setattr(brief, key, data[key])


def merge_bbot(brief: Brief, data: dict) -> None:
    if not data:
        return
    brief.subdomains = data.get("subdomains", [])
    brief.emails = data.get("emails", [])
    brief.technologies = data.get("technologies", [])
    brief.takeovers = data.get("takeovers", [])


def merge_crtsh(brief: Brief, data: dict) -> None:
    """Merge crt.sh subdomains into brief.subdomains (union, dedup, sorted)."""
    if not data:
        return
    crtsh_subs = data.get("subdomains", [])
    if not crtsh_subs:
        return
    combined = set(brief.subdomains) | set(crtsh_subs)
    brief.subdomains = sorted(combined)


def merge_http_fingerprints(brief: Brief, data: dict) -> None:
    if not data:
        return
    brief.http_fingerprints = data.get("fingerprints", [])


def merge_cloud(brief: Brief, data: dict) -> None:
    """Merge cloud service discoveries into brief."""
    if not data:
        return
    brief.cloud_storage = data.get("cloud_storage", {})
    brief.cloud_services = data.get("cloud_services", {})
    brief.cloud_m365_services = data.get("cloud_m365_services", {})
    brief.cloud_tokens_tried = data.get("cloud_tokens_tried", [])
    brief.cloud_wildcard_suffixes = data.get("wildcard_suffixes", [])


# ============================================================================
# Recommendations Engine
# ============================================================================

def add_recommendations(brief: Brief) -> None:
    """Evaluate findings, append actionable recommendations."""
    log("RECS", "evaluating findings", level="run")
    r = brief.recommendations
    initial_count = len(r)

    def add(priority: str, category: str, text: str, short: str | None = None) -> None:
        """Append a recommendation and log it live so the user sees the analysis happen."""
        r.append(Recommendation(priority, category, text, short=short))
        # Truncate long texts in the log line for readability
        snippet = text if len(text) <= 90 else text[:87] + "..."
        icon_level = {"CRITICAL": "err", "HIGH": "warn", "MEDIUM": "warn",
                      "LOW": "info", "INFO": "info"}.get(priority, "info")
        log("RECS", f"[{priority}] {category}: {snippet}", level=icon_level)

    # M365 presence check
    if not brief.tenant_id and not brief.tenant_brand:
        add("HIGH", "scope",
            f"No M365 tenant detected for {brief.domain}. Verify target uses O365 before TeamFiltration.",
            short=f"No M365 tenant — verify target uses O365 before TF")

    # Subsidiary / parent-company detection — tenant brand doesn't match domain
    # Uses token-based matching with corporate-suffix stripping to avoid false
    # positives (e.g., a brand like "Example Corporation Inc." vs example.com —
    # tokens overlap on "example" so it correctly skips).
    # Fires when domain label and brand share zero tokens after suffix stripping.
    if brief.tenant_brand and brief.domain:
        CORP_SUFFIXES = {"inc", "llc", "corp", "corporation", "ltd", "limited",
                         "group", "holdings", "company", "co", "plc", "ag",
                         "gmbh", "sa", "nv", "sarl", "srl", "bv", "ab", "oy",
                         "pty", "the"}

        def _tokenize(s: str) -> set[str]:
            """Lowercase, strip punctuation+corp suffixes, return token set."""
            import re as _re
            tokens = _re.sub(r"[^a-z0-9\s]", " ", s.lower()).split()
            return {t for t in tokens if t not in CORP_SUFFIXES and len(t) > 1}

        brand_tokens = _tokenize(brief.tenant_brand)
        # Only compare against the second-level label (e.g., "example" from "example.com")
        domain_label = brief.domain.split(".")[0] if "." in brief.domain else brief.domain
        domain_tokens = _tokenize(domain_label)

        # Only fire when there's zero overlap. A brand that shares no tokens with
        # the domain label is likely a parent/acquirer, not the direct owner.
        if brand_tokens and domain_tokens and not (brand_tokens & domain_tokens):
            # Strong evidence: AADOutsider returned another tenant domain that
            # matches the brand name — near-certain subsidiary relationship.
            # brief.tenant_domains is list[dict] with keys: name, type, sts
            parent_domain = None
            for td in brief.tenant_domains:
                td_name = td.get("name", "") if isinstance(td, dict) else str(td)
                if not td_name:
                    continue
                td_label = td_name.split(".")[0] if "." in td_name else td_name
                if _tokenize(td_label) & brand_tokens:
                    parent_domain = td_name
                    break

            if parent_domain:
                add("HIGH", "scope",
                    f"Target domain `{brief.domain}` shares M365 tenant with "
                    f"`{parent_domain}` (parent brand: {brief.tenant_brand}). "
                    f"Subsidiary relationship confirmed. Verify engagement scope: "
                    f"parent org or subsidiary carve-out only?",
                    short=f"Subsidiary: {brief.domain} under {brief.tenant_brand} "
                          f"({parent_domain}) — verify scope")
            else:
                # Weaker evidence: only the brand/domain mismatch, no parent domain
                # confirmed in tenant list (common when AADOutsider throttles).
                add("MEDIUM", "scope",
                    f"Tenant brand `{brief.tenant_brand}` does not match domain "
                    f"`{brief.domain}`. Likely a subsidiary using a parent's "
                    f"M365 tenant — verify scope with client before engaging.",
                    short=f"Brand `{brief.tenant_brand}` ≠ domain — possible subsidiary")

    # Federation path — detect IdP type from STS server hostname
    # Different IdPs need different spray endpoints/tools
    if brief.federation_type == "Federated" and brief.sts_server:
        sts = brief.sts_server.lower()
        if ".okta.com" in sts or ".oktapreview.com" in sts:
            add("HIGH", "spray",
                f"Okta federation at `{brief.sts_server}`. Spray directly against Okta, not M365: "
                f"`MSOLSpray` won't work here. Use `TrevorSpray -s okta` or OktaTerrify. "
                f"Okta often has weaker MFA enforcement on legacy API endpoints.",
                short=f"Okta IdP: spray via TrevorSpray --sprayer okta (not MSOLSpray)")
        elif ".pingidentity.com" in sts or "ping" in sts and "federate" in sts:
            add("HIGH", "spray",
                f"PingFederate at `{brief.sts_server}`. Use `TrevorSpray -s ping` or manual "
                f"spray against `/idp/startSSO.ping`. Standard M365 spray won't hit this IdP.",
                short=f"PingFederate IdP: spray via TrevorSpray --sprayer ping")
        elif ".onelogin.com" in sts:
            add("HIGH", "spray",
                f"OneLogin federation at `{brief.sts_server}`. Spray against OneLogin's auth "
                f"endpoints directly, not M365.",
                short=f"OneLogin IdP: spray against OneLogin directly")
        elif "auth0" in sts:
            add("HIGH", "spray",
                f"Auth0 federation at `{brief.sts_server}`. Spray via Auth0 Resource Owner "
                f"Password Grant flow if enabled. Check `/oauth/token` endpoint.",
                short=f"Auth0 IdP: check /oauth/token ROP grant")
        elif "cloudflareaccess.com" in sts or ".access.cloudflare" in sts:
            add("HIGH", "spray",
                f"Cloudflare Access (Zero Trust) at `{brief.sts_server}`. This is a ZTNA "
                f"gateway, not traditional IdP. Traditional M365 spray won't work — "
                f"Cloudflare Access enforces its own policies (IP allowlists, device posture, "
                f"service tokens). Try spray against `/cdn-cgi/access/sso/...` endpoints or "
                f"check for exposed service tokens in GitHub dumps.",
                short=f"Cloudflare Access (ZTNA) — try /cdn-cgi/access/sso/ endpoints")
        elif "adfs" in sts or sts.startswith("sts.") or sts.startswith("fs."):
            # Classic ADFS naming — "adfs.company.com" or "sts.company.com"
            add("HIGH", "spray",
                f"ADFS at `{brief.sts_server}`. Alt spray path: "
                f"`MSOLSpray --url https://{brief.sts_server}/adfs/ls/`",
                short=f"ADFS spray: {brief.sts_server}/adfs/ls/")
        else:
            # Unknown federation — flag for manual investigation
            add("HIGH", "spray",
                f"Federated via `{brief.sts_server}` — unknown IdP type. Visit the URL to "
                f"fingerprint (ADFS/Okta/Ping/OneLogin/Auth0/custom). Different tools for each.",
                short=f"Federated via {brief.sts_server} — fingerprint IdP manually")

    if brief.desktop_sso:
        add("MEDIUM", "spray",
            "Seamless SSO (DesktopSSO) enabled. AzureAD SSO brute-force technique applicable.",
            short="Seamless SSO enabled — AzureAD SSO brute-force applicable")

    # Email security -> phishing viability
    if brief.mx_provider == "Proofpoint":
        add("HIGH", "phishing",
            "Proofpoint email filtering detected. Phishing success likely low. Focus on spray/enum.",
            short="Proofpoint — skip phishing, focus on spray/enum")
    elif brief.mx_provider == "Mimecast":
        add("MEDIUM", "phishing",
            "Mimecast detected. Phishing harder but possible with quality lures.",
            short="Mimecast — phishing harder but possible with quality lures")
    elif brief.mx_provider == "unknown" and not brief.dmarc_policy:
        add("MEDIUM", "phishing",
            "Weak email security posture (no known vendor, no DMARC). Phishing viable if in scope.",
            short="Weak email security — phishing viable if in scope")

    # Self-hosted MX detection — target runs its own mail infrastructure.
    # Common in FSI, gov, legal, healthcare. Implies:
    #   1. No vendor email security layer (target is on its own for inbound filtering)
    #   2. Exposed mail infra is a direct recon target (MTA fingerprint, CVEs)
    #   3. Often indicates on-prem Exchange / legacy MTA — larger attack surface
    # Detection: MX hostname ends in target domain (mx01.target.com, mail.target.com)
    # and MX vendor wasn't identified by the known-vendors list.
    if brief.mx_raw and brief.mx_provider == "unknown":
        self_hosted_mx = [mx for mx in brief.mx_raw
                          if mx.endswith(f".{brief.domain}") or mx == brief.domain]
        if self_hosted_mx:
            add("MEDIUM", "recon",
                f"Self-hosted mail infrastructure: {', '.join(self_hosted_mx[:2])}. "
                f"Target runs own MTA — no vendor email security layer. Fingerprint "
                f"versions for CVEs (check for legacy Exchange, unpatched Postfix/Exim, "
                f"etc.). Inbound phishing has no vendor filter to bypass.",
                short=f"Self-hosted MX ({self_hosted_mx[0]}) — no vendor filter, "
                      f"fingerprint MTA for CVEs")

    # DMARC enforcement level — spans the full range of policies
    # p=reject: domain cannot be spoofed (barring SPF/DKIM alignment tricks)
    # p=quarantine: spoofing lands in spam, some risk
    # p=none: monitoring only, spoofed mail delivered normally — worth flagging
    # no DMARC: no DMARC record at all — worst case
    if brief.dmarc_policy == "reject":
        add("INFO", "phishing",
            "DMARC `p=reject` enforced. External spoofing of this domain will fail.",
            short="DMARC p=reject — external spoofing will fail")
    elif brief.dmarc_policy == "quarantine":
        add("MEDIUM", "phishing",
            "DMARC `p=quarantine`. Spoofing lands in spam folder but can still be delivered; "
            "some clients auto-approve sender-spoof patterns.",
            short="DMARC p=quarantine — spoofing possible, lands in spam")
    elif brief.dmarc_policy == "none":
        add("MEDIUM", "phishing",
            "DMARC `p=none` — record exists but monitoring only, zero enforcement. "
            "Spoofed mail delivered normally to inbox. Phishing from spoofed sender viable.",
            short="DMARC p=none — monitor only, spoofing delivered to inbox")
    elif not brief.dmarc_policy:
        # No DMARC record at all — already partially covered by the "unknown vendor" rule above
        # but this fires even when a vendor IS detected (Proofpoint + no DMARC = still a finding)
        if brief.mx_provider != "unknown":
            add("MEDIUM", "phishing",
                f"No DMARC record configured despite {brief.mx_provider} at MX. "
                f"Spoofing this domain's own outbound mail is trivial.",
                short=f"No DMARC (but {brief.mx_provider} inbound) — outbound spoof trivial")

    # SaaS -> alternate identity paths
    if "Okta IdP" in brief.txt_verifications:
        add("HIGH", "spray",
            "Okta IdP confirmed. M365 may federate through Okta. Consider direct Okta spray.",
            short="Okta IdP — consider direct Okta spray")

    if "OneLogin IdP" in brief.txt_verifications:
        add("MEDIUM", "spray",
            "OneLogin IdP confirmed. Alternate auth path.",
            short="OneLogin IdP — alternate auth path")

    if "Google Workspace" in brief.txt_verifications and brief.tenant_id:
        add("HIGH", "scope",
            "Hybrid identity: Google Workspace + M365 both present. Verify primary auth source before scoping.",
            short="Hybrid Google + M365 — verify primary IdP")

    # M365 integration signals
    if "enterpriseenrollment" in brief.m365_subdomains:
        add("MEDIUM", "spray",
            "Intune MDM detected. Device compliance Conditional Access likely. Some spray paths may hit device checks.",
            short="Intune MDM — device compliance CA likely")

    if "enterpriseregistration" in brief.m365_subdomains:
        add("INFO", "enum",
            "Hybrid AD Join detected. On-prem AD + Entra ID coexist.",
            short="Hybrid AD Join detected")

    # MDI / Cloud Sync — auto-detected by AADOutsider-py or manually captured
    if brief.mdi_detected is True:
        mdi_note = f" (`{brief.mdi_instance}`)" if brief.mdi_instance else ""
        short_note = f" ({brief.mdi_instance})" if brief.mdi_instance else ""
        add("HIGH", "opsec",
            f"Microsoft Defender for Identity (MDI) detected{mdi_note}. Mature SOC capability. "
            "Use longest possible spray sleeps (4hr+), shuffle everything, "
            "consider OPSEC-evading tooling beyond TF defaults. Expect detection of obvious patterns.",
            short=f"MDI detected{short_note} — mature SOC, use 4hr+ sleeps")
    elif brief.mdi_detected is False:
        add("INFO", "opsec",
            "No MDI detected. SOC may have limited identity-layer visibility — slightly higher tolerance for spray volume.",
            short="No MDI — SOC may have limited identity visibility")
    elif brief.signals_source == "aadoutsider" and brief.tenant_id:
        add("MEDIUM", "opsec",
            "MDI status UNKNOWN — AADOutsider could not resolve tenant `.onmicrosoft` name "
            "(likely throttled or single-domain result). Re-run later or use paste mode "
            "to verify before assuming SOC posture.",
            short="MDI status unknown — verify before spraying")

    if brief.aad_connect_cloud_sync is True:
        add("INFO", "enum",
            "Azure AD Connect Cloud Sync in use (modern cloud-side sync, not classic on-prem AD Connect). "
            "Passwords sync but no on-prem AD compromise path via this — different attack model than ADFS/AAD Connect.",
            short="AAD Connect Cloud Sync — no on-prem AD compromise path")

    # US Government cloud detection — major scope/regulatory signal
    if brief.tenant_subregion in ("GCC", "GCCH", "DOD", "DODCON"):
        gov_cloud_name = {
            "GCC": "Government Community Cloud (GCC)",
            "GCCH": "Government Community Cloud High (GCC High)",
            "DOD": "DoD Cloud",
            "DODCON": "DoD Cloud (DODCON)",
        }.get(brief.tenant_subregion, brief.tenant_subregion)
        short_gov = {"GCC": "GCC", "GCCH": "GCC High", "DOD": "DoD", "DODCON": "DoD"}.get(brief.tenant_subregion, brief.tenant_subregion)
        add("HIGH", "scope",
            f"⚠ {gov_cloud_name} tenant detected. US Government cloud — different "
            "API endpoints (`login.microsoftonline.us`), tighter compliance posture, "
            "potential additional regulatory exposure. Verify engagement scope explicitly "
            "authorizes government cloud testing and that all tooling targets "
            "the correct endpoints (TF, MSOLSpray, etc. need GCC-aware flags).",
            short=f"⚠ {short_gov} tenant — US Government cloud, check auth scope")

    # Exposed auth services
    if "adfs" in brief.security_subdomains:
        target = brief.security_subdomains["adfs"]
        add("HIGH", "spray",
            f"ADFS exposed at `adfs.{brief.domain}` ({target}). Direct spray target.",
            short=f"ADFS exposed: adfs.{brief.domain} — direct spray target")

    if "vpn" in brief.security_subdomains:
        target = brief.security_subdomains["vpn"]
        add("INFO", "enum",
            f"VPN portal at `vpn.{brief.domain}` ({target}). Consider if in scope.",
            short=f"VPN portal: vpn.{brief.domain} — check scope")

    if "citrix" in brief.security_subdomains or "rdweb" in brief.security_subdomains:
        add("MEDIUM", "spray",
            "Citrix/RDWeb portal detected. Alternate spray target for external access.",
            short="Citrix/RDWeb portal — alternate spray target")

    # Subdomain takeovers / dangling records — highest-value external findings
    for t in brief.takeovers:
        host = t.get("host", "unknown")
        module = t.get("module", "?").upper()
        desc_snippet = t.get("description", "")[:80]
        if t.get("type") == "VULNERABILITY":
            # signature-matched, confirmed/probable takeover
            add("HIGH", "takeover",
                f"Subdomain takeover opportunity at `{host}` ({module}). {desc_snippet}",
                short=f"⚠ Takeover: {host} [{module}]")
        else:
            # FINDING — dangling record without signature match (possible but not confirmed)
            add("MEDIUM", "takeover",
                f"Dangling DNS record at `{host}` ({module}) — investigate for takeover potential. {desc_snippet}",
                short=f"Dangling: {host} [{module}] — investigate")

    # External attack surface
    if len(brief.subdomains) > 100:
        add("INFO", "scope",
            f"Large external footprint ({len(brief.subdomains)} subdomains). Review scope carefully.",
            short=f"Large footprint ({len(brief.subdomains)} subdomains) — review scope")

    if brief.emails:
        add("INFO", "enum",
            f"{len(brief.emails)} emails found via BBOT. Review for format pattern before TF enum.",
            short=f"{len(brief.emails)} emails found — review format before TF enum")

    # ============================================================================
    # Enhanced rules — DNS hygiene, tech stack CVEs, IdP diversity, dev/test exposure
    # ============================================================================

    # Email format detection from captured emails (when BBOT finds multiple)
    if brief.emails and len(brief.emails) >= 2:
        # Filter out generic role emails and count format patterns
        personal = [e for e in brief.emails
                    if not any(role in e.lower().split("@")[0]
                               for role in ("info", "admin", "support", "contact", "sales",
                                            "noreply", "postmaster", "abuse", "security",
                                            "webmaster", "hostmaster", "alumni", "registrar"))]
        if personal:
            # Categorize by format
            first_last = sum(1 for e in personal
                             if "." in e.split("@")[0] and e.split("@")[0].count(".") == 1
                             and all(p.isalpha() or "-" in p for p in e.split("@")[0].split(".")))
            if first_last >= len(personal) * 0.6:
                samples = ", ".join(personal[:3])
                add("HIGH", "enum",
                    f"Email format detected: `first.last@{brief.domain}` ({first_last}/{len(personal)} samples). "
                    f"Use for TF enum: `TeamFiltration --enum --validate-onedrive`. Samples: {samples}",
                    short=f"Format: first.last@ ({first_last}/{len(personal)} samples)")

    # DMARC — partial enforcement (pct < 100) is a real finding
    if brief.dmarc_pct is not None and brief.dmarc_pct < 100:
        add("HIGH", "phishing",
            f"DMARC enforces at only pct={brief.dmarc_pct}%. Remaining {100-brief.dmarc_pct}% of "
            f"spoofed email delivered normally. Spoofing viable in most attempts.",
            short=f"DMARC pct={brief.dmarc_pct}% — partial enforcement, spoofing viable")

    # DMARC — subdomain policy weaker than domain policy
    if (brief.dmarc_subdomain_policy and brief.dmarc_policy
            and brief.dmarc_subdomain_policy != brief.dmarc_policy
            and brief.dmarc_subdomain_policy in ("none", "quarantine")):
        add("MEDIUM", "phishing",
            f"DMARC subdomain policy `sp={brief.dmarc_subdomain_policy}` weaker than "
            f"`p={brief.dmarc_policy}`. Spoof via unused subdomains (e.g. `it.{brief.domain}`).",
            short=f"DMARC sp={brief.dmarc_subdomain_policy} — spoof via subdomains")

    # DMARC rua — where forensic reports go (attack surface if spoofable)
    if brief.dmarc_rua:
        # Only flag as recon-relevant if the address is external (different domain)
        external_rua = [addr for addr in brief.dmarc_rua
                        if brief.domain not in addr.lower()]
        if external_rua:
            add("INFO", "recon",
                f"DMARC reports sent to external address(es): {', '.join(external_rua[:2])}. "
                f"Reveals 3rd-party DMARC vendor relationship.",
                short=f"DMARC reports → external: {', '.join(external_rua[:2])}")

    # SPF +all — critical misconfiguration
    if brief.spf_all_qualifier == "+":
        add("CRITICAL", "phishing",
            f"SPF record ends in `+all` — anyone on the internet can spoof as this domain. "
            f"No SPF protection at all. Phishing highly viable.",
            short=f"⚠⚠ SPF +all — anyone can spoof this domain")
    elif brief.spf_all_qualifier == "?":
        add("MEDIUM", "phishing",
            f"SPF `?all` (neutral) — no enforcement signal to recipients. Similar to no SPF.",
            short=f"SPF ?all — no enforcement, phishing viable")
    elif brief.spf_all_qualifier == "~":
        add("INFO", "phishing",
            f"SPF `~all` (softfail) — weak enforcement, recipients may still deliver spoofed mail to inbox or spam.",
            short=f"SPF ~all — softfail, partially viable")
    elif brief.spf_record_present is False and brief.mx_provider != "unknown":
        # Only fire when we CONFIRMED no SPF record exists (not when DNS timed out).
        # spf_record_present is True only when v=spf1 was actually seen.
        # Combined with mx_provider being known (MX lookup succeeded), we're confident.
        add("HIGH", "phishing",
            f"No SPF record configured. Spoofing this domain is trivial — no validation "
            f"possible. Combined with DMARC posture, determines phishing viability.",
            short=f"No SPF record — spoofing trivial")

    # SPF lookup count exceeds 10 (breaks SPF entirely per RFC)
    if brief.spf_lookup_count and brief.spf_lookup_count > 10:
        add("HIGH", "phishing",
            f"SPF record exceeds 10 DNS lookups ({brief.spf_lookup_count}). Per RFC, this causes "
            f"permerror — all SPF validation fails, effectively no protection. Phishing viable.",
            short=f"SPF lookups={brief.spf_lookup_count} (>10) — permerror, no protection")

    # MTA-STS absent on M365 tenant = common defensive gap
    if brief.mx_provider == "Microsoft 365" and not brief.mta_sts_present:
        add("INFO", "phishing",
            f"No MTA-STS configured despite M365. Man-in-the-middle downgrade on inbound mail "
            f"is theoretically possible. Report for defender guidance.",
            short=f"No MTA-STS on M365 — MITM downgrade possible (defender note)")

    # CAA records absent = any CA can issue certs (DNS-hijack + rogue cert = impersonation)
    if not brief.caa_records and brief.domain.count(".") == 1:
        add("INFO", "opsec",
            f"No CAA records. Any CA can issue certs for `{brief.domain}`. "
            f"DNS hijack + rogue cert would enable full impersonation.",
            short=f"No CAA — any CA can issue certs")

    # IdP diversity = password reuse risk across multiple login surfaces
    idp_signals = []
    if brief.tenant_id:
        idp_signals.append("M365")
    if "Okta IdP" in brief.txt_verifications:
        idp_signals.append("Okta")
    if "OneLogin IdP" in brief.txt_verifications:
        idp_signals.append("OneLogin")
    if "Adobe IdP" in brief.txt_verifications:
        idp_signals.append("Adobe")
    # Check for CAS / Shibboleth / IdP subdomain signals
    subdomain_str = " ".join(brief.subdomains).lower()
    if "shibboleth" in subdomain_str:
        idp_signals.append("Shibboleth")
    if any(s.startswith("cas.") or ".cas." in s for s in brief.subdomains):
        idp_signals.append("CAS")
    if any("idp." in s for s in brief.subdomains):
        idp_signals.append("custom IdP")
    if len(idp_signals) >= 3:
        add("HIGH", "spray",
            f"Multiple IdPs detected: {', '.join(idp_signals)}. Password reuse risk HIGH. "
            f"Failed spray on one surface → retry same creds on others.",
            short=f"{len(idp_signals)} IdPs ({', '.join(idp_signals[:3])}) — password reuse risk")

    # Dev/test/staging subdomains — classically weaker auth
    dev_patterns = ("-dev", "-test", "-staging", "-stage", "-uat", "-qa", "-prod",
                    "dev1.", "dev2.", "test1.", "test2.", "devtest", "testdev")
    dev_subs = [s for s in brief.subdomains
                if any(p in s.lower() for p in dev_patterns)]
    if len(dev_subs) >= 3:
        add("MEDIUM", "scope",
            f"{len(dev_subs)} dev/test/staging subdomains externally reachable "
            f"(e.g. {', '.join(dev_subs[:3])}). Often weaker auth, stale data, shared creds.",
            short=f"{len(dev_subs)} dev/test subs exposed — often weaker auth")

    # WAF in path = origin may be directly reachable if IP leaks
    tech_str = " ".join(brief.technologies).lower()
    if "cloudflare" in tech_str:
        add("INFO", "recon",
            f"Cloudflare WAF detected. Traditional port scans against public IPs may miss "
            f"the origin server. Check DNS history / crt.sh for origin IP leaks.",
            short=f"Cloudflare WAF — check DNS history for origin IP leaks")
    if "incapsula" in tech_str or "imperva" in tech_str:
        add("INFO", "recon",
            f"Incapsula/Imperva WAF detected. Active web testing will be rate-limited. "
            f"Consider authenticated testing from inside client's network if available.",
            short=f"Incapsula WAF — web testing rate-limited")

    # FortiOS VPN — 2024-2025 had multiple critical CVEs
    if "fortinet" in tech_str or "fortios" in tech_str:
        add("HIGH", "recon",
            f"FortiOS detected. Cross-check version against recent CVEs: CVE-2024-55591 "
            f"(pre-auth RCE), CVE-2024-21762 (SSL VPN), CVE-2023-27997. Fingerprint first.",
            short=f"FortiOS — check CVE-2024-55591, CVE-2024-21762, CVE-2023-27997")

    # SonicWall — similar recent CVE history
    if "sonicwall" in tech_str or "sonicos" in tech_str:
        add("MEDIUM", "recon",
            f"SonicWall appliance detected. Recent CVEs: CVE-2024-40766 (access control bypass), "
            f"CVE-2024-38475. Fingerprint version against public advisories.",
            short=f"SonicWall — check CVE-2024-40766, CVE-2024-38475")

    # Pulse Secure / Ivanti Connect Secure — persistent CVE target
    if "pulse" in tech_str or "ivanti" in tech_str:
        add("HIGH", "recon",
            f"Pulse/Ivanti VPN detected. Heavy CVE history: CVE-2024-21887, CVE-2023-46805, "
            f"CVE-2024-22024. Version check is critical.",
            short=f"Pulse/Ivanti — multiple critical CVEs (2024)")

    # Citrix NetScaler / ADC — CitrixBleed class
    if any(s in tech_str for s in ("netscaler", "citrix adc")):
        add("HIGH", "recon",
            f"Citrix NetScaler/ADC detected. CitrixBleed (CVE-2023-4966) and successors active. "
            f"Fingerprint version immediately.",
            short=f"Citrix NetScaler — check CVE-2023-4966 (CitrixBleed)")

    # Legacy Exchange on-prem — large attack surface (ProxyShell, etc.)
    if any(s.startswith(("exchange.", "owa.", "ecp.", "mail.")) and
           "outlook.com" not in brief.m365_subdomains.get(s.split(".")[0], "")
           for s in brief.subdomains):
        on_prem_exchange = [s for s in brief.subdomains
                            if s.startswith(("exchange.", "owa.", "ecp."))]
        if on_prem_exchange:
            add("HIGH", "recon",
                f"Legacy on-prem Exchange surface: {', '.join(on_prem_exchange[:2])}. "
                f"ProxyShell (CVE-2021-34473), ProxyLogon (CVE-2021-26855) still commonly unpatched.",
                short=f"Legacy Exchange: {on_prem_exchange[0]} — check ProxyShell/ProxyLogon")

    # GCC tenant → TF needs specific flag
    if brief.tenant_subregion == "GCC":
        add("HIGH", "spray",
            f"GCC tenant. TF requires `--us-cloud` flag to target login.microsoftonline.us "
            f"(not login.microsoftonline.com).",
            short=f"GCC tenant — TF needs --us-cloud flag")

    # Multiple SaaS IdP-capable services → same password reuse angle
    idp_saas = [s for s in ("Okta IdP", "OneLogin IdP", "Adobe IdP", "Google Workspace")
                if s in brief.txt_verifications]
    if len(idp_saas) >= 2 and brief.tenant_id:
        add("MEDIUM", "spray",
            f"Target uses M365 + {', '.join(idp_saas)}. Spray failures on one platform → "
            f"try same creds on others (SaaS password reuse is common).",
            short=f"Multi-IdP spray: M365 + {', '.join(idp_saas)}")

    # Hub / Colleague / Moodle / Ellucian — higher-ed specific
    edu_systems = []
    if any("colleague" in s.lower() for s in brief.subdomains):
        edu_systems.append("Ellucian Colleague")
    if any("moodle" in s.lower() for s in brief.subdomains):
        edu_systems.append("Moodle")
    if any("banner" in s.lower() for s in brief.subdomains):
        edu_systems.append("Ellucian Banner")
    if any("canvas" in s.lower() for s in brief.subdomains):
        edu_systems.append("Canvas LMS")
    if any("blackboard" in s.lower() for s in brief.subdomains):
        edu_systems.append("Blackboard")
    if edu_systems:
        add("INFO", "recon",
            f"Higher-ed systems detected: {', '.join(edu_systems)}. Often have separate auth, "
            f"admin portals, and default creds. Worth manual investigation.",
            short=f"Higher-ed systems: {', '.join(edu_systems)}")

    # BBOT skipped → remind about API keys
    if not brief.subdomains and not brief.takeovers:
        add("INFO", "opsec",
            f"BBOT skipped this run. For full coverage, drop API keys in `~/.config/bbot/bbot.yml` "
            f"(Chaos, VirusTotal, GitHub free; SecurityTrails paid) for 20-50% more subdomains.",
            short=f"Tip: add BBOT API keys to ~/.config/bbot/bbot.yml")

    # Proofpoint + weak DMARC = contradiction worth noting
    if brief.mx_provider == "Proofpoint" and brief.dmarc_policy in ("none", None):
        add("MEDIUM", "phishing",
            f"Proofpoint at MX but DMARC p={brief.dmarc_policy or 'none'}. Inbound filtering "
            f"strong, but their own domain can still be spoofed outbound. Vendor impersonation path.",
            short=f"Proofpoint inbound but weak DMARC — vendor impersonation viable")

    # Managed M365 (no ADFS) + no MDI = easiest spray scenario
    if (brief.federation_type == "Managed" and brief.mdi_detected is False
            and brief.tenant_id):
        add("INFO", "spray",
            f"Managed M365 with no MDI. Simplest spray scenario: no federation redirects, "
            f"no identity-layer alerting. Standard TF `--spray --aad-sso` applies.",
            short=f"Managed + no MDI — simplest spray target")

    # =====================================================================
    # Cloud attack surface recommendations — fire on passive discoveries.
    # Severity rationale:
    #   HIGH:   never from passive DNS alone (credentials required for HIGH)
    #   MEDIUM: management interfaces (Kudu/SCM) — direct exploit path if creds obtained
    #   INFO:   storage/apps/M365-cloud — informational, inform active enum phase
    # =====================================================================

    # Azure Kudu / SCM management console exposure
    kudu_hosts = [h for h in brief.cloud_services
                  if "scm.azurewebsites.net" in h]
    if kudu_hosts:
        host = kudu_hosts[0]
        add("MEDIUM", "cloud",
            f"Azure Kudu/SCM console at `{host}` — management interface providing "
            f"file system access and command execution if credentials obtained. "
            f"Becomes HIGH if creds land via spray or other phases. "
            f"Test auth posture and check for IP restrictions in active phase.",
            short=f"Azure Kudu SCM exposed ({host}) — mgmt interface, escalates with creds")

    # Cloud storage discovery
    if brief.cloud_storage:
        providers = sorted({e.get("label", "").split(" (")[0]
                            for e in brief.cloud_storage.values()})
        n_hosts = len(brief.cloud_storage)
        add("INFO", "cloud",
            f"{n_hosts} cloud storage endpoint(s) discovered ({', '.join(providers)}). "
            f"Passive DNS only — run `cloud_enum` or `s3scanner` in active phase to test "
            f"access, enumerate containers, and check for exposed SAS tokens/keys in public sources.",
            short=f"Cloud storage discovered ({', '.join(providers[:3])}) — test access with cloud_enum")

    # AWS apps portal (WorkDocs / Connect / SSO)
    aws_apps = [h for h in brief.cloud_services if h.endswith(".awsapps.com")]
    if aws_apps:
        host = aws_apps[0]
        add("INFO", "cloud",
            f"AWS apps portal at `{host}`. This resolves to services like WorkDocs, "
            f"Amazon Connect, or IAM Identity Center (SSO). Identify specific service "
            f"via active probing — each has different attack paths.",
            short=f"AWS apps portal ({host}) — identify service (WorkDocs/Connect/SSO)")

    # SharePoint / OneDrive M365 cloud surface.
    # Multiple SharePoint tenants resolving from our token set is a meaningful signal:
    # usually indicates parent/acquirer relationship (subsidiary's users sit on parent's
    # M365 tenant) OR a brand-renaming situation. Either way, scope implications matter
    # — creds landed on the target can reach data in a SharePoint tenant that may
    # be out-of-scope. Flag explicitly rather than hiding in a generic rec.
    sp_hosts = [h for h in brief.cloud_m365_services
                if "sharepoint.com" in h and not h.endswith("-my.sharepoint.com")]
    od_hosts = [h for h in brief.cloud_m365_services
                if h.endswith("-my.sharepoint.com")]

    if sp_hosts or od_hosts:
        # Derive distinct tenant tokens from the hostnames we found.
        sp_tokens = sorted({h.split(".")[0] for h in sp_hosts})
        domain_label = brief.domain.split(".")[0].lower()

        if len(sp_tokens) > 1:
            # Multiple SharePoint tenants — parent/subsidiary signal.
            # Pull out the non-domain tokens for the scope flag.
            other_tokens = [t for t in sp_tokens if t != domain_label]
            other_tenant_note = (
                f" Parent/acquirer tenant signal: `{', '.join(other_tokens)}` does not match domain label. "
                f"Creds landing on target may reach data in these tenants — "
                f"CONFIRM SCOPE with client before post-auth exfil."
                if other_tokens and domain_label in sp_tokens
                else f" Multiple M365 tenants detected. Verify ownership + scope before post-auth work."
            )
            add("MEDIUM", "cloud",
                f"M365 cloud surface: {len(sp_tokens)} SharePoint tenants discovered "
                f"({', '.join(f'`{t}.sharepoint.com`' for t in sp_tokens)}). "
                f"{other_tenant_note} "
                f"Post-auth target for TeamFiltration (`--exfil --sharepoint`, `--exfil --onedrive`) — "
                f"scope all tenants before exfil.",
                short=f"Multiple SharePoint tenants ({', '.join(sp_tokens)}) — verify scope before exfil")
        else:
            # Single tenant — standard informational finding.
            parts = []
            if sp_hosts:
                parts.append(f"SharePoint Online (`{sp_hosts[0]}`)")
            if od_hosts:
                parts.append(f"OneDrive for Business (`{od_hosts[0]}`)")
            add("INFO", "cloud",
                f"M365 cloud surface confirmed: {', '.join(parts)}. "
                f"Post-auth target for TeamFiltration modules (`--exfil --sharepoint`, "
                f"`--exfil --onedrive`) if spray lands credentials in Phase 7.",
                short=f"M365 cloud surface: {' + '.join(['SP' if sp_hosts else '', 'OneDrive' if od_hosts else '']).strip(' +')} — post-auth target")

    # Dynamics 365 — separate rec since it's a distinct attack surface from SP/OneDrive
    dynamics_hosts = [h for h in brief.cloud_m365_services
                      if h.endswith(".crm.dynamics.com")]
    if dynamics_hosts:
        add("INFO", "cloud",
            f"Dynamics 365 CRM at `{dynamics_hosts[0]}`. Customer / sales data surface. "
            f"Post-auth target — if creds land with Dynamics license, accessible via "
            f"the Dataverse Web API.",
            short=f"Dynamics 365 CRM ({dynamics_hosts[0]}) — customer/sales data post-auth target")

    # Always end with next action
    add("INFO", "next",
            f"Next: `TeamFiltration --enum --tenant-info --domain {brief.domain}`",
            short=f"TeamFiltration --enum --tenant-info --domain {brief.domain}")

    fired = len(r) - initial_count
    log("RECS", f"done — {fired} recommendation{'s' if fired != 1 else ''} generated", level="ok")



# ============================================================================
# Markdown Template
# ============================================================================

TEMPLATE = """# Pre-Engagement Brief - {{ b.domain }}

*Generated: {{ b.generated_at }}*

---

## M365 Tenant

> **Cross-check:** [osint.aadinternals.com](https://osint.aadinternals.com) — query `{{ b.domain }}` to verify these signals against DrAzureAD's hosted OSINT tool. Requires Entra ID login with a non-default (.onmicrosoft.com) domain.

{% if b.tenant_id or b.tenant_brand or b.manual_signals_captured %}
{% if b.tenant_id or b.tenant_brand %}
- **Brand:** {{ b.tenant_brand or 'Unknown' }}
- **Tenant ID:** `{{ b.tenant_id or 'Unknown' }}`
{% if b.tenant_name %}
- **Tenant Name:** `{{ b.tenant_name }}`
{% endif %}
- **Region:** {{ b.tenant_region or 'Unknown' }}
{% if b.tenant_subregion %}
- **Sub-region:** {{ b.tenant_subregion }}
{% endif %}
- **Federation:** {{ b.federation_type or 'Unknown' }}
{% if b.sts_server %}
- **STS Server:** `{{ b.sts_server }}`
{% endif %}
- **DesktopSSO:** {{ b.desktop_sso }}
{% else %}
*Local AAD collector returned no data — install AADOutsider-py for full tenant intel.*
{% endif %}
{% if b.manual_signals_captured %}
{% set mdi_label = 'Yes' if b.mdi_detected is sameas true else ('No' if b.mdi_detected is sameas false else 'Unknown') %}
{% set cs_label = 'Yes' if b.aad_connect_cloud_sync is sameas true else ('No' if b.aad_connect_cloud_sync is sameas false else 'Unknown') %}
- **MDI Detected:** {{ mdi_label }}
{% if b.mdi_instance %}
- **MDI Instance:** `{{ b.mdi_instance }}`
{% endif %}
- **AAD Connect Cloud Sync:** {{ cs_label }}

{% if b.signals_source == 'aadoutsider' and not b.tenant_name and (b.mdi_detected is none or b.aad_connect_cloud_sync is none) %}
*MDI/Cloud Sync detection requires the tenant's `.onmicrosoft.{com,us}` name, which AADOutsider could not resolve (likely throttled or single-domain result). Re-run later, or cross-check via [osint.aadinternals.com](https://osint.aadinternals.com) and use `--paste-domains` to override.*
{% elif b.signals_source == 'aadoutsider' %}
*Signals auto-detected by AADOutsider-py.*
{% elif b.signals_source == 'manual_paste' %}
*Signals manually captured via paste mode from osint.aadinternals.com.*
{% endif %}
{% endif %}
{% else %}
**No M365 tenant detected for `{{ b.domain }}`.**
{% endif %}

### Tenant Domains

{% if b.tenant_domains %}
| Domain | Type |
|--------|------|
{% for d in b.tenant_domains %}
| {{ d.name }} | {{ d.type or '-' }} |
{% endfor %}

{% if b.tenant_domains_source == 'manual_paste' %}
*Source: manually pasted from osint.aadinternals.com*
{% elif b.tenant_domains_source == 'aadoutsider' %}
*Source: AADOutsider-py via Autodiscover SOAP endpoint{% if b.tenant_domains|length == 1 %} (small tenant — only 1 domain registered){% endif %}*
{% else %}
*Only the queried domain is shown — install AADOutsider-py for full tenant domain enumeration, or paste from osint.aadinternals.com (requires Entra ID login):*

1. Visit https://osint.aadinternals.com (sign in with an Entra ID account that has a non-default `.onmicrosoft.com` domain)
2. Query `{{ b.domain }}`
3. Run `python3 brief.py {{ b.domain }} --paste-domains` and paste the result
{% endif %}
{% else %}
_No tenant domain data available._
{% endif %}

---

## Email Security

- **MX Provider:** {{ b.mx_provider }}
- **DMARC Policy:** {{ b.dmarc_policy or 'not configured' }}

{% if b.mx_raw %}
**MX Records:**
{% for mx in b.mx_raw %}
- `{{ mx }}`
{% endfor %}
{% endif %}

{% if b.spf_includes %}
**SPF Includes:**
{% for inc in b.spf_includes %}
- `{{ inc }}`
{% endfor %}
{% endif %}

---

## Confirmed SaaS Services

{% if b.txt_verifications %}
{% for service in b.txt_verifications.keys() %}
- **{{ service }}**
{% endfor %}
{% else %}
_No SaaS verification tokens found in DNS._
{% endif %}

---

## M365 Integration Signals

{% if b.m365_subdomains %}
{% for label, target in b.m365_subdomains.items() %}
- `{{ label }}.{{ b.domain }}` -> `{{ target }}`
{% endfor %}
{% else %}
_No M365 integration CNAMEs found._
{% endif %}

---

## Auth/Security Subdomains

{% if b.security_subdomains %}
{% for label, target in b.security_subdomains.items() %}
- `{{ label }}.{{ b.domain }}` -> `{{ target }}`
{% endfor %}
{% else %}
_No common auth subdomains exposed._
{% endif %}

---

## Infrastructure (BBOT)

- **Subdomains:** {{ b.subdomains | length }}
- **Emails found:** {{ b.emails | length }}
- **Technologies:** {{ b.technologies | length }}

{% if b.subdomains %}
### Top Subdomains (first 25)
{% for s in b.subdomains[:25] %}
- `{{ s }}`
{% endfor %}
{% if b.subdomains | length > 25 %}
_...and {{ b.subdomains | length - 25 }} more (see `bbot-output/`)_
{% endif %}
{% endif %}

{% if b.technologies %}
### Technologies Detected
{% for t in b.technologies[:20] %}
- {{ t }}
{% endfor %}
{% endif %}

---

## Supplementary Data

{% if b.dkim_selectors %}
**DKIM Selectors Present:** {{ b.dkim_selectors | join(', ') }}
{% endif %}

{% if b.srv_records %}
**SRV Records:**
{% for name, records in b.srv_records.items() %}
- `{{ name }}`: {{ records | join('; ') }}
{% endfor %}
{% endif %}

---

## Recommendations

{% if not b.recommendations %}
_No recommendations generated._
{% else %}
{% for rec in b.recommendations %}
- **[{{ rec.priority }}]** _{{ rec.category }}_ - {{ rec.text }}
{% endfor %}
{% endif %}

---

## Raw Data Files

- `aad-raw.json` - AADOutsider-py output
- `dns-raw.json` - DNS collector output
- `bbot-output/` - full BBOT scan results
{% if b.tenant_domains_source == 'manual_paste' %}
- `pasted-domains.txt` - raw paste from osint.aadinternals.com
{% endif %}
"""


def render_markdown(brief: Brief) -> str:
    template = jinja2.Template(TEMPLATE, trim_blocks=True, lstrip_blocks=True)
    return template.render(b=brief)


def render_text(brief: Brief, companion_files: dict | None = None) -> str:
    """Render the full brief as plain text — same content as markdown, no md syntax.

    Used for environments where markdown rendering is inconvenient (terminal viewing,
    email body, Slack paste, report attachments). For the compact terminal summary,
    see render_plain() — this is the FULL brief, not the summary.

    companion_files: optional dict of {key: Path} from write_companion_files(). When
    provided, "see companion file" notes become copy-pasteable `cat <path>` commands.
    """
    companion_files = companion_files or {}
    width = 79
    lines: list[str] = []
    hr_eq = "=" * width
    hr_dash = "-" * width

    def section(title: str) -> None:
        lines.append("")
        lines.append(hr_eq)
        lines.append(f"  {title}")
        lines.append(hr_eq)

    def subsection(title: str) -> None:
        lines.append("")
        lines.append(title)
        lines.append(hr_dash)

    # Header
    lines.append(hr_eq)
    lines.append(f"  PRE-ENGAGEMENT BRIEF — {brief.domain}")
    lines.append(f"  Generated: {brief.generated_at}")
    lines.append(hr_eq)

    # M365 Tenant
    section("M365 TENANT")
    lines.append("  Cross-check:  https://osint.aadinternals.com  (Entra ID login required)")
    lines.append("")
    if not brief.tenant_id and not brief.tenant_brand:
        lines.append(f"  No M365 tenant detected for {brief.domain}.")
    else:
        def kv(key: str, value) -> None:
            if value is not None and value != "":
                lines.append(f"  {key:<20} {value}")

        kv("Brand", brief.tenant_brand or "Unknown")
        kv("Tenant ID", brief.tenant_id or "Unknown")
        if brief.tenant_name:
            kv("Tenant Name", brief.tenant_name)
        elif brief.signals_source == "aadoutsider" and brief.tenant_id:
            kv("Tenant Name", "(unresolved — throttled)")
        kv("Region", brief.tenant_region or "Unknown")
        if brief.tenant_subregion:
            kv("Sub-region", brief.tenant_subregion)
        kv("Federation", brief.federation_type or "Unknown")
        if brief.sts_server:
            kv("STS Server", brief.sts_server)
        kv("DesktopSSO", str(brief.desktop_sso))
        if brief.manual_signals_captured:
            throttled = ""
            if brief.signals_source == "aadoutsider" and not brief.tenant_name:
                throttled = " (throttled)"
            if brief.mdi_detected is True:
                val = f"Yes ({brief.mdi_instance})" if brief.mdi_instance else "Yes"
            elif brief.mdi_detected is False:
                val = "No"
            else:
                val = f"Unknown{throttled}"
            kv("MDI", val)
            if brief.aad_connect_cloud_sync is True:
                kv("AAD Cloud Sync", "Yes")
            elif brief.aad_connect_cloud_sync is False:
                kv("AAD Cloud Sync", "No")
            else:
                kv("AAD Cloud Sync", f"Unknown{throttled}")

    # Tenant Domains
    if brief.tenant_domains:
        section(f"TENANT DOMAINS ({len(brief.tenant_domains)})")
        shown = brief.tenant_domains[:25]
        name_w = max(len(d.get("name", "")) for d in shown) + 2
        for d in shown:
            name = d.get("name", "")
            dtype = d.get("type", "")
            sts = d.get("sts", "") if isinstance(d, dict) else ""
            line = f"  {name.ljust(name_w)}{dtype}"
            if sts:
                line += f"  (STS: {sts})"
            lines.append(line)
        if len(brief.tenant_domains) > 25:
            td_path = companion_files.get("tenant-domains")
            td_ref = f"cat {td_path}" if td_path else "see companion file"
            lines.append(f"  ... and {len(brief.tenant_domains) - 25} more  →  {td_ref}")
        source_notes = {
            "manual_paste": "Source: manually pasted from osint.aadinternals.com",
            "aadoutsider": f"Source: AADOutsider-py ({'small tenant' if len(brief.tenant_domains) == 1 else 'Autodiscover SOAP'})",
        }
        note = source_notes.get(brief.tenant_domains_source, "")
        if note:
            lines.append("")
            lines.append(f"  {note}")

    # Email Security
    # Extended gate so the section renders when spf_record_present is true even
    # without includes — otherwise a bare 'v=spf1 -all' record would be invisible.
    if (brief.mx_raw or brief.mx_provider != "unknown" or brief.dmarc_policy
            or brief.spf_includes or brief.spf_record_present):
        section("EMAIL SECURITY")
        if brief.mx_provider and brief.mx_provider != "unknown":
            lines.append(f"  MX Provider:    {brief.mx_provider}")
        if brief.dmarc_policy:
            lines.append(f"  DMARC:          p={brief.dmarc_policy}")
        else:
            lines.append(f"  DMARC:          not configured")
        # SPF summary line — shows qualifier even when no includes present.
        # A record like "v=spf1 -all" has no includes but is still meaningful.
        if brief.spf_record_present:
            if brief.spf_all_qualifier:
                q_desc = {"+": "+all (CRITICAL — anyone can spoof)",
                          "-": "-all (hardfail)",
                          "~": "~all (softfail)",
                          "?": "?all (neutral)"}.get(brief.spf_all_qualifier,
                                                      brief.spf_all_qualifier + "all")
                lines.append(f"  SPF:            present, {q_desc}")
            else:
                lines.append(f"  SPF:            present")

        if brief.mx_raw:
            subsection("MX Records")
            for mx in brief.mx_raw:
                lines.append(f"  {mx}")
        if brief.spf_includes:
            subsection("SPF Includes")
            for inc in brief.spf_includes:
                lines.append(f"  {inc}")
        elif brief.spf_record_present:
            # SPF exists but has no includes — unusual, worth showing explicitly
            subsection("SPF Includes")
            lines.append(f"  (none — empty SPF record, no SaaS sending paths authorized)")

    # SaaS
    if brief.txt_verifications:
        section(f"CONFIRMED SaaS SERVICES ({len(brief.txt_verifications)})")
        for service, token in brief.txt_verifications.items():
            lines.append(f"  - {service}")
            lines.append(f"      token: {token[:70]}")

    # M365 Integration CNAMEs
    if brief.m365_subdomains:
        section(f"M365 INTEGRATION SIGNALS ({len(brief.m365_subdomains)})")
        max_src = max(len(f"{k}.{brief.domain}") for k in brief.m365_subdomains) + 2
        for label, target in brief.m365_subdomains.items():
            src = f"{label}.{brief.domain}"
            lines.append(f"  {src.ljust(max_src)}-> {target}")

    # Auth Surface
    if brief.security_subdomains:
        section(f"AUTH / SECURITY SUBDOMAINS ({len(brief.security_subdomains)})")
        max_src = max(len(f"{k}.{brief.domain}") for k in brief.security_subdomains) + 2
        for label, target in brief.security_subdomains.items():
            src = f"{label}.{brief.domain}"
            lines.append(f"  {src.ljust(max_src)}-> {target}")

    # Cloud Attack Surface — passive DNS discoveries across cloud providers.
    # Each category gets its own subsection because the operator follow-ups differ:
    #   Storage:  run cloud_enum / s3scanner for access testing
    #   Platform: identify specific service (WorkDocs? Kudu? CloudFront?)
    #   M365:     post-auth scope for TeamFiltration if creds land
    total_cloud = (len(brief.cloud_storage) + len(brief.cloud_services)
                   + len(brief.cloud_m365_services))
    if total_cloud > 0:
        section(f"CLOUD ATTACK SURFACE ({total_cloud})")
        lines.append("  Passive DNS resolution only. Test access in the active phase.")

        if brief.cloud_storage:
            subsection(f"Storage ({len(brief.cloud_storage)})")
            max_h = max(len(h) for h in brief.cloud_storage) + 2
            for hostname, entry in brief.cloud_storage.items():
                label = entry.get("label", "?")
                resolution = entry.get("resolution", "")
                lines.append(f"  {hostname.ljust(max_h)}[{label}] -> {resolution}")

        if brief.cloud_services:
            subsection(f"Platform Services ({len(brief.cloud_services)})")
            max_h = max(len(h) for h in brief.cloud_services) + 2
            for hostname, entry in brief.cloud_services.items():
                label = entry.get("label", "?")
                resolution = entry.get("resolution", "")
                lines.append(f"  {hostname.ljust(max_h)}[{label}] -> {resolution}")

        if brief.cloud_m365_services:
            subsection(f"M365 Cloud Services ({len(brief.cloud_m365_services)})")
            max_h = max(len(h) for h in brief.cloud_m365_services) + 2
            for hostname, entry in brief.cloud_m365_services.items():
                label = entry.get("label", "?")
                resolution = entry.get("resolution", "")
                lines.append(f"  {hostname.ljust(max_h)}[{label}] -> {resolution}")

        if brief.cloud_tokens_tried:
            lines.append("")
            lines.append(f"  Tokens probed: {', '.join(brief.cloud_tokens_tried)}")
        if brief.cloud_wildcard_suffixes:
            lines.append(f"  Wildcard zones skipped: {', '.join(brief.cloud_wildcard_suffixes)}")

    # HTTP fingerprints (if any succeeded)
    if brief.http_fingerprints:
        section(f"HTTP FINGERPRINTS ({len(brief.http_fingerprints)})")
        for fp in brief.http_fingerprints:
            lines.append(f"  {fp.get('host', '?')} [{fp.get('status', '?')}]")
            if fp.get("server"):
                lines.append(f"      Server:       {fp['server']}")
            if fp.get("powered_by"):
                lines.append(f"      X-Powered-By: {fp['powered_by']}")
            if fp.get("title"):
                lines.append(f"      Title:        {fp['title']}")
            if fp.get("missing_security_headers"):
                lines.append(f"      Missing sec headers: {', '.join(fp['missing_security_headers'])}")
            # Show TLS cert SANs — reveals vhosts on shared IPs (esp. ADFS/WAP farms)
            if fp.get("cert_sans"):
                sans = fp["cert_sans"]
                if len(sans) <= 10:
                    lines.append(f"      Cert SANs:    {', '.join(sans)}")
                else:
                    # Wildcard certs and large farms can have 20-50+ SANs — abbreviate
                    lines.append(f"      Cert SANs:    {', '.join(sans[:8])}, "
                                 f"... ({len(sans)} total)")
            elif fp.get("cert_error"):
                # Cert extraction failed — show the reason so it's not a silent mystery
                lines.append(f"      Cert SANs:    (unavailable — {fp['cert_error']})")
            # Honest 404 note when probe hit a Host-header-routed surface
            if fp.get("probe_note"):
                # Wrap to fit column width
                import textwrap
                wrapped = textwrap.wrap(fp["probe_note"], width=width - 10,
                                        initial_indent="      Note:         ",
                                        subsequent_indent="                    ")
                lines.extend(wrapped)

    # Infrastructure (BBOT + canvass's own discoveries)
    # Gate opens whenever we have ANY host data — BBOT, probes, or CNAMEs — so
    # users who --skip-bbot still see Notable Subdomains categorization.
    if (brief.subdomains or brief.emails or brief.technologies or brief.takeovers
            or brief.security_subdomains or brief.m365_subdomains):
        section("EXTERNAL INFRASTRUCTURE (BBOT)")
        # Build copy-pasteable `cat <path>` hints when we know the file path.
        # Falls back to "(see companion file)" text if called without file dict.
        def _ref(key: str) -> str:
            p = companion_files.get(key)
            return f"cat {p}" if p else "see companion file"

        if brief.subdomains:
            lines.append(f"  Subdomains:    {len(brief.subdomains)}  →  {_ref('subdomains')}")
        else:
            lines.append(f"  Subdomains:    (BBOT skipped)")

        # Show total unique host count across ALL sources (bbot + probes + cnames)
        # — surfaces canvass's own discoveries that don't appear in BBOT output.
        bbot_set = set(brief.subdomains)
        probe_set = {f"{label}.{brief.domain}" for label in brief.security_subdomains}
        cname_set = {f"{label}.{brief.domain}" for label in brief.m365_subdomains}
        all_set = bbot_set | probe_set | cname_set
        if len(all_set) > len(bbot_set):
            overlap = len((probe_set | cname_set) & bbot_set)
            lines.append(f"  All Hosts:     {len(all_set)} total ("
                         f"{len(bbot_set)} BBOT + {len(probe_set)} DNS probes + "
                         f"{len(cname_set)} M365 CNAMEs"
                         + (f", {overlap} overlap" if overlap else "")
                         + f")  →  {_ref('all-hosts')}")

        if brief.emails:
            lines.append(f"  Emails:        {len(brief.emails)}  →  {_ref('emails')}")
        else:
            lines.append(f"  Emails:        0")
        if brief.technologies:
            lines.append(f"  Technologies:  {len(brief.technologies)}  →  {_ref('technologies')}")
        else:
            lines.append(f"  Technologies:  0")

        if brief.takeovers:
            subsection(f"Takeover Findings ({len(brief.takeovers)})")
            for t in brief.takeovers:
                severity = t.get("severity", "?")
                host = t.get("host", "?")
                module = t.get("module", "?")
                ttype = t.get("type", "?")
                lines.append(f"  [{ttype}/{severity}] {host} ({module})")
                desc = t.get("description", "")
                if desc:
                    lines.append(f"      {desc[:180]}")

        # Notable subdomains — categorize from ALL sources, not just BBOT.
        # Previous behavior missed canvass's own discoveries (adfs, owa, vpn, etc.)
        # Build merged set: BBOT + canvass auth probes + M365 CNAMEs.
        all_hosts_set: set[str] = set()
        all_hosts_set.update(brief.subdomains)  # BBOT
        all_hosts_set.update(
            f"{label}.{brief.domain}" for label in brief.security_subdomains
        )
        all_hosts_set.update(
            f"{label}.{brief.domain}" for label in brief.m365_subdomains
        )

        if all_hosts_set:
            notable: dict[str, list[str]] = {}
            # Only categorize hosts that are actually under the target domain.
            # BBOT follows CNAMEs and resolves them, which means Microsoft's global
            # endpoints (login.windows.net, outlook.office365.com, manage.microsoft.com,
            # etc.) end up in all_hosts_set because they're CNAME targets of the
            # target's own subdomains. These aren't target-owned assets and mislead
            # operators scanning the brief — e.g. "SSO / IdP login.windows.net"
            # reads as if the target owns it. Filter to hosts ending in .{domain}
            # (or equal to domain) so Notable Subdomains only surfaces real target
            # assets. The CNAME relationships are still visible in M365 INTEGRATION
            # SIGNALS and in BBOT raw output for anyone who wants them.
            domain_suffix = f".{brief.domain}"
            for sub in sorted(all_hosts_set):
                if not (sub == brief.domain or sub.endswith(domain_suffix)):
                    continue
                cat = categorize_subdomain(sub)
                if cat:
                    notable.setdefault(cat, []).append(sub)
            if notable:
                subsection("Notable Subdomains (auto-categorized)")
                cat_w = max(len(c) for c in notable) + 2
                for cat, subs in notable.items():
                    for sub in subs[:5]:
                        lines.append(f"  {cat.ljust(cat_w)}{sub}")

        # Technology stack (humanized)
        if brief.technologies:
            subsection("Technology Stack")
            seen = set()
            for cpe in brief.technologies:
                human = humanize_cpe(cpe)
                if human and human not in seen:
                    lines.append(f"  {human}")
                    seen.add(human)

    # Supplementary DNS
    if brief.dkim_selectors or brief.srv_records:
        section("SUPPLEMENTARY DNS")
        if brief.dkim_selectors:
            lines.append(f"  DKIM Selectors:  {', '.join(brief.dkim_selectors)}")
        if brief.srv_records:
            subsection("SRV Records")
            for srv, records in brief.srv_records.items():
                for rec in records:
                    lines.append(f"  {srv:<28}{rec}")

    # Recommendations — placed LAST so readers see the evidence first, then the
    # actionable interpretation. Scanning top-down leads the reader through
    # raw findings → tenant intel → attack surface → then "so what do I do".
    section("RECOMMENDATIONS")
    if not brief.recommendations:
        lines.append("  No recommendations generated.")
    else:
        import textwrap
        prio_w = max(len(r.priority) for r in brief.recommendations)
        cat_w = max(len(r.category) for r in brief.recommendations)
        for rec in brief.recommendations:
            prio = f"[{rec.priority}]".ljust(prio_w + 2)
            cat = rec.category.ljust(cat_w)
            prefix = f"  {prio}  {cat}  "
            indent = " " * len(prefix)
            wrapped = textwrap.wrap(
                rec.text, width=width,
                initial_indent=prefix, subsequent_indent=indent,
                break_long_words=False, break_on_hyphens=False,
            )
            for line in (wrapped or [prefix]):
                lines.append(line)

    lines.append("")
    lines.append(hr_eq)
    lines.append(f"  END OF BRIEF — {brief.domain}")
    lines.append(hr_eq)

    return "\n".join(lines) + "\n"


# ============================================================================
# Plain Text Summary
# ============================================================================

# Auto-highlight keywords for BBOT subdomain triage
NOTABLE_KEYWORDS: dict[str, list[str]] = {
    "VPN":           ["vpn", "openvpn", "anyconnect", "ipsec", "pulse", "globalprotect"],
    "Remote Access": ["citrix", "rdweb", "rdp", "bastion", "gateway", "remote", "teamviewer"],
    "SSO / IdP":     ["sso", "adfs", "okta", "auth", "login", "idp", "saml", "idms", "oauth",
                      "shibboleth", "cas"],
    "Email":         ["mail", "webmail", "owa", "smtp", "exchange", "outlook", "mx"],
    "Admin":         ["admin", "portal", "console", "manage", "dashboard", "control",
                      "backoffice", "ops"],
    # Client/member portals — common in banking, healthcare, membership orgs, SaaS products.
    # These are real auth surfaces adjacent to the main app but rarely covered by
    # generic "portal" and often distinct from employee-facing admin.
    "Client Portal": ["private", "client", "clients", "customer", "customers", "member",
                      "members", "online", "account", "accounts", "my", "banking",
                      "investor", "investors", "partner-portal", "broker"],
    "API":           ["api", "apis", "rest", "graphql", "webhook", "webhooks", "gateway-api"],
    "Docs / Wiki":   ["docs", "wiki", "confluence", "knowledge", "kb", "help",
                      "support-docs"],
    "Vendor":        ["vendor", "vendors", "partner", "partners", "supplier",
                      "suppliers", "integration"],
    "Development":   ["dev", "test", "staging", "stage", "qa", "uat", "localhost",
                      "beta", "sandbox", "preview", "demo", "predep", "preprod"],
    "File / Share":  ["files", "share", "shares", "ftp", "sftp", "storage", "cdn",
                      "assets", "media", "upload", "uploads", "download", "downloads"],
    "Monitoring":    ["monitor", "monitoring", "grafana", "metrics", "prometheus",
                      "logs", "kibana", "splunk", "sentry", "status", "health"],
}


def categorize_subdomain(sub: str) -> str | None:
    """Return a category name if the subdomain matches a notable keyword, else None."""
    # Look at the leftmost label (before first dot) for keyword matches
    leftmost = sub.split(".")[0].lower()
    for category, keywords in NOTABLE_KEYWORDS.items():
        for kw in keywords:
            # Match as full label or word-boundary substring
            if leftmost == kw or f"-{kw}" in leftmost or f"{kw}-" in leftmost or kw in leftmost.split("-"):
                return category
    return None


def humanize_cpe(cpe: str) -> str:
    """Parse a CPE string into a human-readable name.
    cpe:/a:microsoft:internet_information_services:10.0 -> Microsoft IIS 10.0
    cpe:/o:sonicwall:sonicos -> SonicWall SonicOS
    """
    if not cpe.startswith("cpe:"):
        return cpe
    parts = cpe.replace("cpe:/", "").split(":")
    if len(parts) < 3:
        return cpe
    # parts: [type, vendor, product, (version)?]
    vendor = parts[1].replace("_", " ").title()
    product = parts[2].replace("_", " ").title()
    version = parts[3] if len(parts) > 3 else ""
    # Common acronym cleanup
    product_fixes = {
        "Internet Information Services": "IIS",
        "Asp.Net": "ASP.NET",
        "Sonicos": "SonicOS",
        "Amazon Cloudfront": "CloudFront",
    }
    product = product_fixes.get(product, product)
    if vendor.lower() == "amazon" and "cloudfront" in product.lower():
        return "Amazon CloudFront"
    out = f"{vendor} {product}".strip()
    if version:
        out += f" {version}"
    return out


def wrap_text(text: str, width: int, indent: str = "") -> list[str]:
    """Simple word-wrap preserving indent on continuation lines."""
    import textwrap
    return textwrap.wrap(text, width=width, subsequent_indent=indent) or [""]


def render_plain(brief: Brief, brief_md_path: Path, companion_files: dict[str, Path],
                 elapsed: float = 0.0) -> str:
    """Render a compact plain-text summary — single line per field where possible."""
    width = 71
    lines: list[str] = []
    hr_eq = "═" * width
    hr_dash = "─" * width

    # Header with duration right-aligned
    lines.append(hr_eq)
    elapsed_str = f"{elapsed:.1f}s" if elapsed else ""
    header_text = f"  SUMMARY — {brief.domain}"
    padding = width - len(header_text) - len(elapsed_str) - 2
    lines.append(f"{header_text}{' ' * max(1, padding)}{elapsed_str}  ")
    lines.append(hr_eq)

    # Collect rows of key -> value pairs for the main data block
    rows: list[tuple[str, str]] = []

    if brief.tenant_brand:
        rows.append(("Tenant", brief.tenant_brand))
    if brief.tenant_id:
        rows.append(("Tenant ID", brief.tenant_id))
    if brief.tenant_region:
        region = brief.tenant_region
        if brief.tenant_subregion:
            region += f" / {brief.tenant_subregion}"
        rows.append(("Region", region))
    if brief.federation_type:
        fed = brief.federation_type
        if brief.sts_server:
            fed += f" → {brief.sts_server}"
        rows.append(("Federation", fed))
    if brief.desktop_sso:
        rows.append(("DesktopSSO", "enabled"))

    # MDI / Cloud Sync — only if we have signals (auto-detected or manual paste)
    if brief.manual_signals_captured:
        throttled_note = ""
        if brief.signals_source == "aadoutsider" and not brief.tenant_name:
            throttled_note = " (throttled)"
        if brief.mdi_detected is True:
            val = "Yes"
            if brief.mdi_instance:
                val += f" ({brief.mdi_instance})"
        elif brief.mdi_detected is False:
            val = "No"
        else:
            val = f"Unknown{throttled_note}"
        rows.append(("MDI", val))

        if brief.aad_connect_cloud_sync is True:
            val = "Yes"
        elif brief.aad_connect_cloud_sync is False:
            val = "No"
        else:
            val = f"Unknown{throttled_note}"
        rows.append(("Cloud Sync", val))

    # Email — combine MX provider and DMARC on one line
    email_bits: list[str] = []
    if brief.mx_provider and brief.mx_provider != "unknown":
        email_bits.append(brief.mx_provider)
    if brief.dmarc_policy:
        email_bits.append(f"DMARC p={brief.dmarc_policy}")
    elif not brief.dmarc_policy and brief.mx_provider != "unknown":
        email_bits.append("no DMARC")
    if email_bits:
        rows.append(("Email", "  |  ".join(email_bits)))

    # SaaS — comma list
    if brief.txt_verifications:
        # Shorten "Microsoft 365" → "M365" for compact display
        saas = [s.replace("Microsoft 365", "M365") for s in brief.txt_verifications.keys()]
        rows.append(("SaaS Stack", ", ".join(saas)))

    # M365 Integration — humanized names, deduplicated
    if brief.m365_subdomains:
        integrations: list[str] = []
        if "autodiscover" in brief.m365_subdomains:
            integrations.append("Exchange Online")
        if "sip" in brief.m365_subdomains or "lyncdiscover" in brief.m365_subdomains:
            integrations.append("Teams")
        if "enterpriseregistration" in brief.m365_subdomains:
            integrations.append("Hybrid AD Join")
        if "enterpriseenrollment" in brief.m365_subdomains:
            integrations.append("Intune MDM")
        if "msoid" in brief.m365_subdomains:
            integrations.append("Legacy SSO")
        if integrations:
            rows.append(("M365 Integration", ", ".join(integrations)))

    # Auth surface — comma list of full subdomain FQDNs
    if brief.security_subdomains:
        auth_fqdns = [f"{label}.{brief.domain}" for label in brief.security_subdomains]
        rows.append(("Auth Surface", ", ".join(auth_fqdns)))

    # Cloud Surface — condensed summary of cloud attack surface discoveries.
    # Groups by provider label and lists distinguishing tokens in parentheses.
    # This matters when multiple tokens match a provider (e.g., two tokens both
    # resolving SharePoint tenants) — operator needs to see BOTH surfaced, not
    # a deduped "SharePoint Online" that hides the parent/sibling-tenant signal.
    # Priority order: Kudu > Storage > other Platform > M365.
    cloud_items: list[str] = []

    def _token_for(hostname: str, suffix: str) -> str:
        """Extract the token used to generate this hostname.
        `example-my.sharepoint.com` with suffix `sharepoint.com` -> `example`
        `exampleprod.blob.core.windows.net` with suffix `blob.core.windows.net` -> `exampleprod`
        """
        if hostname.endswith(f"-my.{suffix}"):
            return hostname[:-(len(suffix) + 4)]  # strip "-my.<suffix>"
        if hostname.endswith(f".{suffix}"):
            return hostname[:-(len(suffix) + 1)]  # strip ".<suffix>"
        return hostname.split(".")[0]  # fallback

    # Group storage/platform/m365 findings by provider label -> set of tokens
    def _group_by_provider(d: dict) -> dict[str, list[str]]:
        groups: dict[str, set[str]] = {}
        for hostname, entry in d.items():
            label = entry.get("label", "?")
            # Strip regional suffixes: "AWS S3 (us-east-1)" -> "AWS S3"
            base_label = label.split(" (")[0] if " (" in label else label
            # Figure out the suffix for this hostname so we can derive the token.
            # Hostname is `<token>.<suffix>` or `<token>-my.<suffix>`.
            # Cheapest: split on first '.' for the bare token approximation.
            token = hostname.split(".")[0]
            if token.endswith("-my"):
                token = token[:-3]
            groups.setdefault(base_label, set()).add(token)
        return {k: sorted(v) for k, v in groups.items()}

    # Kudu first (management interface — highest operator interest)
    kudu_tokens = sorted({
        _token_for(h, "scm.azurewebsites.net")
        for h in brief.cloud_services
        if "scm.azurewebsites.net" in h
    })
    if kudu_tokens:
        cloud_items.append(f"Kudu SCM ({', '.join(kudu_tokens)})")

    # Storage (grouped by provider)
    for provider, tokens in sorted(_group_by_provider(brief.cloud_storage).items()):
        cloud_items.append(f"{provider} ({', '.join(tokens)})")

    # Platform services excluding Kudu (already listed)
    non_kudu_platform = {
        h: e for h, e in brief.cloud_services.items()
        if "scm.azurewebsites.net" not in h
    }
    for provider, tokens in sorted(_group_by_provider(non_kudu_platform).items()):
        cloud_items.append(f"{provider} ({', '.join(tokens)})")

    # M365 cloud services — collapse SharePoint + OneDrive to same token set
    # since OneDrive always implies SharePoint. Show as e.g. "SharePoint + OneDrive (example, parent)".
    # Using " + " instead of "/" avoids ambiguity with path-separator reading.
    # Other M365 services (Dynamics) listed separately.
    sp_tokens: set[str] = set()
    od_tokens: set[str] = set()
    other_m365: dict[str, set[str]] = {}
    for hostname, entry in brief.cloud_m365_services.items():
        label = entry.get("label", "?")
        token = hostname.split(".")[0]
        if token.endswith("-my"):
            token = token[:-3]
        if "SharePoint" in label:
            sp_tokens.add(token)
        elif "OneDrive" in label:
            od_tokens.add(token)
        else:
            other_m365.setdefault(label, set()).add(token)

    if sp_tokens or od_tokens:
        # Combined set of tokens (OneDrive ⊆ SharePoint in practice)
        combined = sorted(sp_tokens | od_tokens)
        if sp_tokens and od_tokens:
            cloud_items.append(f"SharePoint + OneDrive ({', '.join(combined)})")
        elif sp_tokens:
            cloud_items.append(f"SharePoint ({', '.join(sorted(sp_tokens))})")
        else:
            cloud_items.append(f"OneDrive ({', '.join(sorted(od_tokens))})")

    for label, tokens in sorted(other_m365.items()):
        cloud_items.append(f"{label} ({', '.join(sorted(tokens))})")

    if cloud_items:
        # Cap at 5 items for summary readability
        if len(cloud_items) > 5:
            shown = cloud_items[:5]
            rows.append(("Cloud Surface", ", ".join(shown) + f", +{len(cloud_items)-5} more"))
        else:
            rows.append(("Cloud Surface", ", ".join(cloud_items)))

    # BBOT — count + file reference, or skipped note
    sub_file = companion_files.get("subdomains")
    email_file = companion_files.get("emails")
    tech_file = companion_files.get("technologies")

    if brief.subdomains:
        ref = f" → {sub_file.name}" if sub_file else ""
        rows.append(("Subdomains", f"{len(brief.subdomains)}{ref}"))
    else:
        # No subdomains — either BBOT was skipped or found none
        rows.append(("Subdomains", "(BBOT skipped)"))

    if brief.emails:
        ref = f" → {email_file.name}" if email_file else ""
        rows.append(("Emails Found", f"{len(brief.emails)}{ref}"))
    else:
        rows.append(("Emails Found", "(BBOT skipped)" if not brief.subdomains else "0"))

    if brief.technologies:
        ref = f" → {tech_file.name}" if tech_file else ""
        rows.append(("Technologies", f"{len(brief.technologies)}{ref}"))

    # Takeovers / dangling DNS findings — HIGH-value row, show even when count is 0 so user knows it ran
    if brief.takeovers:
        takeover_file = companion_files.get("takeovers")
        n_vuln = sum(1 for t in brief.takeovers if t.get("type") == "VULNERABILITY")
        n_find = len(brief.takeovers) - n_vuln
        bits = []
        if n_vuln:
            bits.append(f"{n_vuln} takeover{'s' if n_vuln != 1 else ''}")
        if n_find:
            bits.append(f"{n_find} dangling")
        val = ", ".join(bits)
        if takeover_file:
            val += f" → {takeover_file.name}"
        rows.append(("Takeovers", val))

    # HTTP fingerprints on auth surface (Tier 2)
    if brief.http_fingerprints:
        servers = sorted({f["server"] for f in brief.http_fingerprints if f.get("server")})
        if servers:
            rows.append(("Auth Stack", ", ".join(servers[:5])))

    # DKIM + SRV on one line if present (compact supplementary)
    if brief.dkim_selectors:
        rows.append(("DKIM Selectors", ", ".join(brief.dkim_selectors)))

    # Render the rows with aligned key column
    if rows:
        label_w = max(len(k) for k, _ in rows) + 2
        for k, v in rows:
            lines.append(f"  {k.ljust(label_w)}{v}")

    # Recommendations block
    if brief.recommendations:
        lines.append(hr_dash)
        lines.append("  TOP RECOMMENDATIONS")
        lines.append(hr_dash)

        # Compact priority labels
        prio_display = {"CRITICAL": "CRIT", "MEDIUM": "MED"}
        prio_w = max(len(prio_display.get(r.priority, r.priority)) for r in brief.recommendations)
        cat_w = max(len(r.category) for r in brief.recommendations)

        for rec in brief.recommendations:
            prio = prio_display.get(rec.priority, rec.priority)
            prio_str = f"[{prio}]".ljust(prio_w + 2)
            cat = rec.category.ljust(cat_w)
            text = rec.short or rec.text
            lines.append(f"  {prio_str}  {cat}  {text}")

    # Footer — absolute paths to everything written this run
    lines.append("")
    lines.append(hr_dash)
    lines.append("  OUTPUT FILES")
    lines.append(hr_dash)

    # Build the list of files in a logical order
    file_order = [
        ("Brief",        brief_md_path),   # parameter name is legacy; we now pass the .txt path
        ("Summary",      companion_files.get("summary")),
        ("Run Log",      companion_files.get("log")),
        ("Subdomains",   companion_files.get("subdomains")),
        ("All Hosts",    companion_files.get("all-hosts")),
        ("Emails",       companion_files.get("emails")),
        ("Technologies", companion_files.get("technologies")),
        ("Takeovers",    companion_files.get("takeovers")),
        ("HTTP Probes",  companion_files.get("http-fingerprints")),
        ("Tenant Dom.",  companion_files.get("tenant-domains")),
    ]

    # Determine label width for alignment
    shown_files = [(label, p) for label, p in file_order if p is not None]
    if shown_files:
        label_w = max(len(label) for label, _ in shown_files) + 2
        for label, path in shown_files:
            lines.append(f"  {label.ljust(label_w)} {path}")

    lines.append(hr_eq)

    return "\n".join(lines) + "\n"


def write_companion_files(brief: Brief, output_dir: Path) -> dict[str, Path]:
    """Write flat companion files for large lists. Returns dict of key->path for files written.

    All files are prefixed with the domain name (dots -> underscores) so engagement
    directories with multiple targets stay organized, e.g. 'example_com_subdomains.txt'.
    """
    written: dict[str, Path] = {}

    # Build a safe prefix from the domain — replace dots + anything non-alnum
    prefix = brief.domain.replace(".", "_").replace("-", "_")
    prefix = "".join(c for c in prefix if c.isalnum() or c == "_")

    if brief.subdomains:
        p = output_dir / f"{prefix}_subdomains.txt"
        p.write_text("\n".join(brief.subdomains) + "\n")
        written["subdomains"] = p

    # Merged source-tagged host list — union of BBOT + DNS probes + M365 CNAMEs.
    # Preserves provenance so users know whether a host came from external
    # enumeration (BBOT, passive) or canvass's own active DNS queries (probe).
    # Format: "host  # source1, source2"  — grep-friendly, one host per line.
    bbot_set = set(brief.subdomains)
    probe_set = {f"{label}.{brief.domain}" for label in brief.security_subdomains}
    cname_set = {f"{label}.{brief.domain}" for label in brief.m365_subdomains}
    all_set = bbot_set | probe_set | cname_set
    if all_set:
        lines_out = []
        for host in sorted(all_set):
            sources = []
            if host in bbot_set:
                sources.append("bbot")
            if host in probe_set:
                sources.append("probe")
            if host in cname_set:
                sources.append("cname")
            lines_out.append(f"{host}  # {', '.join(sources)}")
        p = output_dir / f"{prefix}_all-hosts.txt"
        p.write_text("\n".join(lines_out) + "\n")
        written["all-hosts"] = p

    if brief.emails:
        p = output_dir / f"{prefix}_emails.txt"
        p.write_text("\n".join(brief.emails) + "\n")
        written["emails"] = p

    if brief.technologies:
        p = output_dir / f"{prefix}_technologies.txt"
        # Write both raw CPE and humanized version
        lines = []
        for cpe in brief.technologies:
            human = humanize_cpe(cpe)
            lines.append(f"{human}\t{cpe}" if human != cpe else cpe)
        p.write_text("\n".join(lines) + "\n")
        written["technologies"] = p

    if len(brief.tenant_domains) > 25:
        p = output_dir / f"{prefix}_tenant-domains.txt"
        lines = [f"{d.get('name', '')}\t{d.get('type', '')}\t{d.get('sts', '')}".rstrip()
                 for d in brief.tenant_domains]
        p.write_text("\n".join(lines) + "\n")
        written["tenant-domains"] = p

    if brief.takeovers:
        p = output_dir / f"{prefix}_takeovers.txt"
        lines = ["# Type\tModule\tHost\tSeverity\tDescription"]
        for t in brief.takeovers:
            lines.append(
                f"{t.get('type', '')}\t"
                f"{t.get('module', '')}\t"
                f"{t.get('host', '')}\t"
                f"{t.get('severity', '')}\t"
                f"{t.get('description', '')}"
            )
        p.write_text("\n".join(lines) + "\n")
        written["takeovers"] = p

    if brief.http_fingerprints:
        p = output_dir / f"{prefix}_http-fingerprints.txt"
        lines = ["# Host\tStatus\tServer\tPowered-By\tTitle\tRedirect-To\tMissing-Security-Headers"]
        for f in brief.http_fingerprints:
            lines.append(
                f"{f.get('host', '')}\t"
                f"{f.get('status', '')}\t"
                f"{f.get('server', '')}\t"
                f"{f.get('powered_by', '')}\t"
                f"{f.get('title', '')}\t"
                f"{f.get('final_url', '')}\t"
                f"{','.join(f.get('missing_security_headers', []))}"
            )
        p.write_text("\n".join(lines) + "\n")
        written["http-fingerprints"] = p

    return written


# ============================================================================
# Paste Mode
# ============================================================================

def parse_domain_paste(pasted: str) -> list[dict]:
    """Parse domain list from various formats users might paste."""
    domains = []
    seen = set()

    for line in pasted.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith(("---", "===", "Name", "Domain", "Tenant", "STS", "#")):
            continue

        parts = line.split()
        if not parts:
            continue

        candidate = parts[0].lower().rstrip(",;|")
        if "." not in candidate or candidate.startswith(("http", "https", "/")):
            continue
        if candidate in seen:
            continue

        domain_type = "Unknown"
        for token in parts[1:]:
            t = token.strip().lower().rstrip(",;|")
            if t in ("federated", "managed"):
                domain_type = t.capitalize()
                break

        domains.append({"name": candidate, "type": domain_type})
        seen.add(candidate)

    return domains


def prompt_yes_no(question: str) -> bool | None:
    """Ask a y/N question via /dev/tty (works after stdin EOF). Returns None if non-interactive."""
    try:
        # Open the terminal directly — stdin may be closed after a paste
        with open("/dev/tty", "r") as tty:
            print(f"{question} (y/N): ", end="", flush=True)
            answer = tty.readline().strip().lower()
            return answer in ("y", "yes")
    except (OSError, IOError):
        # Non-interactive (e.g., stdin was piped, or Windows without /dev/tty)
        return None


def handle_paste_mode(domain: str, output_dir: Path,
                      mdi_flag: bool | None = None,
                      cloud_sync_flag: bool | None = None) -> int:
    """Accept pasted domain list, update existing brief.

    NOTE: With AADOutsider-py installed, MDI and AAD Connect Cloud Sync are
    auto-detected — paste mode is mainly useful when AADOutsider-py is missing
    or when you want to cross-check signals from osint.aadinternals.com.
    """
    file_prefix = domain.replace(".", "_").replace("-", "_")
    file_prefix = "".join(c for c in file_prefix if c.isalnum() or c == "_")

    brief_path = output_dir / f"{file_prefix}_brief.md"
    aad_file = output_dir / "aad-raw.json"
    domains_file = output_dir / "pasted-domains.txt"

    if not brief_path.exists() or not aad_file.exists():
        print(f"No existing brief at {brief_path}")
        print(f"Run `python3 brief.py {domain}` first to generate baseline.")
        return 1

    # Check what AADOutsider already gave us
    aad_data = json.loads(aad_file.read_text())
    aad_already_has_mdi = "mdi_detected" in aad_data and aad_data.get("signals_source") != "manual_paste"
    aad_already_has_cs = "aad_connect_cloud_sync" in aad_data and aad_data.get("signals_source") != "manual_paste"
    aad_already_has_domains = bool(aad_data.get("domains")) and len(aad_data.get("domains", [])) > 1

    if aad_already_has_domains and aad_already_has_mdi and aad_already_has_cs:
        print(f"AADOutsider-py already provided full tenant intel ({len(aad_data['domains'])} domains, "
              f"MDI={aad_data.get('mdi_detected')}, CloudSync={aad_data.get('aad_connect_cloud_sync')}).")
        print("Paste mode is unnecessary — your brief is already complete.")
        print(f"To override anyway, delete {aad_file} and re-run.")
        return 0

    print(f"Paste mode for {domain}")
    print()
    if aad_already_has_domains:
        print(f"  Note: AADOutsider already returned {len(aad_data['domains'])} domains; "
              "paste mode will replace this list.")
        print()
    print("1. Visit: https://osint.aadinternals.com")
    print("   (sign in with an Entra ID account that has a non-default .onmicrosoft.com domain)")
    print(f"2. Enter domain: {domain}")
    print("3. Copy the list of domains from the result")
    print("4. Paste below. Press Ctrl-D (Unix) or Ctrl-Z then Enter (Windows) when done.")
    print()
    print("Paste domains (one per line, or table format):")
    print("---")

    pasted = sys.stdin.read()
    domains = parse_domain_paste(pasted)

    if not domains:
        print("No domains parsed from input.")
        return 1

    domains_file.write_text(pasted)

    aad_data["domains"] = domains
    aad_data["domains_source"] = "manual_paste_from_aadinternals"

    # Capture additional signals from the same aadinternals.com result
    # Skip if AADOutsider already detected them (don't double-prompt)
    print()
    print(f"Brief updated with {len(domains)} domains.")
    print()

    if aad_already_has_mdi and aad_already_has_cs and mdi_flag is None and cloud_sync_flag is None:
        print(f"  MDI ({aad_data['mdi_detected']}) and Cloud Sync "
              f"({aad_data['aad_connect_cloud_sync']}) already detected by AADOutsider-py.")
    else:
        print("Two more signals visible in the same osint.aadinternals.com result:")
        print()

        # MDI detection
        if mdi_flag is not None:
            aad_data["mdi_detected"] = mdi_flag
            print(f"  MDI detected: {mdi_flag} (from --mdi flag)")
        elif aad_already_has_mdi:
            print(f"  MDI: {aad_data['mdi_detected']} (from AADOutsider-py auto-detection)")
        else:
            answer = prompt_yes_no("  Microsoft Defender for Identity (MDI) detected?")
            if answer is not None:
                aad_data["mdi_detected"] = answer
            else:
                print("  (skipped - non-interactive; use --mdi to set)")

        # AAD Connect Cloud Sync detection
        if cloud_sync_flag is not None:
            aad_data["aad_connect_cloud_sync"] = cloud_sync_flag
            print(f"  AAD Connect Cloud Sync: {cloud_sync_flag} (from --cloud-sync flag)")
        elif aad_already_has_cs:
            print(f"  Cloud Sync: {aad_data['aad_connect_cloud_sync']} (from AADOutsider-py auto-detection)")
        else:
            answer = prompt_yes_no("  Azure AD Connect Cloud Sync detected?")
            if answer is not None:
                aad_data["aad_connect_cloud_sync"] = answer
            else:
                print("  (skipped - non-interactive; use --cloud-sync to set)")

    aad_file.write_text(json.dumps(aad_data, indent=2))

    # Reconstruct brief from saved raw data + updated AAD
    brief = Brief(domain=domain, generated_at=datetime.now().isoformat())
    merge_aad(brief, aad_data)

    dns_file = output_dir / "dns-raw.json"
    if dns_file.exists():
        merge_dns(brief, json.loads(dns_file.read_text()))

    bbot_dir = output_dir / "bbot-output"
    if bbot_dir.exists():
        merge_bbot(brief, parse_bbot_output(bbot_dir))

    add_recommendations(brief)
    brief_path.write_text(render_markdown(brief))

    print()
    print(f"Brief saved: {brief_path}")
    return 0


# ============================================================================
# Orchestrator
# ============================================================================

async def run_collectors(domain: str, output_dir: Path, skip_bbot: bool) -> Brief:
    """Run all collectors in parallel and return populated Brief."""
    brief = Brief(domain=domain, generated_at=datetime.now().isoformat())

    # Parallel phase: AAD + DNS + crt.sh (+ BBOT optional). All independent.
    tasks = [collect_aad(domain), collect_dns(domain), collect_crtsh(domain)]
    task_names = ["AAD", "DNS", "CRTSH"]
    if not skip_bbot:
        tasks.append(collect_bbot(domain, output_dir))
        task_names.append("BBOT")

    log("MAIN", f"running {len(tasks)} collectors in parallel", level="run")
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Surface exceptions instead of silently swallowing them
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            log(task_names[i], f"crashed: {r!r}", level="err")

    aad_data = results[0] if not isinstance(results[0], Exception) else {}
    dns_data = results[1] if not isinstance(results[1], Exception) else {}
    crtsh_data = results[2] if not isinstance(results[2], Exception) else {}
    bbot_data = (results[3] if len(results) > 3 and not isinstance(results[3], Exception)
                 else {})

    (output_dir / "aad-raw.json").write_text(json.dumps(aad_data, indent=2))
    (output_dir / "dns-raw.json").write_text(json.dumps(dns_data, indent=2))
    if crtsh_data:
        (output_dir / "crtsh-raw.json").write_text(json.dumps(crtsh_data, indent=2))

    merge_aad(brief, aad_data)
    merge_dns(brief, dns_data)
    merge_bbot(brief, bbot_data)
    merge_crtsh(brief, crtsh_data)

    # Sequential phase 1: Cloud service discovery (needs AAD tenant info for token gen)
    # Passive — DNS only. Runs against ~30 patterns × generated tokens.
    cloud_data = await collect_cloud_services(
        domain,
        brief.tenant_brand,
        brief.tenant_domains,
    )
    (output_dir / "cloud-raw.json").write_text(json.dumps(cloud_data, indent=2))
    merge_cloud(brief, cloud_data)

    # Sequential phase 2: HTTP fingerprints on auth subdomains (needs DNS output)
    # Only run if DNS actually found auth subdomains worth probing
    auth_subs = dns_data.get("security_subdomains", {})
    if auth_subs:
        http_data = await collect_http_fingerprints(domain, auth_subs)
        merge_http_fingerprints(brief, http_data)

    add_recommendations(brief)

    return brief


def load_dotenv(path: Path) -> None:
    """Minimal .env loader (no external dependency)."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="canvass",
        description=(
            "canvass — M365 / Entra ID pre-engagement intelligence orchestrator.\n"
            "\n"
            "Collects tenant metadata (AADOutsider-py), DNS posture (SPF/DMARC/MTA-STS/CAA),\n"
            "subdomains (BBOT + crt.sh), HTTP fingerprints on auth surfaces, and generates\n"
            "actionable pre-engagement recommendations for TeamFiltration workflows."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Typical usage:
  python3 brief.py example.com                     # full run (~2-5 min)
  python3 brief.py example.com --skip-bbot         # fast DNS + AAD only (~10s)
  python3 brief.py example.com --paste-domains     # fallback if AADOutsider throttles
  python3 brief.py example.com --output-dir ./x    # override default ~/engagements/ path
  python3 brief.py example.com -q                  # quiet mode — no banner, summary only

Output (default ~/engagements/<domain>/recon/):
  <domain>_brief.{txt,md}     Full engagement brief (human readable)
  <domain>_summary.txt        Terminal summary — top recommendations
  <domain>_run.log            Full run log (every DNS/BBOT/RECS line)
  <domain>_subdomains.txt     All subdomains found (one per line)
  <domain>_emails.txt         Emails discovered via BBOT
  <domain>_technologies.txt   Technology stack from BBOT CPE data
  <domain>_http-fingerprints.txt  HTTP probes on auth surface (webmail/vpn/etc.)
  <domain>_takeovers.txt      Subdomain takeover candidates from baddns (if any)
  aad-raw.json, dns-raw.json, crtsh-raw.json  Raw collector output

Tenant metadata flags (for use with --paste-domains when AADOutsider is throttled):
  --mdi / --no-mdi                       Skip MDI prompt, set detected or not
  --cloud-sync / --no-cloud-sync         Skip Cloud Sync prompt, set detected or not

Dependencies (installed via setup.sh):
  BBOT, AADOutsider-py, Python 3.10+, dnspython, httpx, jinja2

Report bugs: https://github.com/atnovaux/canvass/issues
""",
    )
    parser.add_argument("--version", action="version",
                        version=f"canvass {VERSION} ({BUILD_DATE})")
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--output-dir", type=Path, default=None,
                        help="Output directory (default: ~/engagements/<domain>/recon/)")
    parser.add_argument("--skip-bbot", action="store_true",
                        help="Skip BBOT scan (~10s instead of ~90s-10min)")
    parser.add_argument("--paste-domains", action="store_true",
                        help="Interactive paste mode: manually supply domain list from osint.aadinternals.com when AADOutsider throttles")
    parser.add_argument("--mdi", dest="mdi", action="store_true", default=None,
                        help="With --paste-domains: skip prompt, mark MDI as detected")
    parser.add_argument("--no-mdi", dest="mdi", action="store_false",
                        help="With --paste-domains: skip prompt, mark MDI as NOT detected")
    parser.add_argument("--cloud-sync", dest="cloud_sync", action="store_true", default=None,
                        help="With --paste-domains: skip prompt, mark AAD Connect Cloud Sync detected")
    parser.add_argument("--no-cloud-sync", dest="cloud_sync", action="store_false",
                        help="With --paste-domains: skip prompt, mark AAD Connect Cloud Sync NOT detected")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress banner and progress output (only show summary + errors)")
    args = parser.parse_args()

    # Wire global flags
    global QUIET, START_TIME, LOG_FILE
    QUIET = args.quiet
    START_TIME = time.time()

    load_dotenv(Path(".env"))

    if args.output_dir:
        output_dir = args.output_dir
    else:
        output_dir = Path.home() / "engagements" / args.domain / "recon"

    output_dir.mkdir(parents=True, exist_ok=True)

    if args.paste_domains:
        # Paste mode is interactive — banner gets in the way of the prompts
        return handle_paste_mode(args.domain, output_dir,
                                  mdi_flag=args.mdi,
                                  cloud_sync_flag=args.cloud_sync)

    # Open log file — every log() line will be tee'd here
    log_prefix = args.domain.replace(".", "_").replace("-", "_")
    log_prefix = "".join(c for c in log_prefix if c.isalnum() or c == "_")
    log_path = output_dir / f"{log_prefix}_run.log"
    try:
        LOG_FILE = open(log_path, "w", encoding="utf-8")
        LOG_FILE.write(f"# canvass run log — {args.domain} — {datetime.now().isoformat()}\n\n")
    except OSError as e:
        print(f"Warning: could not open log file {log_path}: {e}", file=sys.stderr)
        LOG_FILE = None

    print_banner()
    log("MAIN", f"target: {args.domain}")
    log("MAIN", f"output: {output_dir}")
    if args.skip_bbot:
        log("MAIN", "BBOT scan skipped (--skip-bbot)")

    try:
        brief = asyncio.run(run_collectors(args.domain, output_dir, args.skip_bbot))
    except KeyboardInterrupt:
        log("MAIN", "interrupted by user", level="err")
        if LOG_FILE:
            LOG_FILE.close()
        return 130

    # Domain-prefixed output files so multi-target engagement dirs stay organized
    file_prefix = brief.domain.replace(".", "_").replace("-", "_")
    file_prefix = "".join(c for c in file_prefix if c.isalnum() or c == "_")

    # Write companion files FIRST so render_text can embed their paths as
    # copy-pasteable `cat /path/to/file` commands inside the brief body.
    companion_files = write_companion_files(brief, output_dir)

    # Brief: plain text only (cross-platform friendly, no markdown editor needed)
    brief_txt_path = output_dir / f"{file_prefix}_brief.txt"
    brief_txt_path.write_text(render_text(brief, companion_files))

    # Render plain-text summary, save to summary.txt AND print to terminal
    summary_path = output_dir / f"{file_prefix}_summary.txt"
    companion_files["summary"] = summary_path
    companion_files["brief_txt"] = brief_txt_path
    if LOG_FILE is not None:
        companion_files["log"] = log_path

    elapsed = time.time() - START_TIME
    summary_text = render_plain(brief, brief_txt_path, companion_files, elapsed=elapsed)
    summary_path.write_text(summary_text)

    log("MAIN", f"brief saved: {brief_txt_path}", level="ok")
    log("MAIN", f"summary saved: {summary_path}", level="ok")

    # Close log file cleanly
    if LOG_FILE is not None:
        try:
            LOG_FILE.close()
        except OSError:
            pass

    # Print the summary to stdout (visible even with --quiet since it's the actual output)
    print()
    print(summary_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
