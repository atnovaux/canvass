# canvass — M365 / Entra ID Pre-Engagement Intelligence

A single-file Python tool that canvasses a target's external footprint before an engagement. Combines M365/Entra tenant fingerprinting, DNS service enumeration, certificate transparency, BBOT subdomain + takeover detection, and HTTP auth-surface fingerprinting into a single actionable markdown brief plus a plain-text summary.

## What it does

For any target domain, the tool runs collectors in parallel and produces a brief covering:

- **M365 tenant intelligence** — tenant ID, brand, region, federation type, ADFS server, DesktopSSO status, MDI detection (with instance hostname), AAD Connect Cloud Sync detection (via AADOutsider-py)
- **DNS service fingerprint** — MX vendor, SPF includes, DMARC policy, SaaS verification tokens, M365 integration CNAMEs, exposed auth subdomains, DKIM selectors, SRV records
- **Certificate transparency** — subdomains discovered from crt.sh CT logs (catches names BBOT misses)
- **Cloud attack surface** — passive DNS discovery of Azure Blob/Files/Queue/Table storage accounts, Azure App Service + Kudu/SCM management consoles, AWS Apps portals (WorkDocs/Connect/SSO), Elastic Beanstalk, SharePoint Online tenants, OneDrive for Business, Dynamics 365 CRM. Wildcard-zone providers (Vercel/Heroku/etc.) excluded to keep output high-signal.
- **External attack surface** — subdomains, emails, technologies (via BBOT)
- **Subdomain takeover detection** — via BBOT's baddns + baddns_zone modules (CNAME/NS/MX dangling records, NSEC walks, zone transfers)
- **HTTP auth-surface fingerprinting** — Server/X-Powered-By/title/missing security headers on exposed webmail, portal, VPN, ADFS subdomains
- **Actionable recommendations** — federation paths, spray strategy, phishing viability, alternate IdPs, exposed services, OPSEC implications of MDI/GCC presence, cloud management console exposure

## Install

```bash
git clone https://github.com/atnovaux/canvass
cd canvass
./setup.sh
```

That's it. `setup.sh` will:
- Verify Python 3.10+ and `git` are installed
- Install `pipx` if missing (prompts for sudo)
- Create a Python virtualenv at `.venv/`
- Install canvass Python deps (jinja2, dnspython)
- Install BBOT via pipx
- Clone AADOutsider-py to `~/tools/AADOutsider-py` and install its deps
- Smoke-test canvass

After setup, activate the venv in new shells:

```bash
source .venv/bin/activate
python3 brief.py <domain>
```

### Manual install (if setup.sh fails)

<details>
<summary>Click to expand</summary>

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# BBOT via pipx (it's a CLI tool)
pipx install bbot

# AADOutsider-py
git clone https://github.com/synacktiv/AADOutsider-py.git ~/tools/AADOutsider-py
pip install -r ~/tools/AADOutsider-py/requirements.txt
```

Alternative: set `AADOUTSIDER_PATH=/your/path` in `.env` to use a non-default location.

</details>

## BBOT API keys (optional but HIGH ROI)

BBOT supports API keys for passive data sources. Adding keys typically yields **20-50% more subdomains** with zero change to canvass. Keys are read automatically from `~/.config/bbot/bbot.yml`:

```yaml
# ~/.config/bbot/bbot.yml
modules:
  securitytrails:
    api_key: "<your-key>"
  virustotal:
    api_key: "<your-key>"
  chaos:
    api_key: "<your-key>"          # free at chaos.projectdiscovery.io
  github:
    api_key: "<your-github-pat>"   # for code search enum
  shodan_dns:
    api_key: "<your-key>"
  c99:
    api_key: "<your-key>"
```

Recommended free/cheap sources to start with: **Chaos** (free, excellent coverage), **VirusTotal** (free tier), **GitHub PAT** (free). Add SecurityTrails/Shodan if you have paid access.

canvass requires no configuration for API keys — BBOT picks them up automatically on every run.

## Usage

```bash
# Standard run (~60-120 sec, BBOT-bound)
python3 brief.py example.com

# Skip BBOT for faster runs (~10-15 sec)
python3 brief.py example.com --skip-bbot

# Custom output directory
python3 brief.py example.com --output-dir ./engagement-example/

# Paste mode: enrich brief with full tenant domain list from osint.aadinternals.com
# Interactive — prompts for MDI / Cloud Sync after paste
python3 brief.py example.com --paste-domains

# Paste mode with signal flags (skip prompts):
python3 brief.py example.com --paste-domains --mdi --cloud-sync
python3 brief.py example.com --paste-domains --no-mdi --no-cloud-sync
```

## Output structure

By default, output lands in `~/engagements/<domain>/recon/`:

```
~/engagements/example.com/recon/
├── brief.md              # human-readable brief (read this first)
├── aad-raw.json          # raw AADOutsider-py output
├── dns-raw.json          # raw DNS collector output
├── cloud-raw.json        # cloud service discovery results
├── bbot-output/          # full BBOT scan results
└── pasted-domains.txt    # raw paste from osint.aadinternals.com (if --paste-domains used)
```

## Cloud attack surface discovery

canvass passively enumerates cloud services owned by the target using DNS resolution only — no HTTP, no API calls, no auth attempts. Token generation pulls from the domain's second-level label, tenant brand, and additional tenant_domains entries to catch subsidiary-owned infrastructure.

**High-signal patterns only** — the collector auto-detects and skips wildcard-resolving zones (Vercel, Heroku, Netlify, etc.) that would produce false positives. Patterns retained are those where a DNS hit genuinely indicates the target owns the resource:

- Azure Blob, Files, Queue, Table storage accounts
- Azure App Service + Kudu/SCM management consoles
- Azure CDN (azureedge.net)
- AWS Apps portals (WorkDocs, Connect, IAM Identity Center)
- AWS Elastic Beanstalk
- SharePoint Online tenants + OneDrive for Business
- Dynamics 365 CRM

Example output (tokens `example` + `parent` — illustrating multi-tenant discovery):

```
CLOUD ATTACK SURFACE (N)
  Passive DNS resolution only. Test access in the active phase.

  Storage (M)
  example.blob.core.windows.net          [Azure Blob]   -> CNAME:...
  exampleprod.file.core.windows.net      [Azure Files]  -> CNAME:...

  Platform Services (K)
  example.scm.azurewebsites.net          [Azure Kudu/SCM]  -> CNAME:...
  example.azurewebsites.net              [Azure App Service] -> CNAME:...
  example.awsapps.com                    [AWS Apps (WorkDocs/Connect/SSO)] -> A:...

  M365 Cloud Services (J)
  example.sharepoint.com                 [SharePoint Online] -> CNAME:...
  example-my.sharepoint.com              [OneDrive for Business] -> CNAME:...
  parent.sharepoint.com                  [SharePoint Online] -> CNAME:...
```

The tool generates a `[MEDIUM] cloud` recommendation when Kudu/SCM consoles are found (management interface escalating to HIGH if creds land in a later phase) and `[INFO] cloud` recommendations directing follow-up active enumeration to `cloud_enum` / `s3scanner` / `MicroBurst`.

## Tenant Intel from AADOutsider-py

When AADOutsider-py is installed (default install at `~/tools/AADOutsider-py/`), the brief automatically gets:

- **Full tenant domain enumeration** — uses the Autodiscover SOAP endpoint with `User-Agent: AutodiscoverClient`, returns ALL custom domains in the tenant (can be hundreds for large multi-brand organizations)
- **Tenant metadata** — brand, ID, region, federation type, STS server, DesktopSSO status
- **MDI (Microsoft Defender for Identity) detection** — via DNS lookup of `<tenant>.atp.azure.com`
- **AAD Connect Cloud Sync detection** — via existence check on `ADToAADSyncServiceAccount@<tenant>`

These signals are auto-detected — no API keys, no authentication, no manual paste needed.

## Paste Mode (Fallback)

If AADOutsider-py isn't installed or you want to cross-check signals from another source, paste mode lets you import data from [osint.aadinternals.com](https://osint.aadinternals.com) (DrAzureAD's web tool):

> **Note:** As of September 2025, the original anonymous OSINT endpoint at `aadinternals.com/osint` was permanently closed due to abuse. The new tool requires authentication with an Entra ID account that has a non-default `.onmicrosoft.com` domain (i.e., a real tenant, not a free trial).

1. Run `python3 brief.py example.com` to generate the baseline
2. Visit https://osint.aadinternals.com and query the target domain
3. Run `python3 brief.py example.com --paste-domains`
4. Paste the domain list when prompted, press Ctrl-D
5. If AADOutsider-py already provided MDI/Cloud Sync signals, the prompts will be skipped automatically. Otherwise, answer the two yes/no questions visible in the same osint.aadinternals.com result.

For scripting, you can skip the prompts using flags:
```bash
python3 brief.py example.com --paste-domains --mdi --cloud-sync < domains.txt
```

## Philosophy

- **Passive only.** No active scanning, no authentication. All queries hit publicly available endpoints.
- **Fast.** ~60-120 seconds total. Parallel collectors.
- **Composable.** Output is markdown + structured JSON. Feed into reports or other tooling.
- **Standalone.** Zero monthly cost, no API keys required.

## Requirements

- Python 3.11+
- AADOutsider-py installed and on PATH
- BBOT installed and on PATH (or use `--skip-bbot`)

## License

Internal tooling. Use at your own risk and only against authorized targets.
