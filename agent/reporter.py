import anthropic
import logging

logger = logging.getLogger(__name__)
_client = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic()
    return _client


def _fmt_table(vulns: list[dict]) -> str:
    rows = []
    for v in sorted(vulns, key=lambda x: (x["severity"] != "CRITICAL", x["id"])):
        fix = v.get("fixed") or "NO FIX"
        rows.append(
            f"| {v['severity']} | `{v['id']}` | `{v['package']}` "
            f"| {v['installed']} | {fix} | {v['title'][:60]} |"
        )
    return (
        "| Severity | CVE ID | Package | Installed | Fix Version | Title |\n"
        "|----------|--------|---------|-----------|-------------|-------|\n"
    ) + ("\n".join(rows) if rows else "_(none)_")


def _govuln_section(go_analysis: dict | None) -> str:
    if not go_analysis:
        return ""

    fp = go_analysis.get("false_positives", [])
    un = go_analysis.get("unexploitable", [])
    co = go_analysis.get("confirmed", [])
    sk = go_analysis.get("skipped", [])

    def _table(vulns: list[dict]) -> str:
        rows = [
            f"| `{v['id']}` | `{v['package']}` | {v['severity']} "
            f"| {v.get('analysis', {}).get('go_version', '?')} "
            f"| {v.get('analysis', {}).get('reason', '')[:120]} |"
            for v in sorted(vulns, key=lambda x: x["id"])
        ]
        hdr = (
            "| CVE ID | Package | Severity | Go Version | govulncheck finding |\n"
            "|--------|---------|----------|------------|---------------------|\n"
        )
        return hdr + "\n".join(rows) if rows else "_(none)_"

    return f"""
## govulncheck Binary Analysis Results

govulncheck performed call-graph analysis on each Go binary in the original image.
This is more precise than Trivy's version-based matching.

### False Positives ({len(fp)}) — suppress in scanner policy
These CVEs do NOT exist in the binary as compiled. The binary was built with a
Go toolchain or dependency version that already contains the fix.

{_table(fp)}

### Unexploitable ({len(un)}) — risk-accept, monitor upstream
These CVEs are present in the binary but the vulnerable symbol is **not reachable**
from any entry point in the call graph. Not exploitable in practice.

{_table(un)}

### Confirmed ({len(co)}) — requires source rebuild
These CVEs are **genuinely exploitable**: the vulnerable symbol is reachable.
They cannot be fixed at the image layer; a source rebuild with patched dependencies is required.

{_table(co)}
{"### Skipped (" + str(len(sk)) + ") — binary not extractable" + chr(10) + _table(sk) if sk else ""}
"""


def generate_summary_report(
    image_ref: str,
    final_image: str,
    status: str,
    iterations: int,
    baseline_vulns: list[dict],
    final_vulns: list[dict],
    go_analysis: dict | None = None,
    unbuilt_dockerfile: str | None = None,
) -> str:
    """
    Generate one before/after Markdown remediation summary using Claude Opus 4.8,
    covering the whole run rather than a single iteration.
    """
    if not baseline_vulns:
        return (
            "# Remediation Summary\n\n"
            f"✅ **`{image_ref}` was already clean** — no HIGH or CRITICAL "
            "vulnerabilities found on the first scan. No changes were made."
        )

    baseline_ids = {v["id"] for v in baseline_vulns}
    final_ids = {v["id"] for v in final_vulns}
    resolved = [v for v in baseline_vulns if v["id"] not in final_ids]
    still_present = [v for v in final_vulns if v["id"] in baseline_ids]
    newly_introduced = [v for v in final_vulns if v["id"] not in baseline_ids]

    b_crit = sum(1 for v in baseline_vulns if v["severity"] == "CRITICAL")
    b_high = sum(1 for v in baseline_vulns if v["severity"] == "HIGH")
    f_crit = sum(1 for v in final_vulns if v["severity"] == "CRITICAL")
    f_high = sum(1 for v in final_vulns if v["severity"] == "HIGH")

    fp_ids = {v["id"] for v in (go_analysis or {}).get("false_positives", [])}
    effective_baseline = len([v for v in baseline_vulns if v["id"] not in fp_ids])
    effective_final = len([v for v in final_vulns if v["id"] not in fp_ids])

    dockerfile_section = ""
    if unbuilt_dockerfile:
        dockerfile_section = f"""
## Generated but unverified patch

A patch Dockerfile was generated but could not be built/verified in this run
(no Docker daemon available). Use it as the starting point for a manual build:

```dockerfile
{unbuilt_dockerfile}
```
"""

    prompt = f"""You are a senior container security engineer. Write a comprehensive Markdown
before/after remediation summary for a multi-iteration automated remediation run.

## Run outcome
- Original image: `{image_ref}`
- Final image: `{final_image}`
- Status: `{status}`
- Iterations run: {iterations}

## Before (first scan)
- Raw total: {len(baseline_vulns)} (CRITICAL: {b_crit}, HIGH: {b_high})
- Effective (excluding govulncheck false positives): {effective_baseline}

{_fmt_table(baseline_vulns)}

## After (final state)
- Raw total: {len(final_vulns)} (CRITICAL: {f_crit}, HIGH: {f_high})
- Effective (excluding govulncheck false positives): {effective_final}

{_fmt_table(final_vulns)}

## Diff
- Resolved ({len(resolved)}): {", ".join(v["id"] for v in resolved) or "(none)"}
- Still present ({len(still_present)}): {", ".join(v["id"] for v in still_present) or "(none)"}
- Newly introduced ({len(newly_introduced)}): {", ".join(v["id"] for v in newly_introduced) or "(none)"}
{_govuln_section(go_analysis)}
{dockerfile_section}

## Required report sections

1. **Executive Summary** — overall risk rating before and after (Critical/High/Medium),
   one-paragraph assessment of the improvement achieved and what remains.

2. **What changed** — plain-language account of how the reduction was achieved
   (base image tag bump, OS package upgrade, or both), and how many iterations it took.

3. **Remaining Risk Breakdown** — for everything still present after remediation:
   - Alpine/OS packages with no fix available
   - Go binary CVEs, broken into false positives / unexploitable / confirmed
     (per the govulncheck section above, if present)
   - Anything else still open, with remediation guidance for each

4. **Risk Acceptance Template** — for unexploitable Go CVEs, a copy-paste risk acceptance entry:
   ```
   CVE: <ID>
   Status: Risk Accepted
   Reason: govulncheck confirms the vulnerable symbol is not reachable in <binary>
   Reviewed by: <name>
   Review date: <date>
   Next review: <date + 90 days>
   ```

5. **Residual Risk Guidance** — compensating controls for confirmed Go binary CVEs:
   network policies, mTLS enforcement, read-only filesystem, seccomp/AppArmor profiles

Be precise, technical, and actionable. Use Markdown headers, code blocks, and tables."""

    logger.info(f"Generating summary report ({iterations} iteration(s))...")
    client = _get_client()
    with client.messages.stream(
        model="claude-opus-4-8",
        max_tokens=8192,
        messages=[{"role": "user", "content": prompt}],
    ) as stream:
        return stream.get_final_text()
