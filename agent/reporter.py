import anthropic
import logging

logger = logging.getLogger(__name__)
_client = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic()
    return _client


def generate_report(
    image_ref: str,
    iteration: int,
    vulnerabilities: list[dict],
    go_analysis: dict | None = None,
) -> str:
    """Generate a detailed Markdown remediation report using Claude Opus 4.8."""
    if not vulnerabilities:
        return (
            f"# Remediation Report — Iteration {iteration}\n\n"
            "✅ **No HIGH or CRITICAL vulnerabilities found.** The image is clean."
        )

    crit = sum(1 for v in vulnerabilities if v["severity"] == "CRITICAL")
    high = sum(1 for v in vulnerabilities if v["severity"] == "HIGH")

    os_vulns = [v for v in vulnerabilities if v["type"] in ("alpine", "debian", "ubuntu", "redhat", "centos")]
    binary_vulns = [v for v in vulnerabilities if v["type"] == "gobinary"]
    other_vulns = [v for v in vulnerabilities if v not in os_vulns and v not in binary_vulns]

    def fmt_table(vulns: list[dict]) -> str:
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
        ) + "\n".join(rows)

    sections = [f"## OS / Package Vulnerabilities ({len(os_vulns)})\n\n{fmt_table(os_vulns)}" if os_vulns else ""]
    if binary_vulns:
        sections.append(f"## Go Binary Vulnerabilities ({len(binary_vulns)})\n\n{fmt_table(binary_vulns)}")
    if other_vulns:
        sections.append(f"## Other Vulnerabilities ({len(other_vulns)})\n\n{fmt_table(other_vulns)}")

    # Build govulncheck analysis section if available
    go_analysis_section = ""
    if go_analysis:
        fp  = go_analysis.get("false_positives", [])
        un  = go_analysis.get("unexploitable", [])
        co  = go_analysis.get("confirmed", [])
        sk  = go_analysis.get("skipped", [])

        def _govuln_table(vulns: list[dict]) -> str:
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

        go_analysis_section = f"""
## govulncheck Binary Analysis Results

govulncheck performed call-graph analysis on each Go binary in this image.
This is more precise than Trivy's version-based matching.

### False Positives ({len(fp)}) — suppress in scanner policy
These CVEs do NOT exist in the binary as compiled. The binary was built with a
Go toolchain or dependency version that already contains the fix.

{_govuln_table(fp)}

### Unexploitable ({len(un)}) — risk-accept, monitor upstream
These CVEs are present in the binary but the vulnerable symbol is **not reachable**
from any entry point in the call graph. Not exploitable in practice.

{_govuln_table(un)}

### Confirmed ({len(co)}) — requires source rebuild
These CVEs are **genuinely exploitable**: the vulnerable symbol is reachable.
They cannot be fixed at the image layer; a source rebuild with patched dependencies is required.

{_govuln_table(co)}
{"### Skipped (" + str(len(sk)) + ") — binary not extractable" + chr(10) + _govuln_table(sk) if sk else ""}
"""

    effective_count = len(vulnerabilities) - len(go_analysis.get("false_positives", []) if go_analysis else [])

    prompt = f"""You are a senior container security engineer. Analyse this Trivy vulnerability report for image `{image_ref}` (remediation pass #{iteration}) and write a comprehensive Markdown remediation report.

## Scan Summary
- Raw total: {len(vulnerabilities)} (CRITICAL: {crit}, HIGH: {high})
- Effective (excluding govulncheck false positives): {effective_count}
- Scan iteration: {iteration}

{chr(10).join(s for s in sections if s)}
{go_analysis_section}

## Required report sections

1. **Executive Summary** — overall risk rating (Critical/High/Medium), one-paragraph assessment.
   If govulncheck analysis is available, lead with the EFFECTIVE risk (excluding false positives)
   and explain that raw Trivy counts include noise.

2. **Attack Surface Breakdown** — separate analysis for:
   - Alpine/OS packages (fixable with `apk upgrade` or pinned versions)
   - Go binary CVEs — broken into three sub-categories based on govulncheck analysis:
     a) **False positives** — describe what they are, recommend scanner suppression
     b) **Unexploitable** — describe why they are low-risk, recommend risk-acceptance template
     c) **Confirmed** — describe genuine risk, recommend source rebuild path
   - If NO govulncheck analysis is provided: note that Go binary CVEs cannot be patched at
     the image layer and require source rebuild; suggest running govulncheck for precise analysis

3. **Prioritised Remediation Steps**
   - For each fixable OS CVE: exact Dockerfile snippet or shell command
   - For confirmed Go binary CVEs: source rebuild guidance (upgrade Go toolchain version, rebuild image from source)
   - For false positives: scanner suppression guidance (trivy.yaml ignore rules)

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

6. **Estimated CVE Reduction** — if recommended patches are applied, how many CVEs are
   expected to be resolved vs remain

Be precise, technical, and actionable. Use Markdown headers, code blocks, and tables."""

    logger.info(f"Generating remediation report (iteration {iteration})...")
    client = _get_client()
    with client.messages.stream(
        model="claude-opus-4-8",
        max_tokens=8192,
        messages=[{"role": "user", "content": prompt}],
    ) as stream:
        return stream.get_final_text()
