import anthropic
import logging

logger = logging.getLogger(__name__)
_client = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic()
    return _client


def generate_report(image_ref: str, iteration: int, vulnerabilities: list[dict]) -> str:
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

    prompt = f"""You are a senior container security engineer. Analyse this Trivy vulnerability report for image `{image_ref}` (remediation pass #{iteration}) and write a comprehensive Markdown remediation report.

## Scan Summary
- Total: {len(vulnerabilities)} (CRITICAL: {crit}, HIGH: {high})
- Scan iteration: {iteration}

{chr(10).join(s for s in sections if s)}

## Required report sections

1. **Executive Summary** — overall risk rating (Critical/High/Medium), one-paragraph assessment
2. **Attack Surface Breakdown** — separate analysis for:
   - Alpine/OS packages (fixable with `apk upgrade` or pinned versions)
   - Go binary CVEs (require source rebuild; cannot be patched at the image layer)
   - False positive assessment: Trivy is known to misreport Go module CVEs when the installed version is a pseudo-version that predates the semantic release where the fix landed — call these out explicitly
3. **Prioritised Remediation Steps** — for each fixable CVE, provide the exact Dockerfile snippet or shell command
4. **What Cannot Be Fixed at the Image Layer** — list Go binary CVEs, explain why (embedded binary, no package manager), and recommend source-level dependency bumps (go get)
5. **Residual Risk Guidance** — what to tell stakeholders about unfixed CVEs, suggested mitigations (network policy, read-only FS, seccomp profiles)
6. **Estimated CVE Reduction** — if recommended patches are applied, how many CVEs are expected to be resolved vs remain

Be precise, technical, and actionable. Use Markdown headers, code blocks, and tables."""

    logger.info(f"Generating remediation report (iteration {iteration})...")
    client = _get_client()
    with client.messages.stream(
        model="claude-opus-4-8",
        max_tokens=4096,
        thinking={"type": "adaptive"},
        messages=[{"role": "user", "content": prompt}],
    ) as stream:
        final = stream.get_final_message()

    return "".join(
        block.text for block in final.content if block.type == "text"
    )
