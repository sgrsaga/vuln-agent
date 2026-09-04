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


def generate_summary_report(
    image_ref: str,
    final_image: str,
    status: str,
    iterations: int,
    baseline_vulns: list[dict],
    final_vulns: list[dict],
    unbuilt_dockerfile: str | None = None,
    trail: list[dict] | None = None,
    deployable: bool = True,
    judgment: dict | None = None,
    base_artifact: dict | None = None,
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

    trail_section = ""
    if trail:
        steps = "\n".join(
            f"- **{t.get('step', '?')}** — {t.get('detail', '')}: {t.get('outcome', '')}"
            + ("" if t.get("tests_passed", True) else " **[TESTS FAILED]**")
            for t in trail
        )
        trail_section = f"""
## Internal remediation trail (base selection story)

Every step below was validated by a full rebuild, the application's own test
suite, and a Trivy rescan — non-improving steps were rolled back but retained
as adjudication candidates:

{steps}
"""

    extra_sections = ""
    if base_artifact and (base_artifact.get("published") or base_artifact.get("ref")):
        extra_sections += (
            f"\n## Base artifact\n- Final base: `{base_artifact.get('ref')}`"
            + (f"\n- Published as: `{base_artifact['published']}`" if base_artifact.get("published") else "")
            + "\n"
        )
    if judgment:
        fixes = "\n".join(f"- {f}" for f in judgment.get("code_fixes", [])) or "- (none)"
        extra_sections += f"""
## Balanced-pick adjudication (LLM judgment)
- Justification: {judgment.get('justification', '')}
- Suggested code-level fixes / developer direction:
{fixes}
"""
    if not deployable:
        extra_sections += (
            "\n## ⚠️ NON-DEPLOYABLE\nThe selected image carries TEST FAILURES. It was "
            "pushed for inspection and code-fix follow-up only; the GitOps promotion PR "
            "was intentionally NOT opened. Do not deploy until the suggested fixes land.\n"
        )

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
- Total: {len(baseline_vulns)} (CRITICAL: {b_crit}, HIGH: {b_high})

{_fmt_table(baseline_vulns)}

## After (final state)
- Total: {len(final_vulns)} (CRITICAL: {f_crit}, HIGH: {f_high})

{_fmt_table(final_vulns)}

## Diff
- Resolved ({len(resolved)}): {", ".join(v["id"] for v in resolved) or "(none)"}
- Still present ({len(still_present)}): {", ".join(v["id"] for v in still_present) or "(none)"}
- Newly introduced ({len(newly_introduced)}): {", ".join(v["id"] for v in newly_introduced) or "(none)"}
{trail_section}
{extra_sections}
{dockerfile_section}

## Required report sections

1. **Executive Summary** — overall risk rating before and after (Critical/High/Medium),
   one-paragraph assessment of the improvement achieved and what remains.

2. **What changed** — plain-language account of how the reduction was achieved
   (base image tag bump, OS package upgrade, base swap, dependency upgrades),
   and how many iterations/steps it took.

3. **Remaining Risk Breakdown** — for everything still present after remediation:
   - OS packages with no fix available yet
   - Compiled-in / application-level CVEs that only an upstream release or code
     change can fix, with remediation guidance for each

4. **Risk Acceptance Template** — for remaining CVEs a team decides to accept, a
   copy-paste entry:
   ```
   CVE: <ID>
   Status: Risk Accepted
   Reason: <why this is acceptable in this deployment>
   Reviewed by: <name>
   Review date: <date>
   Next review: <date + 90 days>
   ```

5. **Residual Risk Guidance** — compensating controls for the remaining CVEs:
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


def generate_run_report(results: list[tuple[str, dict]]) -> str:
    """
    The run-level report (spec 2.9): one Claude call covering every image in a
    discovery run, in two sections — External (improvement summary, residual
    risk, mitigations) and Internal (base selections, security-posture
    improvements, app impact from test failures, justifications for code-level
    changes when a base swap demands them).
    """
    internal_statuses = {"golden_base_app", "optimized_app"}
    ext_lines, int_lines = [], []
    for image, r in results:
        line = (f"- `{image}` → status `{r.get('status')}`, final `{r.get('final_image')}`, "
                f"remaining HIGH/CRITICAL: {r.get('remaining_vulns')}")
        if r.get("status") in internal_statuses or (
            r.get("status") == "no_improvement" and "-app" in str(r.get("final_image", ""))
        ):
            int_lines.append(line)
        else:
            ext_lines.append(line)

    prompt = f"""You are a senior container security engineer writing the run-level summary of
an automated vulnerability remediation sweep across a Kubernetes cluster.

## External (third-party) image results
{chr(10).join(ext_lines) or "(none this run)"}

## Internal (owned application) image results
{chr(10).join(int_lines) or "(none this run)"}

Write a Markdown report with exactly two top-level sections:

1. **External images** — a basic summary of the improvements achieved, the risk
   factors still present, and concrete possible mitigation techniques for what
   remains (compensating controls, upstream-watch guidance, etc.).

2. **Internal images** — detail: which base image selections were made and why
   they improve the security posture, any impact to the applications evidenced
   by test-case failures, and — where a new base or fix implies code-base
   changes — a proper justification of why changing the code is worth the
   overall security improvement.

Close with a short holistic assessment of the cluster's security-posture trend.
Be precise, technical, and actionable."""

    logger.info(f"Generating run-level report for {len(results)} image(s)...")
    client = _get_client()
    with client.messages.stream(
        model="claude-opus-4-8",
        max_tokens=8192,
        messages=[{"role": "user", "content": prompt}],
    ) as stream:
        return stream.get_final_text()
