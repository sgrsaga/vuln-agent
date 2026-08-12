import anthropic
import logging

logger = logging.getLogger(__name__)
_client = None

CANNOT_PATCH = "CANNOT_PATCH_FURTHER"


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic()
    return _client


def _clean_dockerfile(content: str) -> str | None:
    """Strip markdown fences if Claude wrapped the output, then validate."""
    content = content.strip()
    if content.startswith("```"):
        lines = content.splitlines()
        inner = []
        in_block = False
        for line in lines:
            if line.startswith("```") and not in_block:
                in_block = True
                continue
            if line.startswith("```") and in_block:
                break
            if in_block:
                inner.append(line)
        content = "\n".join(inner).strip()

    if not content.upper().startswith("FROM"):
        return None
    return content


def generate_patch(
    current_image: str,
    iteration: int,
    vulnerabilities: list[dict],
    previous_dockerfiles: list[str],
    go_analysis: dict | None = None,
) -> str | None:
    """
    Ask Claude to produce a Dockerfile that patches remaining vulnerabilities.

    Returns:
        Dockerfile string — a valid patch to apply
        None             — no further patches possible at the image layer
    """
    os_fixable = [
        v for v in vulnerabilities
        if v["type"] in ("alpine", "debian", "ubuntu", "redhat", "centos") and v.get("fixed")
    ]
    os_unfixable = [
        v for v in vulnerabilities
        if v["type"] in ("alpine", "debian", "ubuntu", "redhat", "centos") and not v.get("fixed")
    ]
    binary_vulns = [v for v in vulnerabilities if v["type"] == "gobinary"]
    other = [v for v in vulnerabilities if v not in os_fixable and v not in os_unfixable and v not in binary_vulns]

    def fmt_list(vulns: list[dict]) -> str:
        return "\n".join(
            f"  - [{v['severity']}] {v['id']}: `{v['package']}` {v['installed']}"
            + (f" → fix: {v['fixed']}" if v.get("fixed") else " (no fix available)")
            for v in vulns
        ) or "  (none)"

    prev_section = ""
    if previous_dockerfiles:
        prev_section = "\n\n**Previously applied Dockerfiles (do NOT repeat these):**\n"
        for i, df in enumerate(previous_dockerfiles, 1):
            prev_section += f"\n*Iteration {i}:*\n```dockerfile\n{df}\n```\n"

    # Build govulncheck-enhanced Go binary section
    if go_analysis:
        fp  = go_analysis.get("false_positives", [])
        un  = go_analysis.get("unexploitable", [])
        co  = go_analysis.get("confirmed", [])
        sk  = go_analysis.get("skipped", [])

        go_section = f"""
**Go binary CVEs — govulncheck analysis results:**

  FALSE POSITIVES ({len(fp)}) — NOT real vulnerabilities, ignore these:
{fmt_list(fp) if fp else "  (none)"}

  UNEXPLOITABLE ({len(un)}) — present but vulnerable symbol not reachable, risk-accepted:
{fmt_list(un) if un else "  (none)"}

  CONFIRMED exploitable ({len(co)}) — require source rebuild, CANNOT fix via Dockerfile:
{fmt_list(co) if co else "  (none)"}

  SKIPPED ({len(sk)}) — binary extraction failed, treat as unverified:
{fmt_list(sk) if sk else "  (none)"}

  IMPORTANT: Even confirmed Go binary CVEs cannot be fixed by adding Dockerfile layers.
  Do NOT attempt to patch these — only OS/package CVEs can be fixed here.
"""
    else:
        go_section = f"""
**Go binary CVEs — NOT patchable via Dockerfile ({len(binary_vulns)}):**
{fmt_list(binary_vulns)}
  Note: Run govulncheck on these binaries to identify false positives and unexploitable paths.
"""

    prompt = f"""You are a Docker security expert. Image `{current_image}` still has vulnerabilities after {iteration - 1} remediation attempt(s).

## Remaining vulnerabilities

**OS packages with available fixes ({len(os_fixable)}):**
{fmt_list(os_fixable)}

**OS packages — no fix available ({len(os_unfixable)}):**
{fmt_list(os_unfixable)}
{go_section}
**Other ({len(other)}):**
{fmt_list(other)}
{prev_section}

## Your task

Generate a Dockerfile that fixes as many **OS / package** vulnerabilities as possible.

**Rules:**
1. First line MUST be exactly: `FROM {current_image}`
2. For Alpine packages: prefer `RUN apk upgrade --no-cache` (upgrades all fixable packages at once) or `apk add --no-cache <pkg>=<fixed-version>` for targeted pins.
3. **Do NOT touch Go binary CVEs** — they live inside the compiled binary and cannot be patched with image layers. Do not attempt to replace the binary.
4. Do not repeat patches from previous iterations.
5. If **all** remaining CVEs are OS packages with no fix available or Go binary CVEs (including false positives and unexploitable ones from govulncheck) — respond with the single word: `{CANNOT_PATCH}`

**Response format:** Return ONLY the Dockerfile content, or ONLY the word `{CANNOT_PATCH}`. No prose, no markdown fences."""

    logger.info(f"Generating patch Dockerfile (iteration {iteration})...")
    client = _get_client()
    response = client.messages.create(
        model="claude-opus-4-8",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = "".join(
        block.text for block in response.content if block.type == "text"
    ).strip()

    if raw == CANNOT_PATCH or raw.startswith(CANNOT_PATCH):
        logger.info("Claude: no further patches possible")
        return None

    dockerfile = _clean_dockerfile(raw)
    if dockerfile is None:
        logger.warning("Claude returned unexpected content — treating as unpatchable")
        return None

    return dockerfile
