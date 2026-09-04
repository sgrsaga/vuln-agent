"""
Opens a reviewable PR against a GitOps manifests repo bumping an image reference
to the latest optimized tag — the "higher environment" (PPE/Prod) promotion path.

Unlike ArgoCD Image Updater (an independent, separately-installed controller that
polls the registry directly for lower environments — see README.md), this never
writes straight to a deployed branch: it always opens a PR and leaves merging to a
human, since higher environments need a review gate.

Follows the same httpx + GitHub REST API pattern as
agent/publisher.py: create_github_release() — no gh CLI, no new dependency.
"""

import base64
import logging
import re

import httpx

logger = logging.getLogger(__name__)

_GH_API = "https://api.github.com"


def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _patch_image_ref(content: str, repo_name: str, new_image: str) -> str | None:
    """
    Replace the tag on any line referencing `repo_name` with new_image's tag.
    Returns the patched content, or None if the pattern wasn't found or the
    replacement would be a no-op (already up to date) — callers must not open
    an empty PR in either case.
    """
    new_tag = new_image.rsplit(":", 1)[-1]
    pattern = re.compile(rf"({re.escape(repo_name)}:)\S+")
    if not pattern.search(content):
        return None
    patched = pattern.sub(rf"\g<1>{new_tag}", content)
    return patched if patched != content else None


def _find_open_pr(client: httpx.Client, gitops_repo: str, owner: str, branch: str) -> dict | None:
    resp = client.get(
        f"{_GH_API}/repos/{gitops_repo}/pulls",
        params={"head": f"{owner}:{branch}", "state": "open"},
    )
    if resp.status_code != 200:
        return None
    prs = resp.json()
    return {"number": prs[0]["number"], "html_url": prs[0]["html_url"]} if prs else None


# GitHub caps PR/issue bodies at 65536 chars; leave headroom for the fixed part.
_BODY_BUDGET = 50000


def _pr_body(repo_name: str, new_image: str, image_path: str, summary: str | None) -> str:
    body = (
        f"Automated promotion by vuln-agent.\n\n"
        f"- Image: `{repo_name}`\n"
        f"- New reference: `{new_image}`\n"
        f"- File: `{image_path}`\n"
    )
    if summary:
        if len(summary) > _BODY_BUDGET:
            summary = summary[:_BODY_BUDGET] + "\n\n*(truncated — full report in the reports repo / release assets)*"
        body += (
            "\n---\n\n<details><summary>📋 Remediation summary — what changed and why "
            "(review this before merging)</summary>\n\n"
            f"{summary}\n\n</details>\n"
        )
    return body


def open_promotion_pr(
    gitops_repo: str,
    token: str,
    base_branch: str,
    image_path: str,
    repo_name: str,
    new_image: str,
    summary: str | None = None,
) -> str | None:
    """
    Patch image_path in gitops_repo (owner/repo) to reference new_image, on a
    stable per-image branch, and open (or update) a PR. When `summary` is given
    (the run's before/after report), it's folded into the PR body so reviewers
    see the security story exactly where they approve the change — and kept
    fresh on re-runs that update an existing open PR.

    Returns the PR URL, or None if there was nothing to promote (pattern not
    found in the target file, or it already references new_image).
    """
    owner = gitops_repo.split("/", 1)[0]
    branch = f"vuln-agent/optimize-{repo_name}"

    with httpx.Client(base_url=_GH_API, headers=_headers(token), timeout=30.0) as client:
        resp = client.get(
            f"/repos/{gitops_repo}/contents/{image_path}",
            params={"ref": base_branch},
        )
        if resp.status_code != 200:
            logger.warning(f"Could not fetch {image_path} from {gitops_repo}: {resp.status_code}")
            return None
        file_data = resp.json()
        content = base64.b64decode(file_data["content"]).decode()

        patched = _patch_image_ref(content, repo_name, new_image)
        if patched is None:
            logger.info(f"No promotion needed: {repo_name} in {image_path} already up to date, or pattern not found")
            return None

        existing_pr = _find_open_pr(client, gitops_repo, owner, branch)

        # Create or move the branch to point at the current base, then commit the patch.
        ref_resp = client.get(f"/repos/{gitops_repo}/git/ref/heads/{base_branch}")
        if ref_resp.status_code != 200:
            logger.warning(f"Could not resolve base branch {base_branch} in {gitops_repo}")
            return None
        base_sha = ref_resp.json()["object"]["sha"]

        branch_resp = client.get(f"/repos/{gitops_repo}/git/ref/heads/{branch}")
        if branch_resp.status_code == 200:
            client.patch(f"/repos/{gitops_repo}/git/refs/heads/{branch}",
                          json={"sha": base_sha, "force": True})
            # Re-fetch the file's sha on the branch we're about to write to.
            branch_file = client.get(f"/repos/{gitops_repo}/contents/{image_path}",
                                      params={"ref": branch})
            file_sha = branch_file.json()["sha"] if branch_file.status_code == 200 else file_data["sha"]
        else:
            create_resp = client.post(f"/repos/{gitops_repo}/git/refs",
                json={"ref": f"refs/heads/{branch}", "sha": base_sha})
            if create_resp.status_code not in (200, 201):
                logger.warning(f"Could not create branch {branch} in {gitops_repo}: {create_resp.text[:300]}")
                return None
            file_sha = file_data["sha"]

        put_resp = client.put(
            f"/repos/{gitops_repo}/contents/{image_path}",
            json={
                "message": f"vuln-agent: promote {repo_name} to {new_image.rsplit(':', 1)[-1]}",
                "content": base64.b64encode(patched.encode()).decode(),
                "sha": file_sha,
                "branch": branch,
            },
        )
        if put_resp.status_code not in (200, 201):
            logger.warning(f"Could not update {image_path} on {branch}: {put_resp.text[:300]}")
            return None

        if existing_pr:
            # Keep the body current — this run's summary supersedes the old one.
            client.patch(
                f"/repos/{gitops_repo}/pulls/{existing_pr['number']}",
                json={"body": _pr_body(repo_name, new_image, image_path, summary)},
            )
            logger.info(f"Updated existing promotion PR: {existing_pr['html_url']}")
            return existing_pr["html_url"]

        pr_resp = client.post(f"/repos/{gitops_repo}/pulls", json={
            "title": f"Promote {repo_name} to optimized image",
            "head": branch,
            "base": base_branch,
            "body": _pr_body(repo_name, new_image, image_path, summary),
        })
        if pr_resp.status_code not in (200, 201):
            logger.warning(f"Could not open PR in {gitops_repo}: {pr_resp.text[:300]}")
            return None

        pr_url = pr_resp.json()["html_url"]
        logger.info(f"Opened promotion PR: {pr_url}")
        return pr_url


def open_code_fix_issue(
    source_repo: str,
    token: str,
    image_ref: str,
    final_image: str,
    judgment: dict,
    crit: int,
    high: int,
) -> str | None:
    """
    File the adjudication's code-fix suggestions as a GitHub Issue on the app's
    OWN source repo — used when the balanced pick eliminates vulnerabilities but
    fails the test suite, so shipping it needs developer action. Without this,
    those suggestions sit in a report nobody is forced to open; an issue lands
    them in the team's normal triage flow.

    Stable title per image ref → re-runs comment on the existing open issue
    instead of piling up duplicates. Returns the issue URL, or None.
    """
    title = f"vuln-agent: security fix for `{image_ref}` blocked by failing tests"
    fixes = "\n".join(f"- [ ] {f}" for f in judgment.get("code_fixes", [])) or "- (none suggested)"
    update = (
        f"A remediation candidate eliminating CVEs (down to {crit} CRITICAL / {high} HIGH) "
        f"was built and pushed as `{final_image}`, but its tests failed — it is flagged "
        f"**non-deployable** and will not be promoted until the breakage is fixed.\n\n"
        f"**Adjudication justification:**\n> {judgment.get('justification', '(none)')}\n\n"
        f"**Suggested code fixes:**\n{fixes}\n\n"
        f"Once fixed, the next scheduled run re-validates automatically — no manual "
        f"re-trigger needed. Full before/after details are in the run's summary report."
    )

    try:
        with httpx.Client(base_url=_GH_API, headers=_headers(token), timeout=30.0) as client:
            resp = client.get(f"/repos/{source_repo}/issues",
                              params={"state": "open", "per_page": 100})
            if resp.status_code == 200:
                for issue in resp.json():
                    if issue.get("title") == title and "pull_request" not in issue:
                        client.post(f"/repos/{source_repo}/issues/{issue['number']}/comments",
                                    json={"body": update})
                        logger.info(f"Commented on existing code-fix issue: {issue['html_url']}")
                        return issue["html_url"]

            created = client.post(f"/repos/{source_repo}/issues",
                                  json={"title": title, "body": update})
            if created.status_code not in (200, 201):
                logger.warning(f"Could not open code-fix issue in {source_repo}: "
                               f"{created.status_code} {created.text[:300]}")
                return None
            url = created.json()["html_url"]
            logger.info(f"Opened code-fix issue: {url}")
            return url
    except Exception as exc:
        logger.warning(f"Code-fix issue in {source_repo} failed: {exc}")
        return None
