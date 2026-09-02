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


def _find_open_pr(client: httpx.Client, gitops_repo: str, owner: str, branch: str) -> str | None:
    resp = client.get(
        f"{_GH_API}/repos/{gitops_repo}/pulls",
        params={"head": f"{owner}:{branch}", "state": "open"},
    )
    if resp.status_code != 200:
        return None
    prs = resp.json()
    return prs[0]["html_url"] if prs else None


def open_promotion_pr(
    gitops_repo: str,
    token: str,
    base_branch: str,
    image_path: str,
    repo_name: str,
    new_image: str,
) -> str | None:
    """
    Patch image_path in gitops_repo (owner/repo) to reference new_image, on a
    stable per-image branch, and open (or update) a PR.

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
            logger.info(f"Updated existing promotion PR: {existing_pr}")
            return existing_pr

        pr_resp = client.post(f"/repos/{gitops_repo}/pulls", json={
            "title": f"Promote {repo_name} to optimized image",
            "head": branch,
            "base": base_branch,
            "body": (
                f"Automated promotion by vuln-agent.\n\n"
                f"- Image: `{repo_name}`\n"
                f"- New reference: `{new_image}`\n"
                f"- File: `{image_path}`\n"
            ),
        })
        if pr_resp.status_code not in (200, 201):
            logger.warning(f"Could not open PR in {gitops_repo}: {pr_resp.text[:300]}")
            return None

        pr_url = pr_resp.json()["html_url"]
        logger.info(f"Opened promotion PR: {pr_url}")
        return pr_url
