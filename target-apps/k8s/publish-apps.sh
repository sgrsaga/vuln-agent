#!/usr/bin/env bash
# Publish the target-apps as (1) ONE GitHub monorepo holding every app and
# (2) a container image per app — the two things the vuln-agent hardening
# pipeline needs before the Deployments in this directory can be tested:
#   - the vuln-agent.io/source-repo annotation on every app points at this
#     single repo, and vuln-agent.io/dockerfile-path at "<app>/Dockerfile";
#     the agent clones the repo and builds the app's subdirectory as its
#     context (the Dockerfile's directory is the app root), and
#   - each pod's image must exist in the registry so the pod actually runs.
#
# Usage:
#   GITHUB_TOKEN=ghp_... ./publish-apps.sh [owner] [tag] [repo]
#     owner  GitHub user/org to create the repo under (default: sgrsaga)
#     tag    image tag to build and push               (default: v1)
#     repo   name of the monorepo to publish into      (default: target-apps)
#
# Requires: git, docker (logged in to ghcr.io), curl. Idempotent — re-runs
# force-push current content and overwrite the image tags.
set -euo pipefail

OWNER="${1:-sgrsaga}"
TAG="${2:-v1}"
REPO="${3:-target-apps}"
APPS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APPS="python-app go-app java-app nodejs-app typescript-app"
: "${GITHUB_TOKEN:?set GITHUB_TOKEN (repo scope + write:packages)}"

api() {
  curl -sS -H "Authorization: Bearer ${GITHUB_TOKEN}" \
       -H "Accept: application/vnd.github+json" \
       -H "X-GitHub-Api-Version: 2022-11-28" "$@"
}

# 1. Ensure the monorepo exists (user repo; falls back to org endpoint).
echo "=== repo ${OWNER}/${REPO} ==="
if [ "$(api -o /dev/null -w '%{http_code}' "https://api.github.com/repos/${OWNER}/${REPO}")" != "200" ]; then
  resp="$(mktemp)"
  payload="{\"name\":\"${REPO}\",\"private\":false,\"description\":\"vuln-agent sample apps (monorepo)\"}"
  code="$(api -o "${resp}" -w '%{http_code}' -X POST https://api.github.com/user/repos -d "${payload}")"
  if [ "${code}" != "201" ]; then
    code="$(api -o "${resp}" -w '%{http_code}' -X POST "https://api.github.com/orgs/${OWNER}/repos" -d "${payload}")"
  fi
  # Trust only the outcome, not the create call: it can fail (missing scope,
  # expired token) or succeed under the TOKEN'S account when that isn't
  # ${OWNER} — either way ${OWNER}/${REPO} is still missing and the push
  # below would die with a misleading "Repository not found".
  if [ "$(api -o /dev/null -w '%{http_code}' "https://api.github.com/repos/${OWNER}/${REPO}")" != "200" ]; then
    login="$(api https://api.github.com/user | sed -n 's/.*"login": *"\([^"]*\)".*/\1/p' | head -1)"
    {
      echo "ERROR: ${OWNER}/${REPO} still missing after create attempt (HTTP ${code})."
      echo "  GITHUB_TOKEN is for user: ${login:-<invalid token>}"
      echo "  It must belong to '${OWNER}' (or an org admin) and have the classic"
      echo "  'repo' scope — a fine-grained token needs Administration: read/write"
      echo "  to create repos. API response: $(cat "${resp}")"
    } >&2
    rm -f "${resp}"
    exit 1
  fi
  rm -f "${resp}"
  echo "  repo ${OWNER}/${REPO} created"
fi

# 2. Push the whole target-apps tree (all apps + k8s manifests + README) as
#    the repo's root content (fresh history each run).
tmp="$(mktemp -d)"
cp -r "${APPS_DIR}/." "${tmp}/"
rm -rf "${tmp}/.git"
git -C "${tmp}" init -q -b main
git -C "${tmp}" -c user.email=vuln-agent@local -c user.name=vuln-agent \
    add -A
git -C "${tmp}" -c user.email=vuln-agent@local -c user.name=vuln-agent \
    commit -qm "vuln-agent sample apps monorepo"
git -C "${tmp}" push -q --force \
    "https://x-access-token:${GITHUB_TOKEN}@github.com/${OWNER}/${REPO}.git" main
rm -rf "${tmp}"
echo "  source pushed -> github.com/${OWNER}/${REPO}"

# 3. Build each app's runtime image from its subdirectory and push it for the
#    Deployment to pull. Image names stay per-app; only the source repo is shared.
for app in ${APPS}; do
  echo "=== ${app} ==="
  docker build -q -t "ghcr.io/${OWNER}/${app}:${TAG}" "${APPS_DIR}/${app}" >/dev/null
  docker push -q "ghcr.io/${OWNER}/${app}:${TAG}" >/dev/null
  echo "  image pushed  -> ghcr.io/${OWNER}/${app}:${TAG}"
done

echo
echo "Done. Next: kubectl apply -f $(dirname "$0")/namespace.yaml, create the"
echo "ghcr-credentials pull secret in the apps namespace, then apply the app"
echo "manifests — see target-apps/k8s/README.md."
