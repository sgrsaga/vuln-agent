#!/usr/bin/env bash
# Publish each target-app as (1) its own GitHub repo and (2) a container image —
# the two things the vuln-agent hardening pipeline needs before the Deployments
# in this directory can be tested for real:
#   - the vuln-agent.io/source-repo annotation must point at a clonable repo
#     whose ROOT holds the Dockerfile + manifests (the agent builds the clone
#     root — a monorepo subdirectory does not work), and
#   - the pod's image must exist in the registry so the pod actually runs.
#
# Usage:
#   GITHUB_TOKEN=ghp_... ./publish-apps.sh [owner] [tag]
#     owner  GitHub user/org to create the repos under (default: sgrsaga)
#     tag    image tag to build and push               (default: v1)
#
# Requires: git, docker (logged in to ghcr.io), curl. Idempotent — re-runs
# force-push current content and overwrite the image tag.
set -euo pipefail

OWNER="${1:-sgrsaga}"
TAG="${2:-v1}"
APPS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
: "${GITHUB_TOKEN:?set GITHUB_TOKEN (repo scope + write:packages)}"

api() {
  curl -sS -H "Authorization: Bearer ${GITHUB_TOKEN}" \
       -H "Accept: application/vnd.github+json" \
       -H "X-GitHub-Api-Version: 2022-11-28" "$@"
}

for app in python-app go-app java-app nodejs-app typescript-app; do
  echo "=== ${app} ==="
  src="${APPS_DIR}/${app}"

  # 1. Ensure the GitHub repo exists (user repo; falls back to org endpoint).
  if [ "$(api -o /dev/null -w '%{http_code}' "https://api.github.com/repos/${OWNER}/${app}")" != "200" ]; then
    code="$(api -o /dev/null -w '%{http_code}' -X POST https://api.github.com/user/repos \
        -d "{\"name\":\"${app}\",\"private\":false,\"description\":\"vuln-agent sample app (${app})\"}")"
    if [ "${code}" != "201" ]; then
      api -o /dev/null -X POST "https://api.github.com/orgs/${OWNER}/repos" \
          -d "{\"name\":\"${app}\",\"private\":false,\"description\":\"vuln-agent sample app (${app})\"}"
    fi
    echo "  repo ${OWNER}/${app} created"
  fi

  # 2. Push the app directory as the repo's root content (fresh history each run).
  tmp="$(mktemp -d)"
  cp -r "${src}/." "${tmp}/"
  git -C "${tmp}" init -q -b main
  git -C "${tmp}" -c user.email=vuln-agent@local -c user.name=vuln-agent \
      add -A
  git -C "${tmp}" -c user.email=vuln-agent@local -c user.name=vuln-agent \
      commit -qm "vuln-agent sample app: ${app}"
  git -C "${tmp}" push -q --force \
      "https://x-access-token:${GITHUB_TOKEN}@github.com/${OWNER}/${app}.git" main
  rm -rf "${tmp}"
  echo "  source pushed -> github.com/${OWNER}/${app}"

  # 3. Build the runtime image and push it for the Deployment to pull.
  docker build -q -t "ghcr.io/${OWNER}/${app}:${TAG}" "${src}" >/dev/null
  docker push -q "ghcr.io/${OWNER}/${app}:${TAG}" >/dev/null
  echo "  image pushed  -> ghcr.io/${OWNER}/${app}:${TAG}"
done

echo
echo "Done. Next: kubectl apply -f $(dirname "$0")/namespace.yaml, create the"
echo "ghcr-credentials pull secret in the apps namespace, then apply the app"
echo "manifests — see target-apps/k8s/README.md."
