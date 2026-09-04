#!/usr/bin/env bash
# Publish the target-apps into ONE shared GitHub repo (default: sgrsaga/reports —
# the same repo the agent commits its reports into, so application code and the
# reports about it live side by side: <app>/ folders next to reports/), and
# build+push a container image per app.
#
# The vuln-agent.io/source-repo annotation on every app points at this repo and
# vuln-agent.io/dockerfile-path at "<app>/Dockerfile"; the agent clones the repo
# and builds the app's subdirectory as its context (the Dockerfile's directory
# is the app root).
#
# The sync is NON-DESTRUCTIVE: the existing repo history and everything outside
# the app folders (especially reports/ written by the agent) are preserved —
# only the app directories are refreshed. Never force-pushes.
#
# Usage:
#   GITHUB_TOKEN=ghp_... ./publish-apps.sh [owner] [tag] [repo]
#     owner  GitHub user/org owning the repo            (default: sgrsaga)
#     tag    image tag to build and push                (default: v1)
#     repo   shared repo to publish the apps into       (default: reports)
#
# Requires: git, docker, curl. Logs docker into ghcr.io with GITHUB_TOKEN
# itself — the token needs the classic 'repo' AND 'write:packages' scopes.
set -euo pipefail

OWNER="${1:-sgrsaga}"
TAG="${2:-v1}"
REPO="${3:-reports}"
APPS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APPS="python-app go-app java-app nodejs-app typescript-app"
: "${GITHUB_TOKEN:?set GITHUB_TOKEN (classic scopes: repo + write:packages)}"

api() {
  curl -sS -H "Authorization: Bearer ${GITHUB_TOKEN}" \
       -H "Accept: application/vnd.github+json" \
       -H "X-GitHub-Api-Version: 2022-11-28" "$@"
}

# 0. Registry login — docker push authenticates separately from git; this is
#    what "unauthorized: unauthenticated" means when it's skipped.
echo "=== ghcr.io login (${OWNER}) ==="
printf '%s' "${GITHUB_TOKEN}" | docker login ghcr.io -u "${OWNER}" --password-stdin >/dev/null

# 1. Ensure the shared repo exists (user repo; falls back to org endpoint).
echo "=== repo ${OWNER}/${REPO} ==="
if [ "$(api -o /dev/null -w '%{http_code}' "https://api.github.com/repos/${OWNER}/${REPO}")" != "200" ]; then
  payload="{\"name\":\"${REPO}\",\"private\":false,\"description\":\"vuln-agent: sample apps + remediation reports\",\"auto_init\":true}"
  code="$(api -o /dev/null -w '%{http_code}' -X POST https://api.github.com/user/repos -d "${payload}")"
  if [ "${code}" != "201" ]; then
    api -o /dev/null -X POST "https://api.github.com/orgs/${OWNER}/repos" -d "${payload}"
  fi
  if [ "$(api -o /dev/null -w '%{http_code}' "https://api.github.com/repos/${OWNER}/${REPO}")" != "200" ]; then
    login="$(api https://api.github.com/user | sed -n 's/.*"login": *"\([^"]*\)".*/\1/p' | head -1)"
    echo "ERROR: ${OWNER}/${REPO} still missing after create attempt (HTTP ${code})." >&2
    echo "  GITHUB_TOKEN is for user: ${login:-<invalid token>} — it must belong to" >&2
    echo "  '${OWNER}' (or an org admin) with the classic 'repo' scope." >&2
    exit 1
  fi
  echo "  repo ${OWNER}/${REPO} created"
fi

# 2. Sync ONLY the app folders into the existing repo — clone, refresh each
#    <app>/ directory, commit on top of current history. reports/ and anything
#    else in the repo are untouched.
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
git clone -q --depth 1 \
    "https://x-access-token:${GITHUB_TOKEN}@github.com/${OWNER}/${REPO}.git" "${tmp}/repo"
for app in ${APPS}; do
  rm -rf "${tmp}/repo/${app}"
  cp -r "${APPS_DIR}/${app}" "${tmp}/repo/${app}"
done
if [ -n "$(git -C "${tmp}/repo" status --porcelain)" ]; then
  git -C "${tmp}/repo" -c user.email=vuln-agent@local -c user.name=vuln-agent add -A
  git -C "${tmp}/repo" -c user.email=vuln-agent@local -c user.name=vuln-agent \
      commit -qm "vuln-agent sample apps: sync app folders"
  git -C "${tmp}/repo" push -q origin HEAD
  echo "  app folders synced -> github.com/${OWNER}/${REPO} (reports/ untouched)"
else
  echo "  app folders already up to date"
fi

# 3. Build each app's runtime image from its directory and push it for the
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
