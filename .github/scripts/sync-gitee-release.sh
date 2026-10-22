#!/usr/bin/env bash
# Sync ONE GitHub Release — tag $TAG — to Gitee: create the Gitee release if
# it doesn't exist (same name, notes, target and prerelease flag), then
# upload the files it doesn't have yet.  No other release is created,
# changed or deleted.  TLS is verified; the token is never on a command
# line.
#
# Environment:
#   TAG                 tag of the release (e.g. v3.1.2)
#   GITHUB_REPOSITORY   owner/repo on GitHub (set by Actions)
#   GH_TOKEN            token for `gh` (the workflow's github.token)
#   GITEE_OWNER, GITEE_REPO, GITEE_TOKEN
#   GITEE_API           API base (default https://gitee.com/api/v5; tests)
#   RETRIES             attempts per upload (default 3)
set -euo pipefail

: "${TAG:?}" "${GITHUB_REPOSITORY:?}" "${GITEE_OWNER:?}" "${GITEE_REPO:?}" "${GITEE_TOKEN:?}"
api="${GITEE_API:-https://gitee.com/api/v5}/repos/$GITEE_OWNER/$GITEE_REPO"
retries="${RETRIES:-3}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
token="$work/token"
(umask 077 && printf '%s' "$GITEE_TOKEN" > "$token")

# curl with the token as a form/query field read from a file; prints the
# HTTP status, the body goes to $out.
gitee() { # method path out [curl args…]
  local method=$1 path=$2 out=$3
  shift 3
  if [[ $method == GET ]]; then
    curl -sS -G "$api$path" --data-urlencode "access_token@$token" -o "$out" -w '%{http_code}' "$@"
  else
    curl -sS -X "$method" "$api$path" -o "$out" -w '%{http_code}' "$@"
  fi
}

echo "Release $TAG of $GITHUB_REPOSITORY → gitee.com/$GITEE_OWNER/$GITEE_REPO"
gh release view "$TAG" --repo "$GITHUB_REPOSITORY" --json name,body,isPrerelease,targetCommitish > "$work/release.json"
gh release download "$TAG" --repo "$GITHUB_REPOSITORY" --dir "$work/files"

# 1. The Gitee release of this tag, created if missing.
code=$(gitee GET "/releases/tags/$TAG" "$work/gitee.json")
id=""
if [[ $code == 200 ]]; then
  id=$(jq -r 'if type == "object" then .id // empty else empty end' "$work/gitee.json")
elif [[ $code != 404 ]]; then
  echo "::error::Gitee: looking up release $TAG failed (HTTP $code): $(head -c 500 "$work/gitee.json")" >&2
  exit 1
fi
if [[ -z $id ]]; then
  jq -j '.body // ""' "$work/release.json" > "$work/body"
  [[ -s $work/body ]] || printf -- '-' > "$work/body" # Gitee requires a body
  code=$(gitee POST "/releases" "$work/created.json" \
    --data-urlencode "access_token@$token" \
    --data-urlencode "tag_name=$TAG" \
    --data-urlencode "name=$(jq -r '.name // empty' "$work/release.json" | grep . || echo "$TAG")" \
    --data-urlencode "body@$work/body" \
    --data-urlencode "target_commitish=$(jq -r '.targetCommitish' "$work/release.json")" \
    --data-urlencode "prerelease=$(jq -r '.isPrerelease' "$work/release.json")")
  id=$(jq -r 'if type == "object" then .id // empty else empty end' "$work/created.json" 2>/dev/null || true)
  if [[ ! $code =~ ^20[01]$ || -z $id ]]; then
    echo "::error::Gitee: creating release $TAG failed (HTTP $code): $(head -c 500 "$work/created.json")" >&2
    exit 1
  fi
  echo "Created Gitee release $TAG (id $id)"
else
  echo "Gitee release $TAG exists (id $id)"
fi

# 2. Upload the files it lacks.
code=$(gitee GET "/releases/$id/attach_files" "$work/attached.json" --data-urlencode "per_page=100")
if [[ $code != 200 ]]; then
  echo "::error::Gitee: listing the files of $TAG failed (HTTP $code): $(head -c 500 "$work/attached.json")" >&2
  exit 1
fi
jq -r '.[].name' "$work/attached.json" > "$work/have"

uploaded=0
for f in "$work"/files/*; do
  name=$(basename "$f")
  if grep -qxF -- "$name" "$work/have"; then
    echo "  $name: already on Gitee"
    continue
  fi
  for ((attempt = 1; ; attempt++)); do
    code=$(gitee POST "/releases/$id/attach_files" "$work/upload.json" -F "access_token=<$token" -F "file=@$f") || code=000
    [[ $code =~ ^20[01]$ ]] && break
    if ((attempt >= retries)); then
      echo "::error::Gitee: uploading $name failed (HTTP $code): $(head -c 500 "$work/upload.json" 2>/dev/null)" >&2
      exit 1
    fi
    echo "  $name: HTTP $code, retrying ($attempt/$retries)"
    sleep $((attempt * 5))
  done
  echo "  $name: uploaded"
  uploaded=$((uploaded + 1))
done
echo "Done: $uploaded file(s) uploaded to Gitee release $TAG"
