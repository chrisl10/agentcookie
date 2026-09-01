#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
LOCK_FILE="${REPO_ROOT}/release/codex-linux-release.env"
WORKFLOW_FILE="${REPO_ROOT}/.github/workflows/codex-linux-release.yml"

[[ -f "$LOCK_FILE" ]] || { echo "missing release lock: $LOCK_FILE" >&2; exit 1; }
# shellcheck disable=SC1090,SC1091
source "$LOCK_FILE"

PATCHED_FILES=(
  .github/workflows/release.yml
  README.md
  docs/architecture.md
  docs/consumption.md
  docs/dry-run-2026-05-19.md
  docs/dry-run-2026-05-21.md
  docs/plans/2026-05-21-001-feat-headless-sink-click-free-plan.md
  docs/plans/2026-08-13-1720-feat-readme-howto-release-plan.md
  docs/quickstart-beta.md
  docs/quickstart.md
  docs/runbook-v0.9-soup-to-nuts.md
  go.mod
  internal/cli/pair.go
  internal/cli/sink.go
  internal/cli/sink_hardened_test.go
  internal/cli/wizard.go
  internal/config/config.go
  internal/config/config_test.go
  internal/livecdp/attach.go
  internal/livecdp/readback_test.go
  internal/pairing/pairing.go
  internal/pairing/pairing_test.go
  internal/protocol/sequence.go
  internal/protocol/sequence_file_security_other.go
  internal/protocol/sequence_file_security_unix.go
  internal/protocol/sequence_file_security_unix_test.go
  internal/protocol/sequence_hardened_test.go
  internal/protocol/sequence_store.go
  scripts/install-beta.sh
  skill/SKILL.md
  skill/prompts/install-on-both-machines.md
)

ALLOWED_DELTA=(
  .github/workflows/codex-linux-release.yml
  .github/workflows/release.yml
  README.md
  docs/architecture.md
  docs/consumption.md
  docs/dry-run-2026-05-19.md
  docs/dry-run-2026-05-21.md
  docs/plans/2026-05-21-001-feat-headless-sink-click-free-plan.md
  docs/plans/2026-08-13-1720-feat-readme-howto-release-plan.md
  docs/quickstart-beta.md
  docs/quickstart.md
  docs/runbook-v0.9-soup-to-nuts.md
  go.mod
  internal/cli/pair.go
  internal/cli/sink.go
  internal/cli/sink_hardened_test.go
  internal/cli/wizard.go
  internal/config/config.go
  internal/config/config_test.go
  internal/livecdp/attach.go
  internal/livecdp/readback_test.go
  internal/pairing/pairing.go
  internal/pairing/pairing_test.go
  internal/protocol/sequence.go
  internal/protocol/sequence_file_security_other.go
  internal/protocol/sequence_file_security_unix.go
  internal/protocol/sequence_file_security_unix_test.go
  internal/protocol/sequence_hardened_test.go
  internal/protocol/sequence_store.go
  release/codex-linux-release.env
  release/patches/0001-harden-linux-live-cdp-sink.patch
  scripts/codex-linux-release.sh
  scripts/install-beta.sh
  skill/SKILL.md
  skill/prompts/install-on-both-machines.md
)

die() {
  echo "codex-linux-release: $*" >&2
  exit 1
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    die "no SHA-256 utility is available"
  fi
}

assert_hex_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]] || die "$2 is not a lowercase SHA-256 digest"
}

check_candidate_delta() {
  local changed_file allowed_file missing_file unexpected_file
  changed_file="$(mktemp)"
  allowed_file="$(mktemp)"
  missing_file="$(mktemp)"
  unexpected_file="$(mktemp)"

  {
    git -C "$REPO_ROOT" diff --name-only "$CODEX_UPSTREAM_COMMIT" --
    git -C "$REPO_ROOT" ls-files --others --exclude-standard
  } | LC_ALL=C sort -u > "$changed_file"
  printf '%s\n' "${ALLOWED_DELTA[@]}" | LC_ALL=C sort -u > "$allowed_file"

  comm -23 "$changed_file" "$allowed_file" > "$unexpected_file"
  [[ ! -s "$unexpected_file" ]] || {
    echo "unexpected candidate paths:" >&2
    sed 's/^/  /' "$unexpected_file" >&2
    exit 1
  }

  comm -13 "$changed_file" "$allowed_file" > "$missing_file"
  [[ ! -s "$missing_file" ]] || {
    echo "missing candidate paths:" >&2
    sed 's/^/  /' "$missing_file" >&2
    exit 1
  }
  rm -f "$changed_file" "$allowed_file" "$missing_file" "$unexpected_file"
}

check_locks() {
  cd "$REPO_ROOT"
  [[ "$CODEX_RELEASE_VERSION" == "1.1.0-codex.1" ]] || die "unexpected release version"
  [[ "$CODEX_RELEASE_TAG" == "v${CODEX_RELEASE_VERSION}" ]] || die "release tag/version mismatch"
  [[ "$CODEX_ARTIFACT_NAME" == "agentcookie_${CODEX_RELEASE_VERSION}_linux_amd64" ]] || die "artifact name mismatch"
  [[ "$CODEX_SBOM_NAME" == "${CODEX_ARTIFACT_NAME}.cdx.json" ]] || die "SBOM asset name mismatch"
  [[ "$CODEX_PROVENANCE_BUNDLE_NAME" == "${CODEX_ARTIFACT_NAME}.provenance.json" ]] \
    || die "provenance bundle asset name mismatch"
  [[ "$CODEX_SBOM_ATTESTATION_BUNDLE_NAME" == "${CODEX_ARTIFACT_NAME}.sbom-attestation.json" ]] \
    || die "SBOM attestation bundle asset name mismatch"
  [[ "$CODEX_SIGNER_WORKFLOW" == 'chrisl10/agentcookie/.github/workflows/codex-linux-release.yml' ]] \
    || die "release signer workflow identity mismatch"
  [[ "$CODEX_GO_VERSION" == "1.26.7" ]] || die "unexpected Go toolchain"
  [[ "$CODEX_SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || die "invalid SOURCE_DATE_EPOCH"
  assert_hex_sha256 "$CODEX_PATCH_SHA256" "patch lock"
  assert_hex_sha256 "$CODEX_PATCHED_FILES_MANIFEST_SHA256" "patched-files manifest lock"
  assert_hex_sha256 "$CODEX_GO_TARBALL_SHA256" "Go archive lock"
  assert_hex_sha256 "$CODEX_BUILD_CONTAINER_INDEX_SHA256" "build-container index lock"
  [[ "$CODEX_BUILD_CONTAINER_IMAGE" =~ ^docker\.io/library/golang@sha256:[0-9a-f]{64}$ ]] \
    || die "official Go build container is not pinned by linux/amd64 manifest digest"

  git cat-file -e "${CODEX_UPSTREAM_COMMIT}^{commit}" 2>/dev/null \
    || die "locked upstream commit is absent"
  git merge-base --is-ancestor "$CODEX_UPSTREAM_COMMIT" HEAD \
    || die "candidate does not descend from the locked upstream commit"
  [[ "$(git show -s --format=%ct "$CODEX_UPSTREAM_COMMIT")" == "$CODEX_SOURCE_DATE_EPOCH" ]] \
    || die "SOURCE_DATE_EPOCH does not match the upstream commit"

  [[ -f "$CODEX_PATCH_PATH" ]] || die "reviewed patch is absent"
  [[ "$(sha256_file "$CODEX_PATCH_PATH")" == "$CODEX_PATCH_SHA256" ]] \
    || die "reviewed patch digest mismatch"
  git apply --reverse --check "$CODEX_PATCH_PATH" \
    || die "reviewed patch is not applied cleanly to the candidate"

  local manifest_file manifest_digest filepath
  manifest_file="$(mktemp)"
  for filepath in "${PATCHED_FILES[@]}"; do
    [[ -f "$filepath" ]] || die "patched file is absent: $filepath"
    printf '%s  %s\n' "$(sha256_file "$filepath")" "$filepath"
  done > "$manifest_file"
  manifest_digest="$(sha256_file "$manifest_file")"
  [[ "$manifest_digest" == "$CODEX_PATCHED_FILES_MANIFEST_SHA256" ]] \
    || die "patched-files manifest mismatch: $manifest_digest"
  rm -f "$manifest_file"

  [[ -f "$WORKFLOW_FILE" ]] || die "release workflow is absent"
  [[ "$(grep -Fxc "      image: ${CODEX_BUILD_CONTAINER_IMAGE}" "$WORKFLOW_FILE")" -eq 3 ]] \
    || die "workflow build containers drifted from the lock"
  [[ "$(grep -Fxc '      options: --platform linux/amd64 --user 1001:1001' "$WORKFLOW_FILE")" -eq 3 ]] \
    || die "workflow build containers are not locked to the non-root release user"
  [[ "$(grep -Fxc '      GOCACHE: /tmp/agentcookie-go-build' "$WORKFLOW_FILE")" -eq 3 ]] \
    || die "workflow build caches are not scoped to the writable ephemeral path"
  grep -Fq '          path: /tmp/agentcookie-build-a' "$WORKFLOW_FILE" \
    || die "promoted build A is not isolated outside the source checkout"
  grep -Fq '          path: /tmp/agentcookie-build-b' "$WORKFLOW_FILE" \
    || die "promoted build B is not isolated outside the source checkout"
  # shellcheck disable=SC2016 # Match literal workflow environment expansion.
  grep -Fq '          cmp "/tmp/agentcookie-build-a/${ARTIFACT_NAME}" "/tmp/agentcookie-build-b/${ARTIFACT_NAME}"' "$WORKFLOW_FILE" \
    || die "promotion does not compare the two isolated build artifacts"
  # shellcheck disable=SC2016 # Match literal workflow environment expansion.
  grep -Fq '          sha256sum "/tmp/agentcookie-build-a/${ARTIFACT_NAME}" "/tmp/agentcookie-build-b/${ARTIFACT_NAME}"' "$WORKFLOW_FILE" \
    || die "promotion does not hash the two isolated build artifacts"
  # shellcheck disable=SC2016 # Match literal workflow environment expansion.
  grep -Fq '          install -D -m 0755 "/tmp/agentcookie-build-a/${ARTIFACT_NAME}" "dist/${ARTIFACT_NAME}"' "$WORKFLOW_FILE" \
    || die "promotion does not install the compared build A artifact"
  grep -Fq "security-remediated locked patch ${CODEX_PATCH_SHA256}." "$WORKFLOW_FILE" \
    || die "public release notes do not identify the locked patch"
  ! grep -Eq 'uses:[[:space:]]+[^[:space:]]+@(main|master|v[0-9]+)$' "$WORKFLOW_FILE" \
    || die "workflow contains a floating action reference"
  grep -Fq "refs/tags/${CODEX_RELEASE_TAG}" "$WORKFLOW_FILE" \
    || die "workflow exact-tag publication guard is absent"
  grep -Fq '      - "!v*-codex.*"' .github/workflows/release.yml \
    || die "upstream release workflow is not excluded from Codex release tags"
  # shellcheck disable=SC2016 # Match the literal Actions expression syntax.
  ! grep -Fq 'if: ${{ secrets.' .github/workflows/release.yml \
    || die "upstream release workflow contains invalid direct secret conditions"
  grep -Fq 'environment: prd005-release' "$WORKFLOW_FILE" \
    || die "workflow protected release environment is absent"
  # shellcheck disable=SC2016 # Verify the literal Actions runtime expression.
  grep -Fq 'git merge-base --is-ancestor "${GITHUB_SHA}" refs/remotes/origin/main' "$WORKFLOW_FILE" \
    || die "workflow does not prove the release commit is merged into origin/main"
  grep -Fq 'environments/prd005-release' "$WORKFLOW_FILE" \
    || die "workflow does not inspect the runtime release environment"
  grep -Fq 'required_reviewers' "$WORKFLOW_FILE" \
    || die "workflow does not require runtime reviewer protection"
  [[ "$(grep -Fxc '      actions: read' "$WORKFLOW_FILE")" -eq 2 ]] \
    || die "environment API jobs do not have the exact actions: read permission"
  [[ "$(grep -Fc 'outputs.bundle-path' "$WORKFLOW_FILE")" -eq 2 ]] \
    || die "workflow does not retain both offline attestation bundles"
  # shellcheck disable=SC2016 # Verify the literal Actions shell expansion.
  [[ "$(grep -Fc -- '--bundle "dist/${' "$WORKFLOW_FILE")" -eq 2 ]] \
    || die "workflow does not verify both offline attestation bundles"
  grep -Fq "SIGNER_WORKFLOW: ${CODEX_SIGNER_WORKFLOW}" "$WORKFLOW_FILE" \
    || die "workflow signer identity drifted from the lock"
  grep -Fq "PROVENANCE_BUNDLE_NAME: ${CODEX_PROVENANCE_BUNDLE_NAME}" "$WORKFLOW_FILE" \
    || die "workflow provenance bundle name drifted from the lock"
  grep -Fq "SBOM_ATTESTATION_BUNDLE_NAME: ${CODEX_SBOM_ATTESTATION_BUNDLE_NAME}" "$WORKFLOW_FILE" \
    || die "workflow SBOM bundle name drifted from the lock"
  ! grep -Fq 'WIZARD_ARGS+=(--code ' scripts/install-beta.sh \
    || die "install-beta still puts a pairing code in argv"
  grep -Fq -- '--code-stdin' scripts/install-beta.sh \
    || die "install-beta does not pass pairing codes over stdin"
  ! grep -R -n -E --include='*.md' -- '--code([[:space:]=]|$)' README.md docs skill \
    || die "documentation contains obsolete executable pairing-code argv guidance"
  ! grep -Eq 'code was|"code"[[:space:]]*:' internal/cli/wizard.go \
    || die "wizard persists or logs the raw pairing code"
  ! grep -Fq 'pairingInfoWriter' internal/cli/wizard.go \
    || die "wizard still scrapes raw pairing announcements"
  grep -Fq 'openPairingSecretTTY' internal/cli/wizard.go \
    || die "wizard does not bind pairing-code output to the controlling terminal"
  grep -Fq 'writeOwnerSecret(secretWriter, code)' internal/pairing/pairing.go \
    || die "pairing source does not fail closed on owner-secret delivery"
  grep -Fq 'io.ErrShortWrite' internal/pairing/pairing.go \
    || die "pairing source does not reject short owner-secret writes"
  ! grep -Fq 'apt-get' "$WORKFLOW_FILE" \
    || die "workflow contains a mutable OS package installation"

  check_candidate_delta
  echo "release locks and exact candidate delta verified"
}

require_linux_amd64() {
  [[ "$(uname -s)" == "Linux" ]] || die "authoritative build requires Linux"
  [[ "$(uname -m)" == "x86_64" ]] || die "authoritative build requires x86_64"
}

verify_go_toolchain() {
  require_linux_amd64
  local extracted_version required_command
  export GOTOOLCHAIN=local
  extracted_version="$(go version)"
  [[ "$extracted_version" == "go version go${CODEX_GO_VERSION} linux/amd64" ]] \
    || die "unexpected Go toolchain: $extracted_version"
  [[ "${GOLANG_VERSION:-}" == "$CODEX_GO_VERSION" ]] \
    || die "official image GOLANG_VERSION does not match the release lock"
  for required_command in go gcc git sha256sum cmp install grep; do
    command -v "$required_command" >/dev/null 2>&1 \
      || die "pinned build image is missing required command: $required_command"
  done
}

set_go_environment() {
  export CGO_ENABLED=1
  export GOOS=linux
  export GOARCH=amd64
  export GOFLAGS='-mod=readonly'
  export GOPROXY='https://proxy.golang.org,direct'
  export GOSUMDB='sum.golang.org'
  export SOURCE_DATE_EPOCH="$CODEX_SOURCE_DATE_EPOCH"
}

install_go_command() {
  local module="$1" version="$2" output_dir="$3"
  mkdir -p "$output_dir"
  GOBIN="$output_dir" go install "${module}@${version}"
}

verify_source() {
  check_locks
  verify_go_toolchain
  set_go_environment
  cd "$REPO_ROOT"

  go mod verify
  go test ./...
  go vet ./...

  local tool_dir
  tool_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/agentcookie-tools.XXXXXX")"
  install_go_command "golang.org/x/vuln/cmd/govulncheck" "$CODEX_GOVULNCHECK_VERSION" "$tool_dir"
  "$tool_dir/govulncheck" ./...
}

build_binary() {
  local output_dir="$1" output_path
  check_locks
  verify_go_toolchain
  set_go_environment
  cd "$REPO_ROOT"
  go mod verify

  mkdir -p "$output_dir"
  output_path="${output_dir}/${CODEX_ARTIFACT_NAME}"
  umask 022
  go build \
    -mod=readonly \
    -trimpath \
    -buildvcs=false \
    -ldflags "-s -w -buildid= -X github.com/mvanhorn/agentcookie/internal/cli.Version=${CODEX_RELEASE_VERSION}" \
    -o "$output_path" \
    ./cmd/agentcookie
  chmod 0755 "$output_path"
  sha256_file "$output_path"
}

generate_sbom() {
  local binary_path="$1" output_path="$2" tool_dir
  [[ -x "$binary_path" ]] || die "SBOM subject is not an executable: $binary_path"
  check_locks
  verify_go_toolchain
  set_go_environment
  cd "$REPO_ROOT"

  tool_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/agentcookie-tools.XXXXXX")"
  install_go_command \
    "github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod" \
    "$CODEX_CYCLONEDX_GOMOD_VERSION" \
    "$tool_dir"
  "$tool_dir/cyclonedx-gomod" app \
    -json \
    -output-version 1.6 \
    -output "$output_path" \
    -main ./cmd/agentcookie \
    "$REPO_ROOT"
  grep -Eq '"bomFormat"[[:space:]]*:[[:space:]]*"CycloneDX"' "$output_path" \
    || die "generated SBOM does not identify CycloneDX"
  grep -Eq '"specVersion"[[:space:]]*:[[:space:]]*"1\.6"' "$output_path" \
    || die "generated SBOM is not CycloneDX JSON 1.6"
}

write_provenance() {
  local binary_path="$1" sbom_path="$2" output_path="$3"
  [[ -f "$binary_path" ]] || die "binary is absent for provenance"
  [[ -f "$sbom_path" ]] || die "SBOM is absent for provenance"
  cat > "$output_path" <<EOF
release_tag=${CODEX_RELEASE_TAG}
release_version=${CODEX_RELEASE_VERSION}
artifact_name=${CODEX_ARTIFACT_NAME}
artifact_sha256=$(sha256_file "$binary_path")
sbom_name=${CODEX_SBOM_NAME}
sbom_sha256=$(sha256_file "$sbom_path")
provenance_bundle_name=${CODEX_PROVENANCE_BUNDLE_NAME}
sbom_attestation_bundle_name=${CODEX_SBOM_ATTESTATION_BUNDLE_NAME}
signer_workflow=${CODEX_SIGNER_WORKFLOW}
repository=${GITHUB_REPOSITORY:-local}
candidate_commit=${GITHUB_SHA:-$(git -C "$REPO_ROOT" rev-parse HEAD)}
upstream_repository=${CODEX_UPSTREAM_REPOSITORY}
upstream_commit=${CODEX_UPSTREAM_COMMIT}
patch_sha256=${CODEX_PATCH_SHA256}
patched_files_manifest_sha256=${CODEX_PATCHED_FILES_MANIFEST_SHA256}
source_date_epoch=${CODEX_SOURCE_DATE_EPOCH}
go_archive=${CODEX_GO_TARBALL_URL}
go_archive_sha256=${CODEX_GO_TARBALL_SHA256}
build_container=${CODEX_BUILD_CONTAINER_IMAGE}
build_container_index_sha256=${CODEX_BUILD_CONTAINER_INDEX_SHA256}
workflow_run=${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-local}/actions/runs/${GITHUB_RUN_ID:-local}/attempts/${GITHUB_RUN_ATTEMPT:-1}
EOF
}

usage() {
  echo "usage: $0 check-locks | verify | build OUTPUT_DIR | sbom BINARY OUTPUT | provenance BINARY SBOM OUTPUT" >&2
  exit 2
}

case "${1:-}" in
  check-locks)
    [[ "$#" -eq 1 ]] || usage
    check_locks
    ;;
  verify)
    [[ "$#" -eq 1 ]] || usage
    verify_source
    ;;
  build)
    [[ "$#" -eq 2 ]] || usage
    build_binary "$2"
    ;;
  sbom)
    [[ "$#" -eq 3 ]] || usage
    generate_sbom "$2" "$3"
    ;;
  provenance)
    [[ "$#" -eq 4 ]] || usage
    write_provenance "$2" "$3" "$4"
    ;;
  *) usage ;;
esac
