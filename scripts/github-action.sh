#!/usr/bin/env bash
set -euo pipefail

mode="${INPUT_MODE:-check}"
binary="${PROVAVALIDATOR_BIN:?missing PROVAVALIDATOR_BIN}"

declare -a cmd
cmd=("${binary}")

append_common_flags() {
  if [[ -n "${INPUT_AUTH_CONFIG:-}" ]]; then
    cmd+=("--auth-config" "${INPUT_AUTH_CONFIG}")
  fi
}

append_if_set() {
  local flag="$1"
  local value="$2"
  if [[ -n "${value}" ]]; then
    cmd+=("${flag}" "${value}")
  fi
}

append_bool_flag() {
  local flag="$1"
  local value="$2"
  case "${value}" in
    true|TRUE|True|1|yes|YES|on|ON)
      cmd+=("${flag}")
      ;;
  esac
}

require_input() {
  local name="$1"
  local value="$2"
  if [[ -z "${value}" ]]; then
    echo "missing required input: ${name}" >&2
    exit 1
  fi
}

append_common_flags

case "${mode}" in
  check)
    require_input "image" "${INPUT_IMAGE:-}"
    cmd+=("check" "${INPUT_IMAGE}")
    append_if_set "--fail-on" "${INPUT_FAIL_ON:-}"
    append_if_set "--ignore-file" "${INPUT_IGNORE_FILE:-}"
    append_if_set "--baseline" "${INPUT_BASELINE:-}"
    append_if_set "--format" "${INPUT_FORMAT:-}"
    append_bool_flag "--require-provenance" "${INPUT_REQUIRE_PROVENANCE:-true}"
    append_bool_flag "--fail-on-drift" "${INPUT_FAIL_ON_DRIFT:-true}"
    append_bool_flag "--allow-extra" "${INPUT_ALLOW_EXTRA:-false}"
    append_bool_flag "--allow-missing" "${INPUT_ALLOW_MISSING:-false}"
    append_bool_flag "--allow-reorder" "${INPUT_ALLOW_REORDER:-false}"
    ;;
  vuln)
    require_input "image" "${INPUT_IMAGE:-}"
    cmd+=("vuln" "${INPUT_IMAGE}")
    append_if_set "--fail-on" "${INPUT_FAIL_ON:-}"
    append_if_set "--ignore-file" "${INPUT_IGNORE_FILE:-}"
    append_if_set "--format" "${INPUT_FORMAT:-}"
    ;;
  drift)
    require_input "image" "${INPUT_IMAGE:-}"
    require_input "baseline" "${INPUT_BASELINE:-}"
    cmd+=("drift" "${INPUT_IMAGE}" "--baseline" "${INPUT_BASELINE}")
    append_bool_flag "--fail-on-drift" "${INPUT_FAIL_ON_DRIFT:-true}"
    append_bool_flag "--allow-extra" "${INPUT_ALLOW_EXTRA:-false}"
    append_bool_flag "--allow-missing" "${INPUT_ALLOW_MISSING:-false}"
    append_bool_flag "--allow-reorder" "${INPUT_ALLOW_REORDER:-false}"
    ;;
  attest)
    require_input "image" "${INPUT_IMAGE:-}"
    cmd+=("attest" "${INPUT_IMAGE}")
    ;;
  corpus)
    cmd+=("corpus")
    append_if_set "--images-file" "${INPUT_IMAGES_FILE:-}"
    append_if_set "--format" "${INPUT_FORMAT:-}"
    append_if_set "--output" "${INPUT_OUTPUT:-}"
    append_if_set "--concurrency" "${INPUT_CONCURRENCY:-}"
    append_if_set "--image-timeout" "${INPUT_IMAGE_TIMEOUT:-}"
    ;;
  args)
    require_input "args" "${INPUT_ARGS:-}"
    # shellcheck disable=SC2206
    raw_args=( ${INPUT_ARGS} )
    cmd+=("${raw_args[@]}")
    ;;
  *)
    echo "unsupported mode: ${mode}" >&2
    exit 1
    ;;
esac

printf 'command=%q' "${cmd[0]}" > /tmp/provavalidator-action-command.txt
for arg in "${cmd[@]:1}"; do
  printf ' %q' "${arg}" >> /tmp/provavalidator-action-command.txt
done
printf '\n' >> /tmp/provavalidator-action-command.txt

echo "command=$(cat /tmp/provavalidator-action-command.txt)" >> "${GITHUB_OUTPUT}"

"${cmd[@]}"
