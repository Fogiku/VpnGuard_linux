#!/usr/bin/env bash
# Run the existing browser probes as the caller in two prepared network namespaces.
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: run_client_comparison.sh BASE_NETNS BASE_FILE CANDIDATE_NETNS CANDIDATE_FILE
         --control HTTPS_URL [--video-id VIDEO] [--discord] [--runs 2..5]
         [--channel chromium|chrome|msedge] [--egress-v4 URL BASE_CIDR CANDIDATE_CIDR]
         [--egress-v6 URL BASE_CIDR CANDIDATE_CIDR]
Creates a new lab-* directory in the working directory and prints the path to comparison.json.
HELP
}
fail() { echo "$*" >&2; exit 2; }
if [[ ${1:-} == --help ]]; then usage; exit; fi
if (( $# < 4 )); then usage >&2; exit 2; fi
base_ns=$1; base_file=$2; candidate_ns=$3; candidate_file=$4
shift 4
for ns in "$base_ns" "$candidate_ns"; do
  [[ $ns =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$ ]] || fail "Invalid namespace name: $ns"
done
[[ $base_ns != "$candidate_ns" ]] || fail "Select two distinct namespaces"
[[ -f $base_file && -r $base_file && -f $candidate_file && -r $candidate_file ]] || fail "Cannot read both profile files"
if cmp -s -- "$base_file" "$candidate_file"; then fail "Select two different profile revisions"; fi
shared=(); base_extra=(); candidate_extra=()
while (( $# )); do
  case $1 in
    --discord) shared+=("$1"); shift ;;
    --control|--video-id|--channel|--runs)
      (( $# >= 2 )) || fail "Missing value for $1"
      if [[ $1 == --runs && ! $2 =~ ^[2-5]$ ]]; then fail "Expected 2 to 5 samples"; fi
      shared+=("$1" "$2"); shift 2 ;;
    --egress-v4|--egress-v6)
      (( $# >= 4 )) || fail "Expected URL and two networks for $1"
      base_extra+=("$1" "$2" "$3"); candidate_extra+=("$1" "$2" "$4"); shift 4 ;;
    *) fail "Unknown option: $1" ;;
  esac
done
probe_dir=$(cd -- "$(dirname -- "$0")" && pwd)
python=$(command -v python3)
operator=$(id -un)
sudo -v
session=$(mktemp -d ./lab-XXXXXXXXXX)
probe=("$python" "$probe_dir/probe_client_playback.py" --lab-session "${session##*/}" "${shared[@]}")
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
capture() {
  local namespace=$1 profile=$2
  shift 2
  exec sudo -n ip netns exec "$namespace" sudo -H -u "$operator" -- "${probe[@]}" \
    --path-label "$namespace" "--profile-file=$profile" "$@"
}
capture "$base_ns" "$base_file" "${base_extra[@]}" > "$session/base.json" &
pids+=("$!")
capture "$candidate_ns" "$candidate_file" "${candidate_extra[@]}" > "$session/candidate.json" &
pids+=("$!")
failed=0
for index in 0 1; do
  if ! wait "${pids[index]}"; then failed=1; fi
  unset 'pids[index]'
done
(( failed == 0 )) || fail "Capture failed. Session directory: $session"
"$python" "$probe_dir/compare_client_profiles.py" "$session/base.json" "$session/candidate.json" > "$session/comparison.tmp"
mv -- "$session/comparison.tmp" "$session/comparison.json"
printf '%s\n' "$session/comparison.json"
