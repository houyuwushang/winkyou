#!/usr/bin/env bash
set -Eeuo pipefail

# Gate B3 changes the one Linux conntrack ceiling shared by all network
# namespaces. This wrapper is therefore restricted to an explicitly attested,
# GitHub-hosted disposable runner. It owns restoration even if the Go test
# process exits abnormally; loss of the runner itself is safe because the VM is
# discarded.

readonly gate_b3_cap=40000
readonly conntrack_key=net.netfilter.nf_conntrack_max
readonly conntrack_count_key=net.netfilter.nf_conntrack_count

if [[ "${WINKYOU_GATE_B3_REQUIRED:-}" != "1" ||
      "${WINKYOU_GATE_B3_DISPOSABLE_RUNNER:-}" != "github-hosted" ||
      "${GITHUB_ACTIONS:-}" != "true" ||
      "${RUNNER_ENVIRONMENT:-}" != "github-hosted" ]]; then
  echo "Gate B3 disposable-runner authorization is absent" >&2
  exit 2
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "Gate B3 conntrack guard requires root" >&2
  exit 2
fi
if [[ "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)" ]]; then
  echo "Gate B3 conntrack guard is not in the initial network namespace" >&2
  exit 2
fi
for program in sysctl flock readlink setsid; do
  command -v "${program}" >/dev/null
done

exec 9>/run/lock/winkyou-gate-b3-conntrack.lock
if ! flock -n 9; then
  echo "Gate B3 conntrack guard is already owned" >&2
  exit 2
fi

original_cap="$(sysctl -n "${conntrack_key}")"
initial_count="$(sysctl -n "${conntrack_count_key}")"
if [[ ! "${original_cap}" =~ ^[0-9]+$ || ! "${initial_count}" =~ ^[0-9]+$ ]]; then
  echo "Gate B3 conntrack preflight returned an invalid value" >&2
  exit 2
fi
if (( original_cap < gate_b3_cap )); then
  echo "Gate B3 refuses to raise the existing conntrack ceiling" >&2
  exit 2
fi
if (( initial_count * 2 >= gate_b3_cap )); then
  echo "Gate B3 conntrack guard lacks initial-namespace headroom" >&2
  exit 2
fi

restore_gate_b3_conntrack_cap() {
  sysctl -qw "${conntrack_key}=${original_cap}" || return 1
  [[ "$(sysctl -n "${conntrack_key}")" == "${original_cap}" ]]
}

finish_gate_b3_guard() {
  local status=$?
  trap - EXIT HUP INT TERM
  if ! restore_gate_b3_conntrack_cap; then
    echo "Gate B3 conntrack guard restoration failed" >&2
    status=97
  fi
  exit "${status}"
}

child_pid=""
stop_gate_b3_child_group() {
  local signal_name="$1"
  local status="$2"
  trap - HUP INT TERM
  if [[ -n "${child_pid}" ]]; then
    kill -"${signal_name}" -- "-${child_pid}" 2>/dev/null || true
    for _ in {1..50}; do
      if ! kill -0 -- "-${child_pid}" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    if kill -0 -- "-${child_pid}" 2>/dev/null; then
      kill -KILL -- "-${child_pid}" 2>/dev/null || true
    fi
    wait "${child_pid}" 2>/dev/null || true
    child_pid=""
  fi
  exit "${status}"
}

trap 'stop_gate_b3_child_group HUP 129' HUP
trap 'stop_gate_b3_child_group INT 130' INT
trap 'stop_gate_b3_child_group TERM 143' TERM
trap finish_gate_b3_guard EXIT

sysctl -qw "${conntrack_key}=${gate_b3_cap}"
if [[ "$(sysctl -n "${conntrack_key}")" != "${gate_b3_cap}" ]]; then
  echo "Gate B3 conntrack guard installation could not be verified" >&2
  exit 2
fi

export WINKYOU_GATE_B3_HOST_CONNTRACK_CAP="${gate_b3_cap}"
ulimit -n 65536
setsid --wait "$@" &
child_pid=$!
set +e
wait "${child_pid}"
status=$?
set -e
child_pid=""
exit "${status}"
