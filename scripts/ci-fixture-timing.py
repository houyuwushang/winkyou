"""Numeric-only C1b measurement extraction; never change a test or start a run."""
import argparse
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile

FIELDS = {"schema", "profile", "scenario", "failed", "candidate_budget_ns",
          "active_budget_ns", "finish_delay_ns", "stages_ns"}
MAX_NS = 3_600_000_000_000
MAX_SAMPLES = 10_000
MAX_BYTES = 16 * 1024 * 1024
# Matches the independently frozen Go progress slots, not string labels in logs.
PREFLIGHT, SPAWN, CANDIDATES, WINNER, FINISH, READY, TERMINAL = 0, 1, 13, 14, 19, 21, 22


class InvalidTiming(ValueError):
    pass


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise InvalidTiming("invalid_numeric_value")


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidTiming("duplicate_field")
        result[key] = value
    return result


def decode(data):
    if len(data) > MAX_BYTES:
        raise InvalidTiming("input_too_large")
    return json.loads(data, object_pairs_hook=no_duplicates)


def validate(record):
    if type(record) is not dict or set(record) != FIELDS:
        raise InvalidTiming("invalid_fields")
    integer(record["schema"], 1, 1)
    integer(record["profile"], 0, 2)
    integer(record["scenario"], 0, 7)
    integer(record["failed"], 0, 1)
    for key in ("candidate_budget_ns", "active_budget_ns"):
        integer(record[key], 1, MAX_NS)
    if record["candidate_budget_ns"] >= record["active_budget_ns"]:
        raise InvalidTiming("invalid_budgets")
    delay = record["finish_delay_ns"]
    if type(delay) is not list or len(delay) != 2:
        raise InvalidTiming("invalid_delay")
    for item in delay:
        integer(item, 0, MAX_NS)
    expected = {2: [3_500_000_000, 0], 3: [0, 3_500_000_000]}.get(record["scenario"], [0, 0])
    if delay != expected:
        raise InvalidTiming("inconsistent_injection")
    stages = record["stages_ns"]
    if type(stages) is not list or len(stages) != 2:
        raise InvalidTiming("invalid_sides")
    for side in stages:
        if type(side) is not list or len(side) != 23:
            raise InvalidTiming("invalid_stage_count")
        last = -1
        for item in side:
            integer(item, -1, MAX_NS)
            if item >= 0:
                if item < last:
                    raise InvalidTiming("nonmonotonic_stages")
                last = item
    return record


def stats(values, missing):
    values = sorted(values)
    if not values:
        return {"count": 0, "missing": missing, "p50_ns": -1, "p95_ns": -1, "max_ns": -1}
    return {"count": len(values), "missing": missing,
            "p50_ns": values[(len(values) * 50 + 99) // 100 - 1],
            "p95_ns": values[(len(values) * 95 + 99) // 100 - 1], "max_ns": values[-1]}


def summarize(records):
    if not records or len(records) > MAX_SAMPLES:
        raise InvalidTiming("missing_or_excess_samples")
    groups = {}
    for record in records:
        validate(record)
        for side, phases in enumerate(record["stages_ns"]):
            key = (record["profile"], record["scenario"], record["failed"], side)
            groups.setdefault(key, []).append(phases)
    output = []
    for (profile, scenario, failed, side), rows in sorted(groups.items()):
        group = {"profile": profile, "scenario": scenario, "failed": failed, "side": side, "samples": len(rows)}
        for name, start, end in (
            ("candidate_to_winner", CANDIDATES, WINNER),
            ("winner_to_finish", WINNER, FINISH),
            ("active_establishment_upper_bound", PREFLIGHT, FINISH),
            ("active_establishment_lower_bound", SPAWN, FINISH),
        ):
            values = [row[end] - row[start] for row in rows if row[start] >= 0 and row[end] >= 0]
            group[name] = stats(values, len(rows) - len(values))
        group["establishment_complete"] = sum(row[READY] >= 0 for row in rows)
        group["terminal_seen"] = sum(row[TERMINAL] >= 0 for row in rows)
        output.append(group)
    return {"schema": 1, "invocations": len(records), "endpoints": 2 * len(records), "groups": output}


def local_records(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise InvalidTiming("invalid_input_directory")
    paths = sorted(directory.iterdir())
    if len(paths) > MAX_SAMPLES:
        raise InvalidTiming("excess_samples")
    records = []
    for path in paths:
        if path.is_symlink() or not path.is_file() or not re.fullmatch(r"sample-[0-9]+\.json", path.name):
            raise InvalidTiming("unexpected_input_file")
        if path.stat().st_size > 4096:
            raise InvalidTiming("sample_too_large")
        records.append(validate(decode(path.read_bytes())))
    return records


def api(path, binary=False):
    # GET only; never invokes workflow run/rerun/cancel or writes to GitHub.
    result = subprocess.run(["gh", "api", "--method", "GET", path], capture_output=True, timeout=60)
    if result.returncode:
        raise InvalidTiming("github_read_failed")
    return result.stdout if binary else decode(result.stdout)


def download_records(repo, run_id):
    records, archives = [], 0
    page = 1
    while True:
        entries = api(f"repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100&page={page}")["artifacts"]
        for artifact in entries:
            if not re.fullmatch(r"fixture-timing-[a-z0-9-]+", artifact["name"]):
                continue
            if artifact["expired"] or artifact["size_in_bytes"] > MAX_BYTES:
                raise InvalidTiming("artifact_unavailable")
            payload = api(f"repos/{repo}/actions/artifacts/{artifact['id']}/zip", binary=True)
            if len(payload) > MAX_BYTES:
                raise InvalidTiming("artifact_too_large")
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                members = archive.infolist()
                if len(members) != 2 or {item.filename for item in members} != {"measurements.json", "summary.json"}:
                    raise InvalidTiming("unexpected_artifact_members")
                if any(item.file_size > MAX_BYTES for item in members):
                    raise InvalidTiming("artifact_too_large")
                rows = decode(archive.read("measurements.json"))
                if type(rows) is not list:
                    raise InvalidTiming("invalid_artifact_samples")
                summary = summarize(rows)
                if summary != decode(archive.read("summary.json")):
                    raise InvalidTiming("summary_mismatch")
                records.extend(rows)  # Never deduplicate fresh runs or endpoints.
                if len(records) > MAX_SAMPLES:
                    raise InvalidTiming("excess_samples")
                archives += 1
        if len(entries) < 100:
            break
        page += 1
    return records, archives


def emit(directory, records):
    summary = summarize(records)
    # Output must be new: a second run cannot overwrite first-run evidence.
    directory.mkdir(parents=True, exist_ok=False)
    for name, data in (("measurements.json", records), ("summary.json", summary)):
        with (directory / name).open("x", encoding="utf-8", newline="\n") as output:
            json.dump(data, output, separators=(",", ":"), allow_nan=False)
            output.write("\n")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    local = modes.add_parser("summarize")
    local.add_argument("--input", type=Path, required=True)
    local.add_argument("--output", type=Path, required=True)
    remote = modes.add_parser("download")
    remote.add_argument("--run-id", type=int, required=True)
    remote.add_argument("--repo", default="houyuwushang/winkyou")
    remote.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.mode == "summarize":
            rows = local_records(args.input)
        else:
            if args.run_id <= 0 or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
                raise InvalidTiming("invalid_source")
            rows, _ = download_records(args.repo, args.run_id)
        summary = emit(args.output, rows)
        print(json.dumps(summary, separators=(",", ":")))
        return 0
    except (InvalidTiming, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile):
        # API/server errors and local paths are never reflected in diagnostics.
        print("fixture_timing_invalid_or_incomplete", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
