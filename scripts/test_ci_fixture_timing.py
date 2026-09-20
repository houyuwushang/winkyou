"""Offline schema, privacy, censoring and read-only API regression tests."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

SPEC = importlib.util.spec_from_file_location("fixture_timing", Path(__file__).with_name("ci-fixture-timing.py"))
timing = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(timing)


def sample():
    return {"schema": 1, "profile": 0, "scenario": 0, "failed": 0,
            "candidate_budget_ns": 1_000_000_000, "active_budget_ns": 10_000_000_000,
            "finish_delay_ns": [0, 0], "stages_ns": [list(range(23)), list(range(23))]}


class FixtureTimingTest(unittest.TestCase):
    def test_success_failure_and_sides_remain_separate(self):
        ok, bad = sample(), sample()
        bad["failed"] = 1
        summary = timing.summarize([ok, bad, ok])
        self.assertEqual(summary["invocations"], 3)
        self.assertEqual(summary["endpoints"], 6)
        self.assertEqual(len(summary["groups"]), 4)
        self.assertEqual([g["samples"] for g in summary["groups"]], [2, 2, 1, 1])

    def test_censored_is_not_zero_or_terminal(self):
        row = sample()
        row["failed"] = 1
        for side in row["stages_ns"]:
            side[14:22] = [-1] * 8
        groups = timing.summarize([row])["groups"]
        for group in groups:
            self.assertEqual(group["candidate_to_winner"], {"count": 0, "missing": 1, "p50_ns": -1, "p95_ns": -1, "max_ns": -1})
            self.assertEqual(group["winner_to_finish"]["missing"], 1)
            self.assertEqual(group["active_establishment_upper_bound"]["missing"], 1)
            self.assertEqual(group["terminal_seen"], 1)

    def test_zero_is_a_real_offset(self):
        self.assertEqual(timing.summarize([sample()])["groups"][0]["active_establishment_upper_bound"]["max_ns"], 19)

    def test_percentiles_are_nearest_rank(self):
        self.assertEqual(timing.stats(list(range(1, 101)), 2), {"count": 100, "missing": 2, "p50_ns": 50, "p95_ns": 95, "max_ns": 100})

    def test_schema_mutations(self):
        mutations = [
            lambda r: r.update(identity="synthetic-private"),
            lambda r: r.update(profile="predictive"),
            lambda r: r.update(profile=True),
            lambda r: r.update(profile=3),
            lambda r: r.update(schema=2),
            lambda r: r.update(failed=2),
            lambda r: r.update(candidate_budget_ns=0),
            lambda r: r.update(active_budget_ns=1),
            lambda r: r.update(stages_ns=[]),
            lambda r: r["stages_ns"][0].pop(),
            lambda r: r["stages_ns"][0].__setitem__(0, None),
            lambda r: r["stages_ns"][0].__setitem__(0, 1.0),
            lambda r: r["stages_ns"][0].__setitem__(0, -2),
            lambda r: r["stages_ns"][0].__setitem__(0, 100),
            lambda r: r["stages_ns"][0].__setitem__(22, timing.MAX_NS + 1),
            lambda r: r.update(finish_delay_ns=[1, 0]),
            lambda r: r.pop("scenario"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                row = sample()
                mutate(row)
                with self.assertRaises(timing.InvalidTiming):
                    timing.validate(row)

    def test_slow_finish_is_side_bound(self):
        for scenario, delays in ((2, [3_500_000_000, 0]), (3, [0, 3_500_000_000])):
            row = sample()
            row.update(scenario=scenario, finish_delay_ns=delays)
            timing.validate(row)
            row["finish_delay_ns"] = list(reversed(delays))
            with self.assertRaises(timing.InvalidTiming):
                timing.validate(row)

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(timing.InvalidTiming):
            timing.decode(b'{"profile":0,"profile":1}')

    def test_missing_data_is_not_an_empty_success(self):
        with self.assertRaises(timing.InvalidTiming):
            timing.summarize([])

    def test_local_extraction_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            source, output = root / "in", root / "out"
            source.mkdir()
            (source / "sample-1.json").write_text(json.dumps(sample()), encoding="utf-8")
            records = timing.local_records(source)
            timing.emit(output, records)
            before = (output / "measurements.json").read_bytes()
            with self.assertRaises(FileExistsError):
                timing.emit(output, records)
            self.assertEqual(before, (output / "measurements.json").read_bytes())
            (source / "unexpected.txt").touch()
            with self.assertRaises(timing.InvalidTiming):
                timing.local_records(source)

    def test_api_is_get_only_and_errors_are_redacted(self):
        completed = mock.Mock(returncode=0, stdout=b"{}")
        with mock.patch.object(timing.subprocess, "run", return_value=completed) as run:
            timing.api("synthetic")
            self.assertEqual(run.call_args.args[0][:4], ["gh", "api", "--method", "GET"])
        with mock.patch.object(timing.subprocess, "run", return_value=mock.Mock(returncode=1, stderr=b"private")):
            with self.assertRaisesRegex(timing.InvalidTiming, "^github_read_failed$"):
                timing.api("synthetic")

    def test_artifact_zip_validation_without_extracting_paths(self):
        records = [sample()]
        for mutate in (None, "path", "summary"):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("../measurements.json" if mutate == "path" else "measurements.json", json.dumps(records))
                summary = timing.summarize(records)
                if mutate == "summary":
                    summary["invocations"] = 999
                archive.writestr("summary.json", json.dumps(summary))
            with mock.patch.object(timing, "api", side_effect=[{"artifacts": [{"name": "fixture-timing-test", "expired": False, "size_in_bytes": len(buffer.getvalue()), "id": 1}]}, buffer.getvalue()]):
                if mutate is None:
                    got, archives = timing.download_records("synthetic/repository", 1)
                    self.assertEqual(got, records)
                    self.assertEqual(archives, 1)
                else:
                    with self.assertRaises(timing.InvalidTiming):
                        timing.download_records("synthetic/repository", 1)


if __name__ == "__main__":
    unittest.main()
