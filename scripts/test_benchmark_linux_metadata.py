#!/usr/bin/env python3
"""Unit tests: failed/partial workload output cannot become a fast result."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("benchmark", Path(__file__).with_name("benchmark-linux-metadata.py"))
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


class BenchmarkTests(unittest.TestCase):
    def test_failed_process_retains_status_output_and_skips_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = benchmark.run_process(
                [sys.executable, "-c", "import sys; print('partial'); print('failed',file=sys.stderr); sys.exit(7)"],
                root, root, "failure", dict(benchmark.os.environ), 5, root)
            self.assertEqual(result["exit_status"], 7)
            self.assertIsNone(result["barrier"])
            self.assertEqual(Path(result["stdout"]).read_bytes(), b"partial\n")
            self.assertEqual(Path(result["stderr"]).read_bytes(), b"failed\n")
            self.assertEqual(result["stdout_sha256"], benchmark.digest(b"partial\n"))
            self.assertFalse(result["timed_out"])

    def test_partial_search_has_different_path_identity(self):
        expected = benchmark.path_set(b"./one\0./two\0")
        self.assertNotEqual(benchmark.path_set(b"./one\0"), expected)
        self.assertNotEqual(benchmark.path_set(b"./one\0./three\0"), expected)
        self.assertEqual(benchmark.path_set(b"./two\0./one\0"), expected)

    def test_missing_and_reset_counters_are_not_zero(self):
        for before, after in [({"read": 7}, {}), ({"read": 7}, {"read": 2})]:
            with self.assertRaises(ValueError):
                benchmark.counter_delta(before, after)
        self.assertEqual(benchmark.counter_delta({"read": 1}, {"read": 2, "open": 3}), {"open": 3, "read": 1})

    def test_huge_integer_rpc_counter_remains_exact(self):
        raw = 'portablefs_authority_rpc_requests_total{opcode="readdir"} 9007199254740993\n'
        values = benchmark.parse_prometheus(raw)
        self.assertEqual(next(iter(values.values())), 9007199254740993)
        with self.assertRaises(ValueError):
            benchmark.parse_prometheus('portablefs_authority_rpc_requests_total NaN\n')
        with self.assertRaises(ValueError):
            benchmark.parse_prometheus('# scrape failed\n')

    def test_one_failed_fast_sample_fails_the_complete_lane(self):
        manifest = json.loads((Path(__file__).parent / "benchmarks/linux-metadata.json").read_text())
        rows = [{"workload": "status_warm", "mount": mount, "valid": i != 0 or mount != "workspace",
                 "process": {"elapsed_seconds": .01 if i == 0 else 1.0}}
                for mount in ("ordinary", "workspace") for i in range(20)]
        table = benchmark.summarize(rows, manifest)["status_warm"]
        self.assertTrue(table["ordinary"]["passed"])
        self.assertFalse(table["workspace"]["passed"])
        self.assertEqual(table["workspace"]["valid"], 19)

    def test_hold_refuses_before_work(self):
        with tempfile.TemporaryDirectory() as directory:
            hold = Path(directory) / "HOLD"
            hold.write_text("owner hold")
            with self.assertRaises(RuntimeError):
                benchmark.require_no_hold(hold)

    def test_tree_inventory_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "tree"
            root.mkdir()
            (root / "file").write_bytes(b"content")
            (root / "link").symlink_to("unavailable-target")
            value = benchmark.tree_manifest(root)
            self.assertEqual(value["files"], 2)
            self.assertEqual(value["bytes"], len(b"contentunavailable-target"))
            self.assertEqual(benchmark.tree_manifest(root), value)


if __name__ == "__main__":
    unittest.main()
