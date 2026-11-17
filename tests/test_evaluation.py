from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

from auditguard.benchmark import build_dataset, course_manifest
from auditguard.cli import main
from auditguard.evaluate import evaluate, load_dataset, metrics, tune
from auditguard.events import write_json
from auditguard.policy import load_policy

ROOT = Path(__file__).resolve().parents[1]


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.policy = load_policy(ROOT / "config/policy.json")

    def test_metrics_math_and_undefined_denominators(self):
        rows = [{"valid": True, "label": label, "prediction": prediction} for label, prediction in [("attack", "alert"), ("attack", "normal"), ("normal", "normal"), ("normal", "alert")]]
        result = metrics(rows)
        for key in ("precision", "recall", "f1", "fpr"):
            self.assertEqual(result[key], 0.5)
        self.assertIsNone(metrics([])["recall"])
        rows.append({"valid": False, "label": "normal", "prediction": "invalid"})
        self.assertEqual(metrics(rows)["invalid_runs"], 1)
        self.assertEqual(metrics(rows)["tn"], 1)

    def test_supplied_examples(self):
        path = course_manifest(ROOT, self.root / "data" / "manifest.json")
        result = evaluate(path, self.policy, self.root / "results")
        self.assertEqual(result["source_type"], "provided_example")
        for mode in ("b0", "b1", "b2"):
            self.assertEqual(result["configurations"][mode]["tp"], 3)
            self.assertEqual(result["configurations"][mode]["tn"], 1)

    def test_deterministic_data_and_distinct_splits(self):
        a = build_dataset(self.root / "a", "development")
        b = build_dataset(self.root / "b", "development")
        self.assertEqual(a.read_bytes(), b.read_bytes())
        dev = json.loads(a.read_text(encoding="utf-8"))
        other = json.loads(build_dataset(self.root / "eval", "evaluation").read_text(encoding="utf-8"))
        self.assertEqual(len(dev["runs"]), 27)
        self.assertEqual(len(other["runs"]), 65)
        self.assertTrue(all(not r["novel_scenario"] for r in dev["runs"]))
        self.assertEqual(sum(r["novel_scenario"] for r in other["runs"]), 20)

    def test_tune_never_uses_evaluation_labels(self):
        path = build_dataset(self.root, "evaluation", 1)
        with self.assertRaisesRegex(ValueError, "development"):
            tune(path, self.policy, self.root / "tuning")

    def test_hash_mismatch_and_empty_run_are_invalid_not_true_negatives(self):
        path = build_dataset(self.root, "evaluation", 1)
        manifest = json.loads(path.read_text(encoding="utf-8"))
        victim = self.root / manifest["runs"][0]["path"]
        victim.write_text("", encoding="utf-8")
        result = evaluate(path, self.policy, self.root / "results")
        self.assertEqual(result["configurations"]["b2"]["invalid_runs"], 1)
        self.assertEqual(result["configurations"]["b2"]["valid_runs"], 12)

    def test_same_metadata_cannot_reveal_attacker_intent(self):
        path = build_dataset(self.root, "evaluation", 1)
        result = evaluate(path, self.policy, self.root / "results")
        # Slow permitted recon and a compromised approved operator remain FN.
        self.assertGreaterEqual(result["configurations"]["b2"]["fn"], 2)
        self.assertEqual(result["configurations"]["b2"]["fp"], 0)

    def test_cli_invalid_input_has_nonzero_exit_and_no_normal_verdict(self):
        source = self.root / "bad.jsonl"
        source.write_text("not-json\n", encoding="utf-8")
        with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
            code = main(["scan", "--input", str(source), "--policy", str(ROOT / "config/policy.json"), "--output", str(self.root / "out")])
        self.assertEqual(code, 2)
        status = json.loads((self.root / "out" / "status.json").read_text(encoding="utf-8"))
        self.assertEqual(status["status"], "invalid")


if __name__ == "__main__":
    unittest.main()
