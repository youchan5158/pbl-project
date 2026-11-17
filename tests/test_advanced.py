from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import random
import tempfile
import unittest

from auditguard.advanced import detect_advanced, validate_context
from auditguard.benchmark import APP, MONITOR, OPERATOR, Request, identity, synthetic_event, build_dataset
from auditguard.events import normalize, read_events, write_jsonl
from auditguard.policy import load_policy
from auditguard.refinement import calibrate

ROOT = Path(__file__).resolve().parents[1]
KEY = "authentication.kubernetes.io/credential-id"


class AdvancedTests(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy(ROOT / "config/policy.json")
        self.context = json.loads((ROOT / "config/advanced.json").read_text(encoding="utf-8"))
        self.time = datetime(2026, 1, 1, 9, tzinfo=timezone.utc)
        self.rng = random.Random(178)

    def raw(self, account=OPERATOR, credential="JTI=test-work-token"):
        result = synthetic_event(Request("secrets", "get", name="demo-secret"), account, self.time, self.rng)
        result["user"]["extra"] = {KEY: [credential]}
        return result

    def event(self, **kw):
        return normalize(self.raw(**kw))

    def approve(self, event, budget=1, actions=None):
        self.context["intents"] = [{"id": "work", "actor": event.actor, "namespace": event.namespace,
            "credential_id_hash": event.credential_id_hash, "not_before": "2026-01-01T09:00:00Z",
            "not_after": "2026-01-01T09:05:00Z", "max_requests": budget,
            "actions": actions or [{"resource": "secrets", "verb": "get", "name": "demo-secret"}],
            "reason": "independently approved work"}]

    def scan(self, events, mode="b4", **kw):
        return detect_advanced(events, self.policy, self.context, mode, **kw)

    def test_strict_secret_default_and_credential_approval(self):
        event = self.event()
        self.assertEqual(self.scan([event]).prediction, "alert")
        self.approve(event)
        self.assertEqual(self.scan([event]).prediction, "normal")
        self.assertEqual(self.scan([event], "b3").prediction, "alert")

    def test_same_account_different_token_never_inherits_approval(self):
        self.approve(self.event())
        stolen = self.event(credential="JTI=other-token")
        self.assertEqual(self.scan([stolen]).prediction, "alert")

    def test_missing_or_wrong_metadata_cannot_gain_approval(self):
        event = self.event()
        self.approve(event)
        for change in ({"credential_id_hash": ""}, {"caller": identity(APP)}, {"code": 403},
                       {"name": "another"}, {"time": self.time + timedelta(minutes=5)},
                       {"time": self.time - timedelta(microseconds=1)},
                       {"api_group": "other"}, {"subresource": "proxy"}):
            with self.subTest(change=change):
                result = self.scan([replace(event, **change)])
                self.assertFalse(result.suppressed)

    def test_scope_checked_before_approval(self):
        event = replace(self.event(), namespace="unmonitored")
        self.approve(event)
        result = self.scan([event])
        self.assertEqual(result.inspected_events, 0)
        self.assertEqual(result.out_of_scope, 1)
        self.assertFalse(result.suppressed)

    def test_request_budget_cannot_be_reused_in_one_batch(self):
        event = self.event()
        self.approve(event)
        second = replace(event, audit_id="different-request", time=self.time + timedelta(seconds=1))
        result = self.scan([second, event])
        self.assertEqual(len(result.suppressed), 1)
        self.assertIn("R5", {x["rule"] for x in result.findings})
        self.assertEqual(result.prediction, "alert")

    def test_duplicate_stages_do_not_spend_budget(self):
        raw = self.raw()
        self.approve(normalize(raw))
        started = deepcopy(raw)
        started["stage"] = "ResponseStarted"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.jsonl"
            write_jsonl(path, [started, raw, raw])
            events, stats = read_events(path)
        self.assertEqual(len(events), 1)
        self.assertEqual(stats.duplicates, 2)
        self.assertEqual(self.scan(events).prediction, "normal")

    def test_conflicting_credential_id_invalidates_event(self):
        raw, changed = self.raw(), None
        changed = deepcopy(raw)
        changed["user"]["extra"][KEY] = ["JTI=changed"]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.jsonl"
            write_jsonl(path, [raw, changed])
            events, stats = read_events(path)
        self.assertEqual(events, [])
        self.assertEqual(stats.conflicting_ids, 1)

    def test_untrusted_client_hints_are_not_credential_identity(self):
        raw = self.raw()
        raw["user"].pop("extra")
        raw["userAgent"] = "JTI=test-work-token"
        raw["annotations"] = {KEY: "JTI=test-work-token"}
        self.approve(self.event())
        self.assertEqual(self.scan([normalize(raw)]).prediction, "alert")

    def test_malformed_credential_field_rejected(self):
        for value in ("token", ["one", "two"], [None]):
            raw = self.raw()
            raw["user"]["extra"][KEY] = value
            with self.assertRaises(ValueError):
                normalize(raw)

    def lists(self, account=APP, count=6, interval=12):
        event = self.event(account=account)
        return [replace(event, audit_id=f"req-{i}", resource=("pods", "services", "configmaps")[i % 3],
                        verb="list", name="", time=self.time + timedelta(seconds=i * interval)) for i in range(count)]

    def test_long_window_detects_slow_recon_without_short_burst(self):
        events = self.lists()
        result = self.scan(events)
        self.assertIn("R4", {f["rule"] for f in result.findings})
        self.assertNotIn("R3", {f["rule"] for f in result.findings})
        self.assertEqual(self.scan(events, disabled=frozenset({"long_window"})).prediction, "normal")

    def test_long_window_boundary_and_identity_separation(self):
        events = self.lists(interval=18)  # final - first = 90 seconds
        self.assertEqual(self.scan(events).prediction, "alert")
        events[-1] = replace(events[-1], time=events[-1].time + timedelta(microseconds=1))
        self.assertEqual(self.scan(events).prediction, "normal")
        events = self.lists()
        events[-1] = replace(events[-1], actor=identity(MONITOR), caller=identity(MONITOR))
        self.assertEqual(self.scan(events).prediction, "normal")

    def test_named_gets_and_calibrated_configmap_polling_are_normal(self):
        for events in ([replace(e, verb="get", name="known") for e in self.lists()],
                       [replace(e, resource="configmaps") for e in self.lists()]):
            self.assertEqual(self.scan(events).prediction, "normal")

    def test_per_resource_profile_detects_low_diversity_recon(self):
        events = [replace(e, resource="pods") for e in self.lists(count=12, interval=.3)]
        self.assertEqual({f["rule"] for f in self.scan(events).findings}, {"R6"})
        self.assertEqual(self.scan(events, disabled=frozenset({"resource_profile"})).prediction, "normal")

    def test_bounded_monitor_profile_still_detects_excess(self):
        self.assertEqual(self.scan(self.lists(MONITOR, 24, 1)).prediction, "normal")
        self.assertEqual(self.scan(self.lists(MONITOR, 50, 1)).prediction, "alert")

    def test_credential_inventory_approval_and_overrun(self):
        events = self.lists(interval=1)
        actions = [{"resource": r, "verb": "list", "name": ""} for r in ("pods", "services", "configmaps")]
        self.approve(events[0], budget=6, actions=actions)
        self.assertEqual(self.scan(events).prediction, "normal")
        overrun = replace(events[-1], audit_id="overrun", time=self.time + timedelta(seconds=7))
        self.assertEqual(self.scan(events + [overrun]).prediction, "alert")

    def test_stolen_approved_credential_first_use_is_explicit_blind_spot(self):
        event = self.event()
        self.approve(event)
        # Identical authenticated observations cannot encode the user's intent.
        self.assertEqual(self.scan([event]).prediction, "normal")

    def test_unregistered_legitimate_inventory_is_explicit_false_positive(self):
        self.assertEqual(self.scan(self.lists(interval=1)).prediction, "alert")

    def test_context_rejects_overbroad_and_ambiguous_authorization(self):
        self.approve(self.event())
        for edit in ("wildcard", "write", "duplicate", "zero_budget"):
            context = deepcopy(self.context)
            if edit == "wildcard":
                context["intents"][0]["actions"][0]["name"] = "*"
            elif edit == "write":
                context["intents"][0]["actions"][0]["verb"] = "create"
            elif edit == "duplicate":
                context["intents"].append(deepcopy(context["intents"][0]))
            else:
                context["intents"][0]["max_requests"] = 0
            with self.assertRaises(ValueError):
                validate_context(context)

    def test_calibration_refuses_evaluation_data(self):
        with tempfile.TemporaryDirectory() as folder:
            path = build_dataset(Path(folder) / "data", "evaluation", 1)
            with self.assertRaisesRegex(ValueError, "development"):
                calibrate(path, self.policy, Path(folder) / "out")


if __name__ == "__main__":
    unittest.main()
