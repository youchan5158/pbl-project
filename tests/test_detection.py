from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random
import tempfile
import unittest

from auditguard.benchmark import APP, MONITOR, OPERATOR, Request, identity, synthetic_event
from auditguard.detector import detect
from auditguard.events import normalize, read_events, write_jsonl
from auditguard.policy import load_policy, validate_policy

ROOT = Path(__file__).resolve().parents[1]


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy(ROOT / "config/policy.json")
        self.stamp = datetime(2026, 1, 1, 9, tzinfo=timezone.utc)
        self.rng = random.Random(70)

    def event(self, resource="pods", verb="list", code=200, account=APP, **kw):
        return normalize(synthetic_event(Request(resource, verb, code, **kw), account, self.stamp, self.rng))

    def test_denied_non_sensitive_write_is_not_behavior_attack(self):
        e = self.event("configmaps", "patch", 403, name="config")
        self.assertEqual(detect([e], self.policy, "b0").prediction, "alert")
        self.assertEqual(detect([e], self.policy, "b2").prediction, "normal")

    def test_successful_secret_access_still_alerts(self):
        for verb in ("get", "list", "watch"):
            with self.subTest(verb=verb):
                self.assertEqual(detect([self.event("secrets", verb)], self.policy).findings[0]["rule"], "R1")

    def test_get_and_post_exec(self):
        for verb in ("get", "create"):
            with self.subTest(verb=verb):
                e = self.event("pods", verb, 403, name="backend", subresource="exec")
                f = detect([e], self.policy).findings[0]
                self.assertEqual(f["rule"], "R2")
                self.assertEqual(f["outcome"], "denied_attempt")

    def test_custom_resource_with_secret_name_is_not_core_secret(self):
        e = replace(self.event("secrets"), api_group="custom.example")
        self.assertEqual(detect([e], self.policy).prediction, "normal")

    def test_approval_exact_target_and_time_and_success(self):
        original = self.event("secrets", "get", account=OPERATOR, name="demo-secret")
        self.assertEqual(len(detect([original], self.policy).suppressed), 1)
        for modified in (replace(original, name="other-secret"), replace(original, code=403), replace(original, actor=identity(APP)), replace(original, verb="list"), replace(original, time=self.stamp + timedelta(days=1)), replace(original, caller=identity(APP))):
            with self.subTest(event=modified):
                self.assertEqual(detect([modified], self.policy).prediction, "alert")

    def test_approval_end_is_exclusive(self):
        e = self.event("secrets", "get", account=OPERATOR, name="demo-secret")
        e = replace(e, time=datetime(2026, 1, 2, tzinfo=timezone.utc))
        self.assertEqual(detect([e], self.policy).prediction, "alert")

    def burst(self, count, account=APP):
        return [replace(self.event(("pods", "services", "configmaps")[i % 3], account=account), time=self.stamp + timedelta(milliseconds=10 * i)) for i in range(count)]

    def test_monitor_exception_is_bounded(self):
        self.assertEqual(detect(self.burst(24, MONITOR), self.policy, "b1").prediction, "alert")
        self.assertEqual(detect(self.burst(24, MONITOR), self.policy, "b2").prediction, "normal")
        self.assertEqual(detect(self.burst(90, MONITOR), self.policy, "b2").prediction, "alert")

    def test_monitor_cannot_hide_secret_or_denied_reads(self):
        e = self.event("secrets", account=MONITOR)
        self.assertEqual(detect([e], self.policy).prediction, "alert")
        events = self.burst(24, MONITOR)
        events[2] = replace(events[2], code=403)
        self.assertEqual(detect(events, self.policy).prediction, "alert")

    def test_time_window_order_boundary_and_namespace_isolation(self):
        self.policy["burst"] = {"window_seconds": 10, "request_threshold": 3, "resource_threshold": 3}
        events = [replace(self.event(r), time=self.stamp + timedelta(seconds=t)) for r, t in zip(("pods", "services", "configmaps"), (0, 5, 10))]
        self.assertEqual(detect(events[::-1], self.policy).prediction, "alert")
        events[-1] = replace(events[-1], time=events[-1].time + timedelta(microseconds=1))
        self.assertEqual(detect(events, self.policy).prediction, "normal")
        self.policy["scope"]["namespaces"].append("other")
        events = [replace(e, time=self.stamp, namespace="other" if i == 0 else e.namespace) for i, e in enumerate(events)]
        self.assertEqual(detect(events, self.policy).prediction, "normal")

    def test_distinct_subjects_do_not_share_burst(self):
        events = self.burst(self.policy["burst"]["request_threshold"])
        events = [replace(e, actor=identity(f"account-{i}")) for i, e in enumerate(events)]
        self.assertEqual(detect(events, self.policy).prediction, "normal")

    def test_low_rate_permitted_reads_are_documented_blind_spot(self):
        events = [replace(e, time=self.stamp + timedelta(seconds=i * 60)) for i, e in enumerate(self.burst(30))]
        self.assertEqual(detect(events, self.policy).prediction, "normal")

    def test_ip_and_user_agent_do_not_grant_approval(self):
        e = self.event("secrets", "get", name="demo-secret")
        e = replace(e, source_ips=("192.0.2.10",), user_agent="approved-admin")
        self.assertEqual(detect([e], self.policy).prediction, "alert")

    def test_wildcard_or_unbounded_context_rejected(self):
        p = deepcopy(self.policy)
        p["approvals"][0]["name"] = "*"
        with self.assertRaises(ValueError):
            validate_policy(p)
        p = deepcopy(self.policy)
        p["monitor_profiles"][0]["resources"].append("secrets")
        with self.assertRaises(ValueError):
            validate_policy(p)


class ParsingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "input.jsonl"
        self.raw = synthetic_event(Request("secrets", code=403), APP, datetime(2026, 1, 1, tzinfo=timezone.utc), random.Random(90))

    def test_multiple_stages_count_once(self):
        received = self.raw | {"stage": "RequestReceived", "responseStatus": {}}
        started = self.raw | {"stage": "ResponseStarted", "responseStatus": {"code": 200}}
        write_jsonl(self.path, [received, self.raw, started, self.raw])
        events, stats = read_events(self.path)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].code, 403)
        self.assertEqual(stats.duplicates, 2)
        self.assertEqual(stats.ignored_stage, 1)

    def test_started_only_stream_is_analyzable(self):
        write_jsonl(self.path, [self.raw | {"stage": "ResponseStarted"}])
        self.assertEqual(len(read_events(self.path)[0]), 1)

    def test_conflicting_identity_is_invalid(self):
        write_jsonl(self.path, [self.raw, self.raw | {"user": {"username": identity(MONITOR)}}])
        events, stats = read_events(self.path)
        self.assertEqual(events, [])
        self.assertEqual(stats.conflicting_ids, 1)

    def test_conflicting_final_response_codes_are_invalid(self):
        write_jsonl(self.path, [self.raw, self.raw | {"responseStatus": {"code": 200}}])
        events, stats = read_events(self.path)
        self.assertEqual(events, [])
        self.assertEqual(stats.conflicting_ids, 1)

    def test_bom_blank_lines_bad_json_and_missing_fields(self):
        self.path.write_text("\ufeff\n{bad\n" + json.dumps(self.raw | {"auditID": ""}) + "\n" + json.dumps(self.raw), encoding="utf-8")
        events, stats = read_events(self.path)
        self.assertEqual(len(events), 1)
        self.assertEqual(stats.malformed, 2)

    def test_no_credential_or_label_fields_in_normalized_event(self):
        raw = self.raw | {"requestObject": {"token": "DO-NOT-EXPORT"}, "responseObject": {"data": "DO-NOT-EXPORT"}, "annotations": {"label": "attack"}, "requestURI": "/x?token=DO-NOT-EXPORT"}
        event = normalize(raw)
        self.assertNotIn("DO-NOT-EXPORT", json.dumps(event.metadata()))
        self.assertNotIn("annotations", event.metadata())

    def test_impersonated_identity_keeps_actual_caller(self):
        event = normalize(self.raw | {"impersonatedUser": {"username": identity(OPERATOR)}})
        self.assertEqual(event.actor, identity(OPERATOR))
        self.assertEqual(event.caller, identity(APP))

    def test_event_list_and_timezone(self):
        raw = self.raw | {"requestReceivedTimestamp": "2026-01-01T09:00:00+09:00"}
        write_jsonl(self.path, [{"kind": "EventList", "items": [raw]}])
        events, _ = read_events(self.path)
        self.assertEqual(events[0].time.hour, 0)
        raw["requestReceivedTimestamp"] = "2026-01-01T09:00:00"
        with self.assertRaises(ValueError):
            normalize(raw)


if __name__ == "__main__":
    unittest.main()
