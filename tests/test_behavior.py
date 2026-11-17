from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from auditguard.behavior import detect, validate_config
from auditguard.behavior_events import normalize, read_events
from auditguard.events import write_jsonl
from auditguard.policy import load_policy

ROOT = Path(__file__).resolve().parents[1]


class BehaviorTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / "config/behavior.json").read_text(encoding="utf-8"))
        self.legacy = json.loads((ROOT / "config/advanced.json").read_text(encoding="utf-8"))
        self.policy = load_policy(ROOT / "config/live-policy.json")

    def raw(self, resource="pods", group="", body=None, verb="create", name="object"):
        raw = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "auditID": "request-1", "stage": "ResponseComplete",
            "requestReceivedTimestamp": "2026-01-01T00:00:01Z", "user": {"username": "operator-x", "groups": ["authenticated"],
            "extra": {"authentication.kubernetes.io/credential-id": ["JTI:fixture-identity"]}},
            "objectRef": {"resource": resource, "apiGroup": group, "name": name, "namespace": "arbitrary-space"},
            "verb": verb, "requestURI": "/api/request", "responseStatus": {"code": 201}, "sourceIPs": ["10.1.2.3"]}
        if body is not None:
            raw["requestObject"] = body
        return raw

    def scan(self, events):
        return detect(events, self.policy, self.legacy, self.config)

    def rules(self, events):
        return {f["rule"] for f in self.scan(events)[0].findings}

    def approve(self, event, budget=1):
        self.config["work_orders"] = [{"id": "work", "actor": event.actor, "credential_id_hash": event.credential_id_hash,
            "not_before": "2026-01-01T00:00:00Z", "not_after": "2026-01-01T00:05:00Z", "max_requests": budget,
            "fingerprints": [event.request_fingerprint], "reason": "trusted work issuer"}]

    def test_all_scopes_and_nonresource_scan(self):
        raw = self.raw()
        raw.pop("objectRef")
        raw["user"] = {"username": "system:anonymous"}
        raw["responseStatus"]["code"] = 403
        events = []
        for i in range(6):
            raw["auditID"], raw["requestURI"] = str(i), "/path-" + str(i)
            events.append(normalize(raw))
        self.assertIn("G3", self.rules(events))
        self.assertNotIn("G3", self.rules(events[:1]))

    def test_nested_templates_init_and_ephemeral(self):
        for resource, group, body in [
            ("cronjobs", "batch", {"spec": {"jobTemplate": {"spec": {"template": {"spec": {"hostPID": True}}}}}}),
            ("statefulsets", "apps", {"spec": {"template": {"spec": {"initContainers": [{"securityContext": {"privileged": True}}]}}}}),
            ("pods", "", {"spec": {"ephemeralContainers": [{"securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}}}]}})]:
            with self.subTest(resource=resource):
                self.assertIn("G5", self.rules([normalize(self.raw(resource, group, body))]))

    def test_normal_scheduled_and_network_objects(self):
        for resource, group, body in [("cronjobs", "batch", {"spec": {"schedule": "* * * * *"}}),
            ("daemonsets", "apps", {"spec": {"template": {"spec": {"containers": [{"image": "test"}]}}}}),
            ("services", "", {"spec": {"type": "NodePort"}})]:
            self.assertEqual(self.scan([normalize(self.raw(resource, group, body))])[0].prediction, "normal")

    def test_json_patch_add_different_from_false_remove_and_test(self):
        for op, value, alert in [("add", True, True), ("replace", True, True), ("replace", False, False), ("remove", True, False), ("test", True, False)]:
            raw = self.raw("deployments", "apps", [{"op": op, "path": "/spec/template/spec/hostPID", "value": value}], "patch")
            self.assertEqual("G5" in self.rules([normalize(raw)]), alert)

    def test_custom_group_is_not_builtin_workload(self):
        self.assertNotIn("G5", self.rules([normalize(self.raw("pods", "custom.example", {"spec": {"hostPID": True}}))]))

    def test_rbac_custom_role_resolution_not_name_matching(self):
        self.config["role_inventory"] = [{"kind": "ClusterRole", "namespace": "", "name": "ordinary-looking",
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]}]
        raw = self.raw("clusterrolebindings", "rbac.authorization.k8s.io", {"roleRef": {"kind": "ClusterRole", "name": "ordinary-looking", "apiGroup": "rbac.authorization.k8s.io"}})
        self.assertIn("G4", self.rules([normalize(raw)]))
        self.config["role_inventory"] = []
        result, notes = self.scan([normalize(raw)])
        self.assertEqual(result.prediction, "normal")
        self.assertIn("unknown_role_reference", {n["reason"] for n in notes})

    def test_scalar_delegation_patch(self):
        raw = self.raw("roles", "rbac.authorization.k8s.io", [{"op": "add", "path": "/rules/0/verbs/-", "value": "escalate"}], "patch")
        self.assertIn("G4", self.rules([normalize(raw)]))

    def test_custom_secret_resource_is_not_credential_permission(self):
        raw = self.raw("roles", "rbac.authorization.k8s.io", {"rules": [{"apiGroups": ["custom"], "resources": ["secrets"], "verbs": ["get"]}]})
        self.assertNotIn("G4", self.rules([normalize(raw)]))

    def test_approval_requires_credential_caller_time_and_fingerprint(self):
        raw = self.raw("pods", "", {"spec": {"hostPID": True}})
        event = normalize(raw)
        self.approve(event)
        self.assertEqual(self.scan([event])[0].prediction, "normal")
        for change in ({"caller": "another"}, {"credential_id_hash": ""}, {"time": event.time + timedelta(minutes=5)}, {"code": 403}):
            self.assertIn("G5", self.rules([replace(event, **change)]))
        raw["requestObject"]["spec"]["hostNetwork"] = True
        self.assertIn("G5", self.rules([normalize(raw)]))

    def test_workload_approval_covers_commands_and_environment(self):
        raw = self.raw(body={"spec": {"hostPID": True, "containers": [{"name": "worker", "image": "busybox", "command": ["sleep"]}]}})
        self.approve(normalize(raw))
        raw["requestObject"]["spec"]["containers"][0]["command"] = ["different"]
        self.assertIn("G5", self.rules([normalize(raw)]))

    def test_approval_budget_exhaustion(self):
        event = normalize(self.raw(body={"spec": {"hostPID": True}}))
        self.approve(event)
        self.assertIn("G0", self.rules([event, replace(event, audit_id="next", time=event.time + timedelta(seconds=1))]))

    def test_duplicate_credential_approvals_rejected(self):
        self.approve(normalize(self.raw()))
        other = dict(self.config["work_orders"][0], id="second")
        self.config["work_orders"].append(other)
        with self.assertRaises(ValueError):
            validate_config(self.config)

    def test_sensitive_values_never_in_findings(self):
        raw = self.raw(body={"spec": {"hostPID": True, "containers": [{"command": ["DO-NOT-PRINT"], "env": [{"name": "PASSWORD", "value": "SENSITIVE-VALUE"}]}]}})
        output = json.dumps(self.scan([normalize(raw)])[0].findings)
        self.assertNotIn("DO-NOT-PRINT", output)
        self.assertNotIn("SENSITIVE-VALUE", output)

    def test_missing_body_and_unresolved_patch_are_visible(self):
        result, notes = self.scan([normalize(self.raw())])
        self.assertIn("workload_body_unavailable", {n["reason"] for n in notes})
        raw = self.raw(body=[{"op": "copy", "from": "/spec/hostPID", "path": "/spec/hostIPC"}], verb="patch")
        self.assertIn("patch_requires_previous_object", {n["reason"] for n in self.scan([normalize(raw)])[1]})

    def test_labels_names_and_useragent_are_not_detection_signatures(self):
        raw = self.raw(body={"spec": {"hostNetwork": True}})
        baseline = self.rules([normalize(raw)])
        raw.update(label="normal", scenario="N01", userAgent="trusted-operator")
        raw["objectRef"].update(namespace="different-space", name="renamed")
        raw["user"]["username"] = "different-user"
        self.assertEqual(self.rules([normalize(raw)]), baseline)

    def test_conflicting_body_duplicate_rejected(self):
        first = self.raw(body={"spec": {"hostPID": True}})
        second = deepcopy(first)
        second["requestObject"]["spec"]["hostPID"] = False
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "input.jsonl"
            write_jsonl(path, [first, second])
            events, stats = read_events(path)
        self.assertEqual(events, [])
        self.assertEqual(stats.conflicting_ids, 1)

    def test_nonresource_not_discarded_and_bad_role_rejected(self):
        raw = self.raw()
        raw.pop("objectRef")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "input.jsonl"
            write_jsonl(path, [raw])
            events, stats = read_events(path)
            self.assertEqual(len(events), 1)
            self.assertEqual(stats.non_resource, 1)
        with self.assertRaises(ValueError):
            normalize(self.raw("roles", "rbac.authorization.k8s.io", {"rules": [{"verbs": "get"}]}))

    def test_approved_role_update_still_affects_later_bindings(self):
        role = normalize(self.raw("clusterroles", "rbac.authorization.k8s.io", {"rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]}, name="custom-role"))
        role = replace(role, namespace="")
        self.approve(role)
        raw = self.raw("clusterrolebindings", "rbac.authorization.k8s.io", {"roleRef": {"kind": "ClusterRole", "name": "custom-role", "apiGroup": "rbac.authorization.k8s.io"}})
        event = replace(normalize(raw), audit_id="binding", time=role.time + timedelta(seconds=1))
        self.assertIn("G4", self.rules([role, event]))


if __name__ == "__main__":
    unittest.main()
