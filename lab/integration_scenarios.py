"""Predeclared execution outcomes, including known ambiguity controls.

Attack labels describe simulated operator intent; all commands are harmless.
No detector logic is imported by this module.
"""

from copy import deepcopy
from urllib.parse import urlencode

IMAGE = "docker.io/library/busybox:1.36"
MARKER = "AUDITGUARD_VM_ONLY_FIXTURE"


def exec_path(ns, pod, command):
    return f"/api/v1/namespaces/{ns}/pods/{pod}/exec?" + urlencode(
        [("container", "demo"), ("stdout", "true"), ("stderr", "true"), ("stdin", "false"), ("tty", "false")]
        + [("command", s) for s in command])


def workload(kind, name, risk="none"):
    spec = {"automountServiceAccountToken": False, "containers": [{"name": "demo", "image": IMAGE,
        "imagePullPolicy": "Never", "command": ["sh", "-c", "sleep 7200"],
        "resources": {"requests": {"cpu": "5m", "memory": "8Mi"}, "limits": {"memory": "48Mi"}}}]}
    if risk == "privileged":
        spec["containers"][0]["securityContext"] = {"privileged": True}
    if risk == "hostpid":
        spec["hostPID"] = True
    if risk == "hostpath":
        spec["volumes"] = [{"name": "fixture", "hostPath": {"path": "/var/lib/auditguard-fixtures", "type": "Directory"}}]
        spec["containers"][0]["volumeMounts"] = [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}]
    obj = {"apiVersion": "v1" if kind == "Pod" else "apps/v1", "kind": kind,
           "metadata": {"name": name, "labels": {"integration": name}}}
    if kind == "Pod":
        spec["restartPolicy"] = "Never"
        obj["spec"] = spec
    else:
        obj["spec"] = {"selector": {"matchLabels": {"integration": name}},
                       "template": {"metadata": {"labels": {"integration": name}}, "spec": spec}}
        if kind == "Deployment":
            obj["spec"]["replicas"] = 1
    return obj


def request(method, path, body=None, expected=200, client="actor", operation="api"):
    return {"method": method, "path": path, "body": body, "expected_codes": [expected],
            "client": client, "operation": operation}


def definitions(ns="integration-plan", suffix="example"):
    core = f"/api/v1/namespaces/{ns}"
    rbac = f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}"
    cases = []

    def add(id, label, family, description, actor, approval, steps, **extra):
        cases.append(dict(id=id, label=label, family=family, description=description,
                          actor_role=actor, approval=approval, steps=steps, **extra))

    command = ["sh", "-c", "printf 'EXEC_CONFIRMED\\n'; id -u"]
    for id, label, description, actor, approval in (
        ("X01", "normal", "승인된 정상 exec 성공", "operator", "exact"),
        ("X02", "attack", "RBAC는 허용하지만 업무 승인이 없는 exec 성공", "operator", "none"),
        ("X03", "attack", "승인된 명령과 다른 exec 성공", "operator", "different_command"),
        ("X04", "attack", "RBAC가 거부한 exec 대조군", "reader", "none"),
        ("X05", "attack", "승인된 토큰·동일 명령의 첫 도용: 관측상 정상과 동일", "operator", "exact")):
        add(id, label, "execution", description, actor, approval,
            [request("GET", exec_path(ns, "diagnostic", command), expected=403 if id == "X04" else 101, operation="exec")],
            proof="exec_denied" if id == "X04" else "exec", expected_stdout="EXEC_CONFIRMED\n0\n",
            limitation_control=id == "X05")
    for id, label, kind, risk, approval, desc in (
        ("W01", "normal", "Pod", "none", "none", "일반 Pod 실제 실행"),
        ("W02", "normal", "Pod", "privileged", "exact", "승인된 privileged 관리 Pod 실행"),
        ("W03", "attack", "Pod", "privileged", "none", "미승인 privileged Pod 실행"),
        ("W04", "attack", "Pod", "hostpid", "none", "미승인 hostPID Pod에서 VM init 관측"),
        ("W05", "attack", "DaemonSet", "hostpath", "none", "미승인 hostPath DaemonSet에서 VM 더미 파일 읽기"),
        ("W06", "normal", "DaemonSet", "hostpath", "exact", "승인된 hostPath 관리 DaemonSet 실행"),
        ("W07", "normal", "Deployment", "none", "none", "일반 Deployment 실제 실행"),
        ("W08", "normal", "Pod", "privileged", "none", "무해한 관리 작업이지만 승인 등록 누락")):
        name = f"{id.lower()}-{suffix}"
        path = core + "/pods" if kind == "Pod" else f"/apis/apps/v1/namespaces/{ns}/" + {"DaemonSet": "daemonsets", "Deployment": "deployments"}[kind]
        add(id, label, "workload", desc, "admin", approval,
            [request("POST", path, workload(kind, name, risk), 201)],
            proof="workload", workload_kind=kind, workload_name=name, risk=risk,
            limitation_control=id == "W08")
    for id, label, role, approval, desc in (
        ("R01", "normal", "pod-reader", "none", "낮은 권한 연결 후 실제 Pod 조회: 403→200"),
        ("R02", "attack", "secret-reader", "none", "미승인 민감 권한 연결 후 실제 Secret 조회: 403→200"),
        ("R03", "normal", "secret-reader", "exact", "승인된 민감 권한 변경 및 접근, 사전 403 점검 포함")):
        subject = id.lower() + "-subject"
        path = core + ("/pods/diagnostic" if role == "pod-reader" else "/secrets/demo-secret")
        body = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": id.lower() + "-" + suffix},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": role},
                "subjects": [{"kind": "ServiceAccount", "namespace": ns, "name": subject}]}
        add(id, label, "privilege", desc, "admin", approval,
            [request("GET", path, expected=403, client="subject"), request("POST", rbac + "/rolebindings", body, 201),
             request("GET", path, client="subject")],
            proof="rbac_access", subject=subject, role=role, limitation_control=id == "R03")
    return deepcopy(cases)
