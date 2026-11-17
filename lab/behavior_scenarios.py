"""Predeclared requests/labels. This file never imports the detector.

Objects are unscheduled in the agentless lab. Attack labels represent the
controlled scenario intent, not a claim that a real compromise took place.
"""

from copy import deepcopy


def podspec(**extra):
    return {"containers": [{"name": "main", "image": "busybox:1.36", "command": ["sleep", "3600"]}], **extra}


def workload(kind, name, spec=None):
    spec = deepcopy(spec or podspec())
    meta = {"name": name}
    if kind == "Pod":
        return {"apiVersion": "v1", "kind": kind, "metadata": meta, "spec": spec}
    if kind == "CronJob":
        spec["restartPolicy"] = "Never"
        return {"apiVersion": "batch/v1", "kind": kind, "metadata": meta,
                "spec": {"schedule": "0 0 1 1 *", "suspend": True,
                         "jobTemplate": {"spec": {"template": {"spec": spec}}}}}
    template = {"metadata": {"labels": {"app": name}}, "spec": spec}
    outer = {"selector": {"matchLabels": {"app": name}}, "template": template}
    if kind == "StatefulSet":
        outer["serviceName"] = name
    return {"apiVersion": "apps/v1", "kind": kind, "metadata": meta, "spec": outer}


def step(method, path, body=None, codes=(200,), delay=0):
    return {"method": method, "path": path, "body": body, "expected_codes": list(codes), "delay": delay}


def definitions(split, namespace="{ns}", other_namespace="{other}", suffix="{suffix}"):
    ns, other = namespace, other_namespace
    name = "item-" + suffix
    core = f"/api/v1/namespaces/{ns}"
    rbac = "/apis/rbac.authorization.k8s.io/v1"
    def read(resource, named=""):
        return step("GET", core + "/" + resource + ("/" + named if named else ""))
    def execute(command="id", method="POST", codes=(400,)):
        return step(method, core + "/pods/diagnostic/exec?command=" + command + "&stdout=true&stderr=true", codes=codes)
    def token():
        return step("POST", core + "/serviceaccounts/worker/token",
                    {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": {"expirationSeconds": 600}}, (201,))
    def role(rules, cluster=False):
        kind = "ClusterRole" if cluster else "Role"
        path = rbac + ("/clusterroles" if cluster else f"/namespaces/{ns}/roles")
        return step("POST", path, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": kind,
                    "metadata": {"name": name}, "rules": rules}, (201,))
    def binding(ref="lab-wide", cluster=False):
        kind = "ClusterRoleBinding" if cluster else "RoleBinding"
        path = rbac + ("/clusterrolebindings" if cluster else f"/namespaces/{ns}/rolebindings")
        return step("POST", path, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": kind,
                    "metadata": {"name": name}, "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": ref},
                    "subjects": [{"kind": "ServiceAccount", "namespace": ns, "name": "worker"}]}, (201,))
    paths = {"Pod": core + "/pods", "Deployment": f"/apis/apps/v1/namespaces/{ns}/deployments",
             "DaemonSet": f"/apis/apps/v1/namespaces/{ns}/daemonsets", "StatefulSet": f"/apis/apps/v1/namespaces/{ns}/statefulsets",
             "CronJob": f"/apis/batch/v1/namespaces/{ns}/cronjobs"}
    def deploy(kind, spec=None):
        return step("POST", paths[kind], workload(kind, name, spec), (201,))
    safe_rules = [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]
    wide_rules = [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
    privileged = podspec()
    privileged["containers"][0]["securityContext"] = {"privileged": True}
    scan = [step("GET", p, codes=(403,)) for p in ("/api/v9", "/apis/unknown", "/admin", "/debug", "/metrics", "/configz", "/logs", "/openapi/v99")]
    inventory = [read(r) for _ in range(3) for r in ("pods", "services", "configmaps")]
    out = []
    def add(id, label, family, description, role_name, requests, approval="none", limitation=False):
        out.append({"id": id, "label": label, "family": family, "description": description,
                    "actor_role": role_name, "steps": requests, "approval": approval, "limitation_control": limitation})
    if split == "development":
        add("D01", "normal", "discovery", "기본 정상 조회", "reader", [read("pods"), read("services")])
        add("D02", "attack", "credential", "Secret 목록 조회", "operator", [read("secrets")])
        add("D03", "normal", "execution", "승인된 진단 exec 시도", "operator", [execute()], "all")
        add("D04", "attack", "execution", "승인 없는 exec 시도", "reader", [execute(codes=(403,))])
        add("D05", "normal", "discovery", "단발성 권한 오류", "reader", [step("GET", "/metrics", codes=(403,))])
        add("D06", "attack", "discovery", "익명 경로 스캔", "anonymous", scan[:6])
        add("D07", "normal", "privilege", "읽기 전용 Role 생성", "admin", [role(safe_rules)])
        add("D08", "attack", "privilege", "전체 권한 ClusterRole 생성", "admin", [role(wide_rules, True)])
        add("D09", "normal", "workload", "일반 Deployment 생성", "admin", [deploy("Deployment")])
        add("D10", "attack", "workload", "특권 Pod 생성", "admin", [deploy("Pod", privileged)])
        add("D11", "normal", "credential", "승인된 Secret GET", "operator", [read("secrets", "demo-secret")], "all")
        add("D12", "normal", "credential", "승인된 토큰 발급", "operator", [token()], "all")
        return out
    if split != "evaluation":
        raise ValueError("unknown split")
    add("N01", "normal", "credential", "승인된 단일 Secret 조회", "operator", [read("secrets", "demo-secret")], "all")
    add("N02", "normal", "credential", "업무용 단기 토큰 발급", "operator", [token()], "all")
    add("A01", "attack", "credential", "허용된 권한으로 Secret 열거", "operator", [read("secrets")])
    add("A02", "attack", "credential", "다른 SA 토큰의 승인 없는 발급", "operator", [token()])
    add("H01", "attack", "credential", "승인 토큰의 최초 사용을 공격자가 차지", "operator", [read("secrets", "demo-secret")], "all", True)
    add("N03", "normal", "execution", "운영자 승인 exec POST 시도", "operator", [execute("hostname")], "all")
    add("N04", "normal", "execution", "잘못된 Pod 로그 접근 한 번", "reader", [step("GET", core + "/pods/diagnostic/log", codes=(403,))])
    add("A03", "attack", "execution", "GET 방식의 미승인 exec", "reader", [execute("whoami", "GET", (403,))])
    add("A04", "attack", "execution", "승인한 명령과 다른 exec 요청", "operator", [execute("hostname")], "different_command")
    add("N05", "normal", "discovery", "반복 health check", "reader", [step("GET", "/readyz") for _ in range(8)])
    add("N06", "normal", "discovery", "한 번의 비리소스 권한 오류", "reader", [step("GET", "/debug", codes=(403,))])
    add("N07", "normal", "discovery", "승인된 인벤토리 조회", "reader", inventory, "all")
    add("N08", "normal", "discovery", "승인 정보 없는 정상 인벤토리", "reader", inventory, limitation=True)
    add("A05", "attack", "discovery", "익명 비리소스 경로 정찰", "anonymous", scan)
    slow = [dict(read(r), delay=6) for _ in range(2) for r in ("pods", "services", "configmaps")]
    add("A06", "attack", "discovery", "간격을 둔 다종 리소스 정찰", "reader", slow)
    cross = [step("GET", f"/api/v1/namespaces/{n}/{r}") for _ in range(2) for n in (ns, other) for r in ("pods", "services", "configmaps")]
    add("A07", "attack", "discovery", "두 namespace를 가로지르는 정찰", "reader", cross)
    add("H02", "attack", "discovery", "정상 조회와 같은 단일 저빈도 정찰", "reader", [read("pods")], limitation=True)
    add("N09", "normal", "privilege", "읽기 전용 ClusterRole 연결", "admin", [binding("view")])
    add("N10", "normal", "privilege", "사전 승인된 고권한 역할 연결", "admin", [binding(cluster=True)], "all")
    add("N11", "normal", "privilege", "최소권한 Role 생성", "admin", [role(safe_rules)])
    add("A08", "attack", "privilege", "새 이름으로 wildcard 역할 생성", "admin", [role(wide_rules, True)])
    add("A09", "attack", "privilege", "이름만으로 알 수 없는 고권한 역할 연결", "admin", [binding(cluster=True)])
    add("A10", "attack", "privilege", "JSON Patch로 Role 권한 확장", "admin", [step("PATCH", rbac + f"/namespaces/{ns}/roles/editable",
        [{"op": "add", "path": "/rules/-", "value": {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles"], "verbs": ["escalate"]}}], (200,))])
    add("A11", "attack", "privilege", "cluster-admin 역할 연결", "admin", [binding("cluster-admin", True)])
    add("N12", "normal", "workload", "일반 CronJob 생성", "admin", [deploy("CronJob")])
    add("N13", "normal", "workload", "일반 DaemonSet 생성", "admin", [deploy("DaemonSet")])
    add("N14", "normal", "workload", "정상 NodePort 서비스", "admin", [step("POST", core + "/services", {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name}, "spec": {"type": "NodePort", "ports": [{"port": 8080, "targetPort": 8080}], "selector": {"app": name}}}, (201,))])
    add("N15", "normal", "workload", "승인된 인프라 특권 DaemonSet", "admin", [deploy("DaemonSet", privileged)], "all")
    host = podspec(volumes=[{"name": "host", "hostPath": {"path": "/"}}])
    add("A12", "attack", "workload", "CronJob 템플릿에 호스트 경로 추가", "admin", [deploy("CronJob", host)])
    init = podspec(initContainers=[{"name": "prepare", "image": "busybox:1.36", "command": ["true"], "securityContext": {"privileged": True}}])
    add("A13", "attack", "workload", "StatefulSet initContainer 특권 실행 설정", "admin", [deploy("StatefulSet", init)])
    add("A14", "attack", "workload", "Deployment PATCH로 hostPID 활성화", "admin", [step("PATCH", f"/apis/apps/v1/namespaces/{ns}/deployments/editable", [{"op": "add", "path": "/spec/template/spec/hostPID", "value": True}], (200,))])
    cap = podspec()
    cap["containers"][0]["securityContext"] = {"capabilities": {"add": ["SYS_ADMIN"]}}
    add("A15", "attack", "workload", "Pod에 위험한 capability 부여", "admin", [deploy("Pod", cap)])
    add("A16", "attack", "workload", "DaemonSet 호스트 네트워크 공유", "admin", [deploy("DaemonSet", podspec(hostNetwork=True))])
    return out
