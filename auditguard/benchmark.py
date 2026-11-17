"""Deterministic synthetic stress cases, explicitly not live measurements.

This module does not import the detector. Scenario labels live only in the
manifest. Events contain no case IDs or label annotations. Development and
evaluation use different random seeds; four evaluation-only cases probe new
behaviors. Repeated synthetic runs are not independent real-world samples.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import random
import uuid

from .events import iso_time, write_json, write_jsonl
from .policy import digest


NS = "pbl-security"
APP = "pbl-crypto-platform-app"
MONITOR = "pbl-monitor"
OPERATOR = "pbl-operator"


def identity(account: str) -> str:
    return f"system:serviceaccount:{NS}:{account}"


@dataclass(frozen=True)
class Request:
    resource: str
    verb: str = "list"
    code: int = 200
    name: str = ""
    subresource: str = ""
    delay: float = 0.25


@dataclass(frozen=True)
class Scenario:
    id: str
    label: str
    account: str
    description: str
    requests: tuple[Request, ...]
    evaluation_only: bool = False
    expired_approval: bool = False


def scenarios() -> list[Scenario]:
    allowed = ("pods", "services", "configmaps")
    return [
        Scenario("N0", "normal", APP, "기본 허용 조회", tuple(Request(r) for r in allowed) + (Request("pods", "get", name="frontend-demo"),)),
        Scenario("N1", "normal", MONITOR, "정상 모니터링의 빈번한 조회", tuple(Request(r) for _ in range(8) for r in allowed)),
        Scenario("N2", "normal", OPERATOR, "승인된 단일 더미 Secret 조회", (Request("secrets", "get", name="demo-secret"),)),
        Scenario("N3", "normal", APP, "설정 확인 중의 비민감 API 권한 거부", (Request("configmaps", "patch", 403, "demo-config"),)),
        Scenario("A1", "attack", APP, "금지된 Secret 목록 조회", (Request("secrets", code=403),)),
        Scenario("A2", "attack", APP, "금지된 Pod exec POST", (Request("pods", "get", name="backend-demo"), Request("pods", "create", 403, "backend-demo", "exec"))),
        Scenario("A3", "attack", APP, "허용/거부 API를 섞은 반복 조회", tuple(Request(r, code=403 if r == "secrets" else 200) for _ in range(6) for r in ("pods", "secrets", "configmaps"))),
        Scenario("A4", "attack", APP, "모두 허용되는 API를 이용한 빠른 정찰", tuple(Request(r, delay=0.42) for _ in range(6) for r in allowed)),
        Scenario("A5", "attack", APP, "정상 권한과 낮은 빈도를 유지하는 정찰", tuple(Request(r, delay=12.0) for _ in range(2) for r in allowed)),
        Scenario("H1", "attack", APP, "GET 방식의 exec 요청", (Request("pods", "get", 403, "backend-demo", "exec"),), True),
        Scenario("H2", "attack", OPERATOR, "운영 승인 기간 밖의 Secret 조회", (Request("secrets", "get", name="demo-secret"),), True, True),
        Scenario("H3", "attack", MONITOR, "모니터 계정도 허용 한도를 넘는 조회", tuple(Request(r, delay=0.03) for _ in range(30) for r in allowed), True),
        Scenario("H4", "attack", OPERATOR, "승인 작업과 관측상 같은 계정 악용", (Request("secrets", "get", name="demo-secret"),), True),
    ]


def synthetic_event(request: Request, account: str, stamp: datetime, rng: random.Random) -> dict:
    # Same event construction for normal and attack scenarios.
    ref = {"resource": request.resource, "namespace": NS, "apiVersion": "v1"}
    if request.name:
        ref["name"] = request.name
    if request.subresource:
        ref["subresource"] = request.subresource
    uri = f"/api/v1/namespaces/{NS}/{request.resource}"
    if request.name:
        uri += "/" + request.name
    if request.subresource:
        uri += "/" + request.subresource
    return {
        "kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Metadata",
        "auditID": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        "stage": "ResponseComplete", "requestURI": uri, "verb": request.verb,
        "user": {"username": identity(account)}, "sourceIPs": ["192.0.2.10"],
        "userAgent": "pbl-lab-client/1.0", "objectRef": ref,
        "responseStatus": {"code": request.code},
        "requestReceivedTimestamp": iso_time(stamp),
        "stageTimestamp": iso_time(stamp + timedelta(milliseconds=rng.randint(1, 15))),
    }


def build_dataset(root: str | Path, split: str, repetitions: int | None = None) -> Path:
    if split not in {"development", "evaluation"}:
        raise ValueError("unknown split")
    root = Path(root)
    repeats = repetitions or (3 if split == "development" else 5)
    if not 1 <= repeats <= 100:
        raise ValueError("repetitions must be 1..100")
    seed = 731 if split == "development" else 1927
    rng = random.Random(seed)
    selected = [s for s in scenarios() if split == "evaluation" or not s.evaluation_only]
    pairs = [(scenario, repeat) for scenario in selected for repeat in range(1, repeats + 1)]
    rng.shuffle(pairs)
    manifest = {"schema_version": 1, "dataset_id": f"synthetic-{split}-v1", "source_type": "synthetic", "split": split, "seed": seed, "repetitions": repeats, "runs": []}
    for index, (scenario, repeat) in enumerate(pairs):
        run_id = f"{scenario.id}-{repeat:02d}"
        # Cases are isolated by > the largest tuning window, even if joined.
        start = datetime(2026, 1, 1, 8, tzinfo=timezone.utc) + timedelta(minutes=index * 3)
        if scenario.expired_approval:
            start += timedelta(days=2)
        stamp = start
        events = []
        for request in scenario.requests:
            stamp += timedelta(seconds=request.delay * rng.uniform(0.8, 1.2))
            events.append(synthetic_event(request, scenario.account, stamp, rng))
        rng.shuffle(events)  # Input order must not change window decisions.
        path = root / "logs" / f"{run_id}.jsonl"
        write_jsonl(path, events)
        manifest["runs"].append({
            "run_id": run_id, "scenario": scenario.id, "label": scenario.label,
            "description": scenario.description, "path": f"logs/{run_id}.jsonl",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "expected_events": len(events), "status": "complete", "actor": identity(scenario.account),
            "start": iso_time(start), "end": iso_time(stamp),
            "novel_scenario": scenario.evaluation_only,
        })
    manifest["spec_sha256"] = digest([s.__dict__ | {"requests": [r.__dict__ for r in s.requests]} for s in selected])
    target = root / "manifest.json"
    write_json(target, manifest)
    return target


def course_manifest(root: str | Path, output: str | Path) -> Path:
    root, output = Path(root).resolve(), Path(output).resolve()
    runs = []
    for name, case, label, count in [("normal", "N0", "normal", 4), ("abnormal_1", "A1", "attack", 1), ("abnormal_2", "A2", "attack", 1), ("abnormal_3", "A3", "attack", 18)]:
        path = root / "category3" / "logs" / (name + ".log")
        copy = output.parent / "logs" / path.name
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(path.read_bytes())
        runs.append({"run_id": name, "scenario": case, "label": label,
                     "path": "logs/" + path.name,
                     "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                     "expected_events": count, "status": "complete", "actor": identity(APP)})
    write_json(output, {"schema_version": 1, "dataset_id": "course-category3-examples", "source_type": "provided_example", "split": "provided", "upstream_commit": "270bf2df9ae1eddfb26e8dc88cb92326c54a99a8", "runs": runs})
    return output
