"""Command-line entry points. All normal workflows need only Python 3.10+."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from .benchmark import build_dataset, course_manifest
from .detector import detect, MODES
from .evaluate import evaluate, tune
from .events import read_events, write_json, write_jsonl
from .policy import load_policy


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="python -m auditguard", description="Kubernetes audit metadata detection and evaluation")
    sub = root.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="analyze one audit JSONL file")
    scan.add_argument("--input", required=True, type=Path)
    scan.add_argument("--policy", type=Path, default=Path("config/live-policy.json"))
    scan.add_argument("--mode", choices=(*MODES, "b3", "b4"), default="b4")
    scan.add_argument("--context", type=Path, default=Path("config/advanced.json"))
    scan.add_argument("--output", type=Path, required=True)
    scan.add_argument("--allow-invalid", action="store_true", help="write partial findings, keeping an invalid status")
    bench = sub.add_parser("benchmark", help="create explicitly synthetic datasets")
    bench.add_argument("--output", type=Path, default=Path("data/synthetic"))
    for name in ("evaluate", "tune"):
        command = sub.add_parser(name)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--policy", type=Path, default=Path("config/policy.json"))
        command.add_argument("--output", type=Path, required=True)
        if name == "tune":
            command.add_argument("--calibrate-context", action="store_true", help="derive monitor headroom from normal development runs only")
    replay = sub.add_parser("reproduce", help="regenerate published offline experiments using the frozen policy")
    replay.add_argument("--output", type=Path, default=Path("results/reproduced"))
    replay.add_argument("--policy", type=Path, default=Path("config/policy.json"))
    advanced = sub.add_parser("advanced", help="compare B0..B4 with credential-bound context")
    advanced.add_argument("--manifest", type=Path, required=True)
    advanced.add_argument("--policy", type=Path, required=True)
    advanced.add_argument("--context", type=Path, default=Path("config/advanced.json"))
    advanced.add_argument("--output", type=Path, required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "scan":
            policy = load_policy(args.policy)
            events, stats = read_events(args.input)
            bad = bool(stats.malformed or stats.conflicting_ids or not events)
            if bad and not args.allow_invalid:
                write_jsonl(args.output / "findings.jsonl", [])
                write_jsonl(args.output / "suppressed.jsonl", [])
                write_json(args.output / "status.json", {"status": "invalid", "read_stats": asdict(stats)})
                print("Invalid input; see status.json. No normal verdict was issued.", file=sys.stderr)
                return 2
            if args.mode in {"b3", "b4"}:
                from .advanced import detect_advanced
                context = json.loads(args.context.read_text(encoding="utf-8"))
                result = detect_advanced(events, policy, context, args.mode)
            else:
                result = detect(events, policy, args.mode)
            bad = bad or result.inspected_events == 0
            write_jsonl(args.output / "findings.jsonl", result.findings)
            write_jsonl(args.output / "suppressed.jsonl", result.suppressed)
            summary = {"status": "invalid" if bad else "complete", "prediction": "invalid" if bad else result.prediction, "mode": args.mode, "policy_sha256": result.policy_sha256, "read_stats": asdict(stats), "inspected_events": result.inspected_events, "out_of_scope": result.out_of_scope, "alerts": len(result.findings), "suppressed": len(result.suppressed)}
            write_json(args.output / "status.json", summary)
            print(json.dumps(summary, ensure_ascii=False))
            return 2 if bad else 0
        if args.command == "benchmark":
            for split in ("development", "evaluation"):
                print(build_dataset(args.output / split, split))
            return 0
        if args.command == "advanced":
            from .refinement import compare
            context = json.loads(args.context.read_text(encoding="utf-8"))
            summary = compare(args.manifest, load_policy(args.policy), context, args.output)
            print(json.dumps(summary["configurations"], indent=2))
            return 2 if any(m["invalid_runs"] for m in summary["configurations"].values()) else 0
        if args.command == "tune":
            print(json.dumps(tune(args.manifest, load_policy(args.policy), args.output, args.calibrate_context), ensure_ascii=False, indent=2))
            return 0
        if args.command == "evaluate":
            summary = evaluate(args.manifest, load_policy(args.policy), args.output)
            print(json.dumps(summary, ensure_ascii=False, indent=2))
            return 2 if any(m["invalid_runs"] for m in summary["configurations"].values()) else 0
        if args.command == "reproduce":
            policy = load_policy(args.policy)
            root = Path(__file__).resolve().parent.parent
            data = args.output / "datasets"
            provided = course_manifest(root, data / "provided" / "manifest.json")
            development = build_dataset(data / "development", "development")
            evaluation = build_dataset(data / "evaluation", "evaluation")
            selection = tune(development, policy, args.output / "tuning")
            # Never silently retune the evaluated policy. A mismatch means
            # the published freeze decision needs explicit review.
            from .policy import digest
            if selection["policy_sha256"] != digest(policy):
                raise ValueError("development selection differs from frozen policy; inspect tuning/selection.json")
            for name, manifest in (("provided", provided), ("development", development), ("evaluation", evaluation)):
                summary = evaluate(manifest, policy, args.output / name)
                if any(m["invalid_runs"] for m in summary["configurations"].values()):
                    raise ValueError("invalid runs in " + name)
                print(name + ": " + json.dumps(summary["configurations"], ensure_ascii=False))
            print("Reports: " + str(args.output.resolve()))
            return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        # Do not echo raw records or subprocess environments.
        print("Error: " + str(error), file=sys.stderr)
        return 2
    return 0
