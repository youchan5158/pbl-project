"""Bundle source, measured evidence and documents; exclude runtimes/keys/slides."""

import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FINAL_BASELINE_PATHS = ("data/behavior-eval", "data/behavior-plan", "data/external",
                        "results/behavior/fresh", "results/behavior/external",
                        "results/behavior/provided.json", "results/external")
DIRECTORIES = ("auditguard", "config", "tests", "scripts", "lab", "category1", "category2",
               "category3", "workload", ".github", "results/integration/final",
               "data/integration-baseline", "data/integration-eval", *FINAL_BASELINE_PATHS)
ROOT_FILES = ("README.md", "README_EN.md", "install.sh", "pyproject.toml", ".gitignore", ".gitattributes",
              "docs/UPSTREAM_README.md", "docs/upstream-files.json", "docs/UNDERSTAND.md",
              "docs/REPORT.md", "docs/INTEGRATION_REPORT.md", "docs/INTEGRATION_LAB.md",
              "docs/INTEGRATION_PROTOCOL.md", "docs/PROVENANCE.md")


def files():
    found = set()
    for name in DIRECTORIES:
        if (ROOT / name).is_file():
            found.add(ROOT / name)
            continue
        for path in (ROOT / name).rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts or "private" in path.parts or path.suffix in {".pyc", ".key", ".crt", ".pem"}:
                continue
            found.add(path)
    found.update(ROOT / name for name in ROOT_FILES if (ROOT / name).is_file())
    return sorted(found)


def verify_archive(path):
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read("SUBMISSION_MANIFEST.json"))
        names = archive.namelist()
        if len(names) != len(set(names)) or set(names) != {x["path"] for x in manifest["files"]} | {"SUBMISSION_MANIFEST.json"}:
            raise ValueError("unexpected/duplicate archive entry")
        for entry in manifest["files"]:
            if ".." in Path(entry["path"]).parts or Path(entry["path"]).is_absolute():
                raise ValueError("unsafe archive path")
            if hashlib.sha256(archive.read(entry["path"])).hexdigest() != entry["sha256"]:
                raise ValueError("archive hash mismatch")
    return len(names) - 1


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, default=ROOT / "output/submission/auditguard-integration-pbl.zip")
    p.add_argument("--check", type=Path)
    args = p.parse_args()
    if args.check:
        print("Verified files:", verify_archive(args.check))
        return
    if args.output.resolve() == (ROOT / "output/submission/auditguard-pbl.zip").resolve():
        raise ValueError("the previous submission ZIP is preserved; choose a new path")
    verification = json.loads((ROOT / "results/local/verification.json").read_text(encoding="utf-8"))
    if verification["status"] != "passed":
        raise ValueError("run scripts/verify.py before packaging")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    manifest = {"project": "pbl-auditguard", "upstream_commit": "270bf2df9ae1eddfb26e8dc88cb92326c54a99a8", "files": []}
    with zipfile.ZipFile(args.output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in files():
            name = path.relative_to(ROOT).as_posix()
            data = path.read_bytes()
            archive.writestr(name, data)
            manifest["files"].append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
        archive.writestr("SUBMISSION_MANIFEST.json", json.dumps(manifest, ensure_ascii=False, indent=2))
    count = verify_archive(args.output)
    print(f"Created {args.output} ({count} verified files, {args.output.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
