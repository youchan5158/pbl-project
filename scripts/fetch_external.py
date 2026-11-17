"""Download pinned, public Splunk fixtures. No credentials or cluster access."""

import concurrent.futures
import hashlib
import json
from pathlib import Path
import re
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/external/splunk-v1"
CACHE = ROOT / "tmp/external-splunk"


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "AuditGuard-external-evaluation/1"})
    with urllib.request.urlopen(request, timeout=45) as response:
        data = response.read(20_000_001)
    if len(data) > 20_000_000:
        raise ValueError("download exceeds 20 MB limit: " + url)
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    sources = json.loads((DATA / "sources.json").read_text(encoding="utf-8"))
    frozen = json.loads((DATA / "freeze.json").read_text(encoding="utf-8"))
    for name, expected in frozen["files"].items():
        if sha((ROOT / name).read_bytes()) != expected:
            raise ValueError("frozen source changed: " + name)
    CACHE.mkdir(parents=True, exist_ok=True)
    (DATA / "logs").mkdir(exist_ok=True)
    (DATA / "upstream-detections").mkdir(exist_ok=True)

    def fixture(path):
        revision = sources["attack_data_commit"]
        pointer_url = f"https://raw.githubusercontent.com/splunk/attack_data/{revision}/{path}"
        pointer = fetch(pointer_url)
        lfs = pointer.startswith(b"version https://git-lfs.github.com/spec/v1")
        url = f"https://media.githubusercontent.com/media/splunk/attack_data/{revision}/{path}" if lfs else pointer_url
        data = fetch(url) if lfs else pointer
        if lfs:
            expected_sha = re.search(rb"oid sha256:([0-9a-f]{64})", pointer).group(1).decode()
            expected_size = int(re.search(rb"size (\d+)", pointer).group(1))
            if sha(data) != expected_sha or len(data) != expected_size:
                raise ValueError("LFS integrity failure: " + path)
        destination = CACHE / Path(path).name
        destination.write_bytes(data)
        (DATA / "logs" / destination.name).write_bytes(data)
        return {"path": path, "cache_file": destination.relative_to(ROOT).as_posix(),
                "url": url, "sha256": sha(data), "bytes": len(data), "lfs_verified": lfs}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        entries = list(pool.map(fixture, sources["data_paths"]))

    def detection(item):
        path = item["path"]
        url = f"https://raw.githubusercontent.com/splunk/security_content/{sources['security_content_commit']}/{path}"
        data = fetch(url)
        (DATA / "upstream-detections" / Path(path).name).write_bytes(data)
        return {"path": path, "sha256": sha(data), "url": url}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        detections = list(pool.map(detection, sources["detections"]))
    for repo, revision, suffix in (("attack_data", sources["attack_data_commit"], "Splunk"),
                                   ("security_content", sources["security_content_commit"], "SecurityContent")):
        data = fetch(f"https://raw.githubusercontent.com/splunk/{repo}/{revision}/LICENSE")
        (DATA / f"LICENSE-{suffix}.txt").write_bytes(data)
    manifest = {"datasets": entries, "detections": detections}
    (DATA / "downloads.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"datasets": len(entries), "bytes": sum(x["bytes"] for x in entries),
                      "lfs_verified": sum(x["lfs_verified"] for x in entries),
                      "detection_documents": len(detections)}, indent=2))


if __name__ == "__main__":
    main()
