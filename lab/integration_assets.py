"""Fetch public, content-verified integration runtime assets into tmp only."""

import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
from urllib.request import Request, urlopen

from auditguard.events import write_json

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "tmp/integration-runtime"
AIRGAP = {"name": "k3s-airgap-images-amd64.tar.zst", "sha256": "a3caf6692c1495f58bbaa1411a0e2377e9f7ebd262bd33101c3cd1edade68360",
          "url": "https://github.com/k3s-io/k3s/releases/download/v1.35.2%2Bk3s1/k3s-airgap-images-amd64.tar.zst"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def get(url, headers=None):
    with urlopen(Request(url, headers=headers or {}), timeout=90) as response:
        return response.read()


def download(asset):
    path = DEST / asset["name"]
    if path.exists() and sha(path.read_bytes()) == asset["sha256"]:
        print("Verified cached " + path.name, flush=True)
        return
    print("Downloading " + path.name, flush=True)
    with urlopen(asset["url"], timeout=90) as response, path.with_suffix(".part").open("wb") as stream:
        size, next_notice = 0, 32 * 1024 * 1024
        while block := response.read(1024 * 1024):
            stream.write(block)
            size += len(block)
            if size >= next_notice:
                print(f"Downloaded {size // 1024 // 1024} MiB", flush=True)
                next_notice += 32 * 1024 * 1024
    part = path.with_suffix(".part")
    if sha(part.read_bytes()) != asset["sha256"]:
        raise ValueError("asset checksum mismatch")
    part.replace(path)


def busybox():
    lock_path = ROOT / "lab/integration-image.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8")) if lock_path.exists() else None
    archive_path = DEST / "busybox.tar"
    if lock and archive_path.exists() and sha(archive_path.read_bytes()) == lock["archive_sha256"]:
        print("Verified cached busybox archive", flush=True)
        return
    auth = json.loads(get("https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/busybox:pull"))["token"]
    headers = {"Authorization": "Bearer " + auth, "Accept": ",".join([
        "application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.docker.distribution.manifest.v2+json"])}
    base = "https://registry-1.docker.io/v2/library/busybox/"
    if lock:
        digest = lock["manifest_digest"]
    else:
        index = json.loads(get(base + "manifests/1.36", headers))
        digest = next(m["digest"] for m in index["manifests"] if m["platform"].get("os") == "linux" and m["platform"].get("architecture") == "amd64")
    raw_manifest = get(base + "manifests/" + digest, headers)
    if "sha256:" + sha(raw_manifest) != digest:
        raise ValueError("image manifest digest mismatch")
    manifest = json.loads(raw_manifest)
    config_digest = manifest["config"]["digest"]
    config = get(base + "blobs/" + config_digest, headers)
    if "sha256:" + sha(config) != config_digest:
        raise ValueError("image config digest mismatch")
    layers = []
    for layer in manifest["layers"]:
        content = get(base + "blobs/" + layer["digest"], headers)
        if "sha256:" + sha(content) != layer["digest"]:
            raise ValueError("image layer digest mismatch")
        unpacked = gzip.decompress(content) if content[:2] == b"\x1f\x8b" else content
        layers.append((layer["digest"].split(":")[1] + "/layer.tar", unpacked))
    if ["sha256:" + sha(content) for _, content in layers] != json.loads(config)["rootfs"]["diff_ids"]:
        raise ValueError("uncompressed image layers differ from config")
    with tarfile.open(archive_path, "w") as tar:
        def add(name, data):
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            tar.addfile(info, io.BytesIO(data))
        config_name = config_digest.split(":")[1] + ".json"
        add(config_name, config)
        for name, content in layers:
            add(name, content)
        add("manifest.json", json.dumps([{"Config": config_name, "RepoTags": ["docker.io/library/busybox:1.36"], "Layers": [name for name, _ in layers]}], sort_keys=True).encode())
    found = {"image": "docker.io/library/busybox:1.36", "platform": "linux/amd64", "manifest_digest": digest,
        "config_digest": config_digest, "layer_digests": [x["digest"] for x in manifest["layers"]],
        "archive_sha256": sha(archive_path.read_bytes()), "source": "Docker Official Images busybox via registry-1.docker.io"}
    if lock and lock != found:
        raise ValueError("image lock changed")
    write_json(lock_path, found)
    print("Pinned busybox " + digest, flush=True)


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    download(AIRGAP)
    busybox()
    write_json(DEST / "asset-receipts.json", {"airgap": AIRGAP, "busybox": json.loads((ROOT / "lab/integration-image.json").read_text(encoding="utf-8"))})


if __name__ == "__main__":
    main()
