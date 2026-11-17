"""Separate Windows/QEMU lab with a real schedulable K3s node.

Does not change frozen lab/windows.py, old VM state or old certificates.
"""

import argparse
import base64
from datetime import datetime, timezone
from functools import partial
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import threading
import time

from auditguard.events import write_json
from .windows import Console as BaseConsole, QuietHandler, process_path
from .live import Api

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tmp/runtime"
RUNTIME = ROOT / "tmp/integration-runtime"
PRIVATE = ROOT / "lab/private/integration"
STATE = RUNTIME / "vm-state.json"
EXECUTABLE = SOURCE / "qemu/qemu-system-x86_64.exe"
SERVER = "https://127.0.0.1:26443"


class Console(BaseConsole):
    def __init__(self):
        self.socket = socket.create_connection(("127.0.0.1", 43221), timeout=3)
        self.socket.settimeout(1)
        self.buffer = b""


def running():
    if not STATE.exists():
        return False
    state = json.loads(STATE.read_text(encoding="utf-8"))
    actual = process_path(state["pid"])
    if actual and actual != EXECUTABLE.resolve():
        raise ValueError("saved integration PID is not owned by this lab")
    return actual is not None


def stop():
    if running():
        state = json.loads(STATE.read_text(encoding="utf-8"))
        os.kill(state["pid"], signal.SIGTERM)
        print("Integration VM stopped; collected evidence preserved.", flush=True)
    else:
        print("Integration VM is not running.", flush=True)


def boot():
    if running():
        raise ValueError("integration VM already running")
    for port in (26443, 28080, 28081, 43221):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
    RUNTIME.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    disk = RUNTIME / ("node-" + stamp + ".qcow2")
    if disk.exists():
        raise ValueError("refusing to overwrite VM disk")
    subprocess.run([str(SOURCE / "qemu/qemu-img.exe"), "create", "-f", "qcow2", str(disk), "8G"], check=True,
                   creationflags=subprocess.CREATE_NO_WINDOW, stdout=subprocess.DEVNULL)
    args = [str(EXECUTABLE), "-accel", "tcg,thread=multi", "-cpu", "max", "-smp", "2", "-m", "4096",
        "-display", "none", "-monitor", "none", "-serial", "tcp:127.0.0.1:43221,server=on,wait=off",
        "-kernel", str(SOURCE / "alpine/boot/vmlinuz-virt"), "-initrd", str(SOURCE / "alpine/boot/initramfs-virt"),
        "-append", "console=ttyS0 modules=loop,squashfs,sd-mod,usb-storage alpine_dev=cdrom:iso9660 cgroup_enable=memory cgroup_memory=1 cgroup_no_v1=all",
        "-cdrom", str(SOURCE / "alpine.iso"), "-drive", f"file={disk},if=virtio,format=qcow2",
        "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:26443-:6443,hostfwd=tcp:127.0.0.1:28081-:8081",
        "-device", "virtio-net-pci,netdev=net0"]
    with (RUNTIME / "qemu-stderr.log").open("w") as log:
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
    write_json(STATE, {"pid": proc.pid, "exe": str(EXECUTABLE.resolve()), "disk": str(disk.resolve()), "memory_mib": 4096, "vcpus": 2})
    print("Booting isolated container lab...", flush=True)
    console = None
    for _ in range(40):
        try:
            console = Console()
            break
        except OSError:
            time.sleep(.5)
    if console is None:
        raise RuntimeError("integration serial console not ready")
    try:
        console.until("login:", 240)
        console.send("root\n")
        console.until("~#", 30)
        console.send("stty -echo\n")
        console.until("~#", 30)
        console.command("ip link set lo up; ip link set eth0 up; udhcpc -i eth0 -q", 60)
        print("BOOT_READY", flush=True)
    finally:
        console.socket.close()


def start():
    if not running():
        boot()
    for source, target in [(SOURCE / "k3s", "k3s"), (SOURCE / "busybox-extras", "busybox-extras"),
                           (ROOT / "lab/behavior-audit-policy.yaml", "audit-policy.yaml"),
                           (ROOT / "lab/integration-bootstrap.sh", "bootstrap.sh")]:
        shutil.copyfile(source, RUNTIME / target)
    for name in ("k3s-airgap-images-amd64.tar.zst", "busybox.tar"):
        if not (RUNTIME / name).exists():
            raise ValueError("run python -m lab.integration_assets first")
    http = ThreadingHTTPServer(("127.0.0.1", 28080), partial(QuietHandler, directory=str(RUNTIME)))
    threading.Thread(target=http.serve_forever, daemon=True).start()
    console = Console()
    try:
        outcome = console.command("wget -q -O /root/bootstrap.sh http://10.0.2.2:28080/bootstrap.sh && sh /root/bootstrap.sh", 600)
        # Bootstrap output has no credentials; K3s logs remain private in the VM.
        if "BOOTSTRAP_STARTED" not in outcome:
            print(outcome[-4000:], flush=True)
            raise ValueError("container lab bootstrap failed")
        print("K3s container runtime starting...", flush=True)
        for attempt in range(80):
            if "CONFIG_READY" in console.command("test -s /etc/rancher/k3s/k3s.yaml && echo CONFIG_READY", 30):
                break
            if attempt % 6 == 0:
                print("Waiting for API certificates...", flush=True)
            time.sleep(3)
        else:
            raise RuntimeError("API certificates not ready")
        encoded = console.command('printf "\\n__CFG_BEGIN__\\n"; base64 /etc/rancher/k3s/k3s.yaml; printf "\\n__CFG_END__\\n"', 30)
        config = base64.b64decode(encoded.split("__CFG_BEGIN__", 1)[1].split("__CFG_END__", 1)[0]).decode()
        PRIVATE.mkdir(parents=True, exist_ok=True)
        for field, filename in (("certificate-authority-data", "ca.crt"), ("client-certificate-data", "admin.crt"), ("client-key-data", "admin.key")):
            match = re.search(r"\b" + field + r":\s*(\S+)", config)
            if not match:
                raise ValueError("missing integration certificate field")
            (PRIVATE / filename).write_bytes(base64.b64decode(match.group(1)))
        api = Api(SERVER, PRIVATE / "ca.crt", PRIVATE / "admin.crt", PRIVATE / "admin.key")
        for attempt in range(120):
            try:
                code, response, _ = api.call("GET", "/api/v1/nodes")
                ready = code == 200 and any(any(c["type"] == "Ready" and c["status"] == "True" for c in n.get("status", {}).get("conditions", [])) for n in response.get("items", []))
                if ready:
                    print("NODE_READY: real kubelet/containerd available at " + SERVER, flush=True)
                    return
            except OSError:
                pass
            if attempt % 6 == 0:
                print("Waiting for schedulable container node...", flush=True)
            time.sleep(3)
        raise RuntimeError("container node not ready; inspect VM diagnostics")
    finally:
        console.socket.close()
        http.shutdown()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("boot", "start", "stop", "status"))
    args = p.parse_args()
    if os.name != "nt":
        p.error("Windows launcher only")
    if args.action == "status":
        print({"running": running(), "server": SERVER})
    else:
        {"boot": boot, "start": start, "stop": stop}[args.action]()


if __name__ == "__main__":
    main()
