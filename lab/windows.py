"""Portable Windows lab. No Windows feature, service or global install changes.

python -m lab.windows prepare   # Download pinned runtime files into tmp/runtime
python -m lab.windows start     # Boot an isolated, agentless K3s API server
python -m lab.windows stop      # Stop only the QEMU process this project owns
"""

import argparse
import base64
import ctypes
from functools import partial
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import threading
import tarfile
import time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "tmp/runtime"
PRIVATE = ROOT / "lab/private"
STATE = RUNTIME / "vm-state.json"


def prepare():
    if os.name != "nt":
        raise ValueError("this optional launcher is for Windows; use the Linux lab instructions otherwise")
    RUNTIME.mkdir(parents=True, exist_ok=True)
    assets = json.loads((ROOT / "lab/runtime-assets.json").read_text(encoding="utf-8"))
    for asset in assets:
        target = RUNTIME / asset["name"]
        if not target.exists():
            print("Downloading " + asset["name"], flush=True)
            part = target.with_suffix(target.suffix + ".part")
            with urlopen(asset["url"], timeout=90) as response, part.open("wb") as output:
                shutil.copyfileobj(response, output, 1024 * 1024)
            if hashlib.sha256(part.read_bytes()).hexdigest() != asset["sha256"]:
                raise ValueError("download checksum mismatch: " + asset["name"])
            part.replace(target)
        if hashlib.sha256(target.read_bytes()).hexdigest() != asset["sha256"]:
            raise ValueError("runtime checksum mismatch: " + asset["name"])
    extract = RUNTIME / "7zip"
    extract.mkdir(exist_ok=True)
    for asset in assets:
        if asset["name"].endswith(".tar.zst"):
            subprocess.run(["tar", "-xf", str(RUNTIME / asset["name"]), "-C", str(extract)], check=True)
        if asset["name"].endswith(".apk"):
            with tarfile.open(RUNTIME / asset["name"], "r:gz", ignore_zeros=True) as archive:
                member = next(m for m in archive.getmembers() if m.name == "bin/busybox-extras")
                (RUNTIME / "busybox-extras").write_bytes(archive.extractfile(member).read())
    seven = str(extract / "mingw64/bin/7z.exe")
    subprocess.run([seven, "x", str(RUNTIME / "qemu.exe"), "-o" + str(RUNTIME / "qemu"), "-y", "-bso0"], check=True)
    subprocess.run([seven, "x", str(RUNTIME / "alpine.iso"), "-o" + str(RUNTIME / "alpine"), "boot/vmlinuz-virt", "boot/initramfs-virt", "-y", "-bso0"], check=True)
    print("Runtime verified and extracted.", flush=True)


def process_path(pid):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    try:
        code = ctypes.c_uint32()
        if kernel.GetExitCodeProcess(handle, ctypes.byref(code)) and code.value != 259:
            return None
        buffer = ctypes.create_unicode_buffer(32768)
        size = ctypes.c_uint32(len(buffer))
        if not kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise OSError("could not verify process image")
        return Path(buffer.value).resolve()
    finally:
        kernel.CloseHandle(handle)


def stop():
    if not STATE.exists():
        print("No VM state found.")
        return
    state = json.loads(STATE.read_text(encoding="utf-8"))
    actual = process_path(state["pid"])
    expected = (RUNTIME / "qemu/qemu-system-x86_64.exe").resolve()
    if actual is None:
        print("VM is already stopped.")
        return
    if actual != expected:
        raise ValueError("saved PID no longer belongs to this project's QEMU")
    import signal
    os.kill(state["pid"], signal.SIGTERM)
    for _ in range(50):
        if process_path(state["pid"]) is None:
            break
        time.sleep(.05)
    print("Project VM stopped. Measured logs and source files are preserved.")


class Console:
    def __init__(self):
        self.socket = socket.create_connection(("127.0.0.1", 43220), timeout=3)
        self.socket.settimeout(1)
        self.buffer = b""

    def send(self, text):
        self.socket.sendall(text.encode())

    def until(self, marker, timeout=180):
        marker = marker.encode()
        deadline = time.monotonic() + timeout
        while marker not in self.buffer:
            if time.monotonic() > deadline:
                raise TimeoutError("VM console timed out")
            try:
                part = self.socket.recv(65536)
                if not part:
                    raise RuntimeError("VM console disconnected")
                self.buffer += part
            except socket.timeout:
                continue
        before, self.buffer = self.buffer.split(marker, 1)
        return before.decode(errors="replace")

    def command(self, text, timeout=180):
        self.send(text + "\nprintf '\\n__PBL_COMMAND_DONE__\\n'\n")
        return self.until("__PBL_COMMAND_DONE__", timeout)


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_):
        pass


def start(audit_policy=None, anonymous_auth=False):
    executable = RUNTIME / "qemu/qemu-system-x86_64.exe"
    if not executable.exists():
        raise ValueError("run python -m lab.windows prepare first")
    if STATE.exists():
        state = json.loads(STATE.read_text(encoding="utf-8"))
        if process_path(state["pid"]) == executable.resolve():
            raise ValueError("this project's VM is already running; stop it before a fresh boot")
    for port in (16443, 18080, 18081, 43220):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
    PRIVATE.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(audit_policy or ROOT / "lab/audit-policy.yaml", RUNTIME / "audit-policy.yaml")
    http = ThreadingHTTPServer(("127.0.0.1", 18080), partial(QuietHandler, directory=str(RUNTIME)))
    threading.Thread(target=http.serve_forever, daemon=True).start()
    args = [str(executable), "-accel", "tcg,thread=multi", "-cpu", "max", "-smp", "2", "-m", "3072", "-display", "none", "-monitor", "none", "-serial", "tcp:127.0.0.1:43220,server=on,wait=off", "-kernel", str(RUNTIME / "alpine/boot/vmlinuz-virt"), "-initrd", str(RUNTIME / "alpine/boot/initramfs-virt"), "-append", "console=ttyS0 modules=loop,squashfs,sd-mod,usb-storage alpine_dev=cdrom:iso9660", "-cdrom", str(RUNTIME / "alpine.iso"), "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:16443-:6443,hostfwd=tcp:127.0.0.1:18081-:8081", "-device", "virtio-net-pci,netdev=net0"]
    console = None
    try:
        with (RUNTIME / "qemu-stderr.log").open("w") as log:
            proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        STATE.write_text(json.dumps({"pid": proc.pid, "exe": str(executable)}), encoding="utf-8")
        print("Booting isolated Linux VM...", flush=True)
        for _ in range(40):
            try:
                console = Console()
                break
            except OSError:
                if proc.poll() is not None:
                    raise RuntimeError("QEMU exited; see tmp/runtime/qemu-stderr.log")
                time.sleep(.5)
        if console is None:
            raise RuntimeError("VM serial endpoint did not start")
        console.until("login:", 240)
        console.send("root\n")
        console.until("~#", 30)
        console.send("stty -echo\n")
        console.until("~#", 30)
        console.command("ip link set lo up; ip link set eth0 up; udhcpc -i eth0 -q", 60)
        console.command("wget -q -O /usr/local/bin/k3s http://10.0.2.2:18080/k3s && chmod +x /usr/local/bin/k3s && mkdir -p /root/export && wget -q -O /root/audit-policy.yaml http://10.0.2.2:18080/audit-policy.yaml", 240)
        console.command("wget -q -O /usr/local/bin/busybox-extras http://10.0.2.2:18080/busybox-extras && chmod +x /usr/local/bin/busybox-extras && /usr/local/bin/busybox-extras httpd -p 8081 -h /root/export", 60)
        anonymous_arg = " --kube-apiserver-arg=anonymous-auth=true" if anonymous_auth else ""
        console.command("nohup /usr/local/bin/k3s server --disable-agent --disable-scheduler --disable-cloud-controller --disable-helm-controller --disable=traefik,servicelb,local-storage,metrics-server,coredns --flannel-backend=none --disable-network-policy --tls-san 127.0.0.1 --kube-apiserver-arg=audit-policy-file=/root/audit-policy.yaml --kube-apiserver-arg=audit-log-path=/root/export/audit.log --kube-apiserver-arg=audit-log-mode=blocking" + anonymous_arg + " >/root/k3s.log 2>&1 &")
        for attempt in range(60):
            if "CONFIG_READY" in console.command("test -s /etc/rancher/k3s/k3s.yaml && echo CONFIG_READY", 30):
                break
            if attempt % 6 == 0:
                print("Waiting for API certificates...", flush=True)
            time.sleep(5)
        else:
            raise RuntimeError("API certificates did not become ready")
        encoded = console.command('printf "\\n__CFG_BEGIN__\\n"; base64 /etc/rancher/k3s/k3s.yaml; printf "\\n__CFG_END__\\n"', 30)
        config = base64.b64decode(encoded.split("__CFG_BEGIN__", 1)[1].split("__CFG_END__", 1)[0]).decode()
        for field, filename in (("certificate-authority-data", "ca.crt"), ("client-certificate-data", "admin.crt"), ("client-key-data", "admin.key")):
            match = re.search(r"\b" + field + r":\s*(\S+)", config)
            if not match:
                raise ValueError("missing client certificate field")
            (PRIVATE / filename).write_bytes(base64.b64decode(match.group(1)))
        from .live import Api
        api = Api("https://127.0.0.1:16443", PRIVATE / "ca.crt", PRIVATE / "admin.crt", PRIVATE / "admin.key")
        for attempt in range(60):
            try:
                if api.call("GET", "/readyz")[0] == 200:
                    print("API_READY: https://127.0.0.1:16443", flush=True)
                    return
            except OSError:
                pass
            if attempt % 6 == 0:
                print("Waiting for API readiness...", flush=True)
            time.sleep(5)
        raise RuntimeError("API readiness timed out")
    finally:
        if console:
            console.socket.close()
        http.shutdown()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("prepare", "start", "stop"))
    p.add_argument("--audit-policy", type=Path)
    p.add_argument("--anonymous-auth", action="store_true", help="isolated lab only: allow anonymous authentication, still subject to RBAC")
    args = p.parse_args()
    if os.name != "nt":
        p.error("this launcher is Windows-only")
    try:
        if args.action == "start":
            start(args.audit_policy, args.anonymous_auth)
        else:
            {"prepare": prepare, "stop": stop}[args.action]()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print("Lab error: " + str(error), flush=True)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
