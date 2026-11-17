#!/bin/sh
# Runs only inside the new disposable VM. No Windows host shares exist.
set -eu
modprobe virtio_blk
modprobe ext4
modprobe br_netfilter
modprobe veth
modprobe nf_tables
modprobe nft_chain_nat
export IPTABLES_MODE=nft
if ! command -v mkfs.ext4 >/dev/null 2>&1; then
    apk add --no-network e2fsprogs
fi
if test -z "$(blkid /dev/vda)"; then
    mkfs.ext4 -q /dev/vda
fi
mkdir -p /var/lib/rancher
if ! mountpoint -q /var/lib/rancher; then
    mount /dev/vda /var/lib/rancher
fi
mkdir -p /sys/fs/cgroup
if ! test -e /sys/fs/cgroup/cgroup.controllers; then
    mount -t cgroup2 none /sys/fs/cgroup
fi
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.bridge.bridge-nf-call-iptables=1
mkdir -p /root/export /var/lib/rancher/k3s/agent/images /var/lib/auditguard-fixtures
printf 'AUDITGUARD_VM_ONLY_FIXTURE\n' >/var/lib/auditguard-fixtures/marker.txt
chmod 644 /var/lib/auditguard-fixtures/marker.txt
test -x /usr/local/bin/k3s || wget -q -O /usr/local/bin/k3s http://10.0.2.2:28080/k3s
chmod +x /usr/local/bin/k3s
wget -q -O /root/audit-policy.yaml http://10.0.2.2:28080/audit-policy.yaml
test -x /usr/local/bin/busybox-extras || wget -q -O /usr/local/bin/busybox-extras http://10.0.2.2:28080/busybox-extras
chmod +x /usr/local/bin/busybox-extras
pidof busybox-extras >/dev/null || /usr/local/bin/busybox-extras httpd -p 8081 -h /root/export
test -s /var/lib/rancher/k3s/agent/images/k3s-airgap-images-amd64.tar.zst || wget -q -O /var/lib/rancher/k3s/agent/images/k3s-airgap-images-amd64.tar.zst http://10.0.2.2:28080/k3s-airgap-images-amd64.tar.zst
test -s /var/lib/rancher/k3s/agent/images/busybox.tar || wget -q -O /var/lib/rancher/k3s/agent/images/busybox.tar http://10.0.2.2:28080/busybox.tar
if pidof k3s >/dev/null; then
    echo BOOTSTRAP_STARTED
    exit 0
fi
# On retries, replace cached legacy symlinks from the previous attempt.
for helper in /var/lib/rancher/k3s/data/*/bin/aux/xtables-set-mode.sh; do
    if test -f "$helper"; then
        PATH="$(dirname "$helper"):$PATH" sh "$helper" -m nft
    fi
done
nohup /usr/local/bin/k3s server --node-name integration-node --prefer-bundled-bin --snapshotter=native --flannel-backend=host-gw --disable-network-policy --disable-helm-controller --disable=traefik,servicelb,local-storage,metrics-server,coredns --tls-san 127.0.0.1 --kubelet-arg=cgroup-driver=cgroupfs --kubelet-arg=max-pods=60 --kube-apiserver-arg=audit-policy-file=/root/audit-policy.yaml --kube-apiserver-arg=audit-log-path=/root/export/audit.log --kube-apiserver-arg=audit-log-mode=blocking >/root/k3s.log 2>&1 &
echo BOOTSTRAP_STARTED
