# Deploying ioc-enricher on k3s

## 1. Install k3s

```bash
curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 600
sudo k3s kubectl get nodes
mkdir -p ~/.kube && sudo cat /etc/rancher/k3s/k3s.yaml > ~/.kube/config && chmod 600 ~/.kube/config
```

k3s ships Traefik (ingress), CoreDNS, local-path storage, metrics-server (needed for HPA)
and an embedded network policy controller, so the chart's `NetworkPolicy` is enforced
out of the box.

Install Helm on the host (or use the `alpine/helm` container).

## 2. GHCR image pull secret

Only needed if the GHCR package is private. Create a fine-grained / classic PAT with
**`read:packages` only**:

```bash
kubectl create namespace ioc-enricher
kubectl -n ioc-enricher create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io \
  --docker-username=<github-user> \
  --docker-password="$GHCR_READ_TOKEN"
```

Better: seal it too (`--dry-run=client -o yaml | kubeseal ...`, see
`k8s/sealed-secrets/README.md`). Then:

```bash
helm upgrade --install ioc-enricher helm/ioc-enricher -n ioc-enricher \
  --set image.repository=ghcr.io/<owner>/ioc-enricher \
  --set image.tag=<sha-or-version> \
  --set 'imagePullSecrets[0].name=ghcr-pull' \
  --set existingSecret=abuseipdb
kubectl -n ioc-enricher rollout status deploy/ioc-enricher
```

Optional ingress via Traefik: `--set ingress.enabled=true --set ingress.hosts[0].host=ioc.example.lan`.

## 3. Self-hosted GitHub Actions runner on the k3s host

Lets a workflow run `helm upgrade` against the cluster without exposing the API server
to the internet.

```bash
sudo useradd -m -s /bin/bash gh-runner
sudo -iu gh-runner
# Download and configure per Settings -> Actions -> Runners -> New self-hosted runner
./config.sh --url https://github.com/<owner>/ioc-enricher --token <REG_TOKEN> \
  --labels k3s,deploy --unattended
exit
cd /home/gh-runner/actions-runner && sudo ./svc.sh install gh-runner && sudo ./svc.sh start
```

Give the runner a **namespace-scoped** kubeconfig, not the k3s admin one:

```bash
kubectl -n ioc-enricher create serviceaccount deployer
kubectl -n ioc-enricher create rolebinding deployer --clusterrole=edit --serviceaccount=ioc-enricher:deployer
kubectl -n ioc-enricher create token deployer --duration=720h   # build a kubeconfig from this
```

Workflow jobs target it with `runs-on: [self-hosted, k3s, deploy]`.

### Security caveats

- **Never use a self-hosted runner on a public repo for untrusted code.** Anyone opening a
  fork PR could execute arbitrary code on your host. Restrict deploy jobs to `push` on
  `main` / tags, require approval for fork PR workflows, and use a protected
  `environment` with required reviewers.
- The runner is persistent: workspace files, caches and credentials leak between jobs.
  Prefer ephemeral runners (`--ephemeral`) or actions-runner-controller for isolation.
- Do not add `gh-runner` to the `docker` group or sudoers; both are equivalent to root.
- Least privilege: namespace-scoped RBAC (above), short-lived tokens, never
  `/etc/rancher/k3s/k3s.yaml` (cluster-admin).
- Keep the runner updated (it self-updates by default; do not disable it) and the host
  patched; monitor `_diag` logs.
- Pin third-party actions to commit SHAs and set minimal `permissions:` in workflows
  (`contents: read`, `packages: read`).
- Network: the runner only needs outbound HTTPS to GitHub; no inbound ports required.
- A home-lab single node mixes CI and production. Acceptable for a portfolio; in real
  environments separate them.
