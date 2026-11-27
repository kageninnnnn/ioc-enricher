# Kyverno admission policies

Two `ClusterPolicy` objects close the loop between CI and the cluster:

| Policy | What it enforces |
|---|---|
| `verify-ioc-enricher-image` (`verify-image.yaml`) | `ghcr.io/kageninnnnn/ioc-enricher*` must carry a **keyless cosign signature** issued to `ci.yml@refs/heads/main` (GitHub OIDC), plus a signed **SPDX SBOM attestation**. Tags are rewritten to the verified digest. |
| `ioc-enricher-pod-security` (`pod-security.yaml`) | In namespace `ioc-enricher`: no privileged containers, no privilege escalation, `runAsNonRoot`, `readOnlyRootFilesystem`. |

CD (`cd.yml`) already runs `cosign verify` before `helm upgrade`; Kyverno enforces the same
rule **at admission time**, so a `kubectl run` / manual `helm install` of an unsigned image is
blocked too.

## Install Kyverno (k3s)

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm install kyverno kyverno/kyverno -n kyverno --create-namespace
kubectl -n kyverno rollout status deploy/kyverno-admission-controller
kubectl apply -f k8s/policies/
kubectl get clusterpolicy
```

The admission controller needs outbound HTTPS to `ghcr.io`, `rekor.sigstore.dev` and
`fulcio.sigstore.dev` / TUF mirrors to verify signatures.

## Test

Signed image built by CI on `main` is admitted:

```bash
kubectl -n ioc-enricher run signed --image=ghcr.io/kageninnnnn/ioc-enricher:<sha> \
  --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":10001},
  "containers":[{"name":"signed","image":"ghcr.io/kageninnnnn/ioc-enricher:<sha>",
  "securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true}}]}}'
kubectl -n ioc-enricher get pod signed -o jsonpath='{.spec.containers[0].image}'   # now @sha256:...
```

Unsigned image (e.g. built locally and pushed to a branch tag) is rejected:

```bash
docker build -t ghcr.io/kageninnnnn/ioc-enricher:unsigned . && docker push ghcr.io/kageninnnnn/ioc-enricher:unsigned
kubectl -n ioc-enricher run unsigned --image=ghcr.io/kageninnnnn/ioc-enricher:unsigned
# Error from server: admission webhook "mutate.kyverno.svc-fail" denied the request:
#   policy Pod/ioc-enricher/unsigned for resource violation:
#   verify-ioc-enricher-image: ... no matching signatures
```

Pod-security rule:

```bash
kubectl -n ioc-enricher run root --image=busybox -- sleep 3600
# denied: require-run-as-non-root / require-readonly-rootfs
```

Use `validationFailureAction: Audit` first if you are rolling this out on a live cluster,
then check `kubectl get policyreport -A` before switching to `Enforce`.

> Note: the pod-security policy applies to **every** Pod in `ioc-enricher`. If you run Redis
> in the same namespace, give it `runAsNonRoot: true`, `allowPrivilegeEscalation: false` and a
> read-only root filesystem (with an `emptyDir` for `/data`), or deploy it in its own namespace.
