# Sealed Secrets for ioc-enricher

[Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) lets you commit an
*encrypted* Secret to git. Only the controller in the cluster (holding the private key)
can decrypt it into a normal `Secret`.

## 1. Install the controller on k3s

```bash
helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets
helm repo update
helm install sealed-secrets sealed-secrets/sealed-secrets \
  -n kube-system --set fullnameOverride=sealed-secrets-controller
kubectl -n kube-system rollout status deploy/sealed-secrets-controller
```

Alternatively, k3s auto-applies manifests placed in `/var/lib/rancher/k3s/server/manifests/`
(e.g. a `HelmChart` CR for the same chart).

## 2. Install kubeseal (workstation)

Download the `kubeseal` release matching the controller version from the project's GitHub
releases page, then optionally fetch the public cert for offline sealing:

```bash
kubeseal --controller-namespace kube-system --fetch-cert > pub-cert.pem
```

`pub-cert.pem` is public and safe to keep, but there is no need to commit it.

## 3. Create the SealedSecret

```bash
kubectl create namespace ioc-enricher --dry-run=client -o yaml | kubectl apply -f -

# `read -rs` keeps the keys out of shell history; skip any provider you don't use
read -rs ABUSEIPDB_API_KEY; read -rs VIRUSTOTAL_API_KEY; read -rs OTX_API_KEY
read -rs ABUSECH_AUTH_KEY;  read -rs API_KEYS   # API_KEYS: comma-separated client keys
kubectl -n ioc-enricher create secret generic ioc-enricher-keys \
  --from-literal=ABUSEIPDB_API_KEY="$ABUSEIPDB_API_KEY" \
  --from-literal=VIRUSTOTAL_API_KEY="$VIRUSTOTAL_API_KEY" \
  --from-literal=OTX_API_KEY="$OTX_API_KEY" \
  --from-literal=ABUSECH_AUTH_KEY="$ABUSECH_AUTH_KEY" \
  --from-literal=API_KEYS="$API_KEYS" \
  --dry-run=client -o yaml \
| kubeseal --controller-namespace kube-system --format yaml \
  > k8s/sealed-secrets/sealedsecret-ioc-enricher.yaml
unset ABUSEIPDB_API_KEY VIRUSTOTAL_API_KEY OTX_API_KEY ABUSECH_AUTH_KEY API_KEYS

kubectl apply -f k8s/sealed-secrets/sealedsecret-ioc-enricher.yaml
kubectl -n ioc-enricher get secret ioc-enricher-keys
```

The result is bound to the namespace and name (default `strict` scope); renaming either
requires re-sealing.

## 4. Point the chart at it

```bash
helm upgrade --install ioc-enricher helm/ioc-enricher -n ioc-enricher \
  --set existingSecret=ioc-enricher-keys
```

All keys are injected via `envFrom.secretRef` with `optional: true`, so the app still
starts if the secret (or any single key) is missing; providers without a key are skipped.
A v0.1 secret named `abuseipdb` holding only `ABUSEIPDB_API_KEY` keeps working:
`--set existingSecret=abuseipdb`.

## Notes

- `sealedsecret-ioc-enricher.example.yaml` is a **placeholder** showing the shape only.
- Never commit the plain `Secret` produced by `kubectl create secret --dry-run`.
- Back up the controller key (`kubectl -n kube-system get secret -l sealedsecrets.bitnami.com/sealed-secrets-key -o yaml`)
  somewhere safe and offline; without it, sealed secrets cannot be decrypted after a cluster rebuild.
