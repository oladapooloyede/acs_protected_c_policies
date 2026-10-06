# Deployment guide

A phased rollout. Skipping to enforcement will break workloads; the deploy-time
policies in this set are strict on purpose.

## Phase 0 — Prerequisites

1. **Confirm the policy-as-code controller is running** in the Central namespace:

   ```sh
   oc get deployment config-controller -n stackrox
   ```

   If it is absent and you installed with `roxctl` rather than the operator, the
   CRs in this repository will not reconcile. Install via the operator, or import
   the policies as JSON with `roxctl` instead.

2. **Enable OpenShift audit log collection** on the secured cluster
   (ACS → Clusters → *cluster* → Dynamic configuration → Enable audit log
   collection). The four policies under `policies/audit/` are inert without it.

3. **Enable the admission controller** with enforcement on object create and
   update, if you intend to block at deploy time rather than scale to zero after
   the fact.

4. **Record a baseline of current violations** so you can measure progress:

   ```sh
   roxctl central whoami    # confirm connectivity
   # then export the current violation counts from Central before applying
   ```

## Phase 1 — Apply detect-only

```sh
oc apply -k policies/
```

Confirm Central accepted all 35:

```sh
oc get securitypolicies.config.stackrox.io -n stackrox \
  -o custom-columns=NAME:.metadata.name,ACCEPTED:.status.conditions[0].status,MSG:.status.conditions[0].message
```

Anything with `ACCEPTED` not `True` will carry the reason in the message column.
A rejected policy is almost always a criteria validation error — run
`make validate` locally to reproduce it offline.

## Phase 2 — Tune the placeholders

Six policies ship with environment-specific placeholders. Until these are
replaced, they are producing wrong answers, not useful signal:

```sh
grep -rl 'tuning-required: "true"' policies/
```

- `pc-unapproved-registry` — set the real registry allowlist.
- `pc-unsigned-image` — substitute the real signature integration ID and remove
  `disabled: true`. The shipped UUID is all zeroes and matches nothing.
- `pc-vulnerability-remediation-sla` — adjust the 14-day window to your SLA.
- `pc-external-exposure` — exclude your accredited ingress namespace.
- `pc-required-classification-metadata` — use your department's metadata keys.
- `pc-secret-access` — set the namespace scope and the full list of expected
  principals. Do not run this one unscoped on a busy cluster.

## Phase 3 — Triage and exclude

Work through violations by severity. For each finding, either fix the workload or
record a justified exclusion with an expiry date:

```yaml
  exclusions:
    - name: "RHACS-1234 - legacy ingest requires NET_RAW until Q3 rebuild"
      expiration: "2027-03-31T00:00:00Z"
      deployment:
        name: "legacy-ingest"
        scope:
          namespace: "protected-c-ingest"
```

Keep exclusions in Git in this repository, never added through the ACS portal —
portal edits cause drift and are not reviewable. Always set `expiration`; an
exclusion without one becomes permanent by neglect, which is the single most
common way a hardened policy set degrades.

Note that audit log policies do not support deployment exclusions. Reduce their
noise with `scope` (namespace or cluster) and with negated
`Kubernetes User Name` criteria listing expected service accounts in full.

## Phase 4 — Lock the baselines

`pc-unexpected-process` and `pc-unexpected-network-flow` do nothing until the
relevant deployments have observed and locked baselines. Observe through at least
one full business cycle — including month-end and batch jobs — before locking,
otherwise the first scheduled job of the quarter is an incident.

## Phase 5 — Enforce

Only after the detect-only set has run clean for a full cycle:

```sh
oc apply -k overlays/enforce/
```

This adds enforcement to 29 policies. If you want to stage it, copy
`overlays/enforce/kustomization.yaml` into a new overlay and remove the patches
you are not ready for. A reasonable order:

1. Build-stage first (`FAIL_BUILD_ENFORCEMENT`) — it only breaks pipelines, and
   pipeline failures are cheap and visible.
2. Then deploy-stage on the container-escape policies: `pc-privileged-container`,
   `pc-host-namespace-sharing`, `pc-container-runtime-socket`,
   `pc-dangerous-capabilities`, `pc-sensitive-host-mount`.
3. Then the remaining deploy-stage hygiene policies.
4. Runtime `KILL_POD_ENFORCEMENT` last, and only on policies whose false-positive
   rate you have actually measured.

### Rolling back enforcement

```sh
oc apply -k policies/
```

Re-applying the base does **not** remove `enforcementActions` already reconciled
into Central, because the base simply omits the field. To clear enforcement,
patch it explicitly:

```sh
oc patch securitypolicy.config.stackrox.io pc-privileged-container -n stackrox \
  --type merge -p '{"spec":{"enforcementActions":[]}}'
```

Keep this in mind during an incident: the fast path back is an explicit patch, not
a re-apply.

## Operating notes

- **Drift.** Policies remain editable in the ACS portal. With Argo CD, run with
  `selfHeal: true` and `prune: true` so Git stays authoritative. Without GitOps,
  reconcile manually on a schedule.
- **Upgrades.** ACS occasionally adds or renames policy criteria. Re-run
  `make validate` after a Central upgrade; the validator's field table is
  transcribed from `pkg/booleanpolicy` and may need refreshing against the new
  release.
- **Evidence.** The per-policy `protected-c.policy.local/itsg33-controls`
  annotations are machine-readable. To produce a control coverage extract:

  ```sh
  oc get securitypolicies.config.stackrox.io -n stackrox -o json | \
    jq -r '.items[] | [.metadata.name,
      (.metadata.annotations["protected-c.policy.local/itsg33-controls"] // "-")] | @tsv'
  ```
