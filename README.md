# ACS Protected C Policies

A hardened [Red Hat Advanced Cluster Security](https://www.redhat.com/en/technologies/cloud-computing/openshift/advanced-cluster-security-kubernetes)
(RHACS / StackRox) `SecurityPolicy` set for OpenShift clusters that handle
**Protected C** information, managed as code.

35 policies covering build, deploy, runtime and Kubernetes audit log events,
shipped detect-only with an opt-in enforcing overlay, every criterion validated
offline against the ACS policy engine's own field and value rules.

---

## Read this first

**Protected C** is the Government of Canada classification for information whose
compromise could reasonably be expected to cause *extremely grave injury* outside
the national interest. Under current GC and CCCS cloud guidance, Protected C
workloads are **not** approved for public cloud; the
[CCCS Medium cloud profile](https://www.cyber.gc.ca/en/guidance/guidance-cloud-service-cryptographic-services-itsp50106)
tops out at Protected B / Medium Integrity / Medium Availability. A Protected C
OpenShift cluster is expected to be dedicated, on-premises or in an accredited
sovereign enclave, and usually network-isolated.

This repository is a **technical control set**, not an accreditation. It
implements container-platform controls that support an ITSG-33 security control
profile. It does not address personnel screening, physical security, cryptographic
key management, or the dozens of other controls a Protected C authority to operate
requires. Treat the ITSG-33 references here as a starting point for your control
traceability matrix, confirmed with your departmental security authority — not as
evidence of compliance.

---

## What is in here

| Stage | Count | What it does |
|---|---|---|
| `policies/build/` | 9 | Supply chain and vulnerability gates on images |
| `policies/deploy/` | 15 | Workload hardening at admission |
| `policies/runtime/` | 7 | Process, network-baseline and pod-access detection |
| `policies/audit/` | 4 | Kubernetes API audit log detection |

Full list with severities and control mappings: **[docs/policy-catalogue.md](docs/policy-catalogue.md)**.

Design decisions behind the set: **[docs/control-mapping.md](docs/control-mapping.md)**.
Rollout procedure: **[docs/deployment-guide.md](docs/deployment-guide.md)**.

### Layout

```
policies/            detect-only base, one SecurityPolicy per file
  build/             BUILD + DEPLOY image policies
  deploy/            DEPLOY workload hardening policies
  runtime/           RUNTIME policies, eventSource DEPLOYMENT_EVENT
  audit/             RUNTIME policies, eventSource AUDIT_LOG_EVENT
overlays/enforce/    adds enforcementActions to the 29 policies that support it
scripts/             offline validator
docs/                catalogue, control mapping, rollout guide
```

---

## Prerequisites

- **RHACS 4.5 or later** with the policy-as-code controller. The operator installs
  it with Central; if you installed via `roxctl`, confirm the `config-controller`
  deployment exists in the Central namespace.
- Policies are applied to the **namespace where Central runs** (`stackrox` by
  default). The controller reconciles each CR into Central's database.
- **OpenShift audit log collection enabled** on the secured cluster. Without it the
  four policies in `policies/audit/` never fire.
- **Process and network baselines** observed and locked for the workloads you care
  about, before `pc-unexpected-process` and `pc-unexpected-network-flow` are useful.
- A **signature integration** configured in Central if you intend to enable
  `pc-unsigned-image` (see below).

---

## Install

Detect-only — start here, always:

```sh
oc apply -k policies/
```

Enforcing — only after the detect-only baseline runs clean:

```sh
oc apply -k overlays/enforce/
```

Check that Central accepted every policy:

```sh
oc get securitypolicies.config.stackrox.io -n stackrox \
  -o custom-columns=NAME:.metadata.name,ACCEPTED:.status.conditions[0].status,MSG:.status.conditions[0].message
```

With Argo CD, point an Application at `policies/` or `overlays/enforce/` with the
destination namespace set to the Central namespace. Note that policies can also be
edited in the ACS portal, which causes drift against Git; keep Argo CD in
self-heal mode so this repository stays authoritative.

---

## Before you enable anything: required tuning

Six policies contain deliberate placeholders. They will produce wrong results
until you replace them. Find them with:

```sh
grep -rl 'tuning-required: "true"' policies/
```

| Policy | What you must replace |
|---|---|
| `pc-unapproved-registry` | The registry allowlist — set it to the registries accredited for your boundary |
| `pc-unsigned-image` | The signature integration ID. **Ships `disabled: true`** with a placeholder UUID; get the real `io.stackrox.signatureintegration.<uuid>` from Central and remove `disabled` |
| `pc-vulnerability-remediation-sla` | The 14-day patch window, if your SLA differs |
| `pc-external-exposure` | The excluded namespace for your accredited ingress gateway |
| `pc-required-classification-metadata` | The label and annotation keys from your departmental metadata standard |
| `pc-secret-access` | The namespace scope and the allowlist of expected principals |

> `pc-secret-access` is scoped to namespaces matching `protected-c-.*`. Unscoped,
> it fires on routine platform traffic and will bury you. Also note that ACS's
> `Kubernetes User Name` criterion does **not** accept wildcards, so each expected
> service account must be listed in full.

---

## Enforcement model

The base is detect-only by design. `overlays/enforce/` adds enforcement to 29
policies: `FAIL_BUILD_ENFORCEMENT` and `SCALE_TO_ZERO_ENFORCEMENT` at build and
deploy, `KILL_POD_ENFORCEMENT` and `FAIL_KUBE_REQUEST_ENFORCEMENT` at runtime.

Six policies are deliberately never enforced:

| Policy | Why not |
|---|---|
| `pc-missing-network-policy` | ACS rejects enforcement on the network policy criteria outright |
| `pc-unexpected-network-flow` | Baseline-driven; enforcement here causes outages from benign drift |
| All four in `policies/audit/` | ACS forbids enforcement on audit log event policies |

Enforcement only works at deploy time if the ACS **admission controller** is
enabled on the secured cluster, with "enforce on object creates/updates" turned on.
Without it, `SCALE_TO_ZERO_ENFORCEMENT` scales the workload down *after* it is
admitted rather than blocking it.

---

## Validating changes

`scripts/validate_policies.py` checks every manifest offline against the
`config.stackrox.io/v1alpha1` CRD schema, the canonical ACS policy criteria field
list, the per-field value regexes, and the policy validator's lifecycle /
eventSource / enforcement / runtime-criteria-mixing rules. Field names and value
regexes are transcribed from `pkg/booleanpolicy` in
[stackrox/stackrox](https://github.com/stackrox/stackrox), not from prose docs.

```sh
make validate            # validate the manifests
make build               # render both kustomize targets
make validate-overlay    # render the enforce overlay and validate the result
make catalogue           # regenerate docs/policy-catalogue.md
```

CI runs the same checks on every push and pull request.

---

## Known limitations

- Policies are only as good as the baselines behind them. `pc-unexpected-process`
  and `pc-unexpected-network-flow` are no-ops until baselines are locked.
- The ITSG-33 control references are a mapping aid produced from the intent of
  each policy. They have not been reviewed by a departmental security authority.
- `Kubernetes Resource` for audit log policies is limited by ACS to secrets,
  configmaps, cluster roles, cluster role bindings, network policies, SCCs and
  egress firewalls. Other resource types cannot be targeted on current releases.
- Node-event / file-integrity criteria (`File Path`, `File Operation`) are not used
  here; they sit behind a feature flag on current releases.
- Severity levels follow the risk to a Protected C boundary, which is stricter than
  the ACS defaults. Expect more CRITICAL findings than on a stock install.

---

## Licence

Apache-2.0. See [LICENSE](LICENSE).
