# Control mapping and design notes

This set maps to [ITSG-33 Annex 3A](https://www.cyber.gc.ca/en/guidance/annex-3a-security-control-catalogue-itsg-33)
security control identifiers, which track NIST SP 800-53 families. Use these as a
starting point for a traceability matrix, confirmed with your departmental security
authority. A container platform control set can only ever partially satisfy any of
these controls.

## Coverage by control family

### AC — Access Control

| Control | Policies |
|---|---|
| AC-2 Account Management | `pc-elevated-rbac`, `pc-default-service-account`, `pc-account-modification` |
| AC-3 Access Enforcement | `pc-elevated-rbac`, `pc-sensitive-host-mount`, `pc-secret-access` |
| AC-4 Information Flow Enforcement | `pc-missing-network-policy`, `pc-external-exposure`, `pc-unexpected-network-flow`, `pc-network-boundary-modification` |
| AC-6 Least Privilege | `pc-privileged-container`, `pc-dangerous-capabilities`, `pc-capabilities-not-dropped`, `pc-image-runs-as-root`, `pc-host-namespace-sharing`, `pc-container-runtime-socket`, `pc-elevated-rbac` |
| AC-6(9) Auditing Use of Privileged Functions | `pc-pod-exec-attach-portforward`, `pc-root-shell-in-container`, `pc-user-impersonation` |
| AC-16 Security Attributes | `pc-required-classification-metadata` |

### AU — Audit and Accountability

| Control | Policies |
|---|---|
| AU-2 Audit Events | all four policies in `policies/audit/` |
| AU-6 Audit Review, Analysis and Reporting | `pc-secret-access`, `pc-rbac-scc-modification`, `pc-network-boundary-modification` |
| AU-10 Non-repudiation | `pc-user-impersonation` |
| AU-12 Audit Generation | `pc-pod-exec-attach-portforward`, `pc-secret-access` |

### CM — Configuration Management

| Control | Policies |
|---|---|
| CM-2 Baseline Configuration | `pc-mutable-image-tag` |
| CM-3 Configuration Change Control | `pc-mutable-image-tag`, `pc-rbac-scc-modification`, `pc-network-boundary-modification` |
| CM-5 Access Restrictions for Change | `pc-writable-root-filesystem`, `pc-runtime-package-management`, `pc-unsigned-image` |
| CM-7 Least Functionality | `pc-package-manager-in-image`, `pc-dangerous-capabilities`, `pc-unconfined-seccomp-apparmor`, `pc-unapproved-registry` |
| CM-8 Information System Component Inventory | `pc-required-classification-metadata`, `pc-unscanned-or-stale-image`, `pc-mutable-image-tag` |
| CM-11 User-installed Software | `pc-runtime-package-management` |

### IA — Identification and Authentication

| Control | Policies |
|---|---|
| IA-2 Identification and Authentication | `pc-user-impersonation`, `pc-default-service-account` |
| IA-5 Authenticator Management | `pc-secrets-in-environment`, `pc-account-modification`, `pc-secret-access` |
| IA-9 Service Identification and Authentication | `pc-default-service-account` |

### RA / SI — Risk Assessment and System Integrity

| Control | Policies |
|---|---|
| RA-5 Vulnerability Scanning | `pc-fixable-severe-vulnerability`, `pc-known-exploited-vulnerability`, `pc-unscanned-or-stale-image`, `pc-vulnerability-remediation-sla` |
| SI-2 Flaw Remediation | `pc-fixable-severe-vulnerability`, `pc-vulnerability-remediation-sla`, `pc-known-exploited-vulnerability` |
| SI-3 Malicious Code Protection | `pc-offensive-tooling-execution` |
| SI-4 Information System Monitoring | `pc-unexpected-process`, `pc-unexpected-network-flow`, `pc-offensive-tooling-execution`, `pc-account-modification`, `pc-root-shell-in-container` |
| SI-7 Software, Firmware and Information Integrity | `pc-unsigned-image`, `pc-writable-root-filesystem`, `pc-runtime-package-management` |

### SC — System and Communications Protection

| Control | Policies |
|---|---|
| SC-5 / SC-6 Denial of Service Protection, Resource Availability | `pc-missing-resource-limits` |
| SC-7 Boundary Protection | `pc-missing-network-policy`, `pc-external-exposure`, `pc-host-namespace-sharing`, `pc-network-boundary-modification` |
| SC-28 Protection of Information at Rest | `pc-secrets-in-environment` |
| SC-39 Process Isolation | `pc-privileged-container`, `pc-host-namespace-sharing`, `pc-unconfined-seccomp-apparmor`, `pc-container-runtime-socket` |

### SA / PM — Supply Chain and Program Management

| Control | Policies |
|---|---|
| SA-12 Supply Chain Protection | `pc-unapproved-registry`, `pc-unsigned-image` |
| PM-5 Information System Inventory | `pc-required-classification-metadata` |

---

## Why these policies and not the ACS defaults

The ACS default policy set is tuned for a general-purpose cluster. For Protected C
it is both too permissive and mis-prioritised. The differences that matter:

**Severity is re-based on impact to the boundary, not on generic risk.** Anything
that offers a path out of the container or out of the namespace is CRITICAL here,
including policies ACS ships as medium or low. Mounting the CRI-O socket and
holding cluster-wide RBAC are treated as equivalent to a privileged container,
because operationally they are.

**Deny-by-default where ACS alerts-by-default.** `pc-unapproved-registry` negates
an allowlist rather than listing bad registries. `pc-missing-network-policy`
requires both ingress and egress isolation rather than treating segmentation as
optional. `pc-required-classification-metadata` makes the workload inventory a
precondition for admission instead of a reporting exercise.

**Patch windows, not just vulnerability presence.**
`pc-vulnerability-remediation-sla` uses `Days Since CVE Fix Was Available`, which
produces the evidence an accreditation actually asks for — whether the organisation
met its own remediation timeline — rather than a snapshot count of open CVEs.
`pc-known-exploited-vulnerability` short-circuits severity triage entirely for
CVEs with confirmed exploitation.

**Audit-log coverage is treated as mandatory.** Non-repudiation and privileged
function auditing are explicit ITSG-33 requirements. The four audit policies exist
to produce that record for secret access, RBAC and SCC changes, segmentation
changes, and impersonation. These cannot be enforced — they are detection and
evidence controls, and they are the ones most likely to be omitted from a stock
deployment because they require audit log collection to be wired up first.

**Runtime baselining is the core detection control.** At Protected C the
interesting attacks are the ones with no signature. `pc-unexpected-process` and
`pc-unexpected-network-flow` carry the detection weight; the named-tooling policies
(`pc-offensive-tooling-execution`, `pc-runtime-package-management`,
`pc-account-modification`) are high-confidence backstops that work on day one,
before baselines have been locked.

---

## Constraints imposed by the ACS policy engine

These shaped the design and are worth knowing before you edit anything:

- A **BUILD** policy may only use image and vulnerability criteria.
- A **DEPLOY** policy may not contain runtime criteria.
- A **RUNTIME** policy must contain at least one process, network flow, audit log
  or Kubernetes event criterion, and must set `eventSource`.
- Process criteria **cannot coexist** with network flow or Kubernetes event
  criteria in the same policy. This is why pod-exec, unexpected-process and
  unexpected-network-flow are three separate policies rather than one.
- An **audit log** policy may only use audit log criteria, may not have
  enforcement actions, may not have deployment exclusions, and may not use labels
  in its scope.
- `negate` is rejected on boolean and "required"-style criteria — including
  `Drop Capabilities`, `Required Label`, `Required Annotation`,
  `Image Signature Verified By` and `Writable Host Mount`. These alert on absence
  by design: `Drop Capabilities: ALL` fires when the container does *not* drop all.
- `Has Ingress Network Policy` and `Has Egress Network Policy` reject enforcement.
- `Kubernetes User Name` accepts only `[-:a-z0-9]`, so no wildcards.
- `categories` must already exist in Central. The 14 defaults are the safe set;
  anything else must be created first.

`scripts/validate_policies.py` encodes all of the above.
