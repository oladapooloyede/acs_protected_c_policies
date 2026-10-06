# Policy catalogue

Generated from the manifests under `policies/`. Regenerate with `make catalogue`
after adding or changing a policy.

**Tune** marks policies that contain environment-specific placeholders you must
replace before they are meaningful. Find them all with:

```sh
grep -rl 'tuning-required: "true"' policies/
```

| Stage | Policy | Severity | Lifecycle | ITSG-33 controls | Tune | Note |
|---|---|---|---|---|---|---|
| build | `pc-fixable-severe-vulnerability`<br>Protected C - Fixable Important Or Critical Vulnerability | CRITICAL | BUILD/DEPLOY | RA-5, SI-2, SI-2(3) |  |  |
| build | `pc-image-runs-as-root`<br>Protected C - Image Configured To Run As Root | HIGH | BUILD/DEPLOY | AC-6, AC-6(10), CM-7 |  |  |
| build | `pc-known-exploited-vulnerability`<br>Protected C - Known Exploited Vulnerability Present | CRITICAL | BUILD/DEPLOY | RA-5, SI-2, SI-5 |  |  |
| build | `pc-mutable-image-tag`<br>Protected C - Mutable Or Floating Image Tag | HIGH | BUILD/DEPLOY | CM-2, CM-3, CM-8 |  |  |
| build | `pc-package-manager-in-image`<br>Protected C - Package Manager Or Network Tooling In Image | MEDIUM | BUILD/DEPLOY | CM-7, CM-7(5), SI-7 |  |  |
| build | `pc-unapproved-registry`<br>Protected C - Image From Unapproved Registry | CRITICAL | BUILD/DEPLOY | CM-7, SA-12, SI-7 | yes |  |
| build | `pc-unscanned-or-stale-image`<br>Protected C - Unscanned Or Stale Image Scan Data | HIGH | BUILD/DEPLOY | RA-5, SI-2, CM-8 |  |  |
| build | `pc-unsigned-image`<br>Protected C - Unsigned Or Untrusted Container Image | CRITICAL | BUILD/DEPLOY | CM-5, SA-12, SI-7, SI-7(1) | yes | disabled |
| build | `pc-vulnerability-remediation-sla`<br>Protected C - Vulnerability Past Remediation SLA | HIGH | BUILD/DEPLOY | RA-5(1), SI-2, SI-2(3) | yes |  |
| deploy | `pc-capabilities-not-dropped`<br>Protected C - Container Does Not Drop All Capabilities | HIGH | DEPLOY | AC-6, CM-7 |  |  |
| deploy | `pc-container-runtime-socket`<br>Protected C - Container Runtime Socket Mounted | CRITICAL | DEPLOY | AC-6, AC-6(10), SC-39 |  |  |
| deploy | `pc-dangerous-capabilities`<br>Protected C - Dangerous Linux Capability Added | CRITICAL | DEPLOY | AC-6, AC-6(10), CM-7 |  |  |
| deploy | `pc-default-service-account`<br>Protected C - Default Service Account Or Automounted Token | HIGH | DEPLOY | AC-2, AC-6, IA-2, IA-9 |  |  |
| deploy | `pc-elevated-rbac`<br>Protected C - Workload With Cluster Wide RBAC Permissions | CRITICAL | DEPLOY | AC-2, AC-3, AC-6, AC-6(5) |  |  |
| deploy | `pc-external-exposure`<br>Protected C - Workload Exposed Outside The Cluster | HIGH | DEPLOY | AC-4, SC-7, SC-7(3) | yes |  |
| deploy | `pc-host-namespace-sharing`<br>Protected C - Host Namespace Sharing | CRITICAL | DEPLOY | AC-6, SC-7, SC-39 |  |  |
| deploy | `pc-missing-network-policy`<br>Protected C - Workload Without Network Policy Isolation | HIGH | DEPLOY | AC-4, SC-7, SC-7(5) |  |  |
| deploy | `pc-missing-resource-limits`<br>Protected C - Missing CPU Or Memory Limits | MEDIUM | DEPLOY | SC-5, SC-6, CP-2 |  |  |
| deploy | `pc-privileged-container`<br>Protected C - Privileged Container Or Privilege Escalation Allowed | CRITICAL | DEPLOY | AC-6, AC-6(10), CM-7, SC-39 |  |  |
| deploy | `pc-required-classification-metadata`<br>Protected C - Missing Classification Or Ownership Metadata | MEDIUM | DEPLOY | CM-8, PM-5, RA-2, AC-16 | yes |  |
| deploy | `pc-secrets-in-environment`<br>Protected C - Credential In Plaintext Environment Variable | CRITICAL | DEPLOY | IA-5, IA-5(7), SC-28 |  |  |
| deploy | `pc-sensitive-host-mount`<br>Protected C - Sensitive Host Path Mounted | CRITICAL | DEPLOY | AC-6, AC-3, SC-39 |  |  |
| deploy | `pc-unconfined-seccomp-apparmor`<br>Protected C - Unconfined Seccomp Or AppArmor Profile | HIGH | DEPLOY | CM-7, SC-39, SI-16 |  |  |
| deploy | `pc-writable-root-filesystem`<br>Protected C - Writable Container Root Filesystem | MEDIUM | DEPLOY | CM-5, SI-7, SI-7(1) |  |  |
| runtime | `pc-account-modification`<br>Protected C - Account Or Credential Modification In Container | CRITICAL | RUNTIME | AC-2, AC-2(4), IA-5, SI-4 |  |  |
| runtime | `pc-offensive-tooling-execution`<br>Protected C - Reconnaissance Or Mining Tool Executed | CRITICAL | RUNTIME | SI-3, SI-4, SI-4(2) |  |  |
| runtime | `pc-pod-exec-attach-portforward`<br>Protected C - Interactive Access To A Running Pod | HIGH | RUNTIME | AC-6(9), AU-2, AU-6, AU-12 |  |  |
| runtime | `pc-root-shell-in-container`<br>Protected C - Interactive Shell Executed As Root | CRITICAL | RUNTIME | AC-6, AC-6(9), SI-4 |  |  |
| runtime | `pc-runtime-package-management`<br>Protected C - Package Management Executed At Runtime | HIGH | RUNTIME | CM-5, CM-7(5), CM-11, SI-7 |  |  |
| runtime | `pc-unexpected-network-flow`<br>Protected C - Network Flow Outside The Locked Baseline | HIGH | RUNTIME | AC-4, SC-7, SI-4, SI-4(4) |  |  |
| runtime | `pc-unexpected-process`<br>Protected C - Process Outside The Locked Baseline | HIGH | RUNTIME | SI-4, SI-4(2), CM-7(5), AU-6 |  |  |
| audit | `pc-network-boundary-modification`<br>Protected C - Network Policy Or Egress Firewall Modified | HIGH | RUNTIME | AC-4, AU-2, AU-6, CM-3, SC-7, SC-7(5) |  |  |
| audit | `pc-rbac-scc-modification`<br>Protected C - Cluster RBAC Or SCC Modified | CRITICAL | RUNTIME | AC-2(4), AC-6, AU-2, AU-6, CM-3, CM-5 |  |  |
| audit | `pc-secret-access`<br>Protected C - Secret Read Or Modified Through The API | HIGH | RUNTIME | AC-3, AU-2, AU-6, AU-12, IA-5 | yes |  |
| audit | `pc-user-impersonation`<br>Protected C - Kubernetes API Call Using Impersonation | HIGH | RUNTIME | AC-6(9), AU-2, AU-6, AU-10, IA-2 |  |  |
