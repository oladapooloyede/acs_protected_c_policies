#!/usr/bin/env python3
"""Offline validator for RHACS SecurityPolicy custom resources.

Checks every manifest under policies/ against:

  * the SecurityPolicy CRD schema (config.stackrox.io/v1alpha1) - required
    fields, enum values and the policyName / description patterns;
  * the canonical ACS policy criteria list - field names and the per-field
    value regexes taken from pkg/booleanpolicy in stackrox/stackrox;
  * the ACS policy validator rules - lifecycle / event source / enforcement
    compatibility, runtime criteria mixing, and audit log restrictions.

Exit code 0 means the whole set should be accepted by Central. Run it before
pushing; CI runs the same script.
"""

from __future__ import annotations

import pathlib
import re
import sys

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install pyyaml")

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
POLICY_DIRS = ["policies", "overlays"]

API_VERSION = "config.stackrox.io/v1alpha1"
KIND = "SecurityPolicy"

SEVERITIES = {
    "UNSET_SEVERITY",
    "LOW_SEVERITY",
    "MEDIUM_SEVERITY",
    "HIGH_SEVERITY",
    "CRITICAL_SEVERITY",
}
LIFECYCLES = {"BUILD", "DEPLOY", "RUNTIME"}
EVENT_SOURCES = {"NOT_APPLICABLE", "DEPLOYMENT_EVENT", "AUDIT_LOG_EVENT", "NODE_EVENT"}
ENFORCEMENTS = {
    "UNSET_ENFORCEMENT",
    "SCALE_TO_ZERO_ENFORCEMENT",
    "UNSATISFIABLE_NODE_CONSTRAINT_ENFORCEMENT",
    "KILL_POD_ENFORCEMENT",
    "FAIL_BUILD_ENFORCEMENT",
    "FAIL_KUBE_REQUEST_ENFORCEMENT",
    "FAIL_DEPLOYMENT_CREATE_ENFORCEMENT",
    "FAIL_DEPLOYMENT_UPDATE_ENFORCEMENT",
}
# Enforcement action -> the lifecycle stage it requires.
ENFORCEMENT_LIFECYCLE = {
    "FAIL_BUILD_ENFORCEMENT": "BUILD",
    "SCALE_TO_ZERO_ENFORCEMENT": "DEPLOY",
    "UNSATISFIABLE_NODE_CONSTRAINT_ENFORCEMENT": "DEPLOY",
    "FAIL_DEPLOYMENT_CREATE_ENFORCEMENT": "DEPLOY",
    "FAIL_DEPLOYMENT_UPDATE_ENFORCEMENT": "DEPLOY",
    "KILL_POD_ENFORCEMENT": "RUNTIME",
    "FAIL_KUBE_REQUEST_ENFORCEMENT": "RUNTIME",
}
# Categories must already exist in Central; these are the defaults it ships.
CATEGORIES = {
    "Anomalous Activity",
    "Cryptocurrency Mining",
    "DevOps Best Practices",
    "Docker CIS",
    "Kubernetes",
    "Kubernetes Events",
    "Network Tools",
    "Package Management",
    "Privileges",
    "Security Best Practices",
    "Supply Chain Security",
    "System Modification",
    "Vulnerability Management",
    "Zero Trust",
}

POLICY_NAME_RE = re.compile(r"^[^\n\r$]{5,128}$")
DESCRIPTION_RE = re.compile(r"^[^$]{0,800}$", re.DOTALL)
DNS1123 = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")

# -- value regexes, transcribed from pkg/booleanpolicy/value_regex.go ---------
KEY_VALUE = r"[^=]+=.*"
BOOLEAN = r"(?i:(true|false))"
STRING = r".*\S+.*"
INTEGER = r"\d+"
COMPARATOR_DECIMAL = r"(<|>|<=|>=)?\s*\d*\.?\d+"
CAPABILITIES = (
    r"AUDIT_CONTROL|AUDIT_READ|AUDIT_WRITE|BLOCK_SUSPEND|CHOWN|DAC_OVERRIDE|"
    r"DAC_READ_SEARCH|FOWNER|FSETID|IPC_LOCK|IPC_OWNER|KILL|LEASE|LINUX_IMMUTABLE|"
    r"MAC_ADMIN|MAC_OVERRIDE|MKNOD|NET_ADMIN|NET_BIND_SERVICE|NET_BROADCAST|NET_RAW|"
    r"SETGID|SETFCAP|SETPCAP|SETUID|SYS_ADMIN|SYS_BOOT|SYS_CHROOT|SYS_MODULE|SYS_NICE|"
    r"SYS_PACCT|SYS_PTRACE|SYS_RAWIO|SYS_RESOURCE|SYS_TIME|SYS_TTY_CONFIG|SYSLOG|WAKE_ALARM"
)
ADD_CAPS = rf"(?i:({CAPABILITIES}))"
DROP_CAPS = rf"(?i:(ALL|{CAPABILITIES}))"
RBAC_PERMISSION = r"(?i:DEFAULT|ELEVATED_IN_NAMESPACE|ELEVATED_CLUSTER_WIDE|CLUSTER_ADMIN)"
PORT_EXPOSURE = r"(?i:UNSET|EXTERNAL|NODE|HOST|INTERNAL|ROUTE)"
KUBE_EVENT_RESOURCE = r"(?i:PODS_EXEC|PODS_PORTFORWARD|PODS_ATTACH)"
AUDIT_RESOURCE = (
    r"(?i:SECRETS|CONFIGMAPS|CLUSTER_ROLES|CLUSTER_ROLE_BINDINGS|NETWORK_POLICIES|"
    r"SECURITY_CONTEXT_CONSTRAINTS|EGRESS_FIREWALLS)"
)
AUDIT_VERB = r"(?i:CREATE|DELETE|GET|PATCH|UPDATE)"
MOUNT_PROPAGATION = r"(?i:NONE|HOSTTOCONTAINER|BIDIRECTIONAL)"
SECCOMP = r"(?i:UNCONFINED|RUNTIME_DEFAULT|LOCALHOST)"
VULN_SEVERITY = r"(<|>|<=|>=)?\s*(?i:UNKNOWN|LOW|MODERATE|IMPORTANT|CRITICAL)"
KUBE_NAME = r"(?i:[a-z0-9])(?i:[-:a-z0-9]*[a-z0-9])?"
SIGNATURE_ID = r"io\.stackrox\.signatureintegration\.[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
FILE_OPERATION = r"(?i:OPEN|CREATE|RENAME|UNLINK|OWNERSHIP_CHANGE|PERMISSION_CHANGE|XATTR_CHANGE)"
ENV_VAR = (
    r"(?i:(UNSET|RAW|UNKNOWN|)=[^=]*=.*)"
    r"|(?:(SECRET_KEY|CONFIG_MAP_KEY|FIELD|RESOURCE_FIELD)=[^=]*=)"
)
DOCKERFILE_LINE = (
    r"(?i:(ADD|ARG|CMD|COPY|ENTRYPOINT|ENV|EXPOSE|FROM|LABEL|MAINTAINER|ONBUILD|RUN|"
    r"STOPSIGNAL|USER|VOLUME|WORKDIR|)=).*"
)

IMAGE = "image"  # usable at BUILD
DEPLOY = "deploy"
PROCESS = "process"
NETWORK_FLOW = "network_flow"
KUBE_EVENT = "kube_event"
AUDIT = "audit"
FILE_ACCESS = "file_access"

# fieldName -> (value regex, negate allowed, scope)
FIELDS: dict[str, tuple[str, bool, str]] = {
    # --- image and vulnerability (valid at BUILD) ---
    "Image Registry": (STRING, True, IMAGE),
    "Image Remote": (STRING, True, IMAGE),
    "Image Tag": (STRING, True, IMAGE),
    "Image OS": (STRING, True, IMAGE),
    "Image Age": (INTEGER, False, IMAGE),
    "Image Scan Age": (INTEGER, False, IMAGE),
    "Image User": (STRING, True, IMAGE),
    "Image Component": (KEY_VALUE, True, IMAGE),
    "Image Signature Verified By": (SIGNATURE_ID, False, IMAGE),
    "Dockerfile Line": (DOCKERFILE_LINE, True, IMAGE),
    "Unscanned Image": (BOOLEAN, False, IMAGE),
    "Required Image Label": (KEY_VALUE, False, IMAGE),
    "Disallowed Image Label": (KEY_VALUE, True, IMAGE),
    "CVE": (STRING, True, IMAGE),
    "CVSS": (COMPARATOR_DECIMAL, True, IMAGE),
    "NVD CVSS": (COMPARATOR_DECIMAL, True, IMAGE),
    "Severity": (VULN_SEVERITY, True, IMAGE),
    "Fixed By": (STRING, True, IMAGE),
    "Fixable": (BOOLEAN, True, IMAGE),
    "CISA KEV": (BOOLEAN, False, IMAGE),
    "Days Since CVE Was Published": (INTEGER, False, IMAGE),
    "Days Since CVE Fix Was Available": (INTEGER, False, IMAGE),
    "Days Since CVE Was First Discovered In Image": (INTEGER, False, IMAGE),
    "Days Since CVE Was First Discovered In System": (INTEGER, False, IMAGE),
    # --- container configuration and deployment metadata ---
    "Add Capabilities": (ADD_CAPS, True, DEPLOY),
    "Drop Capabilities": (DROP_CAPS, False, DEPLOY),
    "Allow Privilege Escalation": (BOOLEAN, False, DEPLOY),
    "AppArmor Profile": (STRING, True, DEPLOY),
    "Automount Service Account Token": (BOOLEAN, False, DEPLOY),
    "Container CPU Limit": (COMPARATOR_DECIMAL, False, DEPLOY),
    "Container CPU Request": (COMPARATOR_DECIMAL, False, DEPLOY),
    "Container Memory Limit": (COMPARATOR_DECIMAL, False, DEPLOY),
    "Container Memory Request": (COMPARATOR_DECIMAL, False, DEPLOY),
    "Container Name": (STRING, True, DEPLOY),
    "Disallowed Annotation": (KEY_VALUE, True, DEPLOY),
    "Environment Variable": (ENV_VAR, True, DEPLOY),
    "Exposed Node Port": (COMPARATOR_DECIMAL, True, DEPLOY),
    "Exposed Port": (COMPARATOR_DECIMAL, True, DEPLOY),
    "Exposed Port Protocol": (STRING, True, DEPLOY),
    "Has Egress Network Policy": (BOOLEAN, True, DEPLOY),
    "Has Ingress Network Policy": (BOOLEAN, True, DEPLOY),
    "Host IPC": (BOOLEAN, False, DEPLOY),
    "Host Network": (BOOLEAN, False, DEPLOY),
    "Host PID": (BOOLEAN, False, DEPLOY),
    "Liveness Probe Defined": (BOOLEAN, False, DEPLOY),
    "Minimum RBAC Permissions": (RBAC_PERMISSION, True, DEPLOY),
    "Mount Propagation": (MOUNT_PROPAGATION, True, DEPLOY),
    "Namespace": (STRING, True, DEPLOY),
    "Port Exposure Method": (PORT_EXPOSURE, True, DEPLOY),
    "Privileged Container": (BOOLEAN, False, DEPLOY),
    "Read-Only Root Filesystem": (BOOLEAN, False, DEPLOY),
    "Readiness Probe Defined": (BOOLEAN, False, DEPLOY),
    "Replicas": (COMPARATOR_DECIMAL, True, DEPLOY),
    "Required Annotation": (KEY_VALUE, False, DEPLOY),
    "Required Label": (KEY_VALUE, False, DEPLOY),
    "Runtime Class": (STRING, True, DEPLOY),
    "Seccomp Profile Type": (SECCOMP, True, DEPLOY),
    "Service Account": (STRING, True, DEPLOY),
    "Volume Destination": (STRING, True, DEPLOY),
    "Volume Name": (STRING, True, DEPLOY),
    "Volume Source": (STRING, True, DEPLOY),
    "Volume Type": (STRING, True, DEPLOY),
    "Writable Host Mount": (BOOLEAN, False, DEPLOY),
    "Writable Mounted Volume": (BOOLEAN, False, DEPLOY),
    # --- runtime: process ---
    "Process Ancestor": (STRING, True, PROCESS),
    "Process Arguments": (STRING, True, PROCESS),
    "Process Name": (STRING, True, PROCESS),
    "Process UID": (STRING, True, PROCESS),
    "Unexpected Process Executed": (BOOLEAN, False, PROCESS),
    # --- runtime: network flow ---
    "Unexpected Network Flow Detected": (BOOLEAN, False, NETWORK_FLOW),
    # --- runtime: file access (node events) ---
    "File Path": (STRING, False, FILE_ACCESS),
    "File Operation": (FILE_OPERATION, True, FILE_ACCESS),
    # --- runtime: kubernetes events and audit log ---
    "Kubernetes Resource": (None, True, KUBE_EVENT),  # regex depends on eventSource
    "Kubernetes User Name": (KUBE_NAME, True, KUBE_EVENT),
    "Kubernetes User Groups": (KUBE_NAME, True, KUBE_EVENT),
    "Kubernetes API Verb": (AUDIT_VERB, True, AUDIT),
    "Kubernetes Resource Name": (KUBE_NAME, True, AUDIT),
    "Source IP Address": (STRING, True, AUDIT),
    "User Agent": (STRING, True, AUDIT),
    "Is Impersonated User": (BOOLEAN, True, AUDIT),
}

RUNTIME_SCOPES = {PROCESS, NETWORK_FLOW, KUBE_EVENT, AUDIT, FILE_ACCESS}
AUDIT_ONLY_SCOPES = {KUBE_EVENT, AUDIT}


def full_match(pattern: str, value: str) -> bool:
    """Mirror the Go `((?m)^<pattern>$)` wrapper used by the ACS validator."""
    return re.search(rf"(?m)^(?:{pattern})$", value) is not None


class Validator:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.policy_names: dict[str, str] = {}
        self.resource_names: dict[str, str] = {}

    def err(self, where: str, msg: str) -> None:
        self.errors.append(f"{where}: {msg}")

    def check_doc(self, path: str, doc: dict) -> None:
        if doc.get("apiVersion") != API_VERSION:
            self.err(path, f"apiVersion must be {API_VERSION}, got {doc.get('apiVersion')!r}")
        if doc.get("kind") != KIND:
            self.err(path, f"kind must be {KIND}, got {doc.get('kind')!r}")

        meta = doc.get("metadata") or {}
        name = meta.get("name")
        if not name or not DNS1123.match(str(name)):
            self.err(path, f"metadata.name {name!r} is not a valid DNS-1123 subdomain")
        elif name in self.resource_names:
            self.err(path, f"duplicate metadata.name {name!r} (also in {self.resource_names[name]})")
        else:
            self.resource_names[name] = path

        spec = doc.get("spec")
        if not isinstance(spec, dict):
            self.err(path, "spec is missing")
            return
        self.check_spec(path, spec)

    def check_spec(self, path: str, spec: dict) -> None:
        for required in ("policyName", "categories", "lifecycleStages", "policySections", "severity"):
            if not spec.get(required):
                self.err(path, f"spec.{required} is required and must be non-empty")

        policy_name = spec.get("policyName", "")
        if policy_name:
            if not POLICY_NAME_RE.match(policy_name):
                self.err(path, f"policyName {policy_name!r} violates the CRD pattern (5-128 chars, no newline, no '$')")
            if policy_name in self.policy_names:
                self.err(path, f"duplicate policyName {policy_name!r} (also in {self.policy_names[policy_name]})")
            else:
                self.policy_names[policy_name] = path

        description = spec.get("description")
        if description is not None and not DESCRIPTION_RE.match(description):
            self.err(path, "description violates the CRD pattern (max 800 chars, no '$')")

        severity = spec.get("severity")
        if severity and severity not in SEVERITIES:
            self.err(path, f"invalid severity {severity!r}")

        categories = spec.get("categories") or []
        if len(set(categories)) != len(categories):
            self.err(path, "duplicate entries in categories")
        for category in categories:
            if category not in CATEGORIES:
                self.err(path, f"category {category!r} is not a Central default; create it first or use a default")

        stages = set(spec.get("lifecycleStages") or [])
        for stage in stages:
            if stage not in LIFECYCLES:
                self.err(path, f"invalid lifecycleStage {stage!r}")

        event_source = spec.get("eventSource")
        if event_source is not None and event_source not in EVENT_SOURCES:
            self.err(path, f"invalid eventSource {event_source!r}")
        if event_source and event_source != "NOT_APPLICABLE" and "RUNTIME" not in stages:
            self.err(path, "eventSource must not be set for build or deploy time policies")
        if "RUNTIME" in stages and event_source in (None, "NOT_APPLICABLE"):
            self.err(path, "runtime policies must set eventSource to DEPLOYMENT_EVENT, AUDIT_LOG_EVENT or NODE_EVENT")

        is_audit = event_source == "AUDIT_LOG_EVENT"

        enforcements = spec.get("enforcementActions") or []
        for action in enforcements:
            if action not in ENFORCEMENTS:
                self.err(path, f"invalid enforcementAction {action!r}")
                continue
            needed = ENFORCEMENT_LIFECYCLE.get(action)
            if needed and needed not in stages:
                self.err(path, f"enforcementAction {action} requires lifecycleStage {needed}")
        if enforcements and is_audit:
            self.err(path, "enforcement actions are not applicable to audit log event policies")

        self.check_scope(path, spec, is_audit)
        used_scopes = self.check_sections(path, spec, stages, event_source)
        self.check_stage_compatibility(path, stages, event_source, used_scopes, enforcements)

    def check_scope(self, path: str, spec: dict, is_audit: bool) -> None:
        for entry in spec.get("scope") or []:
            if not entry:
                self.err(path, "scope entry must have at least one field populated")
                continue
            if entry.get("cluster") and entry.get("clusterLabel"):
                self.err(path, "scope cannot set both cluster and clusterLabel")
            if entry.get("namespace") and entry.get("namespaceLabel"):
                self.err(path, "scope cannot set both namespace and namespaceLabel")
            if is_audit and any(k in entry for k in ("label", "clusterLabel", "namespaceLabel")):
                self.err(path, "labels in scope are not permitted for audit log event policies")

        for excl in spec.get("exclusions") or []:
            deployment = excl.get("deployment")
            image = excl.get("image")
            if not deployment and not image:
                self.err(path, "every exclusion must define a deployment or an image")
            if deployment and is_audit:
                self.err(path, "deployment exclusions are not applicable to audit log event policies")
            if image and not image.get("name"):
                self.err(path, "image exclusion must have a non-empty name")
            if deployment:
                scope = deployment.get("scope") or {}
                if not deployment.get("name") and not scope:
                    self.err(path, "deployment exclusion must define a name or a scope")
                if is_audit is False and any(k in scope for k in ("clusterLabel", "namespaceLabel")):
                    self.err(path, "exclusion scopes do not support cluster or namespace labels")

    def check_sections(self, path: str, spec: dict, stages: set, event_source: str | None) -> set[str]:
        used_scopes: set[str] = set()
        added_caps: set[str] = set()
        dropped_caps: set[str] = set()

        for s_idx, section in enumerate(spec.get("policySections") or []):
            groups = section.get("policyGroups")
            if not groups:
                self.err(path, f"policySections[{s_idx}].policyGroups is required and must be non-empty")
                continue
            section_scopes: set[str] = set()
            for g_idx, group in enumerate(groups):
                where = f"{path}: policySections[{s_idx}].policyGroups[{g_idx}]"
                field = group.get("fieldName")
                if not field:
                    self.err(where, "fieldName is required")
                    continue
                if field not in FIELDS:
                    self.err(where, f"unknown policy criteria field {field!r}")
                    continue
                pattern, negate_ok, scope = FIELDS[field]
                used_scopes.add(scope)
                if scope in RUNTIME_SCOPES:
                    section_scopes.add(scope)

                if group.get("booleanOperator") not in (None, "OR", "AND"):
                    self.err(where, f"booleanOperator must be OR or AND, got {group.get('booleanOperator')!r}")
                if group.get("negate") and not negate_ok:
                    self.err(where, f"negate is not permitted on {field!r}")

                if field == "Kubernetes Resource":
                    pattern = AUDIT_RESOURCE if event_source == "AUDIT_LOG_EVENT" else KUBE_EVENT_RESOURCE

                values = group.get("values") or []
                if not values:
                    self.err(where, f"{field!r} has no values")
                for value in values:
                    raw = value.get("value")
                    if raw is None:
                        self.err(where, "value entry is missing the 'value' key")
                        continue
                    raw = str(raw)
                    if field == "Add Capabilities":
                        added_caps.add(raw.upper())
                    if field == "Drop Capabilities":
                        dropped_caps.add(raw.upper())
                    if pattern and not full_match(pattern, raw):
                        self.err(where, f"value {raw!r} is not valid for criteria {field!r}")

            # A section may not mix process/file criteria with network flow or
            # Kubernetes event criteria.
            proc_like = section_scopes & {PROCESS, FILE_ACCESS}
            other = section_scopes & {NETWORK_FLOW, KUBE_EVENT, AUDIT}
            if proc_like and other:
                self.err(
                    path,
                    f"policySections[{s_idx}] mixes incompatible runtime criteria "
                    f"({sorted(proc_like)} with {sorted(other)})",
                )

        overlap = added_caps & dropped_caps
        if overlap:
            self.err(path, f"capabilities cannot be both added and dropped: {sorted(overlap)}")
        return used_scopes

    def check_stage_compatibility(
        self, path: str, stages: set, event_source: str | None, used: set[str], enforcements: list
    ) -> None:
        runtime_used = used & RUNTIME_SCOPES

        if "BUILD" in stages:
            non_image = used - {IMAGE}
            if non_image:
                self.err(path, f"BUILD policies may only use image criteria; found {sorted(non_image)}")

        if "DEPLOY" in stages and runtime_used:
            self.err(path, f"deploy time policy cannot contain runtime criteria; found {sorted(runtime_used)}")

        if "RUNTIME" in stages:
            if not runtime_used:
                self.err(
                    path,
                    "a runtime policy must contain at least one process, network flow, "
                    "audit log or Kubernetes event criterion",
                )
            if event_source == "AUDIT_LOG_EVENT":
                non_audit = used - AUDIT_ONLY_SCOPES
                if non_audit:
                    self.err(path, f"audit log policies may only use audit log criteria; found {sorted(non_audit)}")
            if event_source == "DEPLOYMENT_EVENT" and AUDIT in used:
                self.err(path, "audit log only criteria require eventSource AUDIT_LOG_EVENT")
            if (PROCESS in used or FILE_ACCESS in used) and (NETWORK_FLOW in used or KUBE_EVENT in used):
                self.err(path, "process criteria cannot coexist with network flow or Kubernetes event criteria")

        # Enforcement is rejected outright on these two criteria.
        if enforcements:
            for field in ("Has Ingress Network Policy", "Has Egress Network Policy"):
                if field in self._fields_used:
                    self.err(path, f"enforcement of {field} is not allowed")

    _fields_used: set[str] = set()

    def check_stream(self, label: str, text: str) -> int:
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError as exc:
            self.err(label, f"invalid YAML: {exc}")
            return 0
        count = 0
        for doc in docs:
            if doc is None:
                continue
            if not isinstance(doc, dict):
                self.err(label, "top level document must be a mapping")
                continue
            self._fields_used = {
                g.get("fieldName")
                for s in ((doc.get("spec") or {}).get("policySections") or [])
                for g in (s.get("policyGroups") or [])
            }
            self.check_doc(label, doc)
            count += 1
        return count

    def run(self, use_stdin: bool = False) -> int:
        count = 0

        if use_stdin:
            count += self.check_stream("<stdin>", sys.stdin.read())
            if count == 0 and not self.errors:
                print("no policy documents on stdin", file=sys.stderr)
                return 1
        else:
            files = sorted(
                p
                for d in POLICY_DIRS
                for p in (REPO_ROOT / d).rglob("*.yaml")
                if p.name != "kustomization.yaml"
            )
            if not files:
                print("no policy manifests found", file=sys.stderr)
                return 1
            for file in files:
                count += self.check_stream(str(file.relative_to(REPO_ROOT)), file.read_text())

        if self.errors:
            print(f"FAIL  {len(self.errors)} problem(s) in {count} policy document(s):\n", file=sys.stderr)
            for error in self.errors:
                print(f"  - {error}", file=sys.stderr)
            return 1

        print(f"OK    {count} SecurityPolicy document(s) validated, no problems found")
        return 0


if __name__ == "__main__":
    sys.exit(Validator().run(use_stdin="--stdin" in sys.argv[1:]))
