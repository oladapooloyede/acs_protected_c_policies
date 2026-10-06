#!/usr/bin/env python3
"""Regenerate docs/policy-catalogue.md from the manifests under policies/."""

from __future__ import annotations

import pathlib
import sys

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install pyyaml")

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
ANNOTATION_PREFIX = "protected-c.policy.local/"
STAGE_ORDER = {"build": 0, "deploy": 1, "runtime": 2, "audit": 3}

HEADER = """# Policy catalogue

Generated from the manifests under `policies/`. Regenerate with `make catalogue`
after adding or changing a policy.

**Tune** marks policies that contain environment-specific placeholders you must
replace before they are meaningful. Find them all with:

```sh
grep -rl 'tuning-required: "true"' policies/
```

"""


def main() -> int:
    rows = []
    for path in sorted((REPO_ROOT / "policies").glob("*/*.yaml")):
        if path.name == "kustomization.yaml":
            continue
        doc = yaml.safe_load(path.read_text())
        spec, meta = doc["spec"], doc["metadata"]
        annotations = meta.get("annotations") or {}
        rows.append(
            (
                path.parent.name,
                meta["name"],
                spec["policyName"],
                spec["severity"].replace("_SEVERITY", ""),
                "/".join(spec["lifecycleStages"]),
                annotations.get(f"{ANNOTATION_PREFIX}itsg33-controls", ""),
                "yes" if annotations.get(f"{ANNOTATION_PREFIX}tuning-required") == "true" else "",
                "disabled" if spec.get("disabled") else "",
            )
        )

    rows.sort(key=lambda r: (STAGE_ORDER[r[0]], r[1]))

    lines = [
        "| Stage | Policy | Severity | Lifecycle | ITSG-33 controls | Tune | Note |",
        "|---|---|---|---|---|---|---|",
    ]
    lines += [f"| {r[0]} | `{r[1]}`<br>{r[2]} | {r[3]} | {r[4]} | {r[5]} | {r[6]} | {r[7]} |" for r in rows]

    out = REPO_ROOT / "docs" / "policy-catalogue.md"
    out.write_text(HEADER + "\n".join(lines) + "\n")
    print(f"wrote {out.relative_to(REPO_ROOT)} with {len(rows)} policies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
