PYTHON  ?= python3
VENV    := .venv
VPY     := $(VENV)/bin/python
KUSTOMIZE ?= $(shell command -v kustomize 2>/dev/null || echo "oc kustomize")
NAMESPACE ?= stackrox

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

$(VPY):
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install --quiet --upgrade pip pyyaml

.PHONY: validate
validate: $(VPY) ## Validate every policy manifest offline
	$(VPY) scripts/validate_policies.py

.PHONY: build
build: ## Render both kustomize targets
	$(KUSTOMIZE) policies > /dev/null && echo "policies/ renders cleanly"
	$(KUSTOMIZE) overlays/enforce > /dev/null && echo "overlays/enforce renders cleanly"

.PHONY: validate-overlay
validate-overlay: $(VPY) ## Render the enforce overlay and validate the result
	$(KUSTOMIZE) overlays/enforce | $(VPY) scripts/validate_policies.py --stdin

.PHONY: catalogue
catalogue: $(VPY) ## Regenerate docs/policy-catalogue.md from the manifests
	$(VPY) scripts/generate_catalogue.py

.PHONY: check
check: validate build validate-overlay ## Run everything CI runs

.PHONY: apply
apply: ## Apply the detect-only baseline
	oc apply -k policies/

.PHONY: apply-enforce
apply-enforce: ## Apply the enforcing overlay
	oc apply -k overlays/enforce/

.PHONY: status
status: ## Show whether Central accepted each policy
	oc get securitypolicies.config.stackrox.io -n $(NAMESPACE) \
	  -o custom-columns=NAME:.metadata.name,ACCEPTED:.status.conditions[0].status,MSG:.status.conditions[0].message

.PHONY: clean
clean: ## Remove the local virtualenv
	rm -rf $(VENV)
