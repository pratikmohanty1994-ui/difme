#!/usr/bin/env python3
"""Prints deploy/bootstrap/dev-sizing.yaml with memory requests halved as well (CI runners only, ci/up.sh).

The Codespace policy divides CPU requests by 4 and keeps memory requests as declared, because the Codespaces host runs
earlyoom and lower memory requests make a pod its first victim. GitHub-hosted runners don't run earlyoom, and with
production memory requests the single 16 GB node runs out of schedulable memory long before it runs out of RAM
(cluster-verify 2026-11-23: requests 99%, real use about 70%). Memory limits stay unchanged."""
import sys

import yaml

MEMORY = {
    "list": "request.object.spec.containers",
    "preconditions": {"all": [{"key": "{{ element.resources.requests.memory || '' }}", "operator": "NotEquals", "value": ""}]},
    "patchStrategicMerge": {"spec": {"containers": [{
        "name": "{{ element.name }}",
        "resources": {"requests": {"memory": "{{ divide('{{ element.resources.requests.memory }}', `2`) }}"}},
    }]}},
}

policy = yaml.safe_load(open(sys.argv[1]))
rules = {r["name"]: r for r in policy["spec"]["rules"]}
rules["scale-container-requests"]["mutate"]["foreach"].append(MEMORY)
rules["mark-scaled"]["mutate"]["patchStrategicMerge"]["metadata"]["annotations"]["difme.dev/requests-scaled"] = "cpu/4,memory/2"
yaml.safe_dump(policy, sys.stdout, sort_keys=False)
