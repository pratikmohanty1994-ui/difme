#!/usr/bin/env python3
"""Point the vendored Tazama packages at each other instead of GitHub's npm registry (ADR-023).

Upstream publishes the @tazama-lf/* libraries only on npm.pkg.github.com, which needs a token. DIFME builds them from
vendor/tazama/, so every @tazama-lf dependency becomes a file: link to the vendored copy and the registry line goes
from .npmrc. rule-executer's rule alias (`"rule": "npm:@tazama-lf/rule-901@…"`) points at vendor/tazama/rule-901;
the image build swaps it for the rule it packages. Idempotent. Usage: python3 ci/tazama-local-deps.py
"""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent / "vendor" / "tazama"
LOCAL = {
    "@tazama-lf/frms-coe-lib": "frms-coe-lib",
    "@tazama-lf/frms-coe-startup-lib": "frms-coe-startup-lib",
    "@tazama-lf/auth-lib": "auth-lib",
    "@tazama-lf/tcs-lib": "tcs-lib",
}

for pkg_json in sorted(ROOT.glob("*/package.json")):
    repo = pkg_json.parent
    data = json.loads(pkg_json.read_text())
    changed = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        deps = data.get(section, {})
        for name, spec in list(deps.items()):
            target = LOCAL.get(name)
            if target is None and name == "rule" and spec.startswith("npm:@tazama-lf/rule-"):
                target = "rule-901"
            if target and target != repo.name:
                new = f"file:../{target}"
                if section == "peerDependencies":
                    continue  # a peer range stays a range; the consumer supplies the file: link
                if spec != new:
                    deps[name] = new
                    changed.append(f"{section}.{name}: {spec} -> {new}")
    if changed:
        pkg_json.write_text(json.dumps(data, indent=2) + "\n")
    npmrc = repo / ".npmrc"
    if npmrc.exists():
        lines = npmrc.read_text().splitlines()
        kept = [l for l in lines if not re.search(r"npm\.pkg\.github\.com", l)]
        if len(kept) != len(lines):
            npmrc.write_text("\n".join(kept) + "\n")
            changed.append(".npmrc: GitHub registry lines removed")
    for c in changed:
        print(f"{repo.name}: {c}")
