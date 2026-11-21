#!/usr/bin/env bash
# Run a command in the DIFME Codespace from anywhere (a laptop, CI, or a cloud agent session).
#   ci/cs.sh 'kubectl get pods -A'          → runs in /workspaces/difme on the Codespace
#   ci/cs.sh bg NAME 'bash ci/measure.sh 200 60s'   → long job via ci/bg.sh (survives disconnects)
#   ci/cs.sh log NAME                        → tail of /tmp/NAME.log
# Needs gh authenticated with the codespace scope (GH_TOKEN env var, or `gh auth login -s codespace`).
# The Codespace is found by repo; set DIFME_CODESPACE to pick one explicitly. A stopped Codespace is started by ssh.
set -euo pipefail
REPO=${DIFME_REPO:-pratikmohanty1994-ui/difme}
# DIFME_VM=user@host (plus optional DIFME_VM_KEY) drives a plain VM over SSH instead, e.g. the cloud VM runtime
# set up by ci/vm-bootstrap.sh; the repo lives at the same /workspaces/difme path there.
if [ -n "${DIFME_VM:-}" ]; then
  run() { ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30 ${DIFME_VM_KEY:+-i "$DIFME_VM_KEY"} "$DIFME_VM"             "cd /workspaces/difme && git pull -q --ff-only 2>/dev/null; $1" </dev/null; }
else
  CS=${DIFME_CODESPACE:-$(gh codespace list --repo "$REPO" --json name -q '.[0].name')}
  [ -n "$CS" ] || { echo "no codespace for $REPO (create one: gh codespace create -R $REPO -m standardLinux32gb)"; exit 1; }
  run() { gh codespace ssh -c "$CS" -- "cd /workspaces/difme && git pull -q --ff-only 2>/dev/null; $1" </dev/null; }
fi
case "${1:-}" in
  bg)  run "bash ci/bg.sh $2 bash -c $(printf %q "$3")" ;;
  log) run "tail -n ${3:-40} /tmp/$2.log" ;;
  "")  echo "usage: ci/cs.sh 'command' | bg NAME 'command' | log NAME [lines]"; exit 2 ;;
  *)   run "$1" ;;
esac
