#!/usr/bin/env bash
# Builds one Mifos PH-EE connector jar from the vendored source (vendor/mifos-ph-ee) on DIFME's replacements:
#   1. java-ilp-core (vendored, Apache-2.0) and services/fspiop-ilp-models: in place of interop-ilp-conditions (licence)
#   2. services/zeebe-on-fluxnova: in place of the Zeebe client (Fluxnova instead of Zeebe)
#   3. connector-common (vendored) to mavenLocal, in place of upstream's SNAPSHOTs from a third-party Artifactory
#   4. the connector, with vendored-common.gradle as init script (dependency swaps, Prometheus registry)
# Usage: build.sh <ams|channel|mojaloop> <out.jar>   (run from the repository root; used by the Dockerfile and locally)
set -euo pipefail
c=$1 out=$2
case "$c" in
  ams) dir=connector-ams-mifos ;; channel) dir=connector-channel ;; mojaloop) dir=connector-mojaloop ;;
  *) echo "unknown connector $c"; exit 1 ;;
esac
here=$(cd "$(dirname "$0")" && pwd)
init=(--init-script "$here/vendored-common.gradle")
[ -z "${MAVEN_MIRROR_INIT:-}" ] || init+=(--init-script "$MAVEN_MIRROR_INIT")
gradle() { (cd "$1" && shift && ./gradlew --no-daemon -q "${init[@]}" "$@"); }
mvn() { command mvn -q -B -ntp ${MAVEN_SETTINGS:+-s "$MAVEN_SETTINGS"} "$@"; }

mvn -f services/zeebe-on-fluxnova/pom.xml install -DskipTests
if [ "$c" = mojaloop ]; then
  mvn -f vendor/interledger/java-ilp-core/pom.xml install -DskipTests
  mvn -f services/fspiop-ilp-models/pom.xml install -DskipTests
fi
gradle vendor/mifos-ph-ee/connector-common publishToMavenLocal -x test -x javadoc
gradle "vendor/mifos-ph-ee/$dir" bootJar -x test
jar=$(ls "vendor/mifos-ph-ee/$dir"/build/libs/*.jar | grep -v -- -plain.jar | head -1)
cp "$jar" "$out"
echo "built $c: $jar -> $out"
