#!/usr/bin/env bash
# Builds one Mifos PH-EE connector jar from the vendored source (vendor/mifos-ph-ee) on DIFME's replacements:
#   1. java-ilp-core (vendored, Apache-2.0) and services/fspiop-ilp-models: in place of interop-ilp-conditions (licence)
#   2. services/zeebe-on-fluxnova: in place of the Zeebe client (Fluxnova instead of Zeebe)
#   3. connector-common (vendored) to mavenLocal, in place of upstream's SNAPSHOTs from a third-party Artifactory
#   4. the connector, with vendored-common.gradle as init script (dependency swaps, Spring Boot 3 / Camel 4 / Java 21,
#      Prometheus registry)
# Needs JDK 21 and Gradle 8.14 ($GRADLE, default "gradle"; upstream's Gradle 7.3 wrapper can't run on Java 21) and Maven.
# Usage: build.sh <ams|channel|mojaloop> <out.jar> [test]   (from the repository root; used by the Dockerfile and locally;
# "test" also runs the connector's and connector-common's unit tests)
set -euo pipefail
c=$1 out=$2 test=${3:-}
case "$c" in
  ams) dir=connector-ams-mifos ;; channel) dir=connector-channel ;; mojaloop) dir=connector-mojaloop ;;
  *) echo "unknown connector $c"; exit 1 ;;
esac
here=$(cd "$(dirname "$0")" && pwd)
init=(--init-script "$here/vendored-common.gradle")
[ -z "${MAVEN_MIRROR_INIT:-}" ] || init+=(--init-script "$MAVEN_MIRROR_INIT")
gradlew_in() { (cd "$1" && shift && "${GRADLE:-gradle}" --no-daemon -q "${init[@]}" "$@"); }
mvn() { command mvn -q -B -ntp ${MAVEN_SETTINGS:+-s "$MAVEN_SETTINGS"} "$@"; }

mvn -f services/zeebe-on-fluxnova/pom.xml install -DskipTests
if [ "$c" = mojaloop ]; then
  mvn -f vendor/interledger/java-ilp-core/pom.xml install -DskipTests
  mvn -f services/fspiop-ilp-models/pom.xml install -DskipTests
fi
tests=(-x test); [ "$test" = test ] && tests=(test)
gradlew_in vendor/mifos-ph-ee/connector-common "${tests[@]}" publishToMavenLocal -x javadoc
gradlew_in "vendor/mifos-ph-ee/$dir" "${tests[@]}" bootJar
jar=$(ls "vendor/mifos-ph-ee/$dir"/build/libs/*.jar | grep -v -- -plain.jar | head -1)
cp "$jar" "$out"
echo "built $c: $jar -> $out"
