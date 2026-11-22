# Mifos Payment Hub EE connectors (vendor/mifos-ph-ee, MPL-2.0) on Fluxnova, one image per connector:
#   --build-arg CONNECTOR=ams|channel|mojaloop   -> ghcr.io/<owner>/difme-ph-ee-<connector>
# Context: repo root. The jar is architecture-neutral: built once on the build platform, both arches share it.
FROM --platform=$BUILDPLATFORM maven:3.9.9-eclipse-temurin-17 AS build
ARG CONNECTOR
WORKDIR /src
COPY vendor/mifos-ph-ee vendor/mifos-ph-ee
COPY vendor/interledger/java-ilp-core vendor/interledger/java-ilp-core
COPY services/zeebe-on-fluxnova services/zeebe-on-fluxnova
COPY services/fspiop-ilp-models services/fspiop-ilp-models
COPY deploy/images/mifos-ph-ee deploy/images/mifos-ph-ee
# Maven Central rate-limits shared CI IPs (429): resolve through Google's public mirror first (Gradle and Maven).
RUN printf '%s' '<settings><mirrors><mirror><id>central-gcs</id><mirrorOf>central</mirrorOf><url>https://maven-central.storage-download.googleapis.com/maven2/</url></mirror></mirrors></settings>' > /tmp/settings.xml
ENV MAVEN_SETTINGS=/tmp/settings.xml MAVEN_MIRROR_INIT=/src/deploy/images/mifos-ph-ee/maven-mirror.gradle
RUN deploy/images/mifos-ph-ee/build.sh "$CONNECTOR" /connector.jar

FROM eclipse-temurin:17-jre-noble
RUN useradd --system --uid 10001 --no-create-home phee
COPY --from=build /connector.jar /app/connector.jar
COPY vendor/mifos-ph-ee/connector-common/LICENSE /app/LICENSE
USER 10001
# Plain HTTP inside the mesh (Istio ambient encrypts pod-to-pod); upstream's dev keystores aren't vendored.
# Payload signing (connector-common's JWS filters) is off: callers are authenticated in the mesh (Keycloak JWT at the
# waypoint), and the filters' conditions have no defaults, so without these the connectors don't start.
ENV SERVER_SSL_ENABLED=false SECURITY_JWS_ENABLE=false SECURITY_JWS_RESPONSE_ENABLE=false
ENTRYPOINT ["java", "-jar", "/app/connector.jar"]
