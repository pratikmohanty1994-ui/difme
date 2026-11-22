# DIFME security module (services/hsm, ADR-026): jPOS JCESecurityModule + DIFME extensions behind an HTTP interface.
# Context: repo root. JVM bytecode is platform-independent: built once on the build platform.
FROM --platform=$BUILDPLATFORM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /src
COPY services/hsm/pom.xml .
RUN mvn -q -B dependency:go-offline
COPY services/hsm/src src
RUN mvn -q -B -DskipTests package dependency:copy-dependencies -DoutputDirectory=target/lib -DincludeScope=runtime

FROM eclipse-temurin:25-jre
RUN apt-get update && apt-get -y upgrade && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/target/classes classes
COPY --from=build /src/target/lib lib
USER 185
EXPOSE 8700
ENV HSM_ADDR=0.0.0.0:8700 JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=70"
ENTRYPOINT ["java", "-cp", "/app/classes:/app/lib/*", "dev.difme.hsm.HsmServer"]
