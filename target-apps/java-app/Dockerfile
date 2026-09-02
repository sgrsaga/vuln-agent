# Reference app for vuln-agent's base-image hardening feature (see
# target-apps/README.md). Base is deliberately an older pinned tag so there's a
# real vulnerability surface for the hardening loop to work against.
#
# Note on the compiled-language tradeoff: `runtime-base` ships the JDK + Maven
# themselves rather than a stripped JRE-only final stage, specifically so
# `test` can descend from the exact same base as `runtime` (never from an
# unrelated builder stage) — required so a passing `docker build --target
# test` is real evidence about the image that actually gets hardened and
# pushed. A production Dockerfile could instead keep a separate minimal
# JRE-only runtime stage and have `test` temporarily install a JDK + Maven
# onto that same base — see target-apps/README.md.
FROM eclipse-temurin:17-jdk-alpine AS runtime-base
RUN apk add --no-cache maven
WORKDIR /app
COPY pom.xml ./
COPY src ./src

FROM runtime-base AS test
RUN mvn -B test

FROM runtime-base AS builder
RUN mvn -B -DskipTests package

FROM runtime-base AS runtime
COPY --from=builder /app/target/app.jar /app/app.jar
EXPOSE 8080
CMD ["java", "-jar", "/app/app.jar"]
