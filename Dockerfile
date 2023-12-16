# syntax=docker/dockerfile:experimental
FROM eclipse-temurin:17-jdk-alpine AS build
WORKDIR /workspace/app

COPY . /workspace/app
RUN mkdir -p /usr/local/newrelic

ADD ./newrelic/newrelic.jar /usr/local/newrelic/newrelic.jar
ADD ./newrelic/newrelic.yml /usr/local/newrelic/newrelic.yml

RUN --mount=type=secret,id=USERNAME --mount=type=secret,id=PERSONAL_ACCESS_TOKEN --mount=type=cache,target=/root/.gradle\
    export USERNAME=$(cat /run/secrets/USERNAME)\
    export PERSONAL_ACCESS_TOKEN=$(cat /run/secrets/PERSONAL_ACCESS_TOKEN) &&\
     ./gradlew clean build
RUN  mkdir -p build/dependency && (cd build/dependency; jar -xf ../libs/authentication-rest-service-1.0.jar)

FROM eclipse-temurin:17-jdk-alpine
VOLUME /tmp
ARG DEPENDENCY=/workspace/app/build/dependency

COPY --from=build ${DEPENDENCY}/BOOT-INF/lib /app/lib
COPY --from=build ${DEPENDENCY}/META-INF /app/META-INF
COPY --from=build ${DEPENDENCY}/BOOT-INF/classes /app
ENTRYPOINT ["java","-javaagent:/usr/local/newrelic/newrelic.jar", "-cp","app:app/lib/*","me.sonam.authentication.Application"]

LABEL org.opencontainers.image.source https://github.com/sonamsamdupkhangsar/authentication-rest-service