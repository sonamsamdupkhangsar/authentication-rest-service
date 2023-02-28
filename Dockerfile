FROM maven:3-openjdk-17-slim as build

WORKDIR /app

COPY pom.xml settings.xml ./
COPY src ./src

RUN --mount=type=secret,id=PERSONAL_ACCESS_TOKEN \
   export PERSONAL_ACCESS_TOKEN=$(cat /run/secrets/PERSONAL_ACCESS_TOKEN) && \
   mvn -s settings.xml clean install

FROM openjdk:17
WORKDIR /app
COPY --from=build /app/target/authentication-rest-service-1.0-SNAPSHOT.jar /app/authentication-rest-service.jar
EXPOSE 8080

ENTRYPOINT [ "java", "-jar", "/app/authentication-rest-service.jar"]

LABEL org.opencontainers.image.source https://github.com/sonamsamdupkhangsar/authentication-rest-service