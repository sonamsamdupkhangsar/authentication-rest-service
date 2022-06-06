FROM maven:3-openjdk-17-slim as build

WORKDIR /app

COPY pom.xml ./
COPY src ./src

RUN ["mvn", "clean", "install"]

FROM openjdk:16
WORKDIR /app
COPY --from=build /app/target/authentication-rest-service-1.0-SNAPSHOT.jar /app/authentication-rest-service.jar
EXPOSE 8080

ENTRYPOINT [ "java", "-jar", "/app/authentication-rest-service.jar"]

LABEL org.opencontainers.image.source https://github.com/sonamsamdupkhangsar/authentication-rest-service