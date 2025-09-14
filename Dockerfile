FROM openjdk:17-jdk-slim
WORKDIR /app
COPY target/helo-identity-service.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
