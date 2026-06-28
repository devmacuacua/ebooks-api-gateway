FROM eclipse-temurin:21-jdk-alpine AS builder
WORKDIR /app

# Install Maven (not bundled in the base image)
RUN apk add --no-cache maven

# Download dependencies first for better layer caching.
# Only pom.xml is copied here so this layer is invalidated only when
# the dependency list changes, not on every source change.
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Build the application
COPY src ./src
RUN mvn package -DskipTests -B

# ---- Runtime image ----
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Create a non-root user for security
RUN addgroup -S gateway && adduser -S gateway -G gateway
USER gateway

COPY --from=builder /app/target/*.jar app.jar

EXPOSE 8080

# JVM tuning for containers:
#   -XX:+UseContainerSupport  — respect cgroup memory/cpu limits
#   -XX:MaxRAMPercentage       — use up to 75 % of the container's RAM for heap
#   -Djava.security.egd       — faster startup on Linux by using /dev/urandom
ENTRYPOINT ["java", \
            "-XX:+UseContainerSupport", \
            "-XX:MaxRAMPercentage=75.0", \
            "-Djava.security.egd=file:/dev/./urandom", \
            "-jar", "app.jar"]
