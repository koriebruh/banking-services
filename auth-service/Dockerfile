# =============================================================================
# STAGE 1 — BUILD
# =============================================================================
FROM maven:3.9.12-eclipse-temurin-25 AS builder

WORKDIR /build

COPY pom.xml .
RUN mvn dependency:go-offline -B

COPY src ./src
RUN mvn clean package -DskipTests -B

# =============================================================================
# STAGE 2 — RUNTIME
# =============================================================================
FROM eclipse-temurin:25-jre-noble

RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

WORKDIR /app

COPY --from=builder /build/target/*.jar app.jar
COPY src/main/resources/application-prod.yaml application.yml

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8081

ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-XX:+UseG1GC", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "app.jar"]