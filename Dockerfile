# ── Stage 1: Build ──────────────────────────────────────────────
FROM gradle:8.5-jdk17 AS build

WORKDIR /app

# Copy Gradle config first (layer caching for dependencies)
COPY build.gradle settings.gradle ./

# Download dependencies (cached unless build files change)
RUN gradle dependencies --no-daemon || true

# Copy source code
COPY src/ src/

# Build the JAR
RUN gradle jar --no-daemon

# ── Stage 2: Export artifact ───────────────────────────────────
FROM scratch AS artifact
COPY --from=build /app/build/libs/BlackMarker-1.0.0.jar /BlackMarker-1.0.0.jar
