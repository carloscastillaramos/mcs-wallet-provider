FROM eclipse-temurin:21-jre
RUN groupadd --system --gid 10001 wallet && \
    useradd --system --uid 10001 --gid 10001 --home /nonexistent wallet
WORKDIR /app
COPY --chown=10001:10001 target/mcs-wallet-provider.jar /app/app.jar
ENV JAVA_TOOL_OPTIONS="-Duser.timezone=UTC -Djava.io.tmpdir=/tmp -XX:MaxRAMPercentage=70"
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
