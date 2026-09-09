FROM gradle@sha256:67b8c4bfd2b064e58a7307e2da1fc3881bc03ecc7a57cf61d8b570a02ebfaea2
USER root
RUN mkdir -p /opt/expertauth/logs /opt/expertauth/.started /run/expertauth && chown -R gradle:gradle /opt/expertauth
COPY --chown=gradle:gradle lib /opt/expertauth/lib
COPY --chown=gradle:gradle plugin /opt/expertauth/plugin
COPY --chown=gradle:gradle version.yaml /opt/expertauth/version.yaml
COPY --chown=gradle:gradle licenses /opt/expertauth/licenses
COPY --chown=root:root native /opt/expertauth/native
RUN mkdir -p /opt/expertauth/.native-tmp && chown gradle:gradle /opt/expertauth/.native-tmp && chmod 0700 /opt/expertauth/.native-tmp && chmod 0644 /opt/expertauth/native/*
USER gradle
WORKDIR /opt/expertauth
EXPOSE 3567
CMD ["sh", "/opt/expertauth/native/start.sh", "java", "-Xmx512m", "--add-opens=java.base/java.lang=ALL-UNNAMED", "--add-opens=java.base/java.util=ALL-UNNAMED", "--add-opens=java.base/java.util.concurrent=ALL-UNNAMED", "-cp", "/opt/expertauth/lib/*", "io.supertokens.Main", "/opt/expertauth", "configFile=/run/expertauth/config.yaml", "forceNoInMemDB=true"]

LABEL org.expertauth.firebase-scrypt.profile="bouncycastle-utf8-v1" org.expertauth.bouncycastle.version="1.85.2"
