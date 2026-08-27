FROM node:22.19.0-alpine
RUN corepack enable \
    && for attempt in 1 2 3; do \
      corepack install --global yarn@4.5.0 && break; \
      if [ "$attempt" = 3 ]; then exit 1; fi; \
      sleep $((attempt * 2)); \
    done
WORKDIR /app
COPY package.json yarn.lock .yarnrc.yml tsconfig.json ./
RUN yarn install --immutable
COPY src ./src
RUN yarn exec tsc
RUN addgroup -S app && adduser -S app -G app && chown -R app:app /app \
    && mkdir -p /shared /data && chown app:app /shared /data
ENV RELAY_IDENTITY_KEY_PATH=/shared/relay-identity.key \
    READINESS_PORT=9000
USER app
EXPOSE 9000 9001 9002
HEALTHCHECK --interval=3s --timeout=3s --retries=20 --start-period=5s \
  CMD node -e "fetch('http://127.0.0.1:9000/readyz').then((response) => process.exit(response.ok ? 0 : 1)).catch(() => process.exit(1))"
CMD ["node", "dist/index.js"]
