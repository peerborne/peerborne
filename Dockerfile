FROM node:22.19-alpine AS builder

RUN apk update && apk add dos2unix

RUN mkdir -p /app
WORKDIR /app

# Setup package dependencies
COPY package.json /app/package.json
COPY yarn.lock /app/yarn.lock
COPY .yarnrc.yml /app/.yarnrc.yml
RUN mkdir -p /app/.yarn
COPY .yarn/releases /app/.yarn/releases
RUN mkdir -p /app/packages/core
RUN mkdir -p /app/packages/automerge
RUN mkdir -p /app/packages/yjs
RUN mkdir -p /app/packages/react
RUN mkdir -p /app/packages/redux
RUN mkdir -p /app/packages/index
RUN mkdir -p /app/examples/browser-test
RUN mkdir -p /app/examples/wiki-swarm
RUN mkdir -p /app/examples/password-manager
COPY packages/core/package.json /app/packages/core/package.json
COPY packages/automerge/package.json /app/packages/automerge/package.json
COPY packages/yjs/package.json /app/packages/yjs/package.json
COPY packages/react/package.json /app/packages/react/package.json
COPY packages/redux/package.json /app/packages/redux/package.json
COPY packages/index/package.json /app/packages/index/package.json
COPY examples/browser-test/package.json /app/examples/browser-test/package.json
COPY examples/wiki-swarm/package.json /app/examples/wiki-swarm/package.json
COPY examples/password-manager/package.json /app/examples/password-manager/package.json
RUN yarn install

FROM node:22.19-alpine
ENV SKIP_PREFLIGHT_CHECK=true
RUN mkdir -p /app
COPY --from=builder /app /app
WORKDIR /app

# Build all packages
COPY packages/core/. /app/packages/core/
RUN yarn workspace @peerborne/core run tsc

COPY packages/automerge/. /app/packages/automerge/
RUN yarn workspace @peerborne/automerge run tsc
# RUN yarn workspace @peerborne/automerge link -A
# RUN chmod +x /usr/local/bin/peerborne-automerge-d

COPY packages/yjs/. /app/packages/yjs/
RUN yarn workspace @peerborne/yjs run tsc
# RUN yarn workspace @peerborne/yjs link -A
# RUN chmod +x /usr/local/bin/peerborne-yjs-d

COPY packages/react/. /app/packages/react/
RUN yarn workspace @peerborne/react run tsc

COPY packages/redux/. /app/packages/redux/
RUN yarn workspace @peerborne/redux run tsc

COPY examples/browser-test/. /app/examples/browser-test/
COPY examples/wiki-swarm/. /app/examples/wiki-swarm/

COPY wait-for-file.sh /app/wait-for-file.sh
RUN chmod +x /app/wait-for-file.sh
RUN dos2unix /app/wait-for-file.sh

WORKDIR /app
RUN chown -R node:node /app
USER node
CMD ["node", "packages/automerge/dist/esm/bin/peerborne-automerge-d.js"]
