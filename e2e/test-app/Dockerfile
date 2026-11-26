FROM node:26.13.1-alpine AS build
RUN npm install --global corepack@0.36.0 && corepack enable
WORKDIR /app
COPY package.json yarn.lock .yarnrc.yml ./
RUN yarn install --immutable --mode=skip-build
COPY app.js build.js index.html ./
RUN yarn build

FROM node:26.13.1-alpine
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY entrypoint.sh ./
COPY serve.mjs ./
RUN chmod +x entrypoint.sh
RUN addgroup -S app && adduser -S app -G app && chown -R app:app /app
USER app
EXPOSE 3000
CMD ["./entrypoint.sh"]
