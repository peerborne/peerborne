FROM node:22-alpine AS build
RUN corepack enable
WORKDIR /app
COPY package.json yarn.lock .yarnrc.yml ./
RUN yarn install --immutable --mode=skip-build
COPY . .
RUN yarn build

FROM node:22-alpine
RUN npm install -g serve
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY entrypoint.sh ./
RUN chmod +x entrypoint.sh
RUN addgroup -S app && adduser -S app -G app && chown -R app:app /app
USER app
EXPOSE 3000
CMD ["./entrypoint.sh"]
