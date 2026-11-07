FROM node:24.22.2-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json vitest.config.ts ./
COPY web ./web
COPY src ./src
COPY contracts ./contracts
COPY scripts ./scripts
RUN npm ci --include=optional --ignore-scripts
RUN npm run build
RUN find src -name '*.test.ts' -delete
RUN rm -rf src/saas/testing src/testing

FROM node:24.22.2-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3000
ENV NODE_OPTIONS=--enable-source-maps
COPY --chown=node:node package.json package-lock.json ./
COPY --chown=node:node web/package.json ./web/package.json
COPY --chown=node:node LICENSE.txt LICENSE-APACHE-2.0.txt NOTICE.md ./
RUN npm ci --omit=dev --include=optional --ignore-scripts
COPY --chown=node:node --from=build /app/src ./src
COPY --chown=node:node --from=build /app/catalog ./catalog
COPY --chown=node:node --from=build /app/dist/web-saas ./dist/web-saas
COPY --chown=node:node --from=build /app/scripts/saas-migrate.ts ./scripts/saas-migrate.ts
COPY --chown=node:node --from=build /app/scripts/saas-backfill-connections.ts ./scripts/saas-backfill-connections.ts
EXPOSE 3000
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget --spider -q http://127.0.0.1:3000/ready || exit 1
USER node
CMD ["node", "--experimental-transform-types", "src/saas/index.ts"]
