FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json vitest.config.ts ./
COPY web ./web
COPY src ./src
COPY scripts ./scripts
RUN npm ci --include=optional --ignore-scripts
RUN npm run build
RUN find src -name '*.test.ts' -delete

FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3000
ENV NODE_OPTIONS=--enable-source-maps
COPY --chown=node:node package.json package-lock.json ./
COPY --chown=node:node web/package.json ./web/package.json
COPY --chown=node:node --from=build /app/src ./src
COPY --chown=node:node --from=build /app/catalog ./catalog
COPY --chown=node:node --from=build /app/dist ./dist
COPY --chown=node:node --from=build /app/scripts/saas-migrate.ts ./scripts/saas-migrate.ts
COPY --chown=node:node --from=build /app/scripts/saas-backfill-connections.ts ./scripts/saas-backfill-connections.ts
RUN npm ci --omit=dev --ignore-scripts
EXPOSE 3000
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget --spider -q http://127.0.0.1:3000/ready || exit 1
USER node
CMD ["node", "src/saas/index.ts"]
