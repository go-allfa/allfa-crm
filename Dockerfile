FROM node:22-alpine

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    DB_PATH=/app/data/crm.sqlite

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY src ./src
COPY public ./public
COPY scripts ./scripts

# Roda sem privilégios de root; o banco fica num volume.
RUN mkdir -p /app/data && chown -R node:node /app/data
USER node
VOLUME ["/app/data"]
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:3000/ >/dev/null || exit 1
CMD ["node", "--disable-warning=ExperimentalWarning", "src/server.js"]
