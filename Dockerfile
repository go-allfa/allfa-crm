FROM node:22-alpine

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    DB_PATH=/app/data/crm.sqlite

WORKDIR /app
COPY package.json package-lock.json ./
RUN apk add --no-cache su-exec && npm ci --omit=dev && npm cache clean --force
COPY src ./src
COPY public ./public
COPY scripts ./scripts

# O banco fica num volume. Volumes novos (ex.: Fly.io) vêm com dono root, então o
# container ajusta a permissão da pasta e só então roda a aplicação sem privilégios.
RUN mkdir -p /app/data && chown -R node:node /app/data
VOLUME ["/app/data"]
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:3000/ >/dev/null || exit 1
CMD ["sh", "-c", "chown -R node:node /app/data && exec su-exec node node --disable-warning=ExperimentalWarning src/server.js"]
