FROM node:20-alpine3.20
WORKDIR /app

# imposta il mirror FRA1 e installa in un colpo solo
RUN set -eux; \
  base="https://mirror.fra1.de.leaseweb.net/alpine/v3.20"; \
  printf '%s\n' "$base/main" "$base/community" > /etc/apk/repositories; \
  apk add --no-cache curl ca-certificates tzdata tini

# utente non-root
RUN addgroup -g 1001 -S nodejs && adduser -S opnsense -u 1001 -G nodejs

COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force && rm -rf /tmp/* /var/tmp/*

COPY src/ ./src/
RUN mkdir -p /app/logs /app/temp && chown -R opnsense:nodejs /app && chmod -R 755 /app

USER opnsense
EXPOSE 3000
ENV NODE_ENV=production PORT=3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -fsS http://localhost:3000/api/v1/health || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "src/app.js"]
