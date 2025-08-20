# Pinna la versione Alpine per evitare cambi improvvisi del tag
FROM node:20-alpine3.20

WORKDIR /app

# Imposta esplicitamente i repository (scegline uno vicino; questo è Leaseweb)
RUN printf '%s\n' \
  "https://mirror.leaseweb.net/alpine/v3.20/main" \
  "https://mirror.leaseweb.net/alpine/v3.20/community" > /etc/apk/repositories

# Install con retry e senza update/upgrade
RUN set -eux; \
  for i in 1 2 3; do \
    apk add --no-cache curl ca-certificates tzdata dumb-init && break; \
    echo "apk add fallito, retry $i/3"; sleep 5; \
  done

# Utente non-root
RUN addgroup -g 1001 -S nodejs && \
    adduser -S opnsense -u 1001 -G nodejs

# Dipendenze Node
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force && rm -rf /tmp/* /var/tmp/*

# Sorgenti
COPY src/ ./src/

# Permessi e dirs
RUN mkdir -p /app/logs /app/temp && \
    chown -R opnsense:nodejs /app && chmod -R 755 /app

USER opnsense
EXPOSE 3000

ENV NODE_ENV=production
ENV PORT=3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -fsS http://localhost:3000/api/v1/health || exit 1

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "src/app.js"]