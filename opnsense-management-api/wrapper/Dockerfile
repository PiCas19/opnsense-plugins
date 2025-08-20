# Usa Node.js LTS su Alpine pin-ato (evita sorprese)
FROM node:20-alpine3.20

LABEL maintainer="OPNsense Management API"
LABEL version="1.0.0"
LABEL description="REST API wrapper for OPNsense firewall management"

# Working dir
WORKDIR /app

# Pacchetti di sistema minimi: curl, CA, timezone, tini (init)
# 1) prova mirror FRA1; 2) se fallisce, fallback su dl-cdn
RUN set -euo pipefail; \
  FRA1="https://mirror.fra1.de.leaseweb.net/alpine/v3.20"; \
  CDN="https://dl-cdn.alpinelinux.org/alpine/v3.20"; \
  printf '%s\n' "$FRA1/main" "$FRA1/community" > /etc/apk/repositories; \
  if ! apk add --no-cache curl ca-certificates tzdata tini; then \
    echo "FRA1 non disponibile, passo a dl-cdn"; \
    printf '%s\n' "$CDN/main" "$CDN/community" > /etc/apk/repositories; \
    apk add --no-cache curl ca-certificates tzdata tini; \
  fi

# Utente non-root
RUN addgroup -g 1001 -S nodejs \
 && adduser -S opnsense -u 1001 -G nodejs

# Dipendenze Node (solo produzione)
COPY package*.json ./
RUN npm ci --omit=dev \
 && npm cache clean --force \
 && rm -rf /tmp/* /var/tmp/*

# Sorgente applicazione
COPY src/ ./src/

# Dirs e permessi
RUN mkdir -p /app/logs /app/temp /app/certs \
 && chown -R opnsense:nodejs /app \
 && chmod -R 755 /app

# Ambiente e porta
ENV NODE_ENV=production \
    PORT=3000
EXPOSE 3000

# Healthcheck (usa curl installato sopra)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -fsS http://localhost:3000/api/v1/health || exit 1

# Usa tini come init process (percorso assoluto)
ENTRYPOINT ["/sbin/tini", "--"]
USER opnsense

# Comando di avvio
CMD ["node", "src/app.js"]