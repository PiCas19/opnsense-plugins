# Pin del tag per evitare cambi Alpine improvvisi
FROM node:20-alpine3.20

LABEL maintainer="OPNsense Management API"
LABEL version="1.0.0"
LABEL description="REST API wrapper for OPNsense firewall management"

WORKDIR /app

# Pacchetti di sistema (senza update/upgrade)
RUN apk add --no-cache \
    curl \
    ca-certificates \
    tzdata \
    dumb-init

# Utente non-root
RUN addgroup -g 1001 -S nodejs && \
    adduser -S opnsense -u 1001 -G nodejs

# Dipendenze Node
COPY package*.json ./
RUN npm ci --omit=dev && \
    npm cache clean --force && \
    rm -rf /tmp/* /var/tmp/*

# Sorgenti
COPY src/ ./src/

# Permessi e dirs
RUN mkdir -p /app/logs /app/temp && \
    chown -R opnsense:nodejs /app && \
    chmod -R 755 /app

USER opnsense
EXPOSE 3000

ENV NODE_ENV=production
ENV PORT=3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:3000/api/v1/health || exit 1

ENTRYPOINT ["dumb-in]()