# Node LTS su Alpine pin-ato (evita sorprese)
FROM node:20-alpine3.20

LABEL maintainer="OPNsense Management API"
LABEL version="1.0.0"
LABEL description="REST API wrapper for OPNsense firewall management"

WORKDIR /app

# Pacchetti minimi (senza apk update/upgrade)
# --no-cache scarica gli indici freschi in modo atomico
RUN apk add --no-cache \
    curl \
    ca-certificates \
    tzdata

# Utente non-root
RUN addgroup -g 1001 -S nodejs \
 && adduser -S opnsense -u 1001 -G nodejs

# Dipendenze Node (solo produzione)
COPY package*.json ./
RUN npm ci --omit=dev \
 && npm cache clean --force \
 && rm -rf /tmp/* /var/tmp/*

# Codice sorgente
COPY src/ ./src/

# Dirs e permessi
RUN mkdir -p /app/logs /app/temp /app/certs \
 && chown -R opnsense:nodejs /app \
 && chmod -R 755 /app

# Env & porta
ENV NODE_ENV=production \
    PORT=3000
EXPOSE 3000

# L’init è gestito dal runtime (compose: init: true)
USER opnsense

# Avvio
CMD ["node", "src/app.js"]