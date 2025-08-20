FROM node:20-alpine3.20

LABEL maintainer="OPNsense Management API"
LABEL version="1.0.0"
LABEL description="REST API wrapper for OPNsense firewall management"

WORKDIR /app

# Utente non-root
RUN addgroup -g 1001 -S nodejs \
 && adduser -S opnsense -u 1001 -G nodejs

# Dipendenze prod
COPY package*.json ./
RUN npm ci --omit=dev \
 && npm cache clean --force \
 && rm -rf /tmp/* /var/tmp/*

# Codice
COPY src/ ./src/

# Dirs & permessi
RUN mkdir -p /app/logs /app/temp /app/certs \
 && chown -R opnsense:nodejs /app \
 && chmod -R 755 /app

USER opnsense

ENV NODE_ENV=production \
    PORT=3000

EXPOSE 3000

# NIENTE entrypoint/apt/apk/ curl
CMD ["node", "src/app.js"]