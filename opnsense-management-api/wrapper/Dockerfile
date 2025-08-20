# Usa Node.js LTS con Alpine per dimensioni ridotte
FROM node:20-alpine

# Metadata
LABEL maintainer="OPNsense Management API"
LABEL version="1.0.0"
LABEL description="REST API wrapper for OPNsense firewall management"

# Imposta working directory
WORKDIR /app

# Configura mirror alternativo per Alpine
RUN echo "http://nl.alpinelinux.org/alpine/v3.22/main" > /etc/apk/repositories && \
    echo "http://nl.alpinelinux.org/alpine/v3.22/community" >> /etc/apk/repositories

# Installa dipendenze di sistema minime
RUN apk update && apk upgrade && \
    apk add --no-cache \
        curl \
        ca-certificates \
        tzdata \
        dumb-init \
    && rm -rf /var/cache/apk/*

# Crea utente non-root per sicurezza
RUN addgroup -g 1001 -S nodejs && \
    adduser -S opnsense -u 1001 -G nodejs

# Copia package files per layer caching ottimale
COPY package*.json ./

# Installa solo dipendenze di produzione
RUN npm ci --omit=dev && \
    npm cache clean --force && \
    rm -rf /tmp/* /var/tmp/*

# Copia codice sorgente
COPY src/ ./src/

# Crea directory per logs e temp files
RUN mkdir -p /app/logs /app/temp && \
    chown -R opnsense:nodejs /app && \
    chmod -R 755 /app

# Cambia all'utente non-root
USER opnsense

# Espone porta dell'applicazione
EXPOSE 3000

# Imposta variabili ambiente di default
ENV NODE_ENV=production
ENV PORT=3000

# Healthcheck integrato nel container
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:3000/api/v1/health || exit 1

# Usa dumb-init per gestire segnali correttamente
ENTRYPOINT ["dumb-init", "--"]

# Comando di avvio
CMD ["node", "src/app.js"]