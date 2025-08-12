# Base LTS aggiornata
FROM node:20-alpine

WORKDIR /app

# Dipendenze di sistema minime
RUN apk update && apk upgrade && \
    apk add --no-cache \
      curl \
      ca-certificates \
      tzdata \
    && rm -rf /var/cache/apk/*

# Utente non-root
RUN addgroup -g 1001 -S nodejs && \
    adduser -S opnsense -u 1001 -G nodejs

# Copia manifest e installa solo deps di produzione
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copia sorgenti e docs
COPY src/ ./src/
COPY docs/ ./docs/

# Directory runtime
RUN mkdir -p /app/logs /app/temp && \
    chown -R opnsense:nodejs /app

USER opnsense

EXPOSE 3000

# Healthcheck dell'app (lato immagine; puoi tenerlo anche nel compose)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/api/v1/health || exit 1

CMD ["node", "src/app.js"]
