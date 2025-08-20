FROM node:20-alpine3.20

LABEL maintainer="OPNsense Management API"
LABEL version="1.0.0"
LABEL description="REST API wrapper for OPNsense firewall management"

WORKDIR /app

# utente non-root
RUN addgroup -g 1001 -S nodejs && adduser -S opnsense -u 1001 -G nodejs

# ---- deps (diagnostica + fallback) ----
COPY package.json package-lock.json* ./

# (facoltativo) stampa l'entry del lock per dotenv
RUN node -e "const l=require('./package-lock.json'); \
  const e=l && l.packages && l.packages['node_modules/dotenv']; \
  console.log('lock dotenv entry:', e || 'NONE');"

# installa solo deps prod
RUN npm ci --omit=dev --silent

# prova a risolvere dotenv; se fallisce, forza install e riprova
RUN set -eux; \
  node -e "console.log('cwd=',process.cwd()); \
           try{console.log('resolve dotenv =',require.resolve('dotenv'))} \
           catch(e){process.exit(42)}" \
  || { \
       echo 'dotenv non risolvibile: eseguo npm install --no-save dotenv@17.2.1'; \
       npm install --no-save dotenv@17.2.1 --silent; \
       node -e "console.log('after install, resolve =', require.resolve('dotenv'))"; \
     }

# ---- codice ----
COPY src/ ./src/

# dirs & permessi
RUN mkdir -p /app/logs /app/temp /app/certs \
 && chown -R opnsense:nodejs /app \
 && chmod -R 755 /app

USER opnsense

ENV NODE_ENV=production \
    PORT=3000 \
    NODE_PATH=/app/node_modules

EXPOSE 3000
CMD ["node", "src/app.js"]