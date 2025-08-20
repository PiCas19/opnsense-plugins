FROM node:20-alpine3.20

LABEL maintainer="OPNsense Management API"
LABEL version="1.0.0"
LABEL description="REST API wrapper for OPNsense firewall management"

WORKDIR /app

# Utente non-root
RUN addgroup -g 1001 -S nodejs \
 && adduser -S opnsense -u 1001 -G nodejs

# --- Dependencies (con diagnostica dotenv) ---
COPY package.json package-lock.json* ./

# Mostra se dotenv è presente nel lock
RUN node -e "const lock=require('./package-lock.json'); \
 if(lock && lock.packages && lock.packages['node_modules/dotenv']) \
   console.log('dotenv entry nel lock:', lock.packages['node_modules/dotenv']); \
 else console.log('dotenv NON trovato nel lock');"

# Installa solo dipendenze production
RUN npm ci --omit=dev --silent || (echo 'npm ci failed' && exit 1)

# Verifica subito se dotenv è risolvibile
RUN node -e "console.log('cwd=',process.cwd()); \
 try{console.log('resolve dotenv=',require.resolve('dotenv'))} \
 catch(e){console.error('resolve dotenv FAIL'); process.exit(42)}" \
 || (echo 'dotenv non risolvibile → forzo install' \
      && npm install --no-save dotenv@17.2.1 --silent \
      && node -e \"console.log('after force install:', require.resolve('dotenv'))\")

# --- Codice applicativo ---
COPY src/ ./src/

# Dirs & permessi
RUN mkdir -p /app/logs /app/temp /app/certs \
 && chown -R opnsense:nodejs /app \
 && chmod -R 755 /app

USER opnsense

ENV NODE_ENV=production \
    PORT=3000 \
    NODE_PATH=/app/node_modules

EXPOSE 3000

CMD ["node", "src/app.js"]