FROM node:20-alpine3.20
WORKDIR /app

RUN addgroup -g 1001 -S nodejs && adduser -S opnsense -u 1001 -G nodejs

COPY package.json package-lock.json* ./
RUN npm i --package-lock-only --silent \
 && npm ci --omit=dev --silent \
 && node -e "console.log('dotenv path:', require.resolve('dotenv'))"

COPY src/ ./src/

RUN mkdir -p /app/logs /app/temp /app/certs \
 && chown -R opnsense:nodejs /app && chmod -R 755 /app

USER opnsense
ENV NODE_ENV=production PORT=3000 NODE_PATH=/app/node_modules
EXPOSE 3000
CMD ["node", "src/app.js"]