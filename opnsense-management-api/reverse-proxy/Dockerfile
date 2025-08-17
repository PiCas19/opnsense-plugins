FROM nginx:1.25-alpine

# utilità per healthcheck e SSL
RUN apk add --no-cache bash curl openssl

# entrypoint per generare SSL se mancano e avviare nginx
COPY nginx/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# log dir (monti anche volumi, ma assicuriamo esistenza)
RUN mkdir -p /var/log/nginx

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost/health >/dev/null 2>&1 || exit 1

CMD ["/entrypoint.sh"]