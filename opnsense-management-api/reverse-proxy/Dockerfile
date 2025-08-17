FROM nginx:1.25-alpine

# utilità per healthcheck e SSL
RUN apk add --no-cache bash curl openssl

# entrypoint che genera SSL se mancano e avvia nginx (lo lancia Docker, NON tu)
COPY nginx/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# dir log (persistenti via volume)
RUN mkdir -p /var/log/nginx

EXPOSE 80 443

# healthcheck usa curl (già installato) e l'endpoint /health del tuo nginx.conf
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost/health >/dev/null || exit 1

# usa entrypoint (non CMD) così non parte il default di nginx
ENTRYPOINT ["/entrypoint.sh"]