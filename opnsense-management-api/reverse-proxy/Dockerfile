FROM nginx:1.25-alpine

# Fallback mirror: alcuni ambienti hanno problemi con dl-cdn
RUN sed -i -e 's#https://dl-cdn.alpinelinux.org#https://mirror.cloudflare.alpinelinux.org#g' /etc/apk/repositories \
 || sed -i -e 's#https://dl-cdn.alpinelinux.org#http://dl-2.alpinelinux.org#g' /etc/apk/repositories

# solo quello che serve all’entrypoint e all’healthcheck
RUN apk update && apk add --no-cache curl openssl && rm -rf /var/cache/apk/*

# entrypoint
COPY nginx/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# log dir
RUN mkdir -p /var/log/nginx

EXPOSE 80 443

# ATTENZIONE: il tuo server 80 fa redirect a 443 -> usa HTTPS e -k
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD curl -kfsS https://localhost/health >/dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]