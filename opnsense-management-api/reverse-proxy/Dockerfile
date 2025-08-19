FROM nginx:1.25-alpine

# Versione dei repo Alpine (3.19 o 3.20 vanno bene)
ARG ALPINE_MAJOR=3.19

# Imposta i repository espliciti su HTTPS e fai update con retry
RUN set -eux; \
    echo "https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_MAJOR}/main" > /etc/apk/repositories; \
    echo "https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_MAJOR}/community" >> /etc/apk/repositories; \
    for i in 1 2 3; do apk update && break || { echo 'apk update retry...'; sleep 3; }; done; \
    apk add --no-cache openssl apache2-utils gettext bash

# Template + entrypoint (copiati nell'immagine)
COPY nginx/nginx.conf.template /etc/nginx/templates/nginx.conf.template
COPY nginx/entrypoint.sh /usr/local/bin/reverse-proxy-entrypoint

# Eseguibile e normalizzazione CRLF
RUN chmod +x /usr/local/bin/reverse-proxy-entrypoint \
 && sed -i 's/\r$//' /usr/local/bin/reverse-proxy-entrypoint

EXPOSE 80 443
ENTRYPOINT ["/usr/local/bin/reverse-proxy-entrypoint"]