FROM nginx:1.25-alpine

# Tooling: bash, openssl (cert), apache2-utils (htpasswd), gettext (envsubst)
RUN apk add --no-cache bash openssl apache2-utils gettext

# Template e entrypoint
COPY nginx/nginx.conf.template /etc/nginx/templates/nginx.conf.template
COPY nginx/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 443
CMD ["/entrypoint.sh"]