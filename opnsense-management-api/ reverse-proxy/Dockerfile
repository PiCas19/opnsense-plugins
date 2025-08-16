FROM nginx:1.25-alpine

# Install curl for health checks
RUN apk add --no-cache curl

# Create directories for logs and SSL
RUN mkdir -p /var/log/nginx /etc/ssl/nginx

# Copy configuration files
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/htpasswd /etc/nginx/htpasswd

# Copy and run SSL certificate generation script
COPY nginx/ssl/generate-ssl.sh /tmp/generate-ssl.sh
RUN chmod +x /tmp/generate-ssl.sh && /tmp/generate-ssl.sh

# Expose ports
EXPOSE 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost/health || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]