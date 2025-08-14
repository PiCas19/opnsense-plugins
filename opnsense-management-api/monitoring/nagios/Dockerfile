FROM jasonrivers/nagios:latest

# Imposta utente root per modifiche
USER root

# Copia file di configurazione
COPY nagios.cfg /opt/nagios/etc/nagios.cfg

# Copia plugins con gestione errori
COPY plugins/ /opt/nagios/libexec/custom/

# Copia script entrypoint
COPY docker-entrypoint.sh /docker-entrypoint.sh

# Fix permessi con gestione errori robusta
RUN mkdir -p /opt/nagios/libexec/custom && \
    mkdir -p /opt/nagios/var/rw && \
    chmod +x /docker-entrypoint.sh && \
    find /opt/nagios/libexec/custom -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true && \
    chown -R nagios:nagios /opt/nagios || true

ENTRYPOINT ["/docker-entrypoint.sh"]