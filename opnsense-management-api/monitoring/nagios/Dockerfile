# Usa l'immagine ufficiale jasonrivers/nagios
FROM jasonrivers/nagios:latest

# Copia il file di configurazione personalizzato
COPY nagios.cfg /opt/nagios/etc/nagios.cfg

# Copia i plugin personalizzati
COPY plugins/ /opt/nagios/libexec/custom/

# Copia lo script di entrypoint
COPY docker-entrypoint.sh /docker-entrypoint.sh

# Rendi eseguibili i file
RUN chmod +x /opt/nagios/libexec/custom/*.sh || true && \
    chmod +x /docker-entrypoint.sh

# Crea directory necessarie e imposta permessi
RUN mkdir -p /opt/nagios/var/rw && \
    chown -R nagios:nagios /opt/nagios && \
    chmod -R 755 /opt/nagios

# Espone la porta 80
EXPOSE 80

ENTRYPOINT ["/docker-entrypoint.sh"]