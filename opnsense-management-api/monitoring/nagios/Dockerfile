FROM jasonrivers/nagios:latest

# Mantieni l'utente originale dell'immagine
USER root

# Copia solo la configurazione personalizzata
COPY nagios.cfg /opt/nagios/etc/nagios.cfg

# Copia i plugin nella directory (NOTA: destinazione DEVE finire con /)
COPY plugins/ /opt/nagios/libexec/custom/

# Imposta permessi minimi necessari
RUN chmod 644 /opt/nagios/etc/nagios.cfg && \
    find /opt/nagios/libexec/custom -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true