# Usa un’immagine consolidata di Nagios Core
FROM jasonrivers/nagios:latest

# Copia configurazioni personalizzate e plugin
COPY nagios.cfg /opt/nagios/etc/nagios.cfg
COPY plugins/ /opt/nagios/libexec/custom/

# Permessi
RUN chmod +x /opt/nagios/libexec/custom/*.sh || true