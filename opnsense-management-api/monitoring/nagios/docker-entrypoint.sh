#!/bin/bash
set -e

# Log function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting Nagios container..."

# Configure user if specified by environment variables
if [[ -n "${NAGIOS_USER}" ]] && [[ -n "${NAGIOS_PASS}" ]]; then
    log "Configuring Nagio user ${NAGIOS_USER}"
    htpasswd -cb /opt/nagios/etc/htpasswd.users "${NAGIOS_USER}" "${NAGIOS_PASS}"
else
    log "Using default credentials: nagiosadmin/nagiosadmin"
    htpasswd -cb /opt/nagios/etc/htpasswd.users nagiosadmin nagiosadmin
fi

# Check that the configuration file exists
if [[ ! -f /opt/nagios/etc/nagios.cfg ]]; then
    log "ERROR: Configuration file /opt/nagios/etc/nagios.cfg not found!"
    exit 1
fi

# Check Nagios configuration
log "Checking Nagios configuration..."
if ! /opt/nagios/bin/nagios -v /opt/nagios/etc/nagios.cfg; then
    log "ERROR: Invalid Nagios configuration!"
    exit 1
fi

# Set correct permissions
log "Setting permissions..."
chown -R nagios:nagios /opt/nagios/var || true
chmod -R 755 /opt/nagios/var || true
chmod 600 /opt/nagios/etc/htpasswd.users || true

# Start Apache if it is not already running
if ! pgrep apache2 > /dev/null; then
    log "Starting Apache..."
    /etc/init.d/apache2 start || service apache2 start
fi

# Start Nagios
log "Starting Nagios Core..."
exec /opt/nagios/bin/nagios /opt/nagios/etc/nagios.cfg