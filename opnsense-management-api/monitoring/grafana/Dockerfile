FROM grafana/grafana:10.2.0

# Installa plugin JSON compatibili con Grafana 10.2.0
ENV GF_INSTALL_PLUGINS="marcusolsson-json-datasource,grafana-clock-panel"

# Configurazione per reverse proxy
ENV GF_SERVER_ROOT_URL="%(protocol)s://%(domain)s/grafana/"
ENV GF_SERVER_SERVE_FROM_SUB_PATH="true"

# Disabilita analytics
ENV GF_ANALYTICS_REPORTING_ENABLED="false"
ENV GF_ANALYTICS_CHECK_FOR_UPDATES="false"

USER grafana