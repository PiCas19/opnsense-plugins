FROM grafana/grafana:10.2.0

# Installa un SOLO plugin JSON. Scegliamo marcusolsson-json-datasource
ENV GF_INSTALL_PLUGINS="marcusolsson-json-datasource,grafana-clock-panel"

# (Opzionale) se servi Grafana sotto /grafana via Nginx
# ENV GF_SERVER_ROOT_URL="%(protocol)s://%(domain)s/grafana"
# ENV GF_SERVER_SERVE_FROM_SUB_PATH="true"