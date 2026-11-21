FROM grafana/grafana:11.6.0
# Configuración incluida en la imagen (sin bind mounts) para que también funcione desde Jenkins.
COPY provisioning /etc/grafana/provisioning
COPY dashboards /var/lib/grafana/dashboards
