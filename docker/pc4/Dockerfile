FROM kathara/base

# This installs Grafana v8.3.0-beta2
# https://grafana.com/grafana/download/8.3.0-beta2?edition=oss
RUN apt-get update \
    && apt-get install -y adduser libfontconfig1 musl \
    && wget https://dl.grafana.com/oss/release/grafana_8.3.0~beta2_amd64.deb \
    && dpkg -i grafana_8.3.0~beta2_amd64.deb \