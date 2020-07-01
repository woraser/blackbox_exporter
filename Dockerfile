FROM scratch

# build cmd:CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o blackbox_exporter .
COPY blackbox_exporter  /bin/blackbox_exporter
COPY blackbox.yml       /etc/blackbox_exporter/config.yml

EXPOSE      9115
ENTRYPOINT  [ "/bin/blackbox_exporter" ]
CMD         [ "--config.file=/etc/blackbox_exporter/config.yml" ]
