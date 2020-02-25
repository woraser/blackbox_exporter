# Blackbox exporter [![Build Status](https://travis-ci.org/prometheus/blackbox_exporter.svg)][travis]
[Source code](https://github.com/prometheus/blackbox_exporter/)


## Customized Changes

### 1. Add UDP Protocol

The additional config for UDP Protocol.
* return error:i/o timeout if udp server return nil
* return error:read connection refused if udp server closed
```yaml
# required. ip4 or ip6
preferred_ip_protocol: "ip4" 
ip_protocol_fallback: false
source_ip_address: "127.0.0.1"  
```
