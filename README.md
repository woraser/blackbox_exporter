# Blackbox exporter [![Build Status](https://travis-ci.org/prometheus/blackbox_exporter.svg)][travis]
[Source code](https://github.com/prometheus/blackbox_exporter/)


## Customized Changes

### 1. Add UDP Protocol

The additional config for UDP Protocol.
```yaml
# required. ip4 or ip6
preferred_ip_protocol: "ip4" 
ip_protocol_fallback: false
source_ip_address: "127.0.0.1"
# required. 
connect_response:
  send: "text"
  expect: "text"
query_response:
  - send: "text"
    expect: "text"
  - send: "text"
    expect: "text"    
```
