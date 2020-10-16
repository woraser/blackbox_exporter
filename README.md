# Blackbox exporter [![Build Status](https://travis-ci.org/woraser/blackbox_exporter.svg?branch=master)](https://travis-ci.org/woraser/blackbox_exporter)
[Source code](https://github.com/prometheus/blackbox_exporter/)


## Changes

### 1. Add new protocol: UDP 

The additional config for UDP Protocol.
* return error:i/o timeout if udp server return nil
* return error:read connection refused if udp server closed
```yaml
# required. ip4 or ip6
preferred_ip_protocol: "ip4" 
ip_protocol_fallback: false
source_ip_address: "127.0.0.1"  
query_response: []query_response
```

### 2. Update probe api
[Config Structure](https://github.com/woraser/blackbox_exporter/blob/master/config/config.go)
```
Method: GET
Path: {host:ip}/probe
Headers: Content-type: application/json
Query params:
# (required) the protocol for what defined in configle,example: UDP.
module: "" 
# (required) the target for probe,example: 127.0.0.1.
target: ""
# (required base64_encode) the json object of config for probe. See `Config Structure`.
# example: {
#            "method": "POST",
#            "preferred_ip_protocol": "ip4"
#          }
# convert to base64:ew0KIm1ldGhvZCI6ICJQT1NUIiwNCiJwcmVmZXJyZWRfaXBfcHJvdG9jb2wiOiAiaXA0Ig0KfQ==
config: "ew0KIm1ldGhvZCI6ICJQT1NUIiwNCiJwcmVmZXJyZWRfaXBfcHJvdG9jb2wiOiAiaXA0Ig0KfQ=="
```
