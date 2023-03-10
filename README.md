# frp Enhance

[Frp README](README_en.md) | [Frp 中文文档](README_zh.md)

## Feature
- [x] support config tls in config file
- [x] https support group
- [x] support redirect
- [ ] support exact location
- [ ] support multi server

## Guide

### https plugin enhance

* "https2http" and "https2https" support config tls in config file

```ini
[https_web]
custom_domains=example.domain
locations=/
plugin=https2http
plugin_crt_base64=
plugin_key_base64=
plugin_local_addr=gitea-http.git.svc.cluster.local:3000
type=https
```

### server_https

* use like type "http", function like "https2http" plugin
* support group

```ini
[https_web]
type = server_https
local_port = 4000
custom_domains=example.domain
tls_crts=publicKey1Base64,publicKey2Base64
tls_keys=privateKey1Base64,privateKey2Base64
group=xxx
group_key=xxx
```

### http redirect
```ini
[http_redirect]
type = http
local_port = 80
custom_domains = example.domain
group=test
group_key=test
redirect=https://example.domain:443
```