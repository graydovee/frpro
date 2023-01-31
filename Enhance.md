# frp Enhance

## Feature

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

### https_reverse_proxy

* use like type "http", function like "https2http" plugin
* support group

```ini
[https_web]
type = https_reverse_proxy
local_port = 4000
custom_domains=example.domain
tls_crts=publicKey1Base64,publicKey2Base64
tls_keys=privateKey1Base64,privateKey2Base64
group=xxx
group_key=xxx
```