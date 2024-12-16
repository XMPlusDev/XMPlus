# XMPlus
XMPlus backend v1.0.18

[Backend Documentation](https://docs.xmplus.dev/backend/install.html)

#### Config directory
```
cd /etc/XMPlus
```

### Onclick XMPlus backennd Install
```
bash <(curl -Ls https://raw.githubusercontent.com/XMPlusDev/XMPlus/scripts/install.sh)
```

### /etc/XMPlus/config.yml
```
Log:
  Level: none # Log level: none, error, warning, info, debug 
  AccessPath: # /etc/XMPlus/access.Log
  ErrorPath: # /etc/XMPlus/error.log
  MaskAddress: half # half, full, quarter
DnsConfigPath:  #/etc/XMPlus/dns.json
RouteConfigPath: # /etc/XMPlus/route.json
InboundConfigPath: # /etc/XMPlus/inbound.json
OutboundConfigPath: # /etc/XMPlus/outbound.json
ConnectionConfig:
  Handshake: 8 
  ConnIdle: 300 
  UplinkOnly: 0 
  DownlinkOnly: 0 
  BufferSize: 64
Nodes:
  -
    ApiConfig:
      ApiHost: "https://www.xyz.com"
      ApiKey: "123"
      NodeID: 1
      Timeout: 30 
      RuleListPath: # /etc/XMPlus/rulelist Path to local rulelist file
    ControllerConfig:
      EnableDNS: false # Use custom DNS config, Please ensure that you set the dns.json well
      DNSStrategy: AsIs # AsIs, UseIP, UseIPv4, UseIPv6
      CertConfig:
        Email: author@xmplus.dev                    # Required when Cert Mode is not none
        CertFile: /etc/XMPlus/node1.xmplus.dev.crt  # Required when Cert Mode is file
        KeyFile: /etc/XMPlus/node1.xmplus.dev.key   # Required when Cert Mode is file
        Provider: cloudflare                        # Required when Cert Mode is dns
        CertEnv:                                    # Required when Cert Mode is dns
          CLOUDFLARE_EMAIL:                         # Required when Cert Mode is dns
          CLOUDFLARE_API_KEY:                       # Required when Cert Mode is dns
      EnableFallback: false # Only support for Trojan and Vless
      FallBackConfigs:  # Support multiple fallbacks
        - SNI: # TLS SNI(Server Name Indication), Empty for any
          Alpn: # Alpn, Empty for any
          Path: # HTTP PATH, Empty for any
          Dest: 80 # Required, Destination of fallback, check https://xtls.github.io/config/features/fallback.html for details.
          ProxyProtocolVer: 0 # Send PROXY protocol version, 0 for disable
      IPLimit:
        Enable: false # Enable the global ip limit of a user 
        RedisNetwork: tcp # Redis protocol, tcp or unix
        RedisAddr: 127.0.0.1:6379 # Redis server address, or unix socket path
        RedisUsername: default # Redis username
        RedisPassword: YOURPASSWORD # Redis password
        RedisDB: 0 # Redis DB
        Timeout: 5 # Timeout for redis request
        Expiry: 60 # Expiry time (second) 
```

## XMPlus Panel Server configuration

### Network Settings

#### TCP
```
{
  "transport" : "tcp",
  "acceptProxyProtocol": false,
  "flow": "xtls-rprx-vision",
  "header": {
    "type": "none"
  }
}
```
#### TCP + HTTP
```
{
  "transport" : "tcp",
  "acceptProxyProtocol": false,
  "header": {
    "type": "http",
    "request": {
      "path": "/xmplus",
      "headers": {
        "Host": ["www.baidu.com", "www.taobao.com", "www.cloudflare.com"]
      }
    }
  }
}
```
####  WS
```
{
  "transport": "ws",
  "acceptProxyProtocol": false,
  "path": "/xmplus?ed=2560",
  "host": "hk1.xyz.com",
  "heartbeatperiod": 30,
  "cdn_host": "fakedomain.com"
}
```

####  GRPC
```
{
  "transport" : "grpc",
  "acceptProxyProtocol": false,
  "serviceName": "xmplus",
  "authority": "hk1.xyz.com"
}
```


####  KCP
```
{
  "transport" : "kcp",
  "acceptProxyProtocol": false,
  "congestion": false,
  "header": {
    "type": "none"
  },
  "seed": "password"
}
```

####  HTTPUPGRADE
```
{
  "transport" : "httpupgrade",
  "acceptProxyProtocol": false,
  "host": "hk1.xyz.com",
  "path": "/xmplus?ed=2560",
  "cdn_host": "fakedomain.com"
}
```

####  XHTTP / SPLITHTTP
```
{
  "transport" : "splithttp",
  "host": "hk1.xyz.com",
  "cdn_host": "fakedomain.com",
  "path": "/",
  "noSSEHeader": false,
  "noGRPCHeader": true,
  "mode": "auto" // "auto", "packet-up", "stream-up", "stream-one"
}
```

### Security Settings


#### TLS
```
{
  "serverName": "xmplus.dev",
  "rejectUnknownSni": false,
  "allowInsecure": false,
  "fingerprint": "chrome",
  "sni": "xmplus.dev",
  "curvepreferences": "X25519",
  "alpn": [
    "h2",
    "http/1.1"
  ]
}
```
#### REALITY

`Generate Private and Public Keys :   xmplus x25519`

```
{
  "show" : false,
  "dest": "www.cloudflare.com:443",
  "privatekey" : "yBaw532IIUNuQWDTncozoBaLJmcd1JZzvsHUgVPxMk8",
  "minclientver":"",
  "maxclientver":"",
  "maxtimediff":0,
  "proxyprotocol":0,
  "shortids" : [
    "6ba85179e30d4fc2"
  ],
  "serverNames": [
    "www.cloudflare.com"
  ],
  "fingerprint": "chrome",
  "spiderx": "",
  "publickey": "7xhH4b_VkliBxGulljcyPOH-bYUA2dl-XAdZAsfhk04"
}
```
