
#### Config directory
```
cd /etc/XMPlus
```

### Onclick Install
```
bash <(curl -Ls https://raw.githubusercontent.com/XMPlusDev/XMPlus/install/install.sh)
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
        "Host": "x.tld.com"
      }
    }
  }
}
```
####  WS
```
{
  "transport" : "ws",
  "acceptProxyProtocol": false,
  "path": "/xmplus",
  "headers": {
    "Host": "x.tld.com"
  }
}
```

####  H2
```
{
  "transport" : "h2",
  "acceptProxyProtocol": false,
  "host": "x.tld.com",
  "path": "/xmplus"
}
```

####  GRPC
```
{
  "transport" : "grpc",
  "acceptProxyProtocol": false,
  "serviceName": "xmplus"
}
```
####  QUIC
```
{
  "transport" : "quic",
  "acceptProxyProtocol": false,
  "security": "none",
  "key": "",
  "header": {
    "type": "none"
  }
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

### Security Settings


#### TLS
```
{
  "serverName": "xmplus.dev",
  "rejectUnknownSni": true,
  "allowInsecure": false,
  "fingerprint": "chrome",
}
```
#### REALITY
```
{
  "show" : false,
  "dest": "www.lovelive-anime.jp:443",
  "privatekey" : "yBaw532IIUNuQWDTncozoBaLJmcd1JZzvsHUgVPxMk8",
  "minclientver":"",
  "maxclientver":"",
  "maxtimediff":0,
  "proxyprotocol":0,
  "shortids" : [
    "6ba85179e30d4fc2"
  ],
  "serverNames": [
    "www.lovelive-anime.jp",
    "www.cloudflare.com"
  ],
  "fingerprint": "chrome",
  "spiderx": "",
  "publickey": "7xhH4b_VkliBxGulljcyPOH-bYUA2dl-XAdZAsfhk04"
}
```
