package all

import (
	// The following are necessary as they register handlers in their init functions.

	_ "github.com/xmplusdev/xray-core/v25/app/proxyman/inbound"
	_ "github.com/xmplusdev/xray-core/v25/app/proxyman/outbound"

	// Required features. Can't remove unless there is replacements.
	// _ "github.com/xmplusdev/xray-core/v25/app/dispatcher"
	_ "github.com/XMPlusDev/XMPlus/app/dispatcher"

	// Default commander and all its services. This is an optional feature.
	_ "github.com/xmplusdev/xray-core/v25/app/commander"
	_ "github.com/xmplusdev/xray-core/v25/app/log/command"
	_ "github.com/xmplusdev/xray-core/v25/app/proxyman/command"
	_ "github.com/xmplusdev/xray-core/v25/app/stats/command"

	// Other optional features.
	_ "github.com/xmplusdev/xray-core/v25/app/dns"
	_ "github.com/xmplusdev/xray-core/v25/app/log"
	_ "github.com/xmplusdev/xray-core/v25/app/metrics"
	_ "github.com/xmplusdev/xray-core/v25/app/policy"
	_ "github.com/xmplusdev/xray-core/v25/app/reverse"
	_ "github.com/xmplusdev/xray-core/v25/app/router"
	_ "github.com/xmplusdev/xray-core/v25/app/stats"

	// Inbound and outbound proxies.
	_ "github.com/xmplusdev/xray-core/v25/proxy/blackhole"
	_ "github.com/xmplusdev/xray-core/v25/proxy/dns"
	_ "github.com/xmplusdev/xray-core/v25/proxy/dokodemo"
	_ "github.com/xmplusdev/xray-core/v25/proxy/freedom"
	_ "github.com/xmplusdev/xray-core/v25/proxy/http"
	_ "github.com/xmplusdev/xray-core/v25/proxy/shadowsocks"
	_ "github.com/xmplusdev/xray-core/v25/proxy/shadowsocks_2022"
	_ "github.com/xmplusdev/xray-core/v25/proxy/socks"
	_ "github.com/xmplusdev/xray-core/v25/proxy/trojan"
	_ "github.com/xmplusdev/xray-core/v25/proxy/vless/inbound"
	_ "github.com/xmplusdev/xray-core/v25/proxy/vless/outbound"
	_ "github.com/xmplusdev/xray-core/v25/proxy/vmess/inbound"
	_ "github.com/xmplusdev/xray-core/v25/proxy/vmess/outbound"
	_ "github.com/xmplusdev/xray-core/v25/proxy/wireguard"
	_ "github.com/xmplusdev/xray-core/v25/proxy/tun"
	_ "github.com/xmplusdev/xray-core/v25/proxy/hysteria"

	// Transports
	_ "github.com/xmplusdev/xray-core/v25/transport/internet/kcp"
	_ "github.com/xmplusdev/xray-core/v25/transport/internet/tcp"
	_ "github.com/xmplusdev/xray-core/v25/transport/internet/tls"
	_ "github.com/xmplusdev/xray-core/v25/transport/internet/udp"
	_ "github.com/xmplusdev/xray-core/v25/transport/internet/websocket"
	_ "github.com/xmplusdev/xray-core/v25/transport/internet/reality"
	_ "github.com/xmplusdev/xray-core/v25/transport/internet/httpupgrade"
	_ "github.com/xmplusdev/xray-core/v25/transport/internet/splithttp"
	_ "github.com/xmplusdev/xray-core/v25/transport/internet/grpc"

	// Transport headers
	_ "github.com/xmplusdev/xray-core/v25/transport/internet/headers/http"
	_ "github.com/xmplusdev/xray-core/v25/transport/internet/headers/noop"
	_ "github.com/xmplusdev/xray-core/v25/transport/internet/headers/srtp"
	_ "github.com/xmplusdev/xray-core/v25/transport/internet/headers/tls"
	_ "github.com/xmplusdev/xray-core/v25/transport/internet/headers/utp"
	_ "github.com/xmplusdev/xray-core/v25/transport/internet/headers/wechat"
	_ "github.com/xmplusdev/xray-core/v25/transport/internet/headers/wireguard"

	// JSON & TOML & YAML
	_ "github.com/xmplusdev/xray-core/v25/main/json"
	_ "github.com/xmplusdev/xray-core/v25/main/toml"
	_ "github.com/xmplusdev/xray-core/v25/main/yaml"

	// Load config from file or http(s)
	_ "github.com/xmplusdev/xray-core/v25/main/confloader/external"

	// Commands
	_ "github.com/xmplusdev/xray-core/v25/main/commands/all"
)
