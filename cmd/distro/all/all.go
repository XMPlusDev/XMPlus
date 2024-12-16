package all

import (
	// The following are necessary as they register handlers in their init functions.

	_ "github.com/xmplusdev/xray-core/v24/app/proxyman/inbound"
	_ "github.com/xmplusdev/xray-core/v24/app/proxyman/outbound"

	// Required features. Can't remove unless there is replacements.
	// _ "github.com/xmplusdev/xray-core/v24/app/dispatcher"
	_ "github.com/XMPlusDev/XMPlus/app/xdispatcher"

	// Default commander and all its services. This is an optional feature.
	_ "github.com/xmplusdev/xray-core/v24/app/commander"
	_ "github.com/xmplusdev/xray-core/v24/app/log/command"
	_ "github.com/xmplusdev/xray-core/v24/app/proxyman/command"
	_ "github.com/xmplusdev/xray-core/v24/app/stats/command"

	// Other optional features.
	_ "github.com/xmplusdev/xray-core/v24/app/dns"
	_ "github.com/xmplusdev/xray-core/v24/app/log"
	_ "github.com/xmplusdev/xray-core/v24/app/metrics"
	_ "github.com/xmplusdev/xray-core/v24/app/policy"
	_ "github.com/xmplusdev/xray-core/v24/app/reverse"
	_ "github.com/xmplusdev/xray-core/v24/app/router"
	_ "github.com/xmplusdev/xray-core/v24/app/stats"

	// Inbound and outbound proxies.
	_ "github.com/xmplusdev/xray-core/v24/proxy/blackhole"
	_ "github.com/xmplusdev/xray-core/v24/proxy/dns"
	_ "github.com/xmplusdev/xray-core/v24/proxy/dokodemo"
	_ "github.com/xmplusdev/xray-core/v24/proxy/freedom"
	_ "github.com/xmplusdev/xray-core/v24/proxy/http"
	_ "github.com/xmplusdev/xray-core/v24/proxy/shadowsocks"
	_ "github.com/xmplusdev/xray-core/v24/proxy/shadowsocks_2022"
	_ "github.com/xmplusdev/xray-core/v24/proxy/socks"
	_ "github.com/xmplusdev/xray-core/v24/proxy/trojan"
	_ "github.com/xmplusdev/xray-core/v24/proxy/vless/inbound"
	_ "github.com/xmplusdev/xray-core/v24/proxy/vless/outbound"
	_ "github.com/xmplusdev/xray-core/v24/proxy/vmess/inbound"
	_ "github.com/xmplusdev/xray-core/v24/proxy/vmess/outbound"
	_ "github.com/xmplusdev/xray-core/v24/proxy/wireguard"

	// Transports
	_ "github.com/xmplusdev/xray-core/v24/transport/internet/kcp"
	_ "github.com/xmplusdev/xray-core/v24/transport/internet/tcp"
	_ "github.com/xmplusdev/xray-core/v24/transport/internet/tls"
	_ "github.com/xmplusdev/xray-core/v24/transport/internet/udp"
	_ "github.com/xmplusdev/xray-core/v24/transport/internet/websocket"
	_ "github.com/xmplusdev/xray-core/v24/transport/internet/reality"
	_ "github.com/xmplusdev/xray-core/v24/transport/internet/httpupgrade"
	_ "github.com/xmplusdev/xray-core/v24/transport/internet/splithttp"
	_ "github.com/xmplusdev/xray-core/v24/transport/internet/grpc"

	// Transport headers
	_ "github.com/xmplusdev/xray-core/v24/transport/internet/headers/http"
	_ "github.com/xmplusdev/xray-core/v24/transport/internet/headers/noop"
	_ "github.com/xmplusdev/xray-core/v24/transport/internet/headers/srtp"
	_ "github.com/xmplusdev/xray-core/v24/transport/internet/headers/tls"
	_ "github.com/xmplusdev/xray-core/v24/transport/internet/headers/utp"
	_ "github.com/xmplusdev/xray-core/v24/transport/internet/headers/wechat"
	_ "github.com/xmplusdev/xray-core/v24/transport/internet/headers/wireguard"

	// JSON & TOML & YAML
	_ "github.com/xmplusdev/xray-core/v24/main/json"
	_ "github.com/xmplusdev/xray-core/v24/main/toml"
	_ "github.com/xmplusdev/xray-core/v24/main/yaml"

	// Load config from file or http(s)
	_ "github.com/xmplusdev/xray-core/v24/main/confloader/external"

	// Commands
	_ "github.com/xmplusdev/xray-core/v24/main/commands/all"
)
