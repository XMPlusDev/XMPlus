package node

import (
	"encoding/json"
	"fmt"

	"github.com/xmplusdev/xray-core/v25/core"
	"github.com/xmplusdev/xray-core/v25/infra/conf"
	"github.com/xmplusdev/xray-core/v25/common/net"
	"github.com/xmplusdev/xray-core/v25/common/protocol"
	"github.com/xmplusdev/xray-core/v25/common/serial"
	"github.com/xmplusdev/xray-core/v25/proxy/vless"
	
	"github.com/XMPlusDev/XMPlus/api"
)


func OutboundBuilder(config *Config, nodeInfo *api.NodeInfo, tag string) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = tag

	// Build Send IP address
	if nodeInfo.SendThroughIP != "" {
		outboundDetourConfig.SendThrough = &nodeInfo.SendThroughIP
	}

	// Freedom Protocol setting
	var domainStrategy = "Asis"
	if config.EnableDNS {
		if config.DNSStrategy != "" {
			domainStrategy = config.DNSStrategy
		} else {
			domainStrategy = "Asis"
		}
	}
	proxySetting := &conf.FreedomConfig{
		DomainStrategy: domainStrategy,
	}
	
	var setting json.RawMessage
	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config fialed: %s", nodeInfo.NodeType, err)
	}
	
	outboundDetourConfig.Settings = &setting
	return outboundDetourConfig.Build()	
}

func OutboundBuilder(tag string) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	
	outboundDetourConfig.Protocol = "blackhole"
	outboundDetourConfig.Tag = fmt.Sprintf("%s_blackhole", tag)
	
	return outboundDetourConfig.Build()	
}


func OutboundRelayBuilder(nodeInfo *api.NodeInfo.RelayNodeInfo , tag string, subscription *api.SubscriptionInfo, Passwd string) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	
	var (
		protocol      string
		streamSetting *conf.StreamConfig
		setting       json.RawMessage
	)

	var proxySetting any
	
	switch nodeInfo.NodeType {
		case "vless":
			protocol = "vless"
			account := &protocol.User{
				Level:   0,
				Email:   fmt.Sprintf("%s|%s|%s", tag, subscription.Email, subscription.Passwd),
				Account: serial.ToTypedMessage(&vless.Account{
					Id: subscription.Passwd,
					Flow: nodeInfo.Flow,
					Encryption: nodeInfo.Encryption,
				}),
			}
			vUser, err := json.Marshal(&account)
			if err != nil {
				return nil, fmt.Errorf("Marshal Vless User %s config fialed: %s", account, err)
			}
			User := []json.RawMessage{}
			User = append(User, vUser)
			
			proxySetting = struct {
				Vnext []*conf.VLessOutboundVnext `json:"vnext"`
			}{
				Vnext: []*conf.VLessOutboundVnext{&conf.VLessOutboundVnext{
						Address: &conf.Address{Address: net.ParseAddress(nodeInfo.Address)},
						Port: uint16(nodeInfo.ListeningPort),
						Users: User,
					},
				},
			}
		case "vmess":
			protocol = "vmess"		
			vmessAccount := &conf.VMessAccount{
				ID:  subscription.Passwd,
				Security: "auto",
			}
			account :=  &protocol.User{
				Level:   0,
				Email:   fmt.Sprintf("%s|%s|%s", tag, subscription.Email, subscription.Passwd), 
				Account: serial.ToTypedMessage(vmessAccount.Build()),
			}			
			userVmess, err := json.Marshal(&account)
			if err != nil {
				return nil, fmt.Errorf("Marshal Vmess User %s config fialed: %s", account, err)
			}
			User := []json.RawMessage{}
			User = append(User, userVmess)
			
			proxySetting = struct {
				Receivers []*conf.VMessOutboundTarget `json:"vnext"`
			}{
				Receivers: []*conf.VMessOutboundTarget{&conf.VMessOutboundTarget{
						Address: &conf.Address{Address: net.ParseAddress(nodeInfo.Address)},
						Port: uint16(nodeInfo.ListeningPort),
						Users: User,
					},
				},
			}
		case "trojan":
			protocol = "trojan"	
			proxySetting = struct {
				Servers []*conf.TrojanServerTarget `json:"servers"`
			}{
				Servers: []*conf.TrojanServerTarget{&conf.TrojanServerTarget{
						Address: &conf.Address{Address: net.ParseAddress(nodeInfo.Address)},
						Port:    uint16(nodeInfo.ListeningPort),
						Password: subscription.Passwd,
						Email:  fmt.Sprintf("%s|%s|%s", tag, subscription.Email, subscription.Passwd),
						Level:  0,
						Flow: "",
					},
				},
			}
		case "Shadowsocks":
			protocol = "shadowsocks"
			proxySetting = struct {
				Servers []*conf.ShadowsocksServerTarget `json:"servers"`
			}{
				Servers: []*conf.ShadowsocksServerTarget{&conf.ShadowsocksServerTarget{
						Address: &conf.Address{Address: net.ParseAddress(nodeInfo.Address)},
						Port:    uint16(nodeInfo.ListeningPort),
						Password: Passwd,
						Email:   fmt.Sprintf("%s|%s|%s", tag, subscription.Email, subscription.Passwd),
						Level:   0,
						Cipher:  nodeInfo.Cipher,
						UoT:     true,
					},
				},
			}
		default:
			return nil, fmt.Errorf("Unsupported Relay Node Type: %s", nodeInfo.NodeType)		
	}
	
	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config fialed: %s", nodeInfo.NodeType, err)
	}
	
	outboundDetourConfig.Protocol = protocol
	outboundDetourConfig.Settings = &setting
	
	streamSetting = new(conf.StreamConfig)
	transportProtocol := conf.TransportProtocol(nodeInfo.NetworkType)
	networkType, err := transportProtocol.Build()
	if err != nil {
		return nil, fmt.Errorf("convert TransportProtocol failed: %s", err)
	}
	
	switch networkType {
	case "tcp", "raw":
		tcpSetting := &conf.TCPConfig{
			AcceptProxyProtocol: nodeInfo.AcceptProxyProtocol,
			HeaderConfig: nodeInfo.RawSettings.Header,
		}
		streamSetting.TCPSettings = tcpSetting
	case "websocket", "ws":
		wsSettings := &conf.WebSocketConfig{
			AcceptProxyProtocol: nodeInfo.AcceptProxyProtocol,
			Path: nodeInfo.WsSettings.Path,
			Host: nodeInfo.WsSettings.Host,
			HeartbeatPeriod: nodeInfo.WsSettings.HeartbeatPeriod,
		}
		streamSetting.WSSettings = wsSettings
	case "httpupgrade":
		httpupgradeSettings := &conf.HttpUpgradeConfig{
		    AcceptProxyProtocol: nodeInfo.AcceptProxyProtocol,
			Host: nodeInfo.HttpSettings.Host,
			Path: nodeInfo.HttpSettings.Path,
		}
		streamSetting.HTTPUPGRADESettings = httpupgradeSettings	
	case "xhttp":
		xhttpSettings := &conf.SplitHTTPConfig{
			Host: nodeInfo.XhttpSettings.Host,
			Path: nodeInfo.XhttpSettings.Path,
			Mode: nodeInfo.XhttpSettings.Mode,
			NoSSEHeader: nodeInfo.XhttpSettings.NoSSEHeader,
			NoGRPCHeader: nodeInfo.XhttpSettings.NoGRPCHeader,
		}
		streamSetting.XHTTPSettings = xhttpSettings		
	case "grpc":
		grpcSettings := &conf.GRPCConfig{
			ServiceName: nodeInfo.GrpcSettings.ServiceName,
			Authority: nodeInfo.GrpcSettings.Authority,
			UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/123.0.6312.52 Mobile/15E148 Safari/604.1",
		}
		streamSetting.GRPCSettings = grpcSettings
	case "mkcp":
		kcpSettings := &conf.KCPConfig{
			HeaderConfig: nodeInfo.KcpSettings.Header,
			Congestion: &nodeInfo.KcpSettings.Congestion,
			Seed: &nodeInfo.KcpSettings.Seed,
		}
		streamSetting.KCPSettings = kcpSettings	
	}
	
	streamSetting.Network = &transportProtocol
	
	if nodeInfo.SecurityType == "tls" {
		streamSetting.Security = "tls"
		tlsSettings := &conf.TLSConfig{
			Insecure: true,
			Fingerprint: nodeInfo.TlsSettings.Fingerprint,
		}
		streamSetting.TLSSettings = tlsSettings	
	}
	
	if nodeInfo.SecurityType == "reality" {
		streamSetting.Security = "reality"		
		realitySettings :=  &conf.REALITYConfig{
			Show:         nodeInfo.RealitySettings.Show,
			ServerName:   nodeInfo.RealitySettings.ServerName,
			PublicKey:    nodeInfo.RealitySettings.PublicKey,
			Fingerprint:  nodeInfo.RealitySettings.Fingerprint,
			ShortId:      nodeInfo.RealitySettings.ShortId,
			SpiderX:      nodeInfo.RealitySettings.SpiderX,
			SpiderX:      nodeInfo.RealitySettings.SpiderX,
			Mldsa65Verify: nodeInfo.RealitySettings.Mldsa65Verify,
		}
		streamSetting.REALITYSettings = realitySettings
	}
	
	outboundDetourConfig.Tag = fmt.Sprintf("%s_%d", tag, subscription.Id)
	if nodeInfo.SendThroughIP != "" {
		outboundDetourConfig.SendThrough = &nodeInfo.SendThroughIP
	}
	outboundDetourConfig.StreamSetting = streamSetting
	
	return outboundDetourConfig.Build()
}