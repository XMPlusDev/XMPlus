package node

import (
	"encoding/json"
	"fmt"

	"github.com/xmplusdev/xray-core/v26/core"
	"github.com/xmplusdev/xray-core/v26/infra/conf"
	"github.com/xmplusdev/xray-core/v26/common/net"
	"github.com/xmplusdev/xray-core/v26/common/protocol"
	"github.com/xmplusdev/xray-core/v26/common/serial"
	"github.com/xmplusdev/xray-core/v26/proxy/vless"
	
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


func OutboundRelayBuilder(nodeInfo *api.NodeInfo , tag string, subscription *api.SubscriptionInfo, Passwd string) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	
	var (
		protocol      string
		streamSetting *conf.StreamConfig
		setting       json.RawMessage
	)

	var proxySetting any
	
	switch nodeInfo.RelayNodeInfo.NodeType {
		case "vless":
			protocol = "vless"
			account := &protocol.User{
				Level:   0,
				Email:   fmt.Sprintf("%s|%s|%s", tag, subscription.Email, subscription.Passwd),
				Account: serial.ToTypedMessage(&vless.Account{
					Id: subscription.Passwd,
					Flow: nodeInfo.RelayNodeInfo.Flow,
					Encryption: nodeInfo.RelayNodeInfo.Encryption,
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
						Address: &conf.Address{Address: net.ParseAddress(nodeInfo.RelayNodeInfo.Address)},
						Port: uint16(nodeInfo.RelayNodeInfo.ListeningPort),
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
						Address: &conf.Address{Address: net.ParseAddress(nodeInfo.RelayNodeInfo.Address)},
						Port: uint16(nodeInfo.RelayNodeInfo.ListeningPort),
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
						Address: &conf.Address{Address: net.ParseAddress(nodeInfo.RelayNodeInfo.Address)},
						Port:    uint16(nodeInfo.RelayNodeInfo.ListeningPort),
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
						Address: &conf.Address{Address: net.ParseAddress(nodeInfo.RelayNodeInfo.Address)},
						Port:    uint16(nodeInfo.RelayNodeInfo.ListeningPort),
						Password: Passwd,
						Email:   fmt.Sprintf("%s|%s|%s", tag, subscription.Email, subscription.Passwd),
						Level:   0,
						Cipher:  nodeInfo.RelayNodeInfo.Cipher,
						UoT:     true,
					},
				},
			}
		default:
			return nil, fmt.Errorf("Unsupported Relay Node Type: %s", nodeInfo.RelayNodeInfo.NodeType)		
	}
	
	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config fialed: %s", nodeInfo.RelayNodeInfo.NodeType, err)
	}
	
	outboundDetourConfig.Protocol = protocol
	outboundDetourConfig.Settings = &setting
	
	streamSetting = new(conf.StreamConfig)
	transportProtocol := conf.TransportProtocol(nodeInfo.RelayNodeInfo.NetworkType)
	networkType, err := transportProtocol.Build()
	if err != nil {
		return nil, fmt.Errorf("convert TransportProtocol failed: %s", err)
	}
	
	switch networkType {
	case "tcp", "raw":
		tcpSetting := &conf.TCPConfig{
			AcceptProxyProtocol: nodeInfo.RelayNodeInfo.AcceptProxyProtocol,
			HeaderConfig: nodeInfo.RelayNodeInfo.RawSettings.Header,
		}
		streamSetting.TCPSettings = tcpSetting
	case "websocket", "ws":
		wsSettings := &conf.WebSocketConfig{
			AcceptProxyProtocol: nodeInfo.RelayNodeInfo.AcceptProxyProtocol,
			Path: nodeInfo.RelayNodeInfo.WsSettings.Path,
			Host: nodeInfo.RelayNodeInfo.WsSettings.Host,
			HeartbeatPeriod: nodeInfo.RelayNodeInfo.WsSettings.HeartbeatPeriod,
		}
		streamSetting.WSSettings = wsSettings
	case "httpupgrade":
		httpupgradeSettings := &conf.HttpUpgradeConfig{
		    AcceptProxyProtocol: nodeInfo.RelayNodeInfo.AcceptProxyProtocol,
			Host: nodeInfo.RelayNodeInfo.HttpSettings.Host,
			Path: nodeInfo.RelayNodeInfo.HttpSettings.Path,
		}
		streamSetting.HTTPUPGRADESettings = httpupgradeSettings	
	case "xhttp":
		xhttpSettings := &conf.SplitHTTPConfig{
			Host: nodeInfo.RelayNodeInfo.XhttpSettings.Host,
			Path: nodeInfo.RelayNodeInfo.XhttpSettings.Path,
			Mode: nodeInfo.RelayNodeInfo.XhttpSettings.Mode,
			NoSSEHeader: nodeInfo.RelayNodeInfo.XhttpSettings.NoSSEHeader,
			NoGRPCHeader: nodeInfo.RelayNodeInfo.XhttpSettings.NoGRPCHeader,
		}
		streamSetting.XHTTPSettings = xhttpSettings		
	case "grpc":
		grpcSettings := &conf.GRPCConfig{
			ServiceName: nodeInfo.RelayNodeInfo.GrpcSettings.ServiceName,
			Authority: nodeInfo.RelayNodeInfo.GrpcSettings.Authority,
			UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/123.0.6312.52 Mobile/15E148 Safari/604.1",
		}
		streamSetting.GRPCSettings = grpcSettings
	case "mkcp":
		kcpSettings := &conf.KCPConfig{
			HeaderConfig: nodeInfo.RelayNodeInfo.KcpSettings.Header,
			Congestion: &nodeInfo.RelayNodeInfo.KcpSettings.Congestion,
			Seed: &nodeInfo.RelayNodeInfo.KcpSettings.Seed,
		}
		streamSetting.KCPSettings = kcpSettings	
	}
	
	streamSetting.Network = &transportProtocol
	
	if nodeInfo.RelayNodeInfo.SecurityType == "tls" {
		streamSetting.Security = "tls"
		tlsSettings := &conf.TLSConfig{
			Insecure: true,
			Fingerprint: nodeInfo.RelayNodeInfo.TlsSettings.Fingerprint,
		}
		streamSetting.TLSSettings = tlsSettings	
	}
	
	if nodeInfo.RelayNodeInfo.SecurityType == "reality" {
		streamSetting.Security = "reality"		
		realitySettings :=  &conf.REALITYConfig{
			Show:         nodeInfo.RelayNodeInfo.RealitySettings.Show,
			ServerName:   nodeInfo.RelayNodeInfo.RealitySettings.ServerName,
			PublicKey:    nodeInfo.RelayNodeInfo.RealitySettings.PublicKey,
			Fingerprint:  nodeInfo.RelayNodeInfo.RealitySettings.Fingerprint,
			ShortId:      nodeInfo.RelayNodeInfo.RealitySettings.ShortId,
			SpiderX:      nodeInfo.RelayNodeInfo.RealitySettings.SpiderX,
			Mldsa65Verify: nodeInfo.RelayNodeInfo.RealitySettings.Mldsa65Verify,
		}
		streamSetting.REALITYSettings = realitySettings
	}
	
	outboundDetourConfig.Tag = fmt.Sprintf("%s_%d", tag, subscription.Id)
	if nodeInfo.RelayNodeInfo.SendThroughIP != "" {
		outboundDetourConfig.SendThrough = &nodeInfo.RelayNodeInfo.SendThroughIP
	}
	outboundDetourConfig.StreamSetting = streamSetting
	
	return outboundDetourConfig.Build()
}