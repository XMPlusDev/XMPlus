package controller

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

// OutboundBuilder build freedom outbound config for addOutbound
func OutboundBuilder(config *Config, nodeInfo *api.NodeInfo, tag string) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = tag

	// Build Send IP address
	if nodeInfo.SendIP != "" {
		outboundDetourConfig.SendThrough = &nodeInfo.SendIP
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

func OutboundRelayBuilder(nodeInfo *api.RelayNodeInfo , tag string, subscription *api.SubscriptionInfo, Passwd string) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	var (
		protocol      string
		streamSetting *conf.StreamConfig
		setting       json.RawMessage
	)

	var proxySetting any
	
	switch nodeInfo.NodeType {
		case "Vless":
			protocol = "vless"
			VUser := vlessUser(tag, nodeInfo.Flow , subscription)
			userVless, err := json.Marshal(&VUser)
			if err != nil {
				return nil, fmt.Errorf("Marshal Vless User %s config fialed: %s", VUser, err)
			}
			
			User := []json.RawMessage{}
			User = append(User, userVless)
			
			proxySetting = struct {
				Vnext []*conf.VLessOutboundVnext `json:"vnext"`
			}{
				Vnext: []*conf.VLessOutboundVnext{&conf.VLessOutboundVnext{
						Address: &conf.Address{Address: net.ParseAddress(nodeInfo.Address)},
						Port: uint16(nodeInfo.Port),
						Users: User,
					},
				},
			}
		case "Vmess":
			protocol = "vmess"		
			Vmser := vmessUser(tag, subscription)		
			userVmess, err := json.Marshal(&Vmser)
			if err != nil {
				return nil, fmt.Errorf("Marshal Vmess User %s config fialed: %s", Vmser, err)
			}
			User := []json.RawMessage{}
			User = append(User, userVmess)
			
			proxySetting = struct {
				Receivers []*conf.VMessOutboundTarget `json:"vnext"`
			}{
				Receivers: []*conf.VMessOutboundTarget{&conf.VMessOutboundTarget{
						Address: &conf.Address{Address: net.ParseAddress(nodeInfo.Address)},
						Port: uint16(nodeInfo.Port),
						Users: User,
					},
				},
			}
		case "Trojan":
			protocol = "trojan"	
			proxySetting = struct {
				Servers []*conf.TrojanServerTarget `json:"servers"`
			}{
				Servers: []*conf.TrojanServerTarget{&conf.TrojanServerTarget{
						Address: &conf.Address{Address: net.ParseAddress(nodeInfo.Address)},
						Port:    uint16(nodeInfo.Port),
						Password: subscription.UUID,
						Email:  fmt.Sprintf("%s|%s|%s", tag, subscription.Email, subscription.UUID),
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
						Port:    uint16(nodeInfo.Port),
						Password: Passwd,
						Email:   fmt.Sprintf("%s|%s|%s", tag, subscription.Email, subscription.UID),
						Level:   0,
						Cipher:  nodeInfo.CypherMethod,
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
	transportProtocol := conf.TransportProtocol(nodeInfo.Transport)
	networkType, err := transportProtocol.Build()
	if err != nil {
		return nil, fmt.Errorf("convert TransportProtocol failed: %s", err)
	}

	switch networkType {
	case "tcp", "raw":
		tcpSetting := &conf.TCPConfig{
			AcceptProxyProtocol: nodeInfo.ProxyProtocol,
			HeaderConfig: nodeInfo.Header,
		}
		streamSetting.TCPSettings = tcpSetting
	case "websocket", "ws":
		wsSettings := &conf.WebSocketConfig{
			AcceptProxyProtocol: nodeInfo.ProxyProtocol,
			Path: nodeInfo.Path,
			Host: nodeInfo.Host,
			HeartbeatPeriod: nodeInfo.HeartbeatPeriod,
		}
		streamSetting.WSSettings = wsSettings
	case "httpupgrade":
		httpupgradeSettings := &conf.HttpUpgradeConfig{
		    AcceptProxyProtocol: nodeInfo.ProxyProtocol,
			Host: nodeInfo.Host,
			Path: nodeInfo.Path,
		}
		streamSetting.HTTPUPGRADESettings = httpupgradeSettings	
	case "xhttp", "splithttp":
		xhttpSettings := &conf.SplitHTTPConfig{
			Host: nodeInfo.Host,
			Path: nodeInfo.Path,
			Mode: nodeInfo.Mode,
			NoSSEHeader: nodeInfo.NoSSEHeader,
			NoGRPCHeader: nodeInfo.NoGRPCHeader,
		}
		streamSetting.XHTTPSettings = xhttpSettings		
	case "grpc":
		grpcSettings := &conf.GRPCConfig{
			ServiceName: nodeInfo.ServiceName,
			Authority: nodeInfo.Authority,
			UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/123.0.6312.52 Mobile/15E148 Safari/604.1",
		}
		streamSetting.GRPCSettings = grpcSettings
	case "mkcp":
		kcpSettings := &conf.KCPConfig{
			HeaderConfig: nodeInfo.Header,
			Congestion: &nodeInfo.Congestion,
			Seed: &nodeInfo.Seed,
		}
		streamSetting.KCPSettings = kcpSettings	
	}
	
	streamSetting.Network = &transportProtocol
	
	if nodeInfo.TLSType == "tls" {
		streamSetting.Security = "tls"
		if nodeInfo.TLSType == "tls" {
			tlsSettings := &conf.TLSConfig{}
			tlsSettings.Insecure = true
			tlsSettings.Fingerprint = nodeInfo.Fingerprint
			streamSetting.TLSSettings = tlsSettings	
		}
	}
	
	if nodeInfo.TLSType == "reality" {
		streamSetting.Security = "reality"		
		realitySettings :=  &conf.REALITYConfig{
			Show:         nodeInfo.Show,
			ServerName:   nodeInfo.ServerName,
			PublicKey:    nodeInfo.PublicKey,
			Fingerprint:  nodeInfo.Fingerprint,
			ShortId:      nodeInfo.ShortId,
			SpiderX:      nodeInfo.SpiderX,
		}
		streamSetting.REALITYSettings = realitySettings
	}
	
	outboundDetourConfig.Tag = fmt.Sprintf("%s_%d", tag, subscription.UID)
	
	if nodeInfo.SendIP != "" {
		outboundDetourConfig.SendThrough = &nodeInfo.SendIP
	}
	outboundDetourConfig.StreamSetting = streamSetting
	
	return outboundDetourConfig.Build()
}

func vmessUser(tag string, subscription *api.SubscriptionInfo) (*protocol.User) {
	vmessAccount := &conf.VMessAccount{
		ID:  subscription.UUID,
		Security: "auto",
	}
	return &protocol.User{
		Level:   0,
		Email:   fmt.Sprintf("%s|%s|%s", tag, subscription.Email, subscription.UUID), 
		Account: serial.ToTypedMessage(vmessAccount.Build()),
	}
}

func vlessUser(tag string, Flow string, subscription *api.SubscriptionInfo) (*protocol.User) {
	return &protocol.User{
		Level:   0,
		Email:   fmt.Sprintf("%s|%s|%s", tag, subscription.Email, subscription.UUID),
		Account: serial.ToTypedMessage(&vless.Account{
			Id: subscription.UUID,
			Flow: Flow,
			Encryption: "none",
		}),
	}
}