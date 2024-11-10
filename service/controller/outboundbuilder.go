package controller

import (
	"encoding/json"
	"fmt"

	"github.com/xmplusdev/xray-core/v24/core"
	"github.com/xmplusdev/xray-core/v24/infra/conf"
	"github.com/xmplusdev/xray-core/v24/common/protocol"
	"github.com/xmplusdev/xray-core/v24/common/serial"
	"github.com/xmplusdev/xray-core/v24/proxy/vless"
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
	
	// Used for Shadowsocks-Plugin
	if nodeInfo.NodeType == "dokodemo-door" {
		proxySetting.Redirect = fmt.Sprintf("127.0.0.1:%d", nodeInfo.Port-1)
	}
	var setting json.RawMessage
	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config fialed: %s", nodeInfo.NodeType, err)
	}
	
	outboundDetourConfig.Settings = &setting
	return outboundDetourConfig.Build()
}

type VMessOutbound struct {
	Address string            `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type VLessOutbound struct {
	Address string            `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type TrojanServer struct {
	Address  string        `json:"address"`
	Port     uint16        `json:"port"`
	Password string        `json:"password"`
	Email    string        `json:"email"`
	Level    byte          `json:"level"`
	Flow     string        `json:"flow"`
}

type ShadowsocksServer struct {
	Address  string          `json:"address"`
	Port     uint16          `json:"port"`
	Cipher   string          `json:"method"`
	Password string          `json:"password"`
	Email    string          `json:"email"`
	Level    byte            `json:"level"`
	UoT      bool            `json:"uot"`
}

func OutboundRelayBuilder(nodeInfo *api.RelayNodeInfo , tag string, UUID string, Email string, Passwd string, UID int) (*core.OutboundHandlerConfig, error) {
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
			VlessUser := buildRVlessUser(tag, nodeInfo.Flow , UUID, Email)
			User := []json.RawMessage{}
			rawUser,err := json.Marshal(&VlessUser)
			if err != nil {
				return nil, fmt.Errorf("Marshal users %s config fialed: %s", VlessUser, err)
			}
			
			User = append(User, rawUser)
			proxySetting = struct {
				Vnext []*VLessOutbound `json:"vnext"`
			}{
				Vnext: []*VLessOutbound{&VLessOutbound{
						Address: nodeInfo.Address,
						Port: uint16(nodeInfo.Port),
						Users: User,
					},
				},
			}
		case "Vmess":
			protocol = "vmess"
			VmessUser := buildRVmessUser(tag, UUID, Email)
			User := []json.RawMessage{}
			rawUser,err := json.Marshal(&VmessUser)
			if err != nil {
				return nil, fmt.Errorf("Marshal users %s config fialed: %s", VmessUser, err)
			}
			
			User = append(User, rawUser)					
			proxySetting = struct {
				Receivers []*VMessOutbound `json:"vnext"`
			}{
				Receivers: []*VMessOutbound{&VMessOutbound{
						Address: nodeInfo.Address,
						Port: uint16(nodeInfo.Port),
						Users: User,
					},
				},
			}
		case "Trojan":
			protocol = "trojan"	
			proxySetting = struct {
				Servers []*TrojanServer `json:"servers"`
			}{
				Servers: []*TrojanServer{&TrojanServer{
						Address: nodeInfo.Address,
						Port:     uint16(nodeInfo.Port),
						Password: UUID,
						Email:    fmt.Sprintf("%s|%s|%s", tag, Email, UUID),
						Level:    0,
					},
				},
			}
		case "Shadowsocks":
			protocol = "shadowsocks"
			proxySetting = struct {
				Servers []*ShadowsocksServer `json:"servers"`
			}{
				Servers: []*ShadowsocksServer{&ShadowsocksServer{
						Address: nodeInfo.Address,
						Port:     uint16(nodeInfo.Port),
						Password: Passwd,
						Email:    fmt.Sprintf("%s|%s|%s", tag, Email, UID),
						Level:    0,
						Cipher:   nodeInfo.CypherMethod,
						UoT:      true,
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
	case "tcp":
		tcpSetting := &conf.TCPConfig{
			AcceptProxyProtocol: nodeInfo.ProxyProtocol,
			HeaderConfig: nodeInfo.Header,
		}
		streamSetting.TCPSettings = tcpSetting
	case "websocket":
		wsSettings := &conf.WebSocketConfig{
			AcceptProxyProtocol: nodeInfo.ProxyProtocol,
			Path: nodeInfo.Path,
			Host: nodeInfo.Host,
		}
		streamSetting.WSSettings = wsSettings
	case "http":
		hosts := conf.StringList{nodeInfo.Host}
		httpSettings := &conf.HTTPConfig{
			Host: &hosts,
			Path: nodeInfo.Path,
		}
		streamSetting.HTTPSettings = httpSettings
	case "httpupgrade":
		httpupgradeSettings := &conf.HttpUpgradeConfig{
		    AcceptProxyProtocol: nodeInfo.ProxyProtocol,
			Host: nodeInfo.Host,
			Path: nodeInfo.Path,
		}
		streamSetting.HTTPUPGRADESettings = httpupgradeSettings	
	case "splithttp":
		scMaxEachPostBytes := &conf.Int32Range{
			From: nodeInfo.ScMaxEachPostBytes, 
			To: nodeInfo.ScMaxEachPostBytes,
		}
		scMaxConcurrentPosts := &conf.Int32Range{
			From: nodeInfo.ScMaxConcurrentPosts, 
			To: nodeInfo.ScMaxConcurrentPosts,
		}
		scMinPostsIntervalMs := &conf.Int32Range{
			From: nodeInfo.ScMinPostsIntervalMs, 
			To: nodeInfo.ScMinPostsIntervalMs,
		}
		xPaddingBytes := &conf.Int32Range{
			From: nodeInfo.XPaddingBytes, 
			To: nodeInfo.XPaddingBytes,
		}
		splithttpSettings := &conf.SplitHTTPConfig{
			Host: nodeInfo.Host,
			Path: nodeInfo.Path,
			ScMaxEachPostBytes: scMaxEachPostBytes,
			ScMaxConcurrentPosts: scMaxConcurrentPosts,
			ScMinPostsIntervalMs: scMinPostsIntervalMs,
			NoSSEHeader: nodeInfo.NoSSEHeader,
			XPaddingBytes: xPaddingBytes,
		}
		streamSetting.SplitHTTPSettings = splithttpSettings		
	case "grpc":
		grpcSettings := &conf.GRPCConfig{
			ServiceName: nodeInfo.ServiceName,
			Authority: nodeInfo.Authority,
			UserAgent:   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/123.0.6312.52 Mobile/15E148 Safari/604.1",
		}
		streamSetting.GRPCConfig = grpcSettings
	case "mkcp":
		kcpSettings := &conf.KCPConfig{
			HeaderConfig:   nodeInfo.Header,
			Congestion:      &nodeInfo.Congestion,
			Seed:  &nodeInfo.Seed,
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
	
	outboundDetourConfig.Tag = fmt.Sprintf("%s_%d", tag,UID)
	
	if nodeInfo.SendIP != "" {
		outboundDetourConfig.SendThrough = &nodeInfo.SendIP
	}
	outboundDetourConfig.StreamSetting = streamSetting
	
	return outboundDetourConfig.Build()
}

func buildRVmessUser(tag string, UUID string, Email string) *protocol.User {
	vmessAccount := &conf.VMessAccount{
		ID:  UUID,
		Security: "auto",
	}
	return &protocol.User{
		Level:   0,
		Email:   fmt.Sprintf("%s|%s|%s", tag, Email, UUID), 
		Account: serial.ToTypedMessage(vmessAccount.Build()),
	}
}

func buildRVlessUser(tag string, Flow string, UUID string, Email string)  *protocol.User {
	vlessAccount := &vless.Account{
		Id:   UUID,
		Flow: Flow,
		Encryption: "none",
	}
	return &protocol.User{
		Level:   0,
		Email:   fmt.Sprintf("%s|%s|%s", tag, Email, UUID),
		Account: serial.ToTypedMessage(vlessAccount),
	}
}
