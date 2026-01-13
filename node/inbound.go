package node

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"strconv"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	"github.com/xmplusdev/xray-core/v26/common/net"
	"github.com/xmplusdev/xray-core/v26/core"
	"github.com/xmplusdev/xray-core/v26/infra/conf"
	
	"github.com/XMPlusDev/XMPlus/api"
	"github.com/XMPlusDev/XMPlus/helper/cert"
)

func InboundBuilder(config *Config, nodeInfo *api.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	inboundDetourConfig := &conf.InboundDetourConfig{}
	
	if nodeInfo.NodeType == "Shadowsocks-Plugin" {
		inboundDetourConfig.ListenOn = &conf.Address{Address: net.ParseAddress("127.0.0.1")}
	} else if nodeInfo.ListeningIP != "" {
		ipAddress := net.ParseAddress(nodeInfo.ListeningIP)
		inboundDetourConfig.ListenOn = &conf.Address{Address: ipAddress}
	}
	
	var Port1, Port2 uint32 = 0, 0
	port := strings.SplitN(nodeInfo.ListeningPort, "-", 2)
	if len(port) == 1 {
		parsedPort, err := strconv.ParseInt(port[0], 10, 32)
		if err != nil {
			return nil, err
		}
		Port1 = uint32(parsedPort)
		Port2 = uint32(parsedPort)
	}else{
		parsedPort1, err := strconv.ParseInt(port[0], 10, 32)
		if err != nil {
			return nil, err
		}
		Port1 = uint32(parsedPort1)
		
		parsedPort2, err := strconv.ParseInt(port[1], 10, 32)
		if err != nil {
			return nil, err
		}
		Port2 = uint32(parsedPort2)
	}
	
	portList := &conf.PortList{
		Range: []conf.PortRange{{From: Port1, To: Port2}},
	}

	inboundDetourConfig.PortList = portList
	inboundDetourConfig.Tag = tag

	sniffingConfig := &conf.SniffingConfig{
		Enabled:      nodeInfo.Sniffing,
		DestOverride: &conf.StringList{"http", "tls", "quic", "fakedns"},
	}
	
	inboundDetourConfig.SniffingConfig = sniffingConfig
	
	var (
		protocol      string
		streamSetting *conf.StreamConfig
		setting       json.RawMessage
	)

	var proxySetting any
	
	switch nodeInfo.NodeType {
		case "vless":
			protocol = "vless"
			if nodeInfo.Decryption == "none" && config.EnableFallback {
				fallbackConfigs, err := buildVlessFallbacks(config.FallBackConfigs)
				if err == nil {
					proxySetting = &conf.VLessInboundConfig{
						Decryption: nodeInfo.Decryption,
						Fallbacks:  fallbackConfigs,
					} 
				}else {
					return nil, err
				}
			} else {
				proxySetting = &conf.VLessInboundConfig{
					Decryption: nodeInfo.Decryption,
				}
			}
		case "vmess":	
			protocol = "vmess"
			proxySetting = &conf.VMessInboundConfig{}

		case "trojan":
			protocol = "trojan"
			if config.EnableFallback {
				fallbackConfigs, err := buildTrojanFallbacks(config.FallBackConfigs)
				if err == nil {
					proxySetting = &conf.TrojanServerConfig{
						Fallbacks: fallbackConfigs,
					}
				}else {
					return nil, err
				}
			} else {
				proxySetting = &conf.TrojanServerConfig{}
			}
		case "shadowsocks", "Shadowsocks-Plugin":
			protocol = "shadowsocks"
			cipher := strings.ToLower(nodeInfo.Cipher)

			shadowsocksSetting := &conf.ShadowsocksServerConfig{  // Fixed: removed duplicate declaration
				Cipher:   cipher,
				Password: nodeInfo.ServerKey, // shadowsocks2022 shareKey
			}

			b := make([]byte, 32)
			rand.Read(b)
			randPasswd := hex.EncodeToString(b)
			if C.Contains(shadowaead_2022.List, cipher) {
				shadowsocksSetting.Users = append(shadowsocksSetting.Users, &conf.ShadowsocksUserConfig{
					Password: base64.StdEncoding.EncodeToString(b),
				})
			} else {
				shadowsocksSetting.Password = randPasswd
			}

			shadowsocksSetting.NetworkList = &conf.NetworkList{"tcp", "udp"}
			shadowsocksSetting.IVCheck = false
			
			proxySetting = shadowsocksSetting
		case "dokodemo-door":
			protocol = "dokodemo-door"
			proxySetting = struct {
				Host        string   `json:"address"`
				NetworkList []string `json:"network"`
			}{
				Host:        "v1.mux.cool",
				NetworkList: []string{"tcp", "udp"},
			}
		default:
			return nil, fmt.Errorf("Unsupported Node Type: %v", nodeInfo.NodeType)	
	}
	
	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config fialed: %s", nodeInfo.NodeType, err)
	}
	inboundDetourConfig.Protocol = protocol
	inboundDetourConfig.Settings = &setting
	
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
				HeaderConfig:  nodeInfo.RawSettings.Header,
			}
			streamSetting.TCPSettings = tcpSetting
		case "websocket":
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
	
	if nodeInfo.SecurityType == "tls" && nodeInfo.TlsSettings.CertMode != "none" {
		streamSetting.Security = "tls"
		certFile, keyFile, err := getCertFile(config.CertConfig, nodeInfo.TlsSettings.CertMode, nodeInfo.TlsSettings.ServerName)
		if err != nil {
			return nil, err
		}
			
		tlsSettings := &conf.TLSConfig{}
		
		tlsSettings.Certs = append(tlsSettings.Certs, &conf.TLSCertConfig{CertFile: certFile, KeyFile: keyFile, OcspStapling: 3600})
		tlsSettings.Insecure = nodeInfo.TlsSettings.AllowInsecure
		tlsSettings.RejectUnknownSNI = nodeInfo.TlsSettings.RejectUnknownSni
		tlsSettings.ServerName = nodeInfo.TlsSettings.ServerName
		tlsSettings.ALPN = &conf.StringList{nodeInfo.TlsSettings.Alpn}
		tlsSettings.CurvePreferences = &conf.StringList{nodeInfo.TlsSettings.CurvePreferences}
		tlsSettings.Fingerprint = nodeInfo.TlsSettings.FingerPrint
		if nodeInfo.TlsSettings.ServerNameToVerify != "" {
			tlsSettings.ServerNameToVerify = nodeInfo.TlsSettings.ServerNameToVerify
		}

		streamSetting.TLSSettings = tlsSettings
	}

	if nodeInfo.SecurityType == "reality" {
		streamSetting.Security = "reality"
		
		realitySettings :=  &conf.REALITYConfig{}
		
		realitySettings.Target = nodeInfo.RealitySettings.Dest
		realitySettings.Show = nodeInfo.RealitySettings.Show
		realitySettings.Xver = nodeInfo.RealitySettings.Xver
		realitySettings.ServerNames = nodeInfo.RealitySettings.ServerNames
		realitySettings.PrivateKey = nodeInfo.RealitySettings.PrivateKey
		realitySettings.ShortIds = nodeInfo.RealitySettings.ShortIds
		if nodeInfo.RealitySettings.MinClientVer != "" {
			realitySettings.MinClientVer = nodeInfo.RealitySettings.MinClientVer
		}
		if nodeInfo.RealitySettings.MaxClientVer != "" {
			realitySettings.MaxClientVer = nodeInfo.RealitySettings.MaxClientVer
		}	
		if nodeInfo.RealitySettings.MaxTimeDiff > 0 {
			realitySettings.MaxTimeDiff = nodeInfo.RealitySettings.MaxTimeDiff
		}
		realitySettings.Mldsa65Seed = nodeInfo.RealitySettings.Mldsa65Seed
		
		streamSetting.REALITYSettings = realitySettings
	}

	if nodeInfo.UseSocket {
		sockoptConfig := &conf.SocketConfig{}
		if networkType != "tcp" && networkType != "ws" && nodeInfo.AcceptProxyProtocol {
			sockoptConfig.AcceptProxyProtocol = nodeInfo.AcceptProxyProtocol
		}
		if nodeInfo.SocketSettings.DomainStrategy != "" {
			sockoptConfig.DomainStrategy = nodeInfo.SocketSettings.DomainStrategy
		}
		if nodeInfo.SocketSettings.TCPKeepAliveInterval > 0 {
			sockoptConfig.TCPKeepAliveInterval = nodeInfo.SocketSettings.TCPKeepAliveInterval
		}
		if nodeInfo.SocketSettings.TCPWindowClamp > 0 {
			sockoptConfig.TCPWindowClamp = nodeInfo.SocketSettings.TCPWindowClamp
		}
		if nodeInfo.SocketSettings.TCPMaxSeg > 0 {
			sockoptConfig.TCPMaxSeg = nodeInfo.SocketSettings.TCPMaxSeg
		}
		if nodeInfo.SocketSettings.TCPUserTimeout > 0 {
			sockoptConfig.TCPUserTimeout = nodeInfo.SocketSettings.TCPUserTimeout
		}
		if nodeInfo.SocketSettings.TCPKeepAliveIdle > 0 {
			sockoptConfig.TCPKeepAliveIdle = nodeInfo.SocketSettings.TCPKeepAliveIdle
		}
		if nodeInfo.SocketSettings.TcpMptcp {
			sockoptConfig.TcpMptcp = nodeInfo.SocketSettings.TcpMptcp
		}
			
		streamSetting.SocketSettings = sockoptConfig
	}	
	
	inboundDetourConfig.StreamSetting = streamSetting

	return inboundDetourConfig.Build()
}


func getCertFile(certConfig *cert.CertConfig, CertMode string, Domain string) (certFile string, keyFile string, err error) {
	switch CertMode {
	case "file":
		if certConfig.CertFile == "" || certConfig.KeyFile == "" {
			return "", "", fmt.Errorf("Cert file path or key file path missing, check your config.yml parameters.")
		}
		return certConfig.CertFile, certConfig.KeyFile, nil
	case "dns":
		lego, err := cert.New(certConfig)
		if err != nil {
			return "", "", err
		}
		certPath, keyPath, err := lego.DNSCert(CertMode, Domain)
		if err != nil {
			return "", "", err
		}
		return certPath, keyPath, err
	case "http", "tls":
		lego, err := cert.New(certConfig)
		if err != nil {
			return "", "", err
		}
		certPath, keyPath, err := lego.HTTPCert(CertMode, Domain)
		if err != nil {
			return "", "", err
		}
		return certPath, keyPath, err
	default:
		return "", "", fmt.Errorf("unsupported certmode: %s", CertMode)
	}
}

func buildVlessFallbacks(fallbackConfigs []*FallBackConfig) ([]*conf.VLessInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}

	vlessFallBacks := make([]*conf.VLessInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {

		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback fialed")
		}

		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config fialed: %s", dest, err)
		}
		vlessFallBacks[i] = &conf.VLessInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return vlessFallBacks, nil
}

func buildTrojanFallbacks(fallbackConfigs []*FallBackConfig) ([]*conf.TrojanInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}

	trojanFallBacks := make([]*conf.TrojanInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {

		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback fialed")
		}

		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config fialed: %s", dest, err)
		}
		trojanFallBacks[i] = &conf.TrojanInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return trojanFallBacks, nil
}