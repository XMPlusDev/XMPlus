// Package controller Package generate the InboundConfig used by add inbound
package controller

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
	"github.com/xmplusdev/xray-core/v25/common/net"
	"github.com/xmplusdev/xray-core/v25/core"
	"github.com/xmplusdev/xray-core/v25/infra/conf"
	"github.com/XMPlusDev/XMPlus/api"
	"github.com/XMPlusDev/XMPlus/utility/mylego"
)

// InboundBuilder build Inbound config for different protocol
func InboundBuilder(config *Config, nodeInfo *api.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	inboundDetourConfig := &conf.InboundDetourConfig{}
	
	if nodeInfo.NodeType == "Shadowsocks-Plugin" {
		inboundDetourConfig.ListenOn = &conf.Address{Address: net.ParseAddress("127.0.0.1")}
	} else if nodeInfo.ListenIP != "" {
		ipAddress := net.ParseAddress(nodeInfo.ListenIP)
		inboundDetourConfig.ListenOn = &conf.Address{Address: ipAddress}
	}

	var Port1, Port2 uint32 = 0, 0
	
	port := strings.SplitN(nodeInfo.Port, "-", 2)
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
		
		parsedPort2, errr := strconv.ParseInt(port[1], 10, 32)
		if errr != nil {
			return nil, errr
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
	// Build Protocol and Protocol setting
	switch nodeInfo.NodeType {
	case "Vless":
		protocol = "vless"
		// Enable fallback
		if config.EnableFallback {
			fallbackConfigs, err := buildVlessFallbacks(config.FallBackConfigs)
			if err == nil {
				proxySetting = &conf.VLessInboundConfig{
					Decryption: "none",
					Fallbacks:  fallbackConfigs,
				} 
			}else {
				return nil, err
			}
		} else {
			proxySetting = &conf.VLessInboundConfig{
				Decryption: "none",
			}
		}
	case "Vmess":	
		protocol = "vmess"
		proxySetting = &conf.VMessInboundConfig{}
	case "Trojan":
		protocol = "trojan"
		// Enable fallback
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
	case "Shadowsocks", "Shadowsocks-Plugin":
		protocol = "shadowsocks"
		cipher := strings.ToLower(nodeInfo.CypherMethod)

		proxySetting = &conf.ShadowsocksServerConfig{
			Cipher:   cipher,
			Password: nodeInfo.ServerKey, // shadowsocks2022 shareKey
		}

		proxySetting, _ := proxySetting.(*conf.ShadowsocksServerConfig)
		
		// shadowsocks must have a random password
		// shadowsocks2022's password == user PSK, thus should a length of string >= 32 and base64 encoder
		
		b := make([]byte, 32)
		rand.Read(b)
		randPasswd := hex.EncodeToString(b)
		if C.Contains(shadowaead_2022.List, cipher) {
			proxySetting.Users = append(proxySetting.Users, &conf.ShadowsocksUserConfig{
				Password: base64.StdEncoding.EncodeToString(b),
			})
		} else {
			proxySetting.Password = randPasswd
		}

		proxySetting.NetworkList = &conf.NetworkList{"tcp", "udp"}
		proxySetting.IVCheck = false

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
		return nil, fmt.Errorf("Unsupported Node Type: %v", nodeInfo)
	}

	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config fialed: %s", nodeInfo.NodeType, err)
	}
	inboundDetourConfig.Protocol = protocol
	inboundDetourConfig.Settings = &setting

	// Build streamSettings
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
			HeaderConfig:  nodeInfo.Header,
		}
		streamSetting.TCPSettings = tcpSetting
	case "websocket":
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
			UserAgent:   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/123.0.6312.52 Mobile/15E148 Safari/604.1",
		}
		streamSetting.GRPCSettings = grpcSettings
	case "mkcp":
		kcpSettings := &conf.KCPConfig{
			HeaderConfig:   nodeInfo.Header,
			Congestion:      &nodeInfo.Congestion,
			Seed:  &nodeInfo.Seed,
		}
		streamSetting.KCPSettings = kcpSettings	
	}

	streamSetting.Network = &transportProtocol

	// Build TLS settings
	if nodeInfo.TLSType == "tls" && nodeInfo.CertMode != "none" {
		streamSetting.Security = nodeInfo.TLSType
		if nodeInfo.TLSType == "tls" {
			certFile, keyFile, err := getCertFile(config.CertConfig, nodeInfo.CertMode, nodeInfo.CertDomain)
			if err != nil {
				return nil, err
			}
			tlsSettings := &conf.TLSConfig{
				RejectUnknownSNI: nodeInfo.RejectUnknownSNI,
			}
			
			curvepreferences := conf.StringList{nodeInfo.CurvePreferences}
			tlsSettings.CurvePreferences = &curvepreferences
			tlsSettings.Fingerprint = nodeInfo.Fingerprint
			tlsSettings.Certs = append(tlsSettings.Certs, &conf.TLSCertConfig{CertFile: certFile, KeyFile: keyFile, OcspStapling: 3600})

			streamSetting.TLSSettings = tlsSettings
		}
	}
	
	// Build REALITY settings
	if nodeInfo.TLSType == "reality" {
		streamSetting.Security = "reality"

		dest, err := json.Marshal(nodeInfo.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config fialed: %s", dest, err)
		}
		realitySettings :=  &conf.REALITYConfig{
			Dest:   dest,
		}
		realitySettings.Show = nodeInfo.Show
		realitySettings.Xver = nodeInfo.Xver
		realitySettings.ServerNames = nodeInfo.ServerNames
		realitySettings.PrivateKey = nodeInfo.PrivateKey
		realitySettings.ShortIds = nodeInfo.ShortIds
		if nodeInfo.MinClientVer != "" {
			realitySettings.MinClientVer = nodeInfo.MinClientVer
		}
		if nodeInfo.MaxClientVer != "" {
			realitySettings.MaxClientVer = nodeInfo.MaxClientVer
		}	
		if nodeInfo.MaxTimeDiff > 0 {
			realitySettings.MaxTimeDiff = nodeInfo.MaxTimeDiff
		}
		
		streamSetting.REALITYSettings = realitySettings
	}

	// sockoptConfig
	if nodeInfo.SocketStatus {
		sockoptConfig := &conf.SocketConfig{}
		// Support ProxyProtocol for any transport protocol
		if networkType != "tcp" && networkType != "ws" && nodeInfo.AcceptProxyProtocol {
			sockoptConfig.AcceptProxyProtocol = nodeInfo.ProxyProtocol
		}
		if nodeInfo.DialerProxy != "" {
			sockoptConfig.DialerProxy = nodeInfo.DialerProxy
		}
		if nodeInfo.DomainStrategy != "" {
			sockoptConfig.DomainStrategy = nodeInfo.DomainStrategy
		}
		if nodeInfo.TCPKeepAliveInterval > 0 {
			sockoptConfig.TCPKeepAliveInterval = nodeInfo.TCPKeepAliveInterval
		}
		if nodeInfo.TCPWindowClamp > 0 {
			sockoptConfig.TCPWindowClamp = nodeInfo.TCPWindowClamp
		}
		if nodeInfo.TCPMaxSeg > 0 {
			sockoptConfig.TCPMaxSeg = nodeInfo.TCPMaxSeg
		}
		if nodeInfo.TCPUserTimeout > 0 {
			sockoptConfig.TCPUserTimeout = nodeInfo.TCPUserTimeout
		}
		if nodeInfo.TCPKeepAliveIdle > 0 {
			sockoptConfig.TCPKeepAliveIdle = nodeInfo.TCPKeepAliveIdle
		}
		if nodeInfo.TcpMptcp {
			sockoptConfig.TcpMptcp = nodeInfo.TcpMptcp
		}
			
		streamSetting.SocketSettings = sockoptConfig
	}
	
	
	inboundDetourConfig.StreamSetting = streamSetting

	return inboundDetourConfig.Build()
}

func getCertFile(certConfig *mylego.CertConfig, CertMode string, Domain string) (certFile string, keyFile string, err error) {
	switch CertMode {
	case "file":
		if certConfig.CertFile == "" || certConfig.KeyFile == "" {
			return "", "", fmt.Errorf("Cert file path or key file path missing, check your config.yml parameters.")
		}
		return certConfig.CertFile, certConfig.KeyFile, nil
	case "dns":
		lego, err := mylego.New(certConfig)
		if err != nil {
			return "", "", err
		}
		certPath, keyPath, err := lego.DNSCert(CertMode, Domain)
		if err != nil {
			return "", "", err
		}
		return certPath, keyPath, err
	case "http", "tls":
		lego, err := mylego.New(certConfig)
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