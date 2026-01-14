package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"errors"

	"github.com/bitly/go-simplejson"
)

func (c *Client) GetNodeInfo() (nodeInfo *NodeInfo, err error) {
	server := new(serverConfig)
	res, err := c.client.R().
		SetBody(map[string]string{"key": c.Key}).
		SetForceResponseContentType("application/json").
		SetPathParam("serverId", string(c.NodeID)).
		SetHeader("If-None-Match", c.eTags["server"]).
		Post("/api/server/info/{serverId}")

	if res.StatusCode() == 304 {
		return nil, errors.New(NodeNotModified)
	}

	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["server"] {
		c.eTags["server"] = res.Header().Get("Etag")
	}

	response, err := c.checkResponse(res, err)
	if err != nil {
		return nil, err
	}

	b, _ := response.Encode()
	json.Unmarshal(b, server)

	if server.Type == "" {
		return nil, fmt.Errorf("server Type cannot be %s", server.Type)
	}

	c.resp.Store(server)

	nodeInfo, err = c.NodeResponse(server)
	if err != nil {
		return nil, fmt.Errorf("Parse node info failed: %s, \nError: %v", res.String(), err)
	}
	
	return nodeInfo, nil
}

func (c *Client) NodeResponse(s *serverConfig) (*NodeInfo, error) {
	nodeInfo := &NodeInfo{}
	
	if transport, err := s.NetworkSettings.MarshalJSON(); err != nil {
		return nil, err
	} else {
		transportData, err := simplejson.NewJson(transport)
		if err != nil {
			return nil, err
		}
		
		nodeInfo.NetworkType = ""
		nodeInfo.NodeType = strings.ToLower(s.Type)
		nodeInfo.NodeID = c.NodeID
		nodeInfo.RelayNodeID = int(s.RelayNodeId)
		nodeInfo.RelayType = transportData.Get("transit_server_type").MustInt()
		nodeInfo.SpeedLimit = uint64(s.Speedlimit * 1000000 / 8)
		nodeInfo.UpdateTime = int(s.updateInterval)
		
		nodeInfo.Sniffing = transportData.Get("sniffing").MustBool()
		nodeInfo.ListeningIP = transportData.Get("listeningIP").MustString()
		nodeInfo.ListeningPort = transportData.Get("listeningPort").MustString()
		nodeInfo.SendThroughIP = transportData.Get("sendThroughIP").MustString()
		
		if nodeInfo.NodeType == "vless" {
			nodeInfo.Decryption = transportData.Get("decryption").MustString()
		}
		
		if nodeInfo.NodeType == "shadowsocks" {
			nodeInfo.Cipher = s.Cipher
			nodeInfo.ServerKey = s.ServerKey
		}
		
		if xhttpSettings, ok := transportData.CheckGet("xhttpSettings"); ok {
			nodeInfo.NetworkType = "xhttp"
			nodeInfo.XhttpSettings = &XhttpSettings{} 
			
			nodeInfo.XhttpSettings.Host = xhttpSettings.Get("host").MustString()
			nodeInfo.XhttpSettings.Path = xhttpSettings.Get("path").MustString()
			nodeInfo.XhttpSettings.Mode = xhttpSettings.Get("mode").MustString()
			nodeInfo.XhttpSettings.NoSSEHeader = xhttpSettings.Get("NoSSEHeader").MustBool()
			nodeInfo.XhttpSettings.NoGRPCHeader = xhttpSettings.Get("NoGRPCHeader").MustBool()
		}
		
		if rawSettings, ok := transportData.CheckGet("rawSettings"); ok {
			nodeInfo.NetworkType = "raw"
			nodeInfo.RawSettings = &RawSettings{} 
			
			if _, flowExists := rawSettings.CheckGet("flow"); flowExists {
				nodeInfo.Flow = rawSettings.Get("flow").MustString()
			}else{
				nodeInfo.Flow = ""
			}
			if _, proxyProtocolExists := transportData.CheckGet("acceptProxyProtocol"); proxyProtocolExists {
				nodeInfo.AcceptProxyProtocol = transportData.Get("acceptProxyProtocol").MustBool()
			}
			if header, headerExist := rawSettings.CheckGet("header"); headerExist {
				headerBytes, err := header.MarshalJSON()
				if err != nil {
					return nil, err
				}
				nodeInfo.RawSettings.Header = headerBytes
			}
		}
		
		if kcpSettings, ok := transportData.CheckGet("kcpSettings"); ok {
			nodeInfo.NetworkType = "kcp"
			nodeInfo.KcpSettings = &KcpSettings{} 
			
			nodeInfo.KcpSettings.Seed = kcpSettings.Get("seed").MustString()
			nodeInfo.KcpSettings.Congestion = kcpSettings.Get("congestion").MustBool()
			if header, headerExist := kcpSettings.CheckGet("header"); headerExist {
				headerBytes, err := header.MarshalJSON()
				if err != nil {
					return nil, err
				}
				nodeInfo.KcpSettings.Header = headerBytes
			}
		}
		
		if grpcSettings, ok := transportData.CheckGet("grpcSettings"); ok {
			nodeInfo.NetworkType = "grpc"
			nodeInfo.GrpcSettings = &GrpcSettings{} 
			
			nodeInfo.GrpcSettings.ServiceName = grpcSettings.Get("servicename").MustString()
			nodeInfo.GrpcSettings.Authority = grpcSettings.Get("authority").MustString()
		}
		
		if wsSettings, ok := transportData.CheckGet("wsSettings"); ok {
			nodeInfo.NetworkType = "ws"
			nodeInfo.WsSettings = &WsSettings{} 
			
			nodeInfo.WsSettings.Host = wsSettings.Get("host").MustString()
			nodeInfo.WsSettings.Path = wsSettings.Get("path").MustString()
			nodeInfo.WsSettings.HeartbeatPeriod = uint32(wsSettings.Get("heartbeat").MustInt())
			if _, proxyProtocolExists := transportData.CheckGet("acceptProxyProtocol"); proxyProtocolExists {
				nodeInfo.AcceptProxyProtocol = transportData.Get("acceptProxyProtocol").MustBool()
			}
		}
		
		if httpupgradeSettings, ok := transportData.CheckGet("httpupgradeSettings"); ok {
			nodeInfo.NetworkType = "httpupgrade"
			nodeInfo.HttpSettings = &HttpSettings{}  
			
			nodeInfo.HttpSettings.Host = httpupgradeSettings.Get("host").MustString()
			nodeInfo.HttpSettings.Path = httpupgradeSettings.Get("path").MustString()
			if _, proxyProtocolExists := transportData.CheckGet("acceptProxyProtocol"); proxyProtocolExists {
				nodeInfo.AcceptProxyProtocol = transportData.Get("acceptProxyProtocol").MustBool()
			}
		}
		
		if nodeInfo.NetworkType == "" {
			return nil, fmt.Errorf("Unable to parse transport protocol")
		}
		
		if socketSettings, ok := transportData.CheckGet("socketSettings"); ok {
			nodeInfo.SocketSettings = &SocketSettings{}
			
			nodeInfo.UseSocket = true
			if tCPKeepAliveInterval, err := socketSettings.Get("tCPKeepAliveInterval").Int(); err == nil {
				nodeInfo.SocketSettings.TCPKeepAliveInterval =  int32(tCPKeepAliveInterval)
			}
			if tCPKeepAliveIdle, err := socketSettings.Get("tCPKeepAliveIdle").Int(); err == nil {
				nodeInfo.SocketSettings.TCPKeepAliveIdle = int32(tCPKeepAliveIdle)
			}
			if tCPUserTimeout, err := socketSettings.Get("tCPUserTimeout").Int(); err == nil {
				nodeInfo.SocketSettings.TCPUserTimeout = int32(tCPUserTimeout)
			}
			if tCPMaxSeg, err := socketSettings.Get("tCPMaxSeg").Int(); err == nil {
				nodeInfo.SocketSettings.TCPMaxSeg = int32(tCPMaxSeg)
			}
			if tCPWindowClamp, err := socketSettings.Get("tCPWindowClamp").Int(); err == nil {
				nodeInfo.SocketSettings.TCPWindowClamp = int32(tCPWindowClamp)
			}
			if tcpMptcp, err := socketSettings.Get("tcpMptcp").Bool(); err == nil {
				nodeInfo.SocketSettings.TcpMptcp = tcpMptcp
			}
			if domainStrategy, err := socketSettings.Get("domainStrategy").String(); err == nil {
				nodeInfo.SocketSettings.DomainStrategy = domainStrategy
			}
		}
	}
	
	if security, err := s.SecuritySettings.MarshalJSON(); err != nil {
		return nil, err
	} else {
		securityData, err := simplejson.NewJson(security)
		if err != nil {
			return nil, err
		}
		
		nodeInfo.SecurityType = "none"
		
		if tlsSettings, ok := securityData.CheckGet("tlsSettings"); ok {
			nodeInfo.SecurityType = "tls"
			nodeInfo.TlsSettings = &TlsSettings{}  
			
			if certMode, err := tlsSettings.Get("certMode").String(); err == nil {
				nodeInfo.TlsSettings.CertMode = certMode
			}
			
			serverName, err := tlsSettings.Get("serverName").String(); 
			if err == nil {
				if serverName == "" {
					return nil, fmt.Errorf("TLS certificate domain is empty: %s", serverName)
				}
				nodeInfo.TlsSettings.ServerName = serverName
			}
			if fingerprint, err := tlsSettings.Get("fingerprint").String(); err == nil {
				nodeInfo.TlsSettings.FingerPrint = fingerprint
			}
			if allowInsecure, err := tlsSettings.Get("allowInsecure").Bool(); err == nil {
				nodeInfo.TlsSettings.AllowInsecure = allowInsecure
			}
			if curvePreferences, err := tlsSettings.Get("curvepreferences").String(); err == nil {
				nodeInfo.TlsSettings.CurvePreferences = curvePreferences
			}
			if rejectUnknownSni, err := tlsSettings.Get("rejectUnknownSni").Bool(); err == nil {
				nodeInfo.TlsSettings.RejectUnknownSni = rejectUnknownSni
			}
			if serverNameToVerify, err := tlsSettings.Get("serverNameToVerify").String(); err == nil {
				nodeInfo.TlsSettings.ServerNameToVerify = serverNameToVerify
			}
			if alpnArray, err := tlsSettings.Get("alpn").Array(); err == nil {
				nodeInfo.TlsSettings.Alpn = alpnArray 
			}
		}
		
		if realitySettings, ok := securityData.CheckGet("realitySettings"); ok {
			nodeInfo.SecurityType = "reality"
			nodeInfo.RealitySettings = &RealitySettings{}
			
			if dest, err := realitySettings.Get("dest").String(); err == nil {
				destBytes, err := json.Marshal(dest)
				if err != nil {
					return nil, err
				}
				nodeInfo.RealitySettings.Dest = json.RawMessage(destBytes)
			}
			if show, err := realitySettings.Get("show").Bool(); err == nil {
				nodeInfo.RealitySettings.Show = show
			}
			if minClientVer, err := realitySettings.Get("minClientVer").String(); err == nil {
				nodeInfo.RealitySettings.MinClientVer = minClientVer
			}
			if maxClientVer, err := realitySettings.Get("maxClientVer").String(); err == nil {
				nodeInfo.RealitySettings.MaxClientVer = maxClientVer
			}
			if maxTimeDiff, err := realitySettings.Get("maxTimeDiff").Int(); err == nil {
				nodeInfo.RealitySettings.MaxTimeDiff = uint64(maxTimeDiff)
			}
			if xver, err := realitySettings.Get("xver").Int(); err == nil {
				nodeInfo.RealitySettings.Xver = uint64(xver)
			}
			if serverNamesArray, err := realitySettings.Get("serverNames").Array(); err == nil {
				nodeInfo.RealitySettings.ServerNames = serverNamesArray
			}
			if shortIdsArray, err := realitySettings.Get("shortids").Array(); err == nil {
				nodeInfo.RealitySettings.ShortIds = shortIdsArray
			}
			if mldsa65Seed, err := realitySettings.Get("Mldsa65Seed").String(); err == nil {
				nodeInfo.RealitySettings.Mldsa65Seed = mldsa65Seed
			}
			if privateKey, err := realitySettings.Get("privateKey").String(); err == nil {
				nodeInfo.RealitySettings.PrivateKey = privateKey
			}	
		}
	}
	
	if rule, err := s.blockingRules.MarshalJSON(); err != nil {
		return nil, err
	} else {
		ruleData, err := simplejson.NewJson(rule)
		if err != nil {
			return nil, err
		}
		
		nodeInfo.BlockingRules = &BlockingRules{}
		
		if ipData, ipKeyExists := ruleData.CheckGet("ip"); ipKeyExists {
			if ipArray, err := ipData.Array(); err == nil {
				nodeInfo.BlockingRules.IP = ipArray
			}
		}
		if domainData, domainKeyExists := ruleData.CheckGet("domain"); domainKeyExists {
			if domainArray, err := domainData.Array(); err == nil {
				nodeInfo.BlockingRules.Domain = domainArray
			}
		}
		if portData, portKeyExists := ruleData.CheckGet("port"); portKeyExists {
			if portStr, err := portData.String(); err == nil {
				nodeInfo.BlockingRules.Port = portStr
			}
		}
		if protocolData, protocolKeyExists := ruleData.CheckGet("protocol"); protocolKeyExists {
			if protocolArray, err := protocolData.Array(); err == nil {
				nodeInfo.BlockingRules.Protocol = protocolArray
			}
		}
	}
	
	if nodeInfo.RelayNodeID > 0 && nodeInfo.RelayType == 1 {
		relayNodeInfo, err := c.TransitNodeResponse()
		if err != nil {
			return nil, fmt.Errorf("Error occured while parsing relay node info: %s", err)
		}
		
		nodeInfo.RelayNodeInfo = &RelayNodeInfo{}
		nodeInfo.RelayNodeInfo = relayNodeInfo
	}

	return nodeInfo, nil
}

func (c *Client) TransitNodeResponse() (*RelayNodeInfo, error) {
	s := c.resp.Load().(*serverConfig)
	
	nodeInfo := &RelayNodeInfo{}
	
	// transport settings
	if transport, err := s.RNetworkSettings.MarshalJSON(); err != nil {
		return nil, err
	} else {
		transportData, err := simplejson.NewJson(transport)
		if err != nil {
			return nil, err
		}
		
		nodeInfo.NetworkType = ""
		nodeInfo.NodeType = s.RType
		nodeInfo.NodeID = s.NodeId
		nodeInfo.Address = s.RAddress
		
		nodeInfo.ListeningPort = uint16(transportData.Get("listeningPort").MustString())
		nodeInfo.SendThroughIP = transportData.Get("sendThroughIP").MustString()
		
		if nodeInfo.NodeType == "vless" {
			nodeInfo.Encryption = transportData.Get("encryption").MustString()
		}
		
		if nodeInfo.NodeType == "shadowsocks" {
			nodeInfo.Cipher = s.Cipher
			nodeInfo.ServerKey = s.ServerKey
		}
		
		if xhttpSettings, ok := transportData.CheckGet("xhttpSettings"); ok {
			nodeInfo.NetworkType = "xhttp"
			nodeInfo.XhttpSettings = &XhttpSettings{} 
			
			nodeInfo.XhttpSettings.Host = xhttpSettings.Get("host").MustString()
			nodeInfo.XhttpSettings.Path = xhttpSettings.Get("path").MustString()
			nodeInfo.XhttpSettings.Mode = xhttpSettings.Get("mode").MustString()
			nodeInfo.XhttpSettings.NoSSEHeader = xhttpSettings.Get("NoSSEHeader").MustBool()
			nodeInfo.XhttpSettings.NoGRPCHeader = xhttpSettings.Get("NoGRPCHeader").MustBool()
		}
		
		if rawSettings, ok := transportData.CheckGet("rawSettings"); ok {
			nodeInfo.NetworkType = "raw"
			nodeInfo.RawSettings = &RawSettings{} 
			
			if _, flowExists := rawSettings.CheckGet("flow"); flowExists {
				nodeInfo.RawSettings.Flow = rawSettings.Get("flow").MustString()
			}
			if _, proxyProtocolExists := transportData.CheckGet("acceptProxyProtocol"); proxyProtocolExists {
				nodeInfo.AcceptProxyProtocol = transportData.Get("acceptProxyProtocol").MustBool()
			}
			if header, headerExist := rawSettings.CheckGet("header"); headerExist {
				headerBytes, err := header.MarshalJSON()
				if err != nil {
					return nil, err
				}
				nodeInfo.RawSettings.Header = headerBytes
			}
		}
		
		if kcpSettings, ok := transportData.CheckGet("kcpSettings"); ok {
			nodeInfo.NetworkType = "kcp"
			nodeInfo.KcpSettings = &KcpSettings{} 
			
			nodeInfo.KcpSettings.Seed = kcpSettings.Get("seed").MustString()
			nodeInfo.KcpSettings.Congestion = kcpSettings.Get("congestion").MustBool()
			if header, headerExist := kcpSettings.CheckGet("header"); headerExist {
				headerBytes, err := header.MarshalJSON()
				if err != nil {
					return nil, err
				}
				nodeInfo.KcpSettings.Header = headerBytes
			}
		}
		
		if grpcSettings, ok := transportData.CheckGet("grpcSettings"); ok {
			nodeInfo.NetworkType = "grpc"
			nodeInfo.GrpcSettings = &GrpcSettings{} 
			
			nodeInfo.GrpcSettings.ServiceName = grpcSettings.Get("servicename").MustString()
			nodeInfo.GrpcSettings.Authority = grpcSettings.Get("authority").MustString()
		}
		
		if wsSettings, ok := transportData.CheckGet("wsSettings"); ok {
			nodeInfo.NetworkType = "ws"
			nodeInfo.WsSettings = &WsSettings{} 
			
			nodeInfo.WsSettings.Host = wsSettings.Get("host").MustString()
			nodeInfo.WsSettings.Path = wsSettings.Get("path").MustString()
			nodeInfo.WsSettings.HeartbeatPeriod = uint32(wsSettings.Get("heartbeat").MustInt())
			if _, proxyProtocolExists := transportData.CheckGet("acceptProxyProtocol"); proxyProtocolExists {
				nodeInfo.AcceptProxyProtocol = transportData.Get("acceptProxyProtocol").MustBool()
			}
		}
		
		if httpupgradeSettings, ok := transportData.CheckGet("httpupgradeSettings"); ok {
			nodeInfo.NetworkType = "httpupgrade"
			nodeInfo.HttpSettings = &HttpSettings{}  
			
			nodeInfo.HttpSettings.Host = httpupgradeSettings.Get("host").MustString()
			nodeInfo.HttpSettings.Path = httpupgradeSettings.Get("path").MustString()
			if _, proxyProtocolExists := transportData.CheckGet("acceptProxyProtocol"); proxyProtocolExists {
				nodeInfo.AcceptProxyProtocol = transportData.Get("acceptProxyProtocol").MustBool()
			}
		}
		
		if nodeInfo.NetworkType == "" {
			return nil, fmt.Errorf("Unable to parse relay transport protocol")
		}
		
		if nodeInfo.NodeType == "shadowsocks" && nodeInfo.NetworkType != "raw" {
			nodeInfo.NetworkType = "Shadowsocks-Plugin"
		}
	}
	
	// security settings
	if security, err := s.RSecuritySettings.MarshalJSON(); err != nil {
		return nil, err
	} else {
		securityData, err := simplejson.NewJson(security)
		if err != nil {
			return nil, err
		}
		
		nodeInfo.SecurityType = "none"
		
		if tlsSettings, ok := securityData.CheckGet("tlsSettings"); ok {
			nodeInfo.SecurityType = "tls"
			nodeInfo.TlsSettings = &TlsSettings{}  
			if fingerprint, err := tlsSettings.Get("fingerprint").String(); err == nil {
				nodeInfo.TlsSettings.FingerPrint = fingerprint
			}
		}
		
		if realitySettings, ok := securityData.CheckGet("realitySettings"); ok {
			nodeInfo.SecurityType = "reality"
			nodeInfo.RealitySettings = &RealitySettings{}
			
			if show, err := realitySettings.Get("show").Bool(); err == nil {
				nodeInfo.RealitySettings.Show = show
			}
			if publicKey, err := realitySettings.Get("publickey").String(); err == nil {
				nodeInfo.RealitySettings.PublicKey = publicKey
			}
			if serverName, err := realitySettings.Get("serverName").String(); err == nil {
				nodeInfo.RealitySettings.ServerName = serverName
			}
			if shortid, err := realitySettings.Get("shortid").String(); err == nil {
				nodeInfo.RealitySettings.ShortId = shortid
			}
			if spiderX, err := realitySettings.Get("spiderX").String(); err == nil {
				nodeInfo.RealitySettings.SpiderX = spiderX
			}
			if fingerprint, err := realitySettings.Get("fingerprint").String(); err == nil {
				nodeInfo.RealitySettings.Fingerprint = fingerprint
			}
			if mldsa65Verify, err := realitySettings.Get("mldsa65Verify").String(); err == nil {
				nodeInfo.RealitySettings.Mldsa65Verify = mldsa65Verify
			}  	
		}
	}

	return nodeInfo, nil
}
