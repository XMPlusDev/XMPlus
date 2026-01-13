package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"errors"

	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"
)

func (c *Client) GetNodeInfo() (nodeInfo *NodeInfo, err error) {
	server := new(serverConfig)
	res, err := c.client.R().
		ForceContentType("application/json").
		SetPathParam("serverId", c.NodeID).
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
	// transport settings
	if transport, err := s.NetworkSettings.MarshalJSON(); err != nil {
		return nil, err
	} else {
		transportData, err := simplejson.NewJson(transport)
		if err != nil {
			return nil, err
		}
		
		nodeInfo := &NodeInfo{}
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
		nodeInfo.SendThrough = transportData.Get("sendThroughIP").MustString()
		
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
			nodeInfo.UseSocket = bool(true)
			nodeInfo.SocketSettings.TCPKeepAliveInterval =  int32(socketSettings.Get("tCPKeepAliveInterval").Int())
			nodeInfo.SocketSettings.TCPKeepAliveIdle = int32(socketSettings.Get("tCPKeepAliveIdle").Int())
			nodeInfo.SocketSettings.TCPUserTimeout = int32(socketSettings.Get("tCPUserTimeout").Int())
			nodeInfo.SocketSettings.TCPMaxSeg = int32(socketSettings.Get("tCPMaxSeg").Int())
			nodeInfo.SocketSettings.TCPWindowClamp = int32(socketSettings.Get("tCPWindowClamp").Int())
			nodeInfo.SocketSettings.TcpMptcp = socketSettings.Get("tcpMptcp").Bool()
			nodeInfo.SocketSettings.DomainStrategy = socketSettings.Get("domainStrategy").String()
		}
	}
	
	// security settings
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
				var alpnStrings []string
				for _, v := range alpnArray {
					if str, ok := v.(string); ok {
						alpnStrings = append(alpnStrings, str)
					}
				}
				nodeInfo.TlsSettings.Alpn = strings.Join(alpnStrings, ",")
			}
		}
		
		if realitySettings, ok := securityData.CheckGet("realitySettings"); ok {
			nodeInfo.SecurityType = "reality"
			nodeInfo.RealitySettings = &RealitySettings{}
    
			if dest, err := realitySettings.Get("dest").String(); err == nil {
				target, err := dest.MarshalJSON(); err != nil {
					return nil, err
				}
				nodeInfo.RealitySettings.Dest = target
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
				var serverNames []string
				for _, v := range serverNamesArray {
					if str, ok := v.(string); ok {
						serverNames = append(serverNames, str)
					}
				}
				nodeInfo.RealitySettings.ServerNames = serverNames
			}
			if shortIdsArray, err := realitySettings.Get("shortids").Array(); err == nil {
				var shortIds []string
				for _, v := range shortIdsArray {
					if str, ok := v.(string); ok {
						shortIds = append(shortIds, str)
					}
				}
				nodeInfo.RealitySettings.ShortIds = shortIds
			}
			if mldsa65Seed, err := realitySettings.Get("Mldsa65Seed").String(); err == nil {
				nodeInfo.RealitySettings.Mldsa65Seed = mldsa65Seed
			}
			
			// transit
			nodeInfo.RealitySettings.PublicKey = realitySettings.Get("publickey").String()
			nodeInfo.RealitySettings.ServerName = realitySettings.Get("serverName").String()
			nodeInfo.RealitySettings.ShortId = realitySettings.Get("shortid").String()
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
	
	if rule, err := s.blockingRules.MarshalJSON(); err != nil {
		return nil, err
	} else {
		ruleData, err := simplejson.NewJson(rule)
		if err != nil {
			return nil, err
		}
		
		nodeInfo.BlockingRules := &BlockingRules{}
		
		if ipData, ipKeyExists := ruleData.CheckGet("ip"); ipKeyExists {
			nodeInfo.BlockingRules.IP = ipData
		}
		if domainData, domainKeyExists := ruleData.CheckGet("domain"); domainKeyExists {
			nodeInfo.BlockingRules.Domain = domainData
		}
		if portData, portKeyExists := ruleData.CheckGet("port"); portKeyExists {
			nodeInfo.BlockingRules.Port = portData
		}
		if protocolData, protocolKeyExists := ruleData.CheckGet("protocol"); protocolKeyExists {
			nodeInfo.BlockingRules.Protocol = protocolData
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
	
	// transport settings
	if transport, err := s.RNetworkSettings.MarshalJSON(); err != nil {
		return nil, err
	} else {
		transportData, err := simplejson.NewJson(transport)
		if err != nil {
			return nil, err
		}
		
		nodeInfo := &RelayNodeInfo{}
		nodeInfo.NetworkType = ""
		nodeInfo.NodeType = s.RType
		nodeInfo.NodeID = s.NodeId
		nodeInfo.Address = s.RAddress
		
		nodeInfo.ListeningPort = transportData.Get("listeningPort").MustString()
		nodeInfo.SendThrough = transportData.Get("sendThroughIP").MustString()
		
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
			nodeInfo.RealitySettings.PublicKey = realitySettings.Get("publickey").String()
			nodeInfo.RealitySettings.ServerName = realitySettings.Get("serverName").String()
			nodeInfo.RealitySettings.ShortId = realitySettings.Get("shortid").String()
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
