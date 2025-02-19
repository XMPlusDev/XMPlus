package xmplus

import (
    "bufio"
	"encoding/json"
	"fmt"
	"errors"
	"log"
	"regexp"
	"sync/atomic"
	"time"
	"sync"
	"os"
	"reflect"

	"github.com/bitly/go-simplejson"
	"github.com/go-resty/resty/v2"
	"github.com/XMPlusDev/XMPlus/api"
)

type APIClient struct {
	client        *resty.Client
	APIHost       string
	NodeID        int
	Key           string
	resp          atomic.Value
	eTags          map[string]string
	LastReportOnline   map[int]int
	access        sync.Mutex
	LocalRuleList []api.DetectRule
}

func New(apiConfig *api.Config) *APIClient {
	client := resty.New()
	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		if v, ok := err.(*resty.ResponseError); ok {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})
	client.SetBaseURL(apiConfig.APIHost)
	
	client.SetQueryParam("key", apiConfig.Key)
	
	localRuleList := readLocalRuleList(apiConfig.RuleListPath)
	
	apiClient := &APIClient{
		client:        client,
		NodeID:        apiConfig.NodeID,
		Key:           apiConfig.Key,
		APIHost:       apiConfig.APIHost,
		LastReportOnline:    make(map[int]int),
		eTags:         make(map[string]string),
		LocalRuleList:    localRuleList,
	}
	
	return apiClient
}

// readLocalRuleList reads the local rule list file
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {

	LocalRuleList = make([]api.DetectRule, 0)
	if path != "" {
		// open the file
		file, err := os.Open(path)

		// handle errors while opening
		if err != nil {
			log.Printf("Error when opening file: %s", err)
			return LocalRuleList
		}

		fileScanner := bufio.NewScanner(file)

		// read line by line
		for fileScanner.Scan() {
			LocalRuleList = append(LocalRuleList, api.DetectRule{
				ID:      -1,
				Pattern: regexp.MustCompile(fileScanner.Text()),
			})
		}
		// handle first encountered error while reading
		if err := fileScanner.Err(); err != nil {
			log.Fatalf("Error while reading file: %s", err)
			return
		}

		file.Close()
	}

	return LocalRuleList
}

func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key}
}

func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*simplejson.Json, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	if res.StatusCode() > 400 {
		body := res.Body()
		return nil, fmt.Errorf("request %s failed: %s, %v", c.assembleURL(path), string(body), err)
	}
	
	rtn, err := simplejson.NewJson(res.Body())
	
	if err != nil {
		return nil, fmt.Errorf("%s", res.String())
	}
	return rtn, nil
}

func (c *APIClient) parseSubscriptionResponse(res *resty.Response, path string, err error) (*SubscriptionResponse, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	if res.StatusCode() > 400 {
		body := res.Body()
		return nil, fmt.Errorf("request %s failed: %s, %v", c.assembleURL(path), string(body), err)
	}
	
	response := res.Result().(*SubscriptionResponse)

	return response, nil
}

func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	server := new(serverConfig)
	path := fmt.Sprintf("/api/server/%d", c.NodeID)
	res, err := c.client.R().
		ForceContentType("application/json").
		SetHeader("If-None-Match", c.eTags["server"]).
		Get(path)

	if res.StatusCode() == 304 {
		return nil, errors.New(api.NodeNotModified)
	}
	// update etag
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["server"] {
		c.eTags["server"] = res.Header().Get("Etag")
	}
	
	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	
	b, _ := response.Encode()
	json.Unmarshal(b, server)

	if server.Port == "" {
		return nil, fmt.Errorf("invalid server port range:  %s.  eg 8000-8999", server.Port)
	}
	
	if server.Type == "" {
		return nil, fmt.Errorf("server Type cannot be %s", server.Type)
	}
	
	c.resp.Store(server)
	
	nodeInfo, err = c.parseNodeResponse(server)
	if err != nil {
		return nil, fmt.Errorf("Parse node info failed: %s, \nError: %v", res.String(), err)
	}
	return nodeInfo, nil
}


func (c *APIClient) GetSubscriptionList() (SubscriptionList *[]api.SubscriptionInfo, err error) {
	path := fmt.Sprintf("/api/subscriptions/%d", c.NodeID)
	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTags["subscriptions"]).
		SetResult(&SubscriptionResponse{}).
		ForceContentType("application/json").
		Get(path)
	
	if res.StatusCode() == 304 {
		return nil, errors.New(api.SubscriptionNotModified)
	}
	// update etag
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["subscriptions"] {
		c.eTags["subscriptions"] = res.Header().Get("Etag")
	}

	response, err := c.parseSubscriptionResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	
	subscriptionsListResponse := new([]Subscription)

	if err := json.Unmarshal(response.Data, subscriptionsListResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(subscriptionsListResponse), err)
	}
	
	subscriptionList, err := c.ParseSubscriptionList(subscriptionsListResponse)
	if err != nil {
		res, _ := json.Marshal(subscriptionsListResponse)
		return nil, fmt.Errorf("parse subscription list failed: %s", string(res))
	}
	
	return subscriptionList, nil
}

func (c *APIClient) ParseSubscriptionList(subscriptionResponse *[]Subscription) (*[]api.SubscriptionInfo, error) {
	c.access.Lock()
	defer func() {
		c.LastReportOnline = make(map[int]int)
		c.access.Unlock()
	}()	
	
	var deviceLimit, onlineipcount, ipcount int = 0, 0, 0
	var speedLimit uint64 = 0
	
	subscriptionList := []api.SubscriptionInfo{}
	
	for _, subscription := range *subscriptionResponse {
		deviceLimit = subscription.Iplimit
		ipcount = subscription.Ipcount
		
		if deviceLimit > 0 && ipcount > 0 {
			lastOnline := 0
			if v, ok := c.LastReportOnline[subscription.Id]; ok {
				lastOnline = v
			}
			if onlineipcount = deviceLimit - ipcount + lastOnline; onlineipcount > 0 {
				deviceLimit = onlineipcount
			} else if lastOnline > 0 {
				deviceLimit = lastOnline
			} else {
				continue
			}
		}

		speedLimit = uint64((subscription.Speedlimit * 1000000) / 8)
		
		subscriptionList = append(subscriptionList, api.SubscriptionInfo{
			UID:  subscription.Id,
			UUID: subscription.Uuid,
			Email: subscription.Email,
			Passwd: subscription.Passwd,
			DeviceLimit: deviceLimit,
			SpeedLimit:  speedLimit,
		})
	}

	return &subscriptionList, nil
}


func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	ruleList := c.LocalRuleList

	routes := c.resp.Load().(*serverConfig).Routes
	
	for i := range routes {
		ruleListItem := api.DetectRule{
			ID: routes[i].Id,
			Pattern: regexp.MustCompile(routes[i].Regex),
		}
		ruleList = append(ruleList, ruleListItem)
	}
	
	return &ruleList, nil
}


func (c *APIClient) ReportSubscriptionTraffic(subscriptionTraffic *[]api.SubscriptionTraffic) error {
	path := fmt.Sprintf("/api/traffic/%d", c.NodeID)

	data := make([]SubscriptionTraffic, len(*subscriptionTraffic))	
	for i, traffic := range *subscriptionTraffic {
		data[i] = SubscriptionTraffic{
			UID:      traffic.UID,
			Upload:   traffic.Upload,
			Download: traffic.Download,
		}
	}
	postData := &PostData{Data: data}
	res, err := c.client.R().
		SetBody(postData).
		ForceContentType("application/json").
		Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

func (c *APIClient) ReportNodeOnlineIPs(onlineSubscriptionList *[]api.OnlineIP) error {
	c.access.Lock()
	defer c.access.Unlock()

	reportOnline := make(map[int]int)
	data := make([]OnlineIP, len(*onlineSubscriptionList))
	for i, subscription := range *onlineSubscriptionList {
		data[i] = OnlineIP{UID: subscription.UID, IP: subscription.IP}
		if _, ok := reportOnline[subscription.UID]; ok {
			reportOnline[subscription.UID]++
		} else {
			reportOnline[subscription.UID] = 1
		}
	}
	c.LastReportOnline = reportOnline 

	postData := &PostData{Data: data}
	path := fmt.Sprintf("/api/onlineip/%d", c.NodeID)
	res, err := c.client.R().
		SetBody(postData).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

func (c *APIClient) parseNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	var (
		path, host, serviceName, seed, Dest, PrivateKey, MinClientVer, MaxClientVer, Flow, Authority, CurvePreferences, mode, DomainStrategy, ServerNameToVerify string
		header  json.RawMessage
		congestion ,RejectUnknownSni, Show, noSSEHeader, noGRPCHeader, TcpMptcp, SocketStatus, Insecure  bool
		MaxTimeDiff,ProxyProtocol  uint64 = 0, 0	
		HeartbeatPeriod uint32 = 10
		ServerNames,  ShortIds []string
		TCPWindowClamp, TCPMaxSeg, TCPUserTimeout, TCPKeepAliveIdle, TCPKeepAliveInterval int32 = 0, 0, 0, 0, 0	
	)
		
	if s.NetworkSettings.Flow == "xtls-rprx-vision" || s.NetworkSettings.Flow == "xtls-rprx-vision-udp443"{
		Flow = s.NetworkSettings.Flow
	}
	
	if s.NetworkSettings.Authority != "" {
		Authority = s.NetworkSettings.Authority
	}

	if s.Security == "tls" {
		RejectUnknownSni = s.SecuritySettings.RejectUnknownSni
		if s.SecuritySettings.ServerName == "" {
			return nil, fmt.Errorf("TLS certificate domain (ServerName) is empty: %s",  s.SecuritySettings.ServerName)
		}
		
		CurvePreferences = "X25519"
		if s.SecuritySettings.CurvePreferences != "" {
			CurvePreferences = s.SecuritySettings.CurvePreferences
		}
		
		ServerNameToVerify = ""
		if s.SecuritySettings.ServerNameToVerify != "" {
			ServerNameToVerify = s.SecuritySettings.ServerNameToVerify
		}
		
		Insecure = s.SecuritySettings.Insecure
	}
	
	if s.Security == "reality" {
		Dest = s.SecuritySettings.Dest
		Show = s.SecuritySettings.Show
		PrivateKey = s.SecuritySettings.PrivateKey
		MinClientVer = s.SecuritySettings.MinClientVer
		MaxClientVer = s.SecuritySettings.MaxClientVer
		MaxTimeDiff = uint64(s.SecuritySettings.MaxTimeDiff)
		ShortIds = s.SecuritySettings.ShortIds
		ServerNames = s.SecuritySettings.ServerNames
		ProxyProtocol = uint64(s.SecuritySettings.ProxyProtocol)
	}

	transportProtocol := s.NetworkSettings.Transport

	switch transportProtocol {
		case "ws", "websocket":
			path = s.NetworkSettings.Path
			host = s.NetworkSettings.Host
			HeartbeatPeriod = uint32(s.NetworkSettings.Heartbeat)
		case "h2", "h3", "http":
			return nil, errors.New("H2/HTTP is deprecated in this version of xray-core")
		case "httpupgrade":
			path = s.NetworkSettings.Path
			host = s.NetworkSettings.Host
		case "xhttp", "splithttp":
			path = s.NetworkSettings.Path
			host = s.NetworkSettings.Host
			noSSEHeader = s.NetworkSettings.noSSEHeader
			noGRPCHeader = s.NetworkSettings.noGRPCHeader
			mode = ""
			if s.NetworkSettings.mode != "" {
			   mode = s.NetworkSettings.mode
			}
		case "grpc":
			serviceName = s.NetworkSettings.ServiceName
		case "raw", "tcp":
			if httpHeader, err := s.NetworkSettings.Header.MarshalJSON(); err != nil {
					return nil, err
			} else {
				t, _ := simplejson.NewJson(httpHeader)
				htype := t.Get("type").MustString()
				if htype == "http" {
					path = t.Get("request").Get("path").MustString()
					header, _ = json.Marshal(map[string]any{
						"type": "http",
						"request": map[string]any{
							"path": path,
						}})
				}else{
					header, _ = json.Marshal(map[string]any{
						"type": "none",
					})
				}
			}
		case "quic":
			return nil, errors.New("Quic is deprecated in this version of xray-core")
		case "kcp", "mkcp":
			seed = s.NetworkSettings.Seed
			congestion = s.NetworkSettings.Congestion
			if httpHeader, err := s.NetworkSettings.Header.MarshalJSON(); err != nil {
					return nil, err
			} else {
				h, _ := simplejson.NewJson(httpHeader)
				htype := h.Get("type").MustString()
				if htype != "none" {
					header, _ = json.Marshal(map[string]any{
						"type": htype,
					})
				}else {
					header, _ = json.Marshal(map[string]any{
						"type": "none",
					})
				}
			}	
	}
	
	NodeType := s.Type
	if NodeType == "Shadowsocks" && transportProtocol != "tcp" {
		//NodeType = "Shadowsocks-Plugin"
		return nil, errors.New("Shadowsocks-Plugin is deprecated in this version of XMPlus backend")
	}
	
	//SocketSettings
	DomainStrategy = ""
	if s.SocketSettings.DomainStrategy != "" {
		DomainStrategy = s.SocketSettings.DomainStrategy
	}
	if s.SocketSettings.TCPKeepAliveInterval > 0 {
		TCPKeepAliveInterval = int32(s.SocketSettings.TCPKeepAliveInterval)
	}
	if s.SocketSettings.TCPKeepAliveIdle > 0 {
		TCPKeepAliveIdle = int32(s.SocketSettings.TCPKeepAliveIdle)
	}
	if s.SocketSettings.TCPUserTimeout > 0 {
		TCPUserTimeout = int32(s.SocketSettings.TCPUserTimeout)
	}
	if s.SocketSettings.TCPMaxSeg > 0 {
		TCPMaxSeg = int32(s.SocketSettings.TCPMaxSeg)
	}
	if s.SocketSettings.TCPWindowClamp > 0 {
		TCPWindowClamp = int32(s.SocketSettings.TCPWindowClamp)
	}
	if s.SocketSettings.TcpMptcp {
		TcpMptcp = s.SocketSettings.TcpMptcp
	}
	if s.SocketSettings.SocketStatus {
		SocketStatus = s.SocketSettings.SocketStatus
	}
	
	
	nodeInfo := &api.NodeInfo{
		NodeType:          NodeType,
		NodeID:            c.NodeID,
		Port:              s.Port,
		Transport:         transportProtocol,
		TLSType:           s.Security,
		Path:              path,
		Host:              host,
		HeartbeatPeriod:   HeartbeatPeriod,
		ServiceName:       serviceName,
		Flow:              Flow,
		Authority:         Authority,
		Header:            header,
		Seed:              seed,
		Congestion:        congestion,
		Sniffing:          s.Sniffing,
		RejectUnknownSNI:  RejectUnknownSni,
		Fingerprint:       s.SecuritySettings.Fingerprint, 
		CurvePreferences:  CurvePreferences, 
		CypherMethod:      s.Cipher,
		Address:           s.Address, 
		ListenIP:          s.Listenip, 
		ProxyProtocol:     s.NetworkSettings.ProxyProtocol,
		CertMode:          s.Certmode,
		CertDomain:        s.SecuritySettings.ServerName,
		ServerKey:         s.ServerKey,
		SpeedLimit:        uint64(s.Speedlimit * 1000000 / 8),
		SendIP:            s.SendThrough,
		Dest:              Dest,
		Show:              Show,
		ServerNames:       ServerNames,  
		PrivateKey:        PrivateKey,
		ShortIds:          ShortIds,
		MinClientVer:      MinClientVer,
		MaxClientVer:      MaxClientVer,
		MaxTimeDiff:       MaxTimeDiff,
		Xver:              ProxyProtocol,
		Relay:             s.Relay,
		RelayNodeID:       s.Relayid,
		NoSSEHeader:      noSSEHeader,
		NoGRPCHeader:     noGRPCHeader,
		Mode:             mode,
		TcpMptcp:         TcpMptcp,
		TCPWindowClamp:   TCPWindowClamp,
		TCPMaxSeg:        TCPMaxSeg,
		TCPUserTimeout:   TCPUserTimeout,
		TCPKeepAliveIdle: TCPKeepAliveIdle,
		TCPKeepAliveInterval: TCPKeepAliveInterval,
		DomainStrategy:   DomainStrategy,
		SocketStatus:     SocketStatus,
		ServerNameToVerify: ServerNameToVerify,
		Insecure:        Insecure,         
	}
	return nodeInfo, nil
}


func (c *APIClient) GetRelayNodeInfo() (*api.RelayNodeInfo, error) {
	s := c.resp.Load().(*serverConfig)
	var (
		path, host, serviceName, seed, PublicKey , ShortId ,SpiderX, ServerName, Flow, Authority, mode string
		header   json.RawMessage
		congestion, Show, noSSEHeader, noGRPCHeader  bool
		HeartbeatPeriod uint32 = 10
	)
		
	if s.RNetworkSettings.Flow == "xtls-rprx-vision" || 
		s.RNetworkSettings.Flow == "xtls-rprx-vision-udp443" &&
		s.RNetworkSettings.Transport == "tcp" {
		Flow = "xtls-rprx-vision-udp443"
	}
	
	if s.RNetworkSettings.Authority != "" {
		Authority = s.RNetworkSettings.Authority
	}

	if s.RSecurity == "reality" {
		PublicKey = s.RSecuritySettings.PublicKey
		Show = s.RSecuritySettings.Show
		ShortId = s.RSecuritySettings.ShortId
		SpiderX = s.RSecuritySettings.SpiderX
		ServerName = s.RSecuritySettings.ServerName
	}

	transportProtocol := s.RNetworkSettings.Transport

	switch transportProtocol {
	case "ws", "websocket":
		path = s.RNetworkSettings.Path
		host = s.RNetworkSettings.Host
		HeartbeatPeriod = uint32(s.RNetworkSettings.Heartbeat)
	case "h2", "h3", "http":
		return nil, errors.New("H2/HTTP is deprecated in this version of xray-core")
	case "httpupgrade":
		path = s.RNetworkSettings.Path
		host = s.RNetworkSettings.Host
	case "xhttp", "splithttp":
		path = s.RNetworkSettings.Path
		host = s.RNetworkSettings.Host
			noSSEHeader = s.RNetworkSettings.noSSEHeader
			noGRPCHeader = s.RNetworkSettings.noGRPCHeader
			mode = ""
			if s.RNetworkSettings.mode != "" {
			   mode = s.RNetworkSettings.mode
			}
	case "grpc":
		serviceName = s.RNetworkSettings.ServiceName
	case "raw", "tcp":
		if httpHeader, err := s.RNetworkSettings.Header.MarshalJSON(); err != nil {
				return nil, err
		} else {
			t, _ := simplejson.NewJson(httpHeader)
			htype := t.Get("type").MustString()
			if htype == "http" {
				path = t.Get("request").Get("path").MustString()
				header, _ = json.Marshal(map[string]any{
					"type": "http",
					"request": map[string]any{
						"path": path,
					}})
			}else{
				header, _ = json.Marshal(map[string]any{
					"type": "none",
				})
			}
		}
	case "quic":
		return nil, errors.New("Quic is deprecated in this version of xray-core")
	case "kcp", "mkcp":
		seed = s.RNetworkSettings.Seed
		congestion = s.RNetworkSettings.Congestion
		if httpHeader, err := s.RNetworkSettings.Header.MarshalJSON(); err != nil {
				return nil, err
		} else {
			h, _ := simplejson.NewJson(httpHeader)
			htype := h.Get("type").MustString()
			if htype != "none" {
				header, _ = json.Marshal(map[string]any{
					"type": htype,
				})
			}else {
				header, _ = json.Marshal(map[string]any{
					"type": "none",
				})
			}
		}		
	}
	
	NodeType := s.RType
	if NodeType == "Shadowsocks"  && transportProtocol != "tcp" {
		//NodeType = "Shadowsocks-Plugin"
		return nil, errors.New("Shadowsocks-Plugin is deprecated in this version of XMPlus backend")
	}
	
	// Create GeneralNodeInfo
	nodeInfo := &api.RelayNodeInfo{
		NodeType:          NodeType,
		NodeID:            s.RServerid,
		Port:              uint32(s.RPort),
		Transport:         transportProtocol,
		TLSType:           s.RSecurity,
		Path:              path,
		Host:              host,
		HeartbeatPeriod:   HeartbeatPeriod,
		Flow:              Flow,
		Authority:         Authority,
		Seed :             seed,
		Congestion:        congestion,	
		ServiceName:       serviceName,
		Fingerprint:       s.RSecuritySettings.Fingerprint, 
		Header:            header,
		CypherMethod:      s.RCipher,
		Address:           s.RAddress, 
		ListenIP:          s.RListenip, 
		ProxyProtocol:     s.RNetworkSettings.ProxyProtocol,
		ServerKey:         s.RServerKey,
		SendIP:            s.RSendThrough,
		PublicKey:         PublicKey,
		ShortId:           ShortId,
		SpiderX:           SpiderX,
		Show:              Show,
		ServerName:        ServerName,
		NoSSEHeader:      noSSEHeader,
		NoGRPCHeader:     noGRPCHeader,
		Mode:             mode,
	}
	return nodeInfo, nil
}