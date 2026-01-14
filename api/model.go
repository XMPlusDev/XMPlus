package api

import (
	"encoding/json"
)

const (
	SubscriptionNotModified = "subscriptions not modified"
	NodeNotModified = "node not modified"
	RuleNotModified = "rules not modified"
)

type Response struct {
	Ret  uint            `json:"ret"`
	Data json.RawMessage `json:"data"`
}

type PostData struct {
	Key  string      `json:"key"`
	Data interface{} `json:"data"`
}

type serverConfig struct {
	server          `json:"server"`
	transitServer   `json:"transit_server"`
	updateInterval   int `json:"update_interval"`
	apiVersion       string  `json:"version"`
	blockingRules   *json.RawMessage `json:"rules"`
}

type server struct {
	Type        string `json:"type"`
	Cipher      string `json:"cipher"`
	IP          string `json:"ip"`
	RelayNodeId int    `json:"transit_server_id"`
	ServerKey   string `json:"server_key"`
	Speedlimit  int    `json:"speed_limit"`
	NetworkSettings  *json.RawMessage `json:"transportSettings"`
	SecuritySettings *json.RawMessage `json:"securitySettings"`
}

type transitServer struct {
	RType        string `json:"type"`
	NodeId       int    `json:"server_id"`
	RAddress     string `json:"address"`
	RCipher      string `json:"cipher"`
	RServerKey   string `json:"server_key"`
	RNetworkSettings  *json.RawMessage `json:"transportSettings"`
	RSecuritySettings *json.RawMessage `json:"securitySettings"`
}

type SubscriptionResponse struct {
	Data json.RawMessage `json:"subscriptions"`
}

type Subscription struct {
	Id         int    `json:"id"`
	Email      string `json:"email"`
	Passwd     string `json:"passwd"`
	Speedlimit int    `json:"speed_limit"`
	Iplimit    int    `json:"IP_limit"`
	Ipcount    int    `json:"alive_ip_count"`
}

type BlockingRules struct {
	Domain      []string
	IP          []string
	Port        string
	Protocol    []string
}

type TlsSettings struct {
	CertMode           string
	ServerName         string 
	FingerPrint    	   string 
	AllowInsecure      bool  
	CurvePreferences   string 
	RejectUnknownSni   bool  
	ServerNameToVerify string 
	Alpn               []string
}

type RealitySettings struct {
	Dest              json.RawMessage
	Show              bool 
	MinClientVer      string 
	MaxClientVer      string 
	MaxTimeDiff       uint64 
	Xver              uint64  
	ServerNames       []string 
	ShortIds          []string 
	Mldsa65Seed       string
	PrivateKey        string
	
	ShortId           string
	SpiderX           string
	ServerName        string
	Fingerprint       string
	PublicKey         string
	Mldsa65Verify     string
}

type SocketSettings struct {
	TCPKeepAliveInterval int32 
	TCPKeepAliveIdle     int32 
	TCPUserTimeout       int32 
	TCPMaxSeg            int32 
	TcpMptcp             bool
	TCPWindowClamp       int32
	DomainStrategy       string
}

type XhttpSettings struct {
	Host           string
	Path           string
	Mode           string
	NoSSEHeader    bool
	NoGRPCHeader   bool
}

type RawSettings struct {
	Flow                string
	Header              json.RawMessage
}

type WsSettings struct {
	Host                string
	Path                string
	HeartbeatPeriod     uint32
}

type HttpSettings struct {
	Host                string
	Path                string
}

type GrpcSettings struct {
	ServiceName    string
	Authority      string
}

type KcpSettings struct {
	Seed           string
	Congestion     bool
	Header         json.RawMessage
}

type NodeInfo struct {
	NodeType        string
	NodeID          int
	RelayNodeID     int
	RelayType       int
	SpeedLimit      uint64
	UpdateTime      int
	Sniffing        bool
	ListeningIP     string
	ListeningPort   string
	SendThroughIP   string
	Cipher          string
	Flow            string
	UseSocket       bool
	AcceptProxyProtocol bool
	ServerKey       string
	Decryption      string
	SecurityType    string
	NetworkType     string
	KcpSettings     *KcpSettings
	GrpcSettings    *GrpcSettings
	RawSettings     *RawSettings
	HttpSettings    *HttpSettings
	WsSettings      *WsSettings
	XhttpSettings   *XhttpSettings
	SocketSettings  *SocketSettings
	RealitySettings *RealitySettings
	TlsSettings     *TlsSettings
	RelayNodeInfo   *RelayNodeInfo
	BlockingRules   *BlockingRules
}

type RelayNodeInfo struct {
	NodeType        string
	NodeID          int
	Address         string
	ListeningPort   uint16
	SendThroughIP   string
	SecurityType    string
	NetworkType     string
	Cipher          string
	Flow            string
	ServerKey       string
	Encryption      string
	AcceptProxyProtocol bool
	KcpSettings     *KcpSettings
	GrpcSettings    *GrpcSettings
	RawSettings     *RawSettings
	HttpSettings    *HttpSettings
	WsSettings      *WsSettings
	XhttpSettings   *XhttpSettings
	RealitySettings *RealitySettings
	TlsSettings     *TlsSettings
}

type SubscriptionInfo struct {
	Id           int
	Email        string
	Passwd       string
	SpeedLimit   uint64
	IPLimit      int
}

type OnlineIP struct {
	Id  int
	IP  string
}

type SubscriptionTraffic struct {
	Id  int
	U   int64
	D   int64
}