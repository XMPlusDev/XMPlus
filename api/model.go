package api

import (
	"encoding/json"
	"regexp"
)

const (
	SubscriptionNotModified = "subscriptions not modified"
	NodeNotModified = "node not modified"
	RuleNotModified = "rules not modified"
)

// Config API config
type Config struct {
	APIHost             string  `mapstructure:"ApiHost"`
	NodeID              int     `mapstructure:"NodeID"`
	Key                 string  `mapstructure:"ApiKey"`
	Timeout             int     `mapstructure:"Timeout"`
	RuleListPath        string  `mapstructure:"RuleListPath"`
}

type NodeInfo struct {
	NodeType          string 
	NodeID            int
	Port              string
	SpeedLimit        uint64 
	Transport         string
	Host              string
	Path              string
	TLSType           string
	CypherMethod      string
	Sniffing          bool
	RejectUnknownSNI  bool
	Fingerprint       string
	CurvePreferences  string
	Address           string
	ListenIP          string
	ProxyProtocol     bool
	CertMode          string
	CertDomain        string
	ServerKey         string
	ServiceName       string
	Authority         string
	Header            json.RawMessage
	SendIP            string
	Flow              string
	Seed              string
	Congestion        bool
	Dest              string
	Show              bool
	ServerNames       []string 
	PrivateKey        string
	ShortIds          []string 
	MinClientVer      string          
	MaxClientVer      string          
	MaxTimeDiff       uint64
	Xver              uint64
	Relay             bool
	RelayNodeID       int
	NoSSEHeader       bool
	Mode              string
	NoGRPCHeader      bool 
	HeartbeatPeriod   uint32
	ServerNameToVerify string
	TCPKeepAliveInterval  int32
	TCPKeepAliveIdle  int32
	TCPUserTimeout    int32
	TCPMaxSeg         int32
	TcpMptcp          bool
	TCPWindowClamp    int32
	DomainStrategy    string
	SocketStatus      bool
	Insecure          bool
}

type RelayNodeInfo struct {
	NodeType          string 
	NodeID            int
	Port              uint32
	Transport         string
	Host              string
	Path              string
	TLSType           string
	CypherMethod      string
	Address           string
	ListenIP          string
	ProxyProtocol     bool
	SendIP            string
	ServerKey         string
	ServiceName       string
	Authority         string
	Header            json.RawMessage
	Flow              string
	Seed              string
	Alpn              string
	Congestion        bool
	Fingerprint       string
	PublicKey         string
	ShortId           string
	SpiderX           string 
	Show              bool
	ServerName        string
	NoSSEHeader       bool
	Mode              string
	NoGRPCHeader      bool
	HeartbeatPeriod   uint32
}

type SubscriptionInfo struct {
	UID           int
	Email         string
	Passwd        string
	SpeedLimit    uint64
	DeviceLimit   int
	UUID          string
}

type OnlineIP struct {
	UID int
	IP  string
}

type SubscriptionTraffic struct {
	UID      int
	Email    string
	Upload   int64
	Download int64
}

type ClientInfo struct {
	APIHost  string
	NodeID   int
	Key      string
}

type DetectRule struct {
	ID      int
	Pattern *regexp.Regexp
}

type DetectResult struct {
	UID    int
	RuleID int
}