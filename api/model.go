package api

import (
	"encoding/json"
	"regexp"
)

const (
	ServiceNotModified = "users not modified"
	NodeNotModified = "node not modified"
	RuleNotModified = "rules not modified"
)

// Config API config
type Config struct {
	APIHost             string  `mapstructure:"ApiHost"`
	NodeID              int     `mapstructure:"NodeID"`
	Key                 string  `mapstructure:"ApiKey"`
	Timeout             int     `mapstructure:"Timeout"`
}

type NodeInfo struct {
	NodeType          string 
	NodeID            int
	Port              uint32
	SpeedLimit        uint64 
	AlterID           uint16
	Transport         string
	Host              string
	Path              string
	EnableTLS         bool
	TLSType           string
	CypherMethod      string
	Sniffing          bool
	RejectUnknownSNI  bool
	Fingerprint       string
	Quic_security     string
	Quic_key          string
	Address           string
	AllowInsecure     bool
	ListenIP          string
	ProxyProtocol     bool
	CertMode          string
	CertDomain        string
	ServerKey         string
	ServiceName       string
	Header            json.RawMessage
	DomainStrategy    string
	SendIP            string
	EnableDNS         bool
	Flow              string
	Seed              string
	Alpn              string
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
}

type ServiceInfo struct {
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

type ServiceTraffic struct {
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