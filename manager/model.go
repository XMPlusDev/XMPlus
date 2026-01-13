package manager

import (
	"github.com/XMPlusDev/XMPlus/api"
	"github.com/XMPlusDev/XMPlus/node"
)

type Config struct {
	LogConfig          *LogConfig        `mapstructure:"Log"`
	DnsConfigPath      string            `mapstructure:"DnsConfigPath"`
	InboundConfigPath  string            `mapstructure:"InboundConfigPath"`
	OutboundConfigPath string            `mapstructure:"OutboundConfigPath"`
	RouteConfigPath    string            `mapstructure:"RouteConfigPath"`
	ConnectionConfig   *ConnectionConfig `mapstructure:"ConnectionConfig"`
	NodesConfig        []*NodesConfig    `mapstructure:"Nodes"`
}

type NodesConfig struct {
	ApiConfig        *api.Config    `mapstructure:"ApiConfig"`
	ControllerConfig *node.Config   `mapstructure:"ControllerConfig"`
}

type LogConfig struct {
	Level      string    `mapstructure:"Level"`
	AccessPath string    `mapstructure:"AccessPath"`
	ErrorPath  string    `mapstructure:"ErrorPath"`
	DNSLog     bool      `mapstructure:"DNSLog"`
	MaskAddress string   `mapstructure:"MaskAddress"`
}

type ConnectionConfig struct {
	Handshake    uint32   `mapstructure:"handshake"`
	ConnIdle     uint32   `mapstructure:"connIdle"`
	UplinkOnly   uint32   `mapstructure:"uplinkOnly"`
	DownlinkOnly uint32   `mapstructure:"downlinkOnly"`
	BufferSize   int32    `mapstructure:"bufferSize"`
}

func getDefaultLogConfig() *LogConfig {
	return &LogConfig{
		Level:      "none",
		AccessPath: "",
		ErrorPath:  "",
		DNSLog:     false,
		MaskAddress: "half",
	}
}

func getDefaultConnectionConfig() *ConnectionConfig {
	return &ConnectionConfig{
		Handshake:    4,
		ConnIdle:     30,
		UplinkOnly:   2,
		DownlinkOnly: 4,
		BufferSize:   64,
	}
}

func getDefaultControllerConfig() *node.Config {
	return &node.Config{}
}

