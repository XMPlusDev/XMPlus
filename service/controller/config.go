package controller

import (
	"github.com/XMPlusDev/XMPlus/utility/mylego"
)

type Config struct {
	CertConfig              *mylego.CertConfig               `mapstructure:"CertConfig"`
	EnableFallback          bool                             `mapstructure:"EnableFallback"`
	FallBackConfigs         []*FallBackConfig                `mapstructure:"FallBackConfigs"`
	EnableDNS               bool                             `mapstructure:"EnableDNS"`
	DNSStrategy             string                           `mapstructure:"DNSStrategy"`
	RealityPrivateKey       string                           `mapstructure:"RealityPrivateKey"`
	EnableFragment          bool                             `mapstructure:"EnableFragment"`
	FragmentConfigs         *FragmentConfig                  `mapstructure:"FragmentConfigs"`
}

type FallBackConfig struct {
	SNI              string `mapstructure:"SNI"`
	Alpn             string `mapstructure:"Alpn"`
	Path             string `mapstructure:"Path"`
	Dest             string `mapstructure:"Dest"`
	ProxyProtocolVer uint64 `mapstructure:"ProxyProtocolVer"`
}

type FragmentConfig struct {
	Packets  string `mapstructure:"Packets"`
	Length   string `mapstructure:"Length"`
	Interval string `mapstructure:"Interval"`
}
