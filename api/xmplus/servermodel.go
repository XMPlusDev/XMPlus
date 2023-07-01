package xmplus

import "encoding/json"

type serverConfig struct {
	server           `json:"server"`
	Routes []route   `json:"rules"`
}

type server struct {
	Address     string 	 `json:"address"`
	Certmode    string 	 `json:"certmode"`
	Cipher      string 	 `json:"cipher"`
	IP          string   `json:"ip"`
	Port        int      `json:"listeningport"`
	Listenip    string   `json:"listenip"`
	NetworkSettings struct {
	    ProxyProtocol bool 	           `json:"acceptProxyProtocol"`
		Path          string           `json:"path"`
		Host          string           `json:"host"`
		QuicSecurity  string           `json:"security"`
		Quickey       string           `json:"key"`
		Headers       *json.RawMessage `json:"headers"`
		ServiceName   string           `json:"serviceName"`
		Header        *json.RawMessage `json:"header"`
		Transport     string           `json:"transport"`
		Seed          string           `json:"seed"`
		Congestion    bool 	           `json:"congestion"`
		Flow          string    `json:"flow"`
	} `json:"networkSettings"`
	Security    string `json:"security"`
	SecuritySettings  struct {
	    AllowInsecure bool 	    `json:"allowInsecure"`
		Fingerprint   string    `json:"fingerprint"`
		RejectUnknownSni bool   `json:"rejectUnknownSni"`
		ServerName    string    `json:"serverName"`
		Alpn          string    `json:"alpn"`
		Dest          string    `json:"dest"`
		Show          bool      `json:"show"`  
		PrivateKey    string    `json:"privatekey"`
		MinClientVer  string    `json:"minclientver"`
		MaxClientVer  string    `json:"maxclientver"`
		MaxTimeDiff   int       `json:"maxtimediff"`
		ProxyProtocol int       `json:"proxyprotocol"`
		ServerNames   []string  `json:"serverNames"`
		ShortIds      []string  `json:"shortids"`
	} `json:"securitySettings"`	
	SendThrough string     `json:"sendthrough"`
	ServerKey   string     `json:"server_key"`
	Sniffing    bool 	   `json:"sniffing"`
	Speedlimit  int        `json:"speedlimit"`
	Type        string     `json:"type"`
}

type route struct {
	Id       int      `json:"id"`
	Regex    string   `json:"regex"`
}


