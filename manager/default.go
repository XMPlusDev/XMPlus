package manager

import "github.com/XMPlusDev/XMPlus/service/controller"

func getDefaultLogConfig() *LogConfig {
	return &LogConfig{
		Level:      "none",
		AccessPath: "",
		ErrorPath:  "",
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

func getDefaultControllerConfig() *controller.Config {
	return &controller.Config{}
}
