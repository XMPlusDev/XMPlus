package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"github.com/XMPlusDev/XMPlus/manager"
)

var (
	configFile   = flag.String("config", "", "Config file for XMPlus.")
	printVersion = flag.Bool("version", false, "show version")
)

var (
	version  = "XMPlus v1.0.0 (A custom version of XrayR)"
)

func showVersion() {
	fmt.Printf("%s \n", version)
}

func getConfig() *viper.Viper {
	config := viper.New()

	// Set custom path and name
	if *configFile != "" {
		configName := path.Base(*configFile)
		configFileExt := path.Ext(*configFile)
		configNameOnly := strings.TrimSuffix(configName, configFileExt)
		configPath := path.Dir(*configFile)
		config.SetConfigName(configNameOnly)
		config.SetConfigType(strings.TrimPrefix(configFileExt, "."))
		config.AddConfigPath(configPath)
		// Set ASSET Path and Config Path for XMPlus
		os.Setenv("XRAY_LOCATION_ASSET", configPath)
		os.Setenv("XRAY_LOCATION_CONFIG", configPath)
	} else {
		// Set default config path
		config.SetConfigName("config")
		config.SetConfigType("yml")
		config.AddConfigPath(".")
	}

	if err := config.ReadInConfig(); err != nil {
		log.Panicf("Config file error: %s \n", err)
	}

	config.WatchConfig() // Watch the config

	return config
}

func main() {
	flag.Parse()
	showVersion()
	if *printVersion {
		return
	}

	config := getConfig()
	managerConfig := &manager.Config{}
	if err := config.Unmarshal(managerConfig); err != nil {
		log.Panicf("Parse config file %v failed: %s \n", configFile, err)
	}
	m := manager.New(managerConfig)
	lastTime := time.Now()
	config.OnConfigChange(func(e fsnotify.Event) {
		// Discarding event received within a short period of time after receiving an event.
		if time.Now().After(lastTime.Add(3 * time.Second)) {
			// Hot reload function
			fmt.Println("Config file changed:", e.Name)
			m.Close()
			// Delete old instance and trigger GC
			runtime.GC()
			if err := config.Unmarshal(managerConfig); err != nil {
				log.Panicf("Parse config file %v failed: %s \n", configFile, err)
			}
			m.Start()
			lastTime = time.Now()
		}
	})
	m.Start()
	defer m.Close()

	// Explicitly triggering GC to remove garbage from config loading.
	runtime.GC()
	// Running backend
	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM)
		<-osSignals
	}
}
