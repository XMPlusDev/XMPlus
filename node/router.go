package node

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	
	"github.com/xmplusdev/xray-core/v26/app/router"
	"github.com/xmplusdev/xray-core/v26/infra/conf"
	"github.com/XMPlusDev/XMPlus/api"
)

func RouterBuilder(nodeInfo *api.NodeInfo, tag string) (*router.Config, error) {
	routerConfig := &conf.RouterConfig{}
	
	// Parse port string into PortRange slice
	portRanges, err := parsePortString(nodeInfo.BlockingRules.Port)
	if err != nil {
		return nil, fmt.Errorf("failed to parse port string: %w", err)
	}
	
	var domain *conf.StringList
	if nodeInfo.BlockingRules.Domain != nil {
		d := conf.StringList(nodeInfo.BlockingRules.Domain)
		domain = &d
	}

	var ip *conf.StringList
	if nodeInfo.BlockingRules.IP != nil {
		i := conf.StringList(nodeInfo.BlockingRules.IP)
		ip = &i
	}

	var protocols *conf.StringList
	if nodeInfo.BlockingRules.Protocol != nil {
		p := conf.StringList(nodeInfo.BlockingRules.Protocol)
		protocols = &p
	}
	
	var ruleList any
	
	ruleList = struct {
		Type        string           `json:"type"`
		RuleTag     string           `json:"ruleTag"`
		OutboundTag string           `json:"outboundTag"`
		Domain      *conf.StringList `json:"domain,omitempty"`
		IP          *conf.StringList `json:"ip,omitempty"`
		Port        *conf.PortList   `json:"port,omitempty"`
		Protocols   *conf.StringList `json:"protocol,omitempty"`
	}{
		Type:        "field",
		RuleTag:     fmt.Sprintf("%s_blackhole", tag),
		OutboundTag: fmt.Sprintf("%s_blackhole", tag),
		Domain:      domain,
		IP:          ip,
		Protocols:   protocols,
		Port: &conf.PortList{
			Range: portRanges,
		},
	}
	
	rule, err := json.Marshal(ruleList)
	if err != nil {
		return nil, fmt.Errorf("Marshal Rule list %s config failed: %s", ruleList, err)
	}
		
	RuleList := []json.RawMessage{}
	RuleList = append(RuleList, rule)
	routerConfig.RuleList = RuleList
	return routerConfig.Build()
}

// parsePortString parses a port string like "53,443,1000-2000" into PortRange slices
func parsePortString(portStr string) ([]conf.PortRange, error) {
	if portStr == "" {
		return nil, nil
	}
	
	var portRanges []conf.PortRange
	
	// Split by comma
	ports := strings.Split(portStr, ",")
	
	for _, p := range ports {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		
		// Check if it's a range (contains "-")
		if strings.Contains(p, "-") {
			rangeParts := strings.SplitN(p, "-", 2)
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range format: %s", p)
			}
			
			fromPort, err := strconv.ParseUint(strings.TrimSpace(rangeParts[0]), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid port number in range: %s", rangeParts[0])
			}
			
			toPort, err := strconv.ParseUint(strings.TrimSpace(rangeParts[1]), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid port number in range: %s", rangeParts[1])
			}
			
			portRanges = append(portRanges, conf.PortRange{
				From: uint32(fromPort),
				To:   uint32(toPort),
			})
		} else {
			// Single port
			port, err := strconv.ParseUint(p, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", p)
			}
			
			portRanges = append(portRanges, conf.PortRange{
				From: uint32(port),
				To:   uint32(port),
			})
		}
	}
	
	return portRanges, nil
}

func RelayRouterBuilder(tag string, relayTag string, subscription *api.SubscriptionInfo) (*router.Config, error) {
	routerConfig := &conf.RouterConfig{}
	var ruleList any
	
	ruleList = struct {
		RuleTag     string           `json:"ruleTag"`
		Type        string           `json:"type"`
		OutboundTag string           `json:"outboundTag"`
		User        *conf.StringList `json:"user"`
	}{
		RuleTag:     fmt.Sprintf("%s_%d", relayTag, subscription.Id),
		Type:        "field",
		OutboundTag: fmt.Sprintf("%s_%d", relayTag, subscription.Id),
		User:        &conf.StringList{fmt.Sprintf("%s|%s|%d", tag, subscription.Email, subscription.Id)},
	}
		
	rule, err := json.Marshal(ruleList)
	if err != nil {
		return nil, fmt.Errorf("Marshal Rule list %s config failed: %s", ruleList, err)
	}
		
	RuleList := []json.RawMessage{}
	RuleList = append(RuleList, rule)
	routerConfig.RuleList = RuleList
	return routerConfig.Build()
}