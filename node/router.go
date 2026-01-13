package node

import (
	"encoding/json"
	"fmt"
	
	"github.com/xmplusdev/xray-core/v25/app/router"
	"github.com/xmplusdev/xray-core/v25/infra/conf"
	"github.com/XMPlusDev/XMPlus/api"
)

func RouterBuilder(nodeInfo *api.NodeInfo, tag string) (*router.Config, error) {
	routerConfig := &conf.RouterConfig{}
	
	var ruleList any
	
	ruleList = struct {
		Type        string   
		RuleTag     string  
		OutboundTag string   
		Domain      *conf.StringList 
		IP          *conf.StringList 
		Port        *conf.PortList   
		Protocols   *conf.StringList 
	}{
		Type: "field",
		RuleTag: fmt.Sprintf("%s_blackhole", tag),
		OutboundTag: fmt.Sprintf("%s_blackhole", tag),
		Domain: &conf.StringList{nodeInfo.BlockingRules.Domain},
		IP: &conf.StringList{nodeInfo.BlockingRules.IP},
		Port: &conf.PortList{nodeInfo.BlockingRules.Port},
		Protocols: &conf.StringList{nodeInfo.BlockingRules.Protocol},
	}
	
	rule, err := json.Marshal(ruleList)
	if err != nil {
		return nil, fmt.Errorf("Marshal Rule list %s config fialed: %s", ruleList, err)
	}
		
	RuleList := []json.RawMessage{}
	RuleList = append(RuleList, rule)

	routerConfig.RuleList = RuleList

	return routerConfig.Build()
}

func RelayRouterBuilder(tag string, relayTag string, subscription *api.SubscriptionInfo) (*router.Config, error) {
	routerConfig := &conf.RouterConfig{}

	var ruleList any
	
	ruleList = struct {
		RuleTag     string
		Type        string 
		OutboundTag string 
		User        *conf.StringList 
	}{
		RuleTag: fmt.Sprintf("%s_%d", relayTag, subscription.Id),
		Type: "field",
		OutboundTag: fmt.Sprintf("%s_%d", relayTag, subscription.Id),
		User: &conf.StringList{fmt.Sprintf("%s|%s|%d", tag, subscription.Email, subscription.Id)},
	}
		
	rule, err := json.Marshal(ruleList)
	if err != nil {
		return nil, fmt.Errorf("Marshal Rule list %s config fialed: %s", ruleList, err)
	}
		
	RuleList := []json.RawMessage{}
	RuleList = append(RuleList, rule)

	routerConfig.RuleList = RuleList

	return routerConfig.Build()
}