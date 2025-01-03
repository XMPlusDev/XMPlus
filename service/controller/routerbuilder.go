package controller

import (
	"encoding/json"
	"fmt"
	
	"github.com/xmplusdev/xray-core/v25/app/router"
	"github.com/xmplusdev/xray-core/v25/infra/conf"
	"github.com/XMPlusDev/XMPlus/api"
)

func RouterBuilder(tag string, rtag string, subscription *api.SubscriptionInfo) (*router.Config, error) {
	routerConfig := &conf.RouterConfig{}

	var ruleList any
	
	buildUser := fmt.Sprintf("%s|%s|%d", tag, subscription.Email, subscription.UID)
	
	ruleList = struct {
		RuleTag   string `json:"ruleTag"`
		Type      string `json:"type"`
		OutboundTag string `json:"outboundTag"`
		User  *conf.StringList  `json:"user"`
	}{
		RuleTag: fmt.Sprintf("%s_%d", rtag, subscription.UID),
		Type: "field",
		OutboundTag: fmt.Sprintf("%s_%d", rtag, subscription.UID),
		User: &conf.StringList{buildUser},
	}
		
	userRule, err := json.Marshal(ruleList)
	if err != nil {
		return nil, fmt.Errorf("Marshal Rule list %s config fialed: %s", ruleList, err)
	}
		
	RuleList := []json.RawMessage{}
	RuleList = append(RuleList, userRule)

	routerConfig.RuleList = RuleList

	return routerConfig.Build()
}
