// node/node.go
package node

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	"github.com/XMPlusDev/XMPlus/api"
	"github.com/XMPlusDev/XMPlus/helper/limiter"
	"github.com/XMPlusDev/XMPlus/app/dispatcher" 
	
	"github.com/xmplusdev/xray-core/v26/core"
	"github.com/xmplusdev/xray-core/v26/features/inbound"
	"github.com/xmplusdev/xray-core/v26/features/outbound"
	"github.com/xmplusdev/xray-core/v26/features/routing"
	"github.com/xmplusdev/xray-core/v26/app/router"
	"github.com/xmplusdev/xray-core/v26/common/serial"
	
	C "github.com/sagernet/sing/common"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
)

// Manager handles node-related operations (inbound/outbound management)
type Manager struct {
	server 		*core.Instance
	ibm    		inbound.Manager
	obm    		outbound.Manager
	router  	*router.Router
	dispatcher  *dispatcher.DefaultDispatcher
}

// NewManager creates a new node manager
func NewManager(server *core.Instance) *Manager {
	return &Manager{
		server: 	server,
		ibm:    	server.GetFeature(inbound.ManagerType()).(inbound.Manager),
		obm:    	server.GetFeature(outbound.ManagerType()).(outbound.Manager),
		router: 	server.GetFeature(routing.RouterType()).(*router.Router),
		dispatcher: server.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher),
	}
}

// AddTag adds both inbound and outbound for a node
func (m *Manager) AddTag(nodeInfo *api.NodeInfo, tag string, config Config) error {
	if nodeInfo.NodeType == "Shadowsocks-Plugin" {
		return nil // Skip for Shadowsocks-Plugin
	}

	// Add inbound
	inboundConfig, err := InboundBuilder(config, nodeInfo, tag)
	if err != nil {
		return fmt.Errorf("failed to build inbound config: %w", err)
	}

	if err := m.addInbound(inboundConfig); err != nil {
		return fmt.Errorf("failed to add inbound: %w", err)
	}

	// Add outbound
	outboundConfig, err := OutboundBuilder(config, nodeInfo, tag)
	if err != nil {
		return fmt.Errorf("failed to build outbound config: %w", err)
	}

	if err := m.addOutbound(outboundConfig); err != nil {
		return fmt.Errorf("failed to add outbound: %w", err)
	}

	log.Printf("Added tag %s for node type %s", tag, nodeInfo.NodeType)
	return nil
}

// RemoveTag removes both inbound and outbound for a node
func (m *Manager) RemoveTag(tag string) error {
	if err := m.removeInbound(tag); err != nil {
		return fmt.Errorf("failed to remove inbound: %w", err)
	}

	if err := m.removeOutbound(tag); err != nil {
		return fmt.Errorf("failed to remove outbound: %w", err)
	}

	log.Printf("Removed tag %s", tag)
	return nil
}

// AddRelayTag adds relay outbounds and routing for all subscriptions
func (m *Manager) AddRelayTag(
	relayNodeInfo *api.NodeInfo.RelayNodeInfo,
	relayTag string,
	mainTag string,
	subscriptionInfo *[]api.SubscriptionInfo,
) error {
	if relayNodeInfo.NodeType == "Shadowsocks-Plugin" {
		return nil
	}

	for _, subscription := range *subscriptionInfo {
		var key string

		// Handle Shadowsocks 2022 key generation
		if C.Contains(shadowaead_2022.List, strings.ToLower(relayNodeInfo.Cipher)) {
			userKey, err := checkShadowsocksPassword(subscription.Passwd, relayNodeInfo.Cipher)
			if err != nil {
				continue
			}
			key = fmt.Sprintf("%s:%s", relayNodeInfo.ServerKey, userKey)
		} else {
			key = subscription.Passwd
		}

		// Build and add relay outbound
		relayTagConfig, err := OutboundRelayBuilder(relayNodeInfo, relayTag, &subscription, key)
		if err != nil {
			return fmt.Errorf("failed to build relay outbound for Id %d: %w", subscription.Id, err)
		}

		if err := m.addOutbound(relayTagConfig); err != nil {
			return fmt.Errorf("failed to add relay outbound for UID %d: %w", subscription.Id, err)
		}

		// Build and add router rule
		routerConfig, err := RelayRouterBuilder(mainTag, relayTag, &subscription)
		if err != nil {
			return fmt.Errorf("failed to build router for UID %d: %w", subscription.Id, err)
		}

		if err := m.addRouterRule(routerConfig, true); err != nil {
			return fmt.Errorf("failed to add router rule for UID %d: %w", subscription.Id, err)
		}
	}

	return nil
}

func checkShadowsocksPassword(password string, method string) (string, error) {
	var userKey string
	if len(password) < 16 {
		return "", fmt.Errorf("shadowsocks2022 key's length must be greater than 16")
	}
	
	switch strings.ToLower(method) {
		case "2022-blake3-aes-128-gcm":
			userKey = password[:16]
		case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
			if len(password) < 32 {
				return "", fmt.Errorf("shadowsocks2022 key's length must be greater than 32")
			}
			userKey = password[:32]
		default:
			return "", fmt.Errorf("unsupported SS2022 method: %s", method)	
	}
	
	return base64.StdEncoding.EncodeToString([]byte(userKey)), nil
}

// RemoveRelayTag removes all relay outbounds for subscriptions
func (m *Manager) RemoveRelayTag(tag string, subscriptionInfo *[]api.SubscriptionInfo) error {
	for _, subscription := range *subscriptionInfo {
		outboundTag := fmt.Sprintf("%s_%d", tag, subscription.Id)
		if err := m.removeOutbound(outboundTag); err != nil {
			return err
		}
	}

	return nil
}

// RemoveRelayRules removes all routing rules for relay
func (m *Manager) RemoveRelayRules(tag string, subscriptionInfo *[]api.SubscriptionInfo) error {
	for _, subscription := range *subscriptionInfo {
		ruleTag := fmt.Sprintf("%s_%d", tag, subscription.Id)
		if err := m.removeRouterRule(ruleTag); err != nil {
			return err
		}
	}

	return nil
}

// RemoveBlockingRules removes all routing rules for relay
func (m *Manager) RemoveBlockingRules(tag string) error {
	ruleTag := fmt.Sprintf("%s_blackhole", tag)
	if err := m.removeRouterRule(ruleTag); err != nil {
		return err
	}

	return nil
}

// Add blocking rule Tag for outbound 
func (m *Manager) BlockingRuleTag(nodeInfo *api.NodeInfo, tag string) error {
	// Add outbound
	blackholeConfig, err := BlackholeOutboundBuilder(tag)
	if err != nil {
		return fmt.Errorf("failed to build outbound config: %w", err)
	}

	if err := m.addOutbound(blackholeConfig); err != nil {
		return fmt.Errorf("failed to add outbound: %w", err)
	}
	
	// Build and add router rule
	routerConfig, err := RouterBuilder(nodeInfo, tag)
	if err != nil {
		return err
	}

	if err := m.addRouterRule(routerConfig, true); err != nil {
		return err
	}
	
	return nil
}

// Private helper methods
func (m *Manager) removeInbound(tag string) error {
	err := m.ibm.RemoveHandler(context.Background(), tag)
	return err
}

func (m *Manager) removeOutbound(tag string) error {
	err := m.obm.RemoveHandler(context.Background(), tag)
	return err
}

func (m *Manager) addInbound(config *core.InboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(m.server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(inbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	if err := m.ibm.AddHandler(context.Background(), handler); err != nil {
		return err
	}
	return nil
}

func (m *Manager) addOutbound(config *core.OutboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(m.server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(outbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	if err := m.obm.AddHandler(context.Background(), handler); err != nil {
		return err
	}
	return nil
}

func (m *Manager) AddRouterRule(config *router.Config, shouldAppend bool) error{
	err := m.router.AddRule(serial.ToTypedMessage(config), shouldAppend)
	log.Printf("Adding router rule (prepend=%v)", prepend)
	return err
}

func (m *Manager) RemoveRouterRule(tag string) error{
	err := m.router.RemoveRule(tag)
	log.Printf("Removing router rule: %s", tag)
	return err
}

func (m *Manager) AddInboundLimiter(tag string, nodeSpeedLimit uint64, subscriptionList *[]api.SubscriptionInfo, redisConfig *limiter.RedisConfig) error {
	err := m.dispatcher.Limiter.AddInboundLimiter(tag, nodeSpeedLimit, subscriptionList, redisConfig)
	return err
}

func (m *Manager) UpdateInboundLimiter(tag string, updatedSubscriptionList *[]api.SubscriptionInfo) error {
	err := m.dispatcher.Limiter.UpdateInboundLimiter(tag, updatedSubscriptionList)
	return err
}

func (m *Manager) DeleteInboundLimiter(tag string) error {
	err := m.dispatcher.Limiter.DeleteInboundLimiter(tag)
	return err
}
