// node/builder.go
package node

import (
	"fmt"

	"github.com/XMPlusDev/XMPlus/api"
	"github.com/xmplusdev/xray-core/v26/core"
)

// Builder interface for creating node configurations
type Builder interface {
	BuildInbound(config Config, nodeInfo *api.NodeInfo, tag string) (*core.InboundHandlerConfig, error)
	BuildOutbound(config Config, nodeInfo *api.NodeInfo, tag string) (*core.OutboundHandlerConfig, error)
	BuildRelayOutbound(relayNodeInfo *api.RelayNodeInfo, relayTag string, subscription *api.SubscriptionInfo, key string) (*core.OutboundHandlerConfig, error)
}

// InboundBuilder builds inbound handler configuration
func InboundBuilder(config Config, nodeInfo *api.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	switch nodeInfo.NodeType {
	case "Vless":
		return buildVlessInbound(config, nodeInfo, tag)
	case "Vmess":
		return buildVmessInbound(config, nodeInfo, tag)
	case "Trojan":
		return buildTrojanInbound(config, nodeInfo, tag)
	case "Shadowsocks":
		return buildShadowsocksInbound(config, nodeInfo, tag)
	default:
		return nil, fmt.Errorf("unsupported node type for inbound: %s", nodeInfo.NodeType)
	}
}

// OutboundBuilder builds outbound handler configuration
func OutboundBuilder(config Config, nodeInfo *api.NodeInfo, tag string) (*core.OutboundHandlerConfig, error) {
	switch nodeInfo.NodeType {
	case "Vless":
		return buildVlessOutbound(config, nodeInfo, tag)
	case "Vmess":
		return buildVmessOutbound(config, nodeInfo, tag)
	case "Trojan":
		return buildTrojanOutbound(config, nodeInfo, tag)
	case "Shadowsocks":
		return buildShadowsocksOutbound(config, nodeInfo, tag)
	default:
		return nil, fmt.Errorf("unsupported node type for outbound: %s", nodeInfo.NodeType)
	}
}

// OutboundRelayBuilder builds relay outbound handler configuration
func OutboundRelayBuilder(relayNodeInfo *api.RelayNodeInfo, relayTag string, subscription *api.SubscriptionInfo, key string) (*core.OutboundHandlerConfig, error) {
	tag := fmt.Sprintf("%s_%d", relayTag, subscription.UID)
	
	switch relayNodeInfo.NodeType {
	case "Vless":
		return buildVlessRelayOutbound(relayNodeInfo, tag, subscription, key)
	case "Vmess":
		return buildVmessRelayOutbound(relayNodeInfo, tag, subscription, key)
	case "Trojan":
		return buildTrojanRelayOutbound(relayNodeInfo, tag, subscription, key)
	case "Shadowsocks":
		return buildShadowsocksRelayOutbound(relayNodeInfo, tag, subscription, key)
	default:
		return nil, fmt.Errorf("unsupported relay node type: %s", relayNodeInfo.NodeType)
	}
}

// RouterBuilder builds routing configuration for relay
func RouterBuilder(mainTag string, relayTag string, subscription *api.SubscriptionInfo) (interface{}, error) {
	// Build a routing rule that directs traffic from mainTag to relayTag for this specific subscription
	routeTag := fmt.Sprintf("%s_%d", relayTag, subscription.UID)
	
	// TODO: Implement actual routing rule creation based on your router implementation
	// This is a placeholder structure
	rule := map[string]interface{}{
		"tag":         routeTag,
		"inboundTag":  []string{mainTag},
		"outboundTag": fmt.Sprintf("%s_%d", relayTag, subscription.UID),
		"user":        []string{subscription.Email},
	}
	
	return rule, nil
}

// Placeholder implementations for specific protocol builders
// These should be implemented based on your actual protocol configurations

func buildVlessInbound(config Config, nodeInfo *api.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	// TODO: Implement Vless inbound builder
	return nil, fmt.Errorf("Vless inbound builder not implemented")
}

func buildVlessOutbound(config Config, nodeInfo *api.NodeInfo, tag string) (*core.OutboundHandlerConfig, error) {
	// TODO: Implement Vless outbound builder
	return nil, fmt.Errorf("Vless outbound builder not implemented")
}

func buildVlessRelayOutbound(relayNodeInfo *api.RelayNodeInfo, tag string, subscription *api.SubscriptionInfo, key string) (*core.OutboundHandlerConfig, error) {
	// TODO: Implement Vless relay outbound builder
	return nil, fmt.Errorf("Vless relay outbound builder not implemented")
}

func buildVmessInbound(config Config, nodeInfo *api.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	// TODO: Implement Vmess inbound builder
	return nil, fmt.Errorf("Vmess inbound builder not implemented")
}

func buildVmessOutbound(config Config, nodeInfo *api.NodeInfo, tag string) (*core.OutboundHandlerConfig, error) {
	// TODO: Implement Vmess outbound builder
	return nil, fmt.Errorf("Vmess outbound builder not implemented")
}

func buildVmessRelayOutbound(relayNodeInfo *api.RelayNodeInfo, tag string, subscription *api.SubscriptionInfo, key string) (*core.OutboundHandlerConfig, error) {
	// TODO: Implement Vmess relay outbound builder
	return nil, fmt.Errorf("Vmess relay outbound builder not implemented")
}

func buildTrojanInbound(config Config, nodeInfo *api.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	// TODO: Implement Trojan inbound builder
	return nil, fmt.Errorf("Trojan inbound builder not implemented")
}

func buildTrojanOutbound(config Config, nodeInfo *api.NodeInfo, tag string) (*core.OutboundHandlerConfig, error) {
	// TODO: Implement Trojan outbound builder
	return nil, fmt.Errorf("Trojan outbound builder not implemented")
}

func buildTrojanRelayOutbound(relayNodeInfo *api.RelayNodeInfo, tag string, subscription *api.SubscriptionInfo, key string) (*core.OutboundHandlerConfig, error) {
	// TODO: Implement Trojan relay outbound builder
	return nil, fmt.Errorf("Trojan relay outbound builder not implemented")
}

func buildShadowsocksInbound(config Config, nodeInfo *api.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	// TODO: Implement Shadowsocks inbound builder
	return nil, fmt.Errorf("Shadowsocks inbound builder not implemented")
}

func buildShadowsocksOutbound(config Config, nodeInfo *api.NodeInfo, tag string) (*core.OutboundHandlerConfig, error) {
	// TODO: Implement Shadowsocks outbound builder
	return nil, fmt.Errorf("Shadowsocks outbound builder not implemented")
}

func buildShadowsocksRelayOutbound(relayNodeInfo *api.RelayNodeInfo, tag string, subscription *api.SubscriptionInfo, key string) (*core.OutboundHandlerConfig, error) {
	// TODO: Implement Shadowsocks relay outbound builder
	return nil, fmt.Errorf("Shadowsocks relay outbound builder not implemented")
}