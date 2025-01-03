package controller

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	"github.com/xmplusdev/xray-core/v25/common/protocol"
	"github.com/xmplusdev/xray-core/v25/common/serial"
	"github.com/xmplusdev/xray-core/v25/infra/conf"
	"github.com/xmplusdev/xray-core/v25/proxy/shadowsocks"
	"github.com/xmplusdev/xray-core/v25/proxy/shadowsocks_2022"
	"github.com/xmplusdev/xray-core/v25/proxy/trojan"
	"github.com/xmplusdev/xray-core/v25/proxy/vless"
	"github.com/XMPlusDev/XMPlus/api"
)

var AEADMethod = map[shadowsocks.CipherType]uint8{
	shadowsocks.CipherType_AES_128_GCM:        0,
	shadowsocks.CipherType_AES_256_GCM:        0,
	shadowsocks.CipherType_CHACHA20_POLY1305:  0,
	shadowsocks.CipherType_XCHACHA20_POLY1305: 0,
}

func (c *Controller) buildVmessUser(subscriptionInfo *[]api.SubscriptionInfo) (subscriptions []*protocol.User) {
	subscriptions = make([]*protocol.User, len(*subscriptionInfo))
	for i, subscription := range *subscriptionInfo {
		vmessAccount := &conf.VMessAccount{
			ID:       subscription.UUID,
			Security: "auto",
		}
		subscriptions[i] = &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&subscription), // Email: InboundTag|email|uid
			Account: serial.ToTypedMessage(vmessAccount.Build()),
		}
	}
	return subscriptions
}

func (c *Controller) buildVlessUser(subscriptionInfo *[]api.SubscriptionInfo, flow string) (subscriptions []*protocol.User) {
	subscriptions = make([]*protocol.User, len(*subscriptionInfo))
	for i, subscription := range *subscriptionInfo {
		vlessAccount := &vless.Account{
			Id:   subscription.UUID,
			Flow: flow,
		}
		subscriptions[i] = &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&subscription),
			Account: serial.ToTypedMessage(vlessAccount),
		}
	}
	return subscriptions
}

func (c *Controller) buildTrojanUser(subscriptionInfo *[]api.SubscriptionInfo) (subscriptions []*protocol.User) {
	subscriptions = make([]*protocol.User, len(*subscriptionInfo))
	for i, subscription := range *subscriptionInfo {
		trojanAccount := &trojan.Account{
			Password: subscription.UUID,
		}
		subscriptions[i] = &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&subscription),
			Account: serial.ToTypedMessage(trojanAccount),
		}
	}
	return subscriptions
}

func (c *Controller) buildSSUser(subscriptionInfo *[]api.SubscriptionInfo, method string) (subscriptions []*protocol.User) {
	subscriptions = make([]*protocol.User, len(*subscriptionInfo))
	for i, subscription := range *subscriptionInfo {
		if C.Contains(shadowaead_2022.List, strings.ToLower(method)) {
			e := c.buildUserTag(&subscription)
			userKey, err := c.checkShadowsocksPassword(subscription.Passwd, method)
			if err != nil {
				newError(fmt.Errorf("[UID: %d] %s", subscription.UID, err)).AtError()
				continue
			}
			subscriptions[i] = &protocol.User{
				Level: 0,
				Email: e,
				Account: serial.ToTypedMessage(&shadowsocks_2022.Account{
					Key:  userKey,
				}),
			}
		} else {
			subscriptions[i] = &protocol.User{
				Level: 0,
				Email: c.buildUserTag(&subscription),
				Account: serial.ToTypedMessage(&shadowsocks.Account{
					Password:   subscription.Passwd,
					CipherType: cipherFromString(method),
				}),
			}
		}
	}
	return subscriptions
}

func (c *Controller) buildSSPluginUser(subscriptionInfo *[]api.SubscriptionInfo, method string) (subscriptions []*protocol.User) {
	subscriptions = make([]*protocol.User, len(*subscriptionInfo))
	for i, subscription := range *subscriptionInfo {
		if C.Contains(shadowaead_2022.List, strings.ToLower(method)) {
			e := c.buildUserTag(&subscription)
			userKey, err := c.checkShadowsocksPassword(subscription.Passwd, method)
			if err != nil {
				newError(fmt.Errorf("[UID: %d] %s", subscription.UID, err)).AtError()
				continue
			}
			subscriptions[i] = &protocol.User{
				Level: 0,
				Email: e,
				Account: serial.ToTypedMessage(&shadowsocks_2022.Account{
					Key:  userKey,
				}),
			}
		} else {
			// Check if the cypher method is AEAD
			cypherMethod := cipherFromString(method)
			if _, ok := AEADMethod[cypherMethod]; ok {
				subscriptions[i] = &protocol.User{
					Level: 0,
					Email: c.buildUserTag(&subscription),
					Account: serial.ToTypedMessage(&shadowsocks.Account{
						Password:   subscription.Passwd,
						CipherType: cypherMethod,
					}),
				}
			}
		}
	}
	return subscriptions
}

func (c *Controller) buildUserTag(subscription *api.SubscriptionInfo) string {
	return fmt.Sprintf("%s|%s|%d", c.Tag, subscription.Email, subscription.UID)
}

func (c *Controller) checkShadowsocksPassword(password string, method string) (string, error) {
	var userKey string
	if len(password) < 16 {
		return "", fmt.Errorf("shadowsocks2022 key's length must be greater than 16")
	}
	if method == "2022-blake3-aes-128-gcm" {
		userKey = password[:16]
	} else {
		if len(password) < 32 {
			return "", fmt.Errorf("shadowsocks2022 key's length must be greater than 32")
		}
		userKey = password[:32]
	}
	return base64.StdEncoding.EncodeToString([]byte(userKey)), nil
}



func cipherFromString(c string) shadowsocks.CipherType {
	switch strings.ToLower(c) {
	case "aes-128-gcm", "aead_aes_128_gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm", "aead_aes_256_gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	case "none", "plain":
		return shadowsocks.CipherType_NONE
	default:
		return shadowsocks.CipherType_UNKNOWN
	}
}