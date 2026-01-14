package subscription

import (
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	"github.com/XMPlusDev/XMPlus/api"
	
	"github.com/xmplusdev/xray-core/v26/common/protocol"
	"github.com/xmplusdev/xray-core/v26/common/serial"
	"github.com/xmplusdev/xray-core/v26/proxy/shadowsocks"
	"github.com/xmplusdev/xray-core/v25/proxy/shadowsocks_2022"
	"github.com/xmplusdev/xray-core/v26/proxy/trojan"
	"github.com/xmplusdev/xray-core/v26/proxy/vless"
	"github.com/xmplusdev/xray-core/v26/infra/conf"
	
	C "github.com/sagernet/sing/common"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
)

// BuildVmessUsers builds Vmess protocol users from subscription info
func BuildVmessUsers(subscriptionInfo *[]api.SubscriptionInfo, tag string) []*protocol.User {
	users := make([]*protocol.User, 0, len(*subscriptionInfo))
	
	for _, subscription := range *subscriptionInfo {
		vmessAccount := &conf.VMessAccount{
			ID: subscription.Passwd,
			Security: "auto",
		}

		users = append(users, &protocol.User{
			Level:   0,
			Email:   buildUserTag(tag, &subscription),
			Account: serial.ToTypedMessage(vmessAccount.Build()),
		})
	}

	return users
}

// BuildVlessUsers builds Vless protocol users from subscription info
func BuildVlessUsers(subscriptionInfo *[]api.SubscriptionInfo, flow string, tag string) []*protocol.User {
	users := make([]*protocol.User, 0, len(*subscriptionInfo))
	
	for _, subscription := range *subscriptionInfo {
		vlessAccount := &vless.Account{
			Id:   subscription.Passwd,
			Flow: flow,
		}

		users = append(users, &protocol.User{
			Level:   0,
			Email:   buildUserTag(tag, &subscription),
			Account: serial.ToTypedMessage(vlessAccount),
		})
	}

	return users
}

// BuildTrojanUsers builds Trojan protocol users from subscription info
func BuildTrojanUsers(subscriptionInfo *[]api.SubscriptionInfo, tag string) []*protocol.User {
	users := make([]*protocol.User, 0, len(*subscriptionInfo))
	
	for _, subscription := range *subscriptionInfo {
		trojanAccount := &trojan.Account{
			Password: subscription.Passwd,
		}

		users = append(users, &protocol.User{
			Level:   0,
			Email:   buildUserTag(tag, &subscription),
			Account: serial.ToTypedMessage(trojanAccount),
		})
	}

	return users
}

// BuildShadowsocksUsers builds Shadowsocks protocol users from subscription info
func BuildShadowsocksUsers(subscriptionInfo *[]api.SubscriptionInfo, method string, tag string) []*protocol.User {
	cypherMethod := "aes-128-gcm"
	if method != "" {  // Fixed: method is a string, not a boolean
		cypherMethod = method
	}
	
	users := make([]*protocol.User, 0, len(*subscriptionInfo))
	
	for _, subscription := range *subscriptionInfo {
		if C.Contains(shadowaead_2022.List, strings.ToLower(cypherMethod)) {
			userKey, err := checkShadowsocksPassword(subscription.Passwd, method)
			if err != nil {
				// Assuming newError is a logging function - if not, use log.Printf
				newError(fmt.Errorf("[UID: %d] %s", subscription.Id, err)).AtError()
				continue
			}
			
			users = append(users, &protocol.User{
				Level: 0,
				Email: buildUserTag(tag, &subscription),
				Account: serial.ToTypedMessage(&shadowsocks_2022.Account{
					Key: userKey,
				}),
			})  
		} else {
			users = append(users, &protocol.User{
				Level: 0,
				Email: buildUserTag(tag, &subscription),
				Account: serial.ToTypedMessage(&shadowsocks.Account{
					Password:   subscription.Passwd,
					CipherType: getCipherType(method),
				}),
			}) 
		}
	}

	return users
}

func getCipherType(method string) shadowsocks.CipherType {
	switch strings.ToLower(method) {
	case "aes-128-gcm":
		return shadowsocks.CipherType_AES_128_GCM
	case "aes-256-gcm":
		return shadowsocks.CipherType_AES_256_GCM
	case "chacha20-poly1305", "chacha20-ietf-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305
	default:
		log.Printf("Warning: unknown cipher method %s, defaulting to AES_128_GCM", method)
		return shadowsocks.CipherType_AES_128_GCM
	}
}

// CheckShadowsocksPassword validates and formats Shadowsocks 2022 passwords
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