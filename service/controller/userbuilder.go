package controller

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/XMPlusDev/XMPlus/api"
)

var AEADMethod = map[shadowsocks.CipherType]uint8{
	shadowsocks.CipherType_AES_128_GCM:        0,
	shadowsocks.CipherType_AES_256_GCM:        0,
	shadowsocks.CipherType_CHACHA20_POLY1305:  0,
	shadowsocks.CipherType_XCHACHA20_POLY1305: 0,
}

func (c *Controller) buildVmessUser(serviceInfo *[]api.ServiceInfo) (services []*protocol.User) {
	services = make([]*protocol.User, len(*serviceInfo))
	for i, service := range *serviceInfo {
		vmessAccount := &conf.VMessAccount{
			ID:       service.UUID,
			Security: "auto",
		}
		services[i] = &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&service), // Email: InboundTag|email|uid
			Account: serial.ToTypedMessage(vmessAccount.Build()),
		}
	}
	return services
}

func (c *Controller) buildVlessUser(serviceInfo *[]api.ServiceInfo, flow string) (services []*protocol.User) {
	services = make([]*protocol.User, len(*serviceInfo))
	for i, service := range *serviceInfo {
		vlessAccount := &vless.Account{
			Id:   service.UUID,
			Flow: flow,
		}
		services[i] = &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&service),
			Account: serial.ToTypedMessage(vlessAccount),
		}
	}
	return services
}

func (c *Controller) buildTrojanUser(serviceInfo *[]api.ServiceInfo) (services []*protocol.User) {
	services = make([]*protocol.User, len(*serviceInfo))
	for i, service := range *serviceInfo {
		trojanAccount := &trojan.Account{
			Password: service.UUID,
			Flow:     "xtls-rprx-direct",
		}
		services[i] = &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&service),
			Account: serial.ToTypedMessage(trojanAccount),
		}
	}
	return services
}

func (c *Controller) buildSSUser(serviceInfo *[]api.ServiceInfo, method string) (services []*protocol.User) {
	services = make([]*protocol.User, len(*serviceInfo))
	for i, service := range *serviceInfo {
		if C.Contains(shadowaead_2022.List, strings.ToLower(method)) {
			e := c.buildUserTag(&service)
			userKey, err := c.checkShadowsocksPassword(service.Passwd, method)
			if err != nil {
				newError(fmt.Errorf("[UID: %d] %s", service.UID, err)).AtError().WriteToLog()
				continue
			}
			services[i] = &protocol.User{
				Level: 0,
				Email: e,
				Account: serial.ToTypedMessage(&shadowsocks_2022.User{
					Key:   userKey,
					Email: e,
					Level: 0,
				}),
			}
		} else {
			services[i] = &protocol.User{
				Level: 0,
				Email: c.buildUserTag(&service),
				Account: serial.ToTypedMessage(&shadowsocks.Account{
					Password:   service.Passwd,
					CipherType: cipherFromString(method),
				}),
			}
		}
	}
	return services
}

func (c *Controller) buildSSPluginUser(serviceInfo *[]api.ServiceInfo, method string) (services []*protocol.User) {
	services = make([]*protocol.User, len(*serviceInfo))
	for i, service := range *serviceInfo {
		if C.Contains(shadowaead_2022.List, strings.ToLower(method)) {
			e := c.buildUserTag(&service)
			userKey, err := c.checkShadowsocksPassword(service.Passwd, method)
			if err != nil {
				newError(fmt.Errorf("[UID: %d] %s", service.UID, err)).AtError().WriteToLog()
				continue
			}
			services[i] = &protocol.User{
				Level: 0,
				Email: e,
				Account: serial.ToTypedMessage(&shadowsocks_2022.User{
					Key:   userKey,
					Email: e,
					Level: 0,
				}),
			}
		} else {
			// Check if the cypher method is AEAD
			cypherMethod := cipherFromString(method)
			if _, ok := AEADMethod[cypherMethod]; ok {
				services[i] = &protocol.User{
					Level: 0,
					Email: c.buildUserTag(&service),
					Account: serial.ToTypedMessage(&shadowsocks.Account{
						Password:   service.Passwd,
						CipherType: cypherMethod,
					}),
				}
			}
		}
	}
	return services
}

func (c *Controller) buildUserTag(service *api.ServiceInfo) string {
	return fmt.Sprintf("%s|%s|%d", c.Tag, service.Email, service.UID)
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