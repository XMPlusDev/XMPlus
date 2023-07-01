// Package limiter is to control the links that go into the dispatcher
package limiter

import (
	"fmt"
	"sync"

	"golang.org/x/time/rate"
	"github.com/XMPlusDev/XMPlus/api"
)

type ServiceInfo struct {
	UID         int
	SpeedLimit  uint64
	DeviceLimit int
}

type InboundInfo struct {
	Tag            string
	NodeSpeedLimit uint64
	ServiceInfo       *sync.Map // Key: Email value: ServiceInfo
	BucketHub      *sync.Map // key: Email, value: *rate.Limiter
	ServiceOnlineIP   *sync.Map // Key: Email, value: {Key: IP, value: UID}
}

type Limiter struct {
	InboundInfo *sync.Map // Key: Tag, Value: *InboundInfo
}

func New() *Limiter {
	return &Limiter{
		InboundInfo: new(sync.Map),
	}
}

func (l *Limiter) AddInboundLimiter(tag string, nodeSpeedLimit uint64, serviceList *[]api.ServiceInfo) error {
	inboundInfo := &InboundInfo{
		Tag:            tag,
		NodeSpeedLimit: nodeSpeedLimit,
		BucketHub:      new(sync.Map),
		ServiceOnlineIP:   new(sync.Map),
	}

	serviceMap := new(sync.Map)
	for _, u := range *serviceList {
		serviceMap.Store(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID), ServiceInfo{
			UID:         u.UID,
			SpeedLimit:  u.SpeedLimit,
			DeviceLimit: u.DeviceLimit,
		})
	}
	inboundInfo.ServiceInfo = serviceMap
	l.InboundInfo.Store(tag, inboundInfo) // Replace the old inbound info
	return nil
}

func (l *Limiter) UpdateInboundLimiter(tag string, updatedServiceList *[]api.ServiceInfo) error {
	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		// Update User info
		for _, u := range *updatedServiceList {
			inboundInfo.ServiceInfo.Store(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID), ServiceInfo{
				UID:         u.UID,
				SpeedLimit:  u.SpeedLimit,
				DeviceLimit: u.DeviceLimit,
			})
			// Update old limiter bucket
			limit := determineRate(inboundInfo.NodeSpeedLimit, u.SpeedLimit)
			if limit > 0 {
				if bucket, ok := inboundInfo.BucketHub.Load(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID)); ok {
					limiter := bucket.(*rate.Limiter)
					limiter.SetLimit(rate.Limit(limit))
					limiter.SetBurst(int(limit))
				}
			} else {
				inboundInfo.BucketHub.Delete(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID))
			}
		}
	} else {
		return fmt.Errorf("no such inbound in limiter: %s", tag)
	}
	return nil
}

func (l *Limiter) DeleteInboundLimiter(tag string) error {
	l.InboundInfo.Delete(tag)
	return nil
}

func (l *Limiter) GetOnlineDevice(tag string) (*[]api.OnlineIP, error) {
	var onlineIP []api.OnlineIP

	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		// Clear Speed Limiter bucket for users who are not online
		inboundInfo.BucketHub.Range(func(key, value interface{}) bool {
			email := key.(string)
			if _, exists := inboundInfo.ServiceOnlineIP.Load(email); !exists {
				inboundInfo.BucketHub.Delete(email)
			}
			return true
		})
		inboundInfo.ServiceOnlineIP.Range(func(key, value interface{}) bool {
			email := key.(string)
			ipMap := value.(*sync.Map)
			ipMap.Range(func(key, value interface{}) bool {
				uid := value.(int)
				ip := key.(string)
				onlineIP = append(onlineIP, api.OnlineIP{UID: uid, IP: ip})
				return true
			})
			inboundInfo.ServiceOnlineIP.Delete(email) // Reset online device
			return true
		})
	} else {
		return nil, fmt.Errorf("no such inbound in limiter: %s", tag)
	}

	return &onlineIP, nil
}

func (l *Limiter) GetUserBucket(tag string, email string, ip string) (limiter *rate.Limiter, SpeedLimit bool, Reject bool) {
	if value, ok := l.InboundInfo.Load(tag); ok {
		var (
			serviceLimit  uint64 = 0
			deviceLimit, uid int
		)

		inboundInfo := value.(*InboundInfo)
		nodeLimit := inboundInfo.NodeSpeedLimit

		if v, ok := inboundInfo.ServiceInfo.Load(email); ok {
			u := v.(ServiceInfo)
			uid = u.UID
			serviceLimit = u.SpeedLimit
			deviceLimit = u.DeviceLimit
		}

		// Local device limit
		ipMap := new(sync.Map)
		ipMap.Store(ip, uid)
		// If any device is online
		if v, ok := inboundInfo.ServiceOnlineIP.LoadOrStore(email, ipMap); ok {
			ipMap := v.(*sync.Map)
			// If this is a new ip
			if _, ok := ipMap.LoadOrStore(ip, uid); !ok {
				counter := 0
				ipMap.Range(func(key, value interface{}) bool {
					counter++
					return true
				})
				if counter > deviceLimit && deviceLimit > 0 {
					ipMap.Delete(ip)
					return nil, false, true
				}
			}
		}

		// Speed limit
		limit := determineRate(nodeLimit, serviceLimit) // Determine the speed limit rate
		if limit > 0 {
			limiter := rate.NewLimiter(rate.Limit(limit), int(limit)) // Byte/s
			if v, ok := inboundInfo.BucketHub.LoadOrStore(email, limiter); ok {
				bucket := v.(*rate.Limiter)
				return bucket, true, false
			} else {
				return limiter, true, false
			}
		} else {
			return nil, false, false
		}
	} else {
		newError("Get Inbound Limiter information failed").AtDebug().WriteToLog()
		return nil, false, false
	}
}


// determineRate returns the minimum non-zero rate
func determineRate(nodeLimit, serviceLimit uint64) (limit uint64) {
	if nodeLimit == 0 || serviceLimit == 0 {
		if nodeLimit > serviceLimit {
			return serviceLimit
		} else if nodeLimit < serviceLimit {
			return nodeLimit
		} else {
			return 0
		}
	} else {
		if nodeLimit > serviceLimit {
			return serviceLimit
		} else if nodeLimit < serviceLimit {
			return nodeLimit
		} else {
			return serviceLimit
		}
	}
}
