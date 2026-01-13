package api

import (
	"encoding/json"
	"fmt"
	"errors"
	"reflect"
)

func (c *Client) parseSubscriptionResponse(res *resty.Response, err error) (*SubscriptionResponse, error) {
	if err != nil {
		return nil, fmt.Errorf("Failed to subscription lists request: %s", err)
	}

	if res.StatusCode() > 400 {
		body := res.Body()
		return nil, fmt.Errorf("Subscription request error: %s, %v", string(body), err)
	}
	
	response := res.Result().(*SubscriptionResponse)

	return response, nil
}

func (c *Client) GetSubscriptionList() (SubscriptionList *[]SubscriptionInfo, err error) {
	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTags["subscriptions"]).
		SetPathParam("serverId", c.NodeID).
		SetResult(&SubscriptionResponse{}).
		ForceContentType("application/json").
		Post("/api/server/subscription/lists/{serverId}")
	
	if res.StatusCode() == 304 {
		return nil, errors.New(SubscriptionNotModified)
	}

	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["subscriptions"] {
		c.eTags["subscriptions"] = res.Header().Get("Etag")
	}

	response, err := c.parseSubscriptionResponse(res, err)
	if err != nil {
		return nil, err
	}
	
	subscriptionsListResponse := new([]Subscription)

	if err := json.Unmarshal(response.Data, subscriptionsListResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(subscriptionsListResponse), err)
	}
	
	subscriptionList, err := c.ParseSubscriptionList(subscriptionsListResponse)
	if err != nil {
		res, _ := json.Marshal(subscriptionsListResponse)
		return nil, fmt.Errorf("parse subscription list failed: %s", string(res))
	}
	
	return subscriptionList, nil
}

func (c *Client) ParseSubscriptionList(subscriptionResponse *[]Subscription) (*[]SubscriptionInfo, error) {
	c.access.Lock()
	defer func() {
		c.LastReportOnline = make(map[int]int)
		c.access.Unlock()
	}()	
	
	var ipLimit, onlineipcount, ipcount int = 0, 0, 0
	var speedLimit uint64 = 0
	
	subscriptionList := []SubscriptionInfo{}
	
	for _, subscription := range *subscriptionResponse {
		ipLimit = subscription.Iplimit
		ipcount = subscription.Ipcount
		
		if ipLimit > 0 && ipcount > 0 {
			lastOnline := 0
			if v, ok := c.LastReportOnline[subscription.Id]; ok {
				lastOnline = v
			}
			if onlineipcount = ipLimit - ipcount + lastOnline; onlineipcount > 0 {
				ipLimit = onlineipcount
			} else if lastOnline > 0 {
				ipLimit = lastOnline
			} else {
				continue
			}
		}

		speedLimit = uint64((subscription.Speedlimit * 1000000) / 8)
		
		subscriptionList = append(subscriptionList, SubscriptionInfo{
			Id:  subscription.Id,
			Email: subscription.Email,
			Passwd: subscription.Passwd,
			IPLimit: ipLimit,
			SpeedLimit:  speedLimit,
		})
	}

	return &subscriptionList, nil
}

func (c *Client) ReportTraffic(subscriptionTraffic *[]SubscriptionTraffic) error {
	data := make([]SubscriptionTraffic, len(*subscriptionTraffic))	
	for i, traffic := range *subscriptionTraffic {
		data[i] = SubscriptionTraffic{
			Id:  traffic.Id,
			U:   traffic.u,
			D:   traffic.d,
		}
	}
	
	postData := &PostData{Data: data}
	res, err := c.client.R().
		SetBody(postData).
		SetPathParam("serverId", c.NodeID).
		ForceContentType("application/json").
		Post("/api/server/subscription/traffic/{serverId}")
	_, err = c.checkResponse(res, err)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) ReportOnlineIPs(onlineSubscriptionList *[]OnlineIP) error {
	c.access.Lock()
	defer c.access.Unlock()

	reportOnline := make(map[int]int)
	data := make([]OnlineIP, len(*onlineSubscriptionList))
	for i, subscription := range *onlineSubscriptionList {
		data[i] = OnlineIP{Id: subscription.Id, IP: subscription.IP}
		if _, ok := reportOnline[subscription.Id]; ok {
			reportOnline[subscription.Id]++
		} else {
			reportOnline[subscription.Id] = 1
		}
	}
	c.LastReportOnline = reportOnline 

	postData := &PostData{Data: data}
	res, err := c.client.R().
		SetBody(postData).
		SetPathParam("serverId", c.NodeID).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post("/api/server/subscription/onlineip/{serverId}")

	_, err = c.checkResponse(res, err)
	if err != nil {
		return err
	}

	return nil
}