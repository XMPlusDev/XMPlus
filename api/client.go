package api

import (
	"log"
	"sync/atomic"
	"encoding/json"
	"time"
	"sync"
	"fmt"
	
	"resty.dev/v3"
	"github.com/bitly/go-simplejson"
)

type Client struct {
	client *resty.Client
	APIHost string
	NodeID  int
	Key  string
	resp  atomic.Value
	eTags map[string]string
	LastReportOnline  map[int]int
	access  sync.Mutex
}

// Config API config
type Config struct {
	APIHost string `mapstructure:"ApiHost"`
	NodeID  int `mapstructure:"NodeID"`
	Key string `mapstructure:"ApiKey"`
	Timeout int `mapstructure:"Timeout"`
}

type ClientInfo struct {
	APIHost  string
	NodeID   int
	Key      string
}

func New(apiConfig *Config) *Client {
	client := resty.New()
	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(30 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		if v, ok := err.(*resty.ResponseError); ok {
			log.Print(v.Err)
		}
	})
	
	client.SetBaseURL(apiConfig.APIHost)
	client.SetBody(map[string]string{"key": apiConfig.Key})
	//client.SetQueryParam("key", apiConfig.Key)
	
	apiClient := &Client{
		client: client,
		NodeID:  apiConfig.NodeID,
		Key: apiConfig.Key,
		APIHost: apiConfig.APIHost,
		LastReportOnline: make(map[int]int),
		eTags: make(map[string]string),
	}
	
	return apiClient
}

func (c *Client) Describe() ClientInfo {
	return ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key}
}

func (c *Client) Debug() {
	c.client.SetDebug(true)
}

func (c *Client) checkResponse(res *resty.Response, err error) (*simplejson.Json, error) {
	if err != nil {
		return nil, fmt.Errorf("A request error occured: %s", err)
	}

	if res.StatusCode() > 400 {
		body := res.Body()
		return nil, fmt.Errorf("A request error occured: %s, %v", string(body), err)
	}
	
	result, err := simplejson.NewJson(res.Body())
	
	if err != nil {
		return nil, fmt.Errorf("%s", res.String())
	}
	
	return result, nil
}