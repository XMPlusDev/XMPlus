package xmplus

import "encoding/json"

type Service struct {
	Id         int    `json:"id"`
	Uuid       string `json:"uuid"`
	Email      string `json:"email"`
	Speedlimit int    `json:"speedlimit"`
	Iplimit    int    `json:"iplimit"`
	Ipcount    int    `json:"ipcount"`
}

// Response is the common response
type Response struct {
	Ret  uint            `json:"ret"`
	Data json.RawMessage `json:"data"`
}

// PostData is the data structure of post data
type PostData struct {
	Data interface{} `json:"data"`
}

// OnlineUser is the data structure of online user
type OnlineIP struct {
	UID int    `json:"serviceid"`
	IP  string `json:"ip"`
}

// UserTraffic is the data structure of traffic
type ServiceTraffic struct {
	UID      int   `json:"serviceid"`
	Upload   int64 `json:"u"`
	Download int64 `json:"d"`
}

type IllegalItem struct {
	ID  int `json:"list_id"`
	UID int `json:"serviceid"`
}
