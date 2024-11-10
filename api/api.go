// To implement an api , one needs to implement the interface below.

package api

type API interface {
	GetNodeInfo() (nodeInfo *NodeInfo, err error)
	GetRelayNodeInfo() (nodeInfo *RelayNodeInfo, err error)
	GetSubscriptionList() (subscriptionList *[]SubscriptionInfo, err error)
	ReportNodeOnlineIPs(onlineIP *[]OnlineIP) (err error)
	ReportSubscriptionTraffic(subscriptionTraffic *[]SubscriptionTraffic) (err error)
	Describe() ClientInfo
	GetNodeRule() (ruleList *[]DetectRule, err error)
	Debug()
}
