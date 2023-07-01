// To implement an api , one needs to implement the interface below.

package api

type API interface {
	GetNodeInfo() (nodeInfo *NodeInfo, err error)
	GetServiceList() (serviceList *[]ServiceInfo, err error)
	ReportNodeOnlineIPs(onlineIP *[]OnlineIP) (err error)
	ReportServiceTraffic(serviceTraffic *[]ServiceTraffic) (err error)
	Describe() ClientInfo
	GetNodeRule() (ruleList *[]DetectRule, err error)
	Debug()
}
