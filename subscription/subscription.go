package subscription

import (
	"context"
	"fmt"
	"log"

	"github.com/XMPlusDev/XMPlus/api"
	"github.com/XMPlusDev/XMPlus/app/dispatcher"
	
	"github.com/xmplusdev/xray-core/v26/common/protocol"
	"github.com/xmplusdev/xray-core/v26/proxy"
	"github.com/xmplusdev/xray-core/v26/core"
	"github.com/xmplusdev/xray-core/v26/features/inbound"
	"github.com/xmplusdev/xray-core/v26/features/stats"
	"github.com/xmplusdev/xray-core/v26/features/routing"
)

// Manager handles subscription-related operations
type Manager struct {
	server *core.Instance
	client  *api.API  
	ibm    inbound.Manager
	stm    stats.Manager
	dispatcher   *dispatcher.DefaultDispatcher
}

// UserBuilder is a function type that builds protocol users from subscription info
type UserBuilder func(subscriptionInfo *[]api.SubscriptionInfo, additionalParam ...interface{}) []*protocol.User

// NewManager creates a new subscription manager
func NewManager(server *core.Instance, client *api.API) *Manager {
	return &Manager{
		server: server,
		client: client,
		ibm:    server.GetFeature(inbound.ManagerType()).(inbound.Manager),
		stm:    server.GetFeature(stats.ManagerType()).(stats.Manager),
		dispatcher:  server.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher),
	}
}

func (m *Manager) addNewSubscription(subscriptionInfo *[]api.SubscriptionInfo, nodeInfo *api.NodeInfo, tag string) (err error) {
	if subscriptionInfo == nil || len(*subscriptionInfo) == 0 {
		return nil
	}

	var users []*protocol.User
	switch nodeInfo.NodeType {
	case "Vless":
		users = BuildVlessUsers(subscriptionInfo, nodeInfo.Flow, tag)
	case "Vmess":
		users = BuildVmessUsers(subscriptionInfo, tag)
	case "Trojan":
		users = BuildTrojanUsers(subscriptionInfo, tag)
	case "Shadowsocks":
		users = BuildShadowsocksUsers(subscriptionInfo, nodeInfo.Cipher, tag)
	default:
		return fmt.Errorf("unsupported node type: %s", nodeInfo.NodeType)
	}

	return m.Add(users, tag)
}

// Add adds new subscriptions to an inbound tag
func (m *Manager) Add(subscriptions []*protocol.User, tag string) error {
	if len(subscriptions) == 0 {
		return nil
	}

	err := m.addInboundSubscriptions(subscriptions, tag)
	if err != nil {
		return fmt.Errorf("failed to add subscriptions to tag %s: %w", tag, err)
	}

	log.Printf("Added %d subscriptions to tag %s", len(subscriptions), tag)
	return nil
}

// Remove removes subscriptions from an inbound tag
func (m *Manager) Remove(emails []string, tag string) error {
	if len(emails) == 0 {
		return nil
	}

	err := m.removeInboundSubscriptions(emails, tag)
	if err != nil {
		return fmt.Errorf("failed to remove subscriptions from tag %s: %w", tag, err)
	}

	log.Printf("Removed %d subscriptions from tag %s", len(emails), tag)
	return nil
}

// AddNew is a convenience method that builds users and adds them
func (m *Manager) AddNew(
	subscriptionInfo *[]api.SubscriptionInfo,
	nodeInfo *api.NodeInfo,
	tag string,
	userBuilder UserBuilder,
	additionalParams ...interface{},
) error {
	if subscriptionInfo == nil || len(*subscriptionInfo) == 0 {
		return nil
	}

	subscriptions := userBuilder(subscriptionInfo, additionalParams...)
	if len(subscriptions) == 0 {
		return fmt.Errorf("no valid subscriptions built")
	}

	return m.Add(subscriptions, tag)
}

// Compare compares two subscription lists and returns deleted and added subscriptions
func Compare(old, new *[]api.SubscriptionInfo) (deleted, added []api.SubscriptionInfo) {
	if old == nil || new == nil {
		return nil, nil
	}

	mSrc := make(map[api.SubscriptionInfo]byte)
	mAll := make(map[api.SubscriptionInfo]byte)
	var set []api.SubscriptionInfo

	// Add all old subscriptions to maps
	for _, v := range *old {
		mSrc[v] = 0
		mAll[v] = 0
	}

	// Check new subscriptions
	for _, v := range *new {
		l := len(mAll)
		mAll[v] = 1
		if l != len(mAll) {
			// New entry added to map
			l = len(mAll)
		} else {
			// Entry already exists (intersection)
			set = append(set, v)
		}
	}

	// Remove intersections
	for _, v := range set {
		delete(mAll, v)
	}

	// Separate deleted and added
	for v := range mAll {
		_, exist := mSrc[v]
		if exist {
			deleted = append(deleted, v)
		} else {
			added = append(added, v)
		}
	}

	return deleted, added
}


func (m *Manager) subscriptionMonitor(
	subscriptionList *[]api.SubscriptionInfo,
	tag string,
	logPrefix string,
) (err error) {  // Added closing parenthesis here
	// Get Subscription traffic
	var subscriptionTraffic []api.SubscriptionTraffic
	var upCounterList []stats.Counter
	var downCounterList []stats.Counter

	for _, subscription := range *subscriptionList {
		up, down, upCounter, downCounter := m.getTraffic(buildUserTag(tag, &subscription))
		if up > 0 || down > 0 {
			subscriptionTraffic = append(subscriptionTraffic, api.SubscriptionTraffic{
				Id: subscription.Id,
				U:  up,
				D:  down,
			})  // Added closing brace and parenthesis here

			if upCounter != nil {
				upCounterList = append(upCounterList, upCounter)
			}
			if downCounter != nil {
				downCounterList = append(downCounterList, downCounter)
			}
		}
	}

	if len(subscriptionTraffic) > 0 {
		var err error // Define an empty error

		err = m.client.ReportTraffic(&subscriptionTraffic)
		// If report traffic error, not clear the traffic
		if err != nil {
			log.Print(err)
		} else {
			m.resetTraffic(&upCounterList, &downCounterList)
		}
	}

	// Report Online info
	if onlineDevice, err := m.GetOnlineIPs(tag); err != nil {
		log.Print(err)
	} else if len(*onlineDevice) > 0 {
		if err = m.client.ReportOnlineIPs(onlineDevice); err != nil {
			log.Print(err)
		} else {
			log.Printf("%s Report %d online IPs", logPrefix, len(*onlineDevice))
		}
	}

	return nil
}

// FormatEmails formats subscription info into email strings for removal
func FormatEmails(subscriptions []api.SubscriptionInfo, tag string) []string {
	if len(subscriptions) == 0 {
		return nil
	}

	emails := make([]string, len(subscriptions))
	for i, u := range subscriptions {
		emails[i] = fmt.Sprintf("%s|%s|%d", tag, u.Email, u.Id)
	}
	return emails
}

func buildUserTag(tag string, subscription *api.SubscriptionInfo) string {
	return fmt.Sprintf("%s|%s|%d", tag, subscription.Email, subscription.Id)
}

// Private helper methods
func (m *Manager) addInboundSubscriptions(subscriptions []*protocol.User, tag string) error {
	handler, err := m.ibm.GetHandler(context.Background(), tag)
	if err != nil {
		return fmt.Errorf("no such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return fmt.Errorf("handler %s has not implemented proxy.GetInbound", tag)
	}

	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return fmt.Errorf("handler %s has not implemented proxy.UserManager", tag)
	}
	for _, item := range subscriptions {
		subscription, err := item.ToMemoryUser()
		if err != nil {
			return err
		}
		err = userManager.AddUser(context.Background(), subscription)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) removeInboundSubscriptions(emails []string, tag string) error {
	handler, err := m.ibm.GetHandler(context.Background(), tag)
	if err != nil {
		return fmt.Errorf("no such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return fmt.Errorf("handler %s is not implement proxy.GetInbound", tag)
	}

	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return fmt.Errorf("handler %s is not implement proxy.UserManager", err)
	}
	for _, email := range emails {
		err = userManager.RemoveUser(context.Background(), email)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) getTraffic(email string) (up int64, down int64, upCounter stats.Counter, downCounter stats.Counter) {
	upName := "user>>>" + email + ">>>traffic>>>uplink"
	downName := "user>>>" + email + ">>>traffic>>>downlink"
	upCounter = m.stm.GetCounter(upName)
	downCounter = m.stm.GetCounter(downName)
	if upCounter != nil && upCounter.Value() != 0 {
		up = upCounter.Value()
	} else {
		upCounter = nil
	}
	if downCounter != nil && downCounter.Value() != 0 {
		down = downCounter.Value()
	} else {
		downCounter = nil
	}
	return up, down, upCounter, downCounter
}

func (m *Manager) resetTraffic(upCounterList *[]stats.Counter, downCounterList *[]stats.Counter) {
	for _, upCounter := range *upCounterList {
		upCounter.Set(0)
	}
	for _, downCounter := range *downCounterList {
		downCounter.Set(0)
	}
}

func (m *Manager) GetOnlineIPs(tag string) (*[]api.OnlineIP, error) {
	return m.dispatcher.Limiter.GetOnlineDevice(tag)
}