package controller

import (
	"fmt"
	"log"
	"reflect"
	"time"
	
	"github.com/xmplusdev/xray-core/v26/core"
	
	"github.com/XMPlusDev/XMPlus/api"
	"github.com/XMPlusDev/XMPlus/node"
	"github.com/XMPlusDev/XMPlus/subscription"
	"github.com/XMPlusDev/XMPlus/helper/cert"
	"github.com/XMPlusDev/XMPlus/helper/task"
)

type ManagerInterface interface {
	Restart() error
}

type Controller struct {
	server       *core.Instance
	config       *node.Config
	clientInfo   api.ClientInfo
	client       api.API
	nodeInfo     *api.NodeInfo
	Tag          string
	LogPrefix    string
	RelayTag     string
	Relay        bool
	subscriptionList  *[]api.SubscriptionInfo
	taskManager  *task.Manager
	startAt      time.Time
	manager      ManagerInterface
	nodeManager  *node.Manager 
	subManager   *subscription.Manager
}

// New return a Controller service with default parameters.
func New(server *core.Instance, api api.API, config *node.Config) *Controller {
	controller := &Controller{
		server:      server,
		config:      config,
		client:      api,
		startAt:     time.Now(),
		taskManager: task.NewManager(), 
		nodeManager: node.NewManager(server),
		subManager:  subscription.NewManager(server, api),
	}

	return controller
}

// SetManager sets the manager reference for this controller
func (c *Controller) SetManager(manager ManagerInterface) {
	c.manager = manager
}

// RestartManager restarts the entire manager
func (c *Controller) RestartManager() error {
	if c.manager == nil {
		return fmt.Errorf("manager reference not set")
	}
	
	log.Printf("%s Initiating full manager restart", c.logPrefix())
	return c.manager.Restart()
}

// Start implement the Start() function of the service interface
func (c *Controller) Start() error {
	c.clientInfo = c.client.Describe()
	
	newNodeInfo, err := c.client.GetNodeInfo() 
	if err != nil {
		return err
	}
	c.nodeInfo = newNodeInfo
	c.Tag = c.buildNodeTag()
	
	// Update Subscription
	subscriptionInfo, err := c.client.GetSubscriptionList() 
	if err != nil {
		return err
	}
	c.subscriptionList = subscriptionInfo
	
	err = c.nodeManager.BlockingRuleTag(
		c.nodeInfo, 
		c.Tag,
	)
	if err != nil {
		log.Panic(err)
		return err
	}
	
	c.Relay = false
	// Add new relay tag
	if c.nodeInfo.RelayType == 1 && c.nodeInfo.RelayNodeID > 0 {
		c.RelayTag = c.buildRNodeTag()
		
		err = c.nodeManager.AddRelayTag(
			newNodeInfo,
			c.RelayTag,
			c.Tag,
			c.subscriptionList,
		)
		if err != nil {
			log.Panic(err)
			return err
		}
		c.Relay = true
	}
	
	// Add new tag
	err = c.nodeManager.AddTag(
		c.nodeInfo, 
		c.Tag, 
		c.config,
	)
	if err != nil {
		log.Panic(err)
		return err
	}
	
	// Add user Subscriptions
	err = c.subManager.AddNewSubscription(
		subscriptionInfo, 
		newNodeInfo,
		c.Tag,
	)
	if err != nil {
		return err
	}
	
	// Add Limiter
	err = c.nodeManager.AddInboundLimiter(
		c.Tag, 
		newNodeInfo.SpeedLimit, 
		subscriptionInfo, 
		c.config.RedisConfig,
	) 
	if err != nil {
		log.Print(err)
	}
	
	c.LogPrefix = c.logPrefix()
	
	// Add periodic tasks using the task manager
	c.taskManager.Add(task.NewWithInterval(
		"server",
		time.Duration(c.nodeInfo.UpdateTime)*time.Second,
		c.nodeInfoMonitor,
	))
	
	c.taskManager.Add(task.NewWithInterval(
		"subscriptions",
		time.Duration(c.nodeInfo.UpdateTime)*time.Second,
		c.subManager.SubscriptionMonitor(c.subscriptionList, c.Tag, c.LogPrefix),
	))
	
	// Check cert service if needed
	if c.nodeInfo.SecurityType == "tls" { 
		if c.nodeInfo.TlsSettings.CertMode != "none" {
			c.taskManager.Add(task.NewWithInterval(
				"cert renew",
				time.Duration(c.nodeInfo.UpdateTime)*time.Second*60,
				c.certMonitor,
			))
		}
	}

	// Start all tasks
	log.Printf("%s Starting %d task schedulers", c.logPrefix(), c.taskManager.Count())
	return c.taskManager.StartAll()
}

func (c *Controller) nodeInfoMonitor() (err error) {
	// delay to start
	if time.Since(c.startAt) < time.Duration(c.nodeInfo.UpdateTime)*time.Second {
		return nil
	}
	
	var nodeInfoChanged = true
	newNodeInfo, err := c.client.GetNodeInfo()
	if err != nil {
		if err.Error() == api.NodeNotModified {
			nodeInfoChanged = false
			newNodeInfo = c.nodeInfo
		} else {
			log.Print(err)
			return nil
		}
	}

    // Update Subscription
	var subscriptionChanged = true
	newSubscriptionInfo, err := c.client.GetSubscriptionList()
	if err != nil {
		if err.Error() == api.SubscriptionNotModified  {
			subscriptionChanged = false
			newSubscriptionInfo = c.subscriptionList
		} else {
			log.Print(err)
			return nil
		}
	}	
	
	var updateRelay = false	
	if subscriptionChanged || nodeInfoChanged {
		updateRelay = true
	}
	
	if c.Relay && updateRelay {
		err := c.nodeManager.RemoveRelayRules(
			c.RelayTag, 
			c.subscriptionList,
		)
		if err != nil {
			log.Print(err)
		}	
	}
	
	// If nodeInfo changed
	if nodeInfoChanged {
		if !reflect.DeepEqual(c.nodeInfo, newNodeInfo) {
			// Remove old tag
			oldTag := c.Tag
			err := c.nodeManager.RemoveTag(oldTag)
			if err != nil {
				log.Print(err)
				return nil
			}
			err = c.nodeManager.RemoveBlockingRules(oldTag)
			if err != nil {
				log.Print(err)
			}
			if c.nodeInfo.NodeType == "Shadowsocks-Plugin" {
				err = c.nodeManager.RemoveTag(fmt.Sprintf("dokodemo-door_%s+1", c.Tag))
			}
			if err != nil {
				log.Print(err)
				return nil
			}
			
			// Add new tag
			c.nodeInfo = newNodeInfo
			c.Tag = c.buildNodeTag()
			err = c.nodeManager.AddTag(newNodeInfo, c.Tag, c.config)
			if err != nil {
				log.Print(err)
				return nil
			}
			err = c.nodeManager.BlockingRuleTag(c.nodeInfo, c.Tag)
			if err != nil {
				log.Print(err)
				return nil
			}
			//nodeInfoChanged = true
		
			// Remove Old limiter
			err = c.nodeManager.DeleteInboundLimiter(oldTag)
			if err != nil {
				log.Print(err)
				return nil
			}
		} else {
			nodeInfoChanged = false
		}
	}
	
	// Remove relay tag
	if c.Relay && updateRelay {
		err := c.nodeManager.RemoveRelayTag(c.RelayTag, c.subscriptionList)
		if err != nil {
			return err
		}
		c.Relay = false
	}
	
	// Update new Relay tag
	if c.nodeInfo.RelayType == 1 && c.nodeInfo.RelayNodeID > 0 && updateRelay {
		c.RelayTag = c.buildRNodeTag()
		
		err := c.nodeManager.AddRelayTag(
			newNodeInfo,
			c.RelayTag,
			c.Tag,
			newSubscriptionInfo,
		)
		if err != nil {
			log.Panic(err)
			return err
		}
		c.Relay = true
	}
	
	if nodeInfoChanged {
		err := c.subManager.AddNewSubscription(
			newSubscriptionInfo, 
			newNodeInfo, 
			c.Tag,
		)
		if err != nil {
			log.Print(err)
			return nil
		}
		
		err = c.nodeManager.AddInboundLimiter(
			c.Tag, 
			newNodeInfo.SpeedLimit, 
			newSubscriptionInfo, 
			c.config.RedisConfig,
		)
		if err != nil {
			log.Print(err)
			return nil
		}	
	}else {
		var deleted, added []api.SubscriptionInfo
		if subscriptionChanged {
			deleted, added = subscription.Compare(c.subscriptionList, newSubscriptionInfo)
			deleted, added = subscription.Compare(c.subscriptionList, newSubscriptionInfo)
			if len(deleted) > 0 {
				deletedEmail := subscription.FormatEmails(deleted, c.Tag)
				err := c.subManager.Remove(deletedEmail, c.Tag)
				if err != nil {
					log.Print(err)
				}
			}
			if len(added) > 0 {
				err := c.subManager.AddNewSubscription(&added, c.nodeInfo, c.Tag)
				if err != nil {
					log.Print(err)
				}
				// Update Limiter
				if err := c.nodeManager.UpdateInboundLimiter(c.Tag, &added); err != nil {
					log.Print(err)
				}
			}
		}
	}
	
	c.subscriptionList = newSubscriptionInfo
	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	log.Printf("%s Closing %d task schedulers", c.logPrefix(), c.taskManager.Count())
	return c.taskManager.CloseAll()
}

func (c *Controller) certMonitor() error {
	switch c.nodeInfo.TlsSettings.CertMode {
	case "dns", "http":
		lego, err := cert.New(c.config.CertConfig)
		if err != nil {
			log.Print(err)
		}
		_, _, _, err = lego.RenewCert(c.nodeInfo.TlsSettings.CertMode, c.nodeInfo.TlsSettings.ServerName)
		if err != nil {
			log.Print(err)
		}
	}
	return nil
}

func (c *Controller) logPrefix() string {
	if c.nodeInfo == nil {
		return "[Controller]"
	}
	return fmt.Sprintf("[%s] %s(NodeID=%d)", 
		c.clientInfo.APIHost, 
		c.nodeInfo.NodeType, 
		c.nodeInfo.NodeID)
}

func (c *Controller) buildNodeTag() string {
	return fmt.Sprintf("%s_%s_%d", 
		c.nodeInfo.NodeType, 
		c.nodeInfo.ListeningPort, 
		c.nodeInfo.NodeID)
}

func (c *Controller) buildRNodeTag() string {
	return fmt.Sprintf("Relay_%d_%s_%d_%d", 
		c.nodeInfo.NodeID, 
		c.nodeInfo.RelayNodeInfo.NodeType, 
		c.nodeInfo.RelayNodeInfo.ListeningPort, 
		c.nodeInfo.RelayNodeInfo.NodeID)
}