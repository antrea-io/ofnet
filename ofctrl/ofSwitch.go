/*
Copyright 2014 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package ofctrl

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"antrea.io/libOpenflow/common"
	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/util"

	log "github.com/sirupsen/logrus"
	cmap "github.com/streamrail/concurrent-map"
)

const (
	messageTimeout = 10 * time.Second
	PC_NO_FLOOD    = 1 << 4
)

var (
	heartbeatInterval, _ = time.ParseDuration("5s")
)

type OFSwitch struct {
	stream *util.MessageStream
	dpid   net.HardwareAddr
	app    AppInterface
	// Following are fgraph state for the switch
	tableDb        map[uint8]*Table
	tableDbMux     sync.Mutex
	dropAction     *Output
	sendToCtrler   *Output
	normalLookup   *Output
	ready          bool
	statusMux      sync.Mutex
	outputPorts    map[uint32]*Output
	portMux        sync.Mutex
	groupDb        map[uint32]*Group
	groupDbMux     sync.Mutex
	meterDb        map[uint32]*Meter
	meterDbMux     sync.Mutex
	connCh         chan int // Channel to notify controller connection status is changed
	mQueue         chan *openflow15.MultipartRequest
	monitorEnabled bool
	lastUpdate     time.Time // time at that receiving the last EchoReply
	// map for receiving reply messages from OFSwitch. Key is Xid, and value is a chan created by request message sender.
	txChans map[uint32]chan MessageResult
	txLock  sync.Mutex         // lock for txChans
	ctx     context.Context    // ctx is used in the lifecycle of a connection
	cancel  context.CancelFunc // cancel is used to cancel the proceeding OpenFlow message when OFSwitch is disconnected.
	ctrlID  uint16

	tlvMgr *tlvMapMgr
}

var switchDb cmap.ConcurrentMap
var monitoredFlows cmap.ConcurrentMap

func init() {
	switchDb = cmap.New()
	monitoredFlows = cmap.New()
}

// Builds and populates a Switch struct then starts listening
// for OpenFlow messages on conn.
func NewSwitch(stream *util.MessageStream, dpid net.HardwareAddr, app AppInterface, connCh chan int, ctrlID uint16) *OFSwitch {
	s := getSwitch(dpid)
	if s == nil {
		log.Infoln("Openflow Connection for new switch:", dpid)

		s = new(OFSwitch)
		s.app = app
		s.stream = stream
		s.dpid = dpid
		s.connCh = connCh
		s.txChans = make(map[uint32]chan MessageResult)
		s.ctrlID = ctrlID

		// Initialize the fgraph elements
		s.initFgraph()

		// Save it
		switchDb.Set(dpid.String(), s)

	} else {
		log.Infoln("Openflow re-connection for switch:", dpid)
		s.stream = stream
		s.dpid = dpid
	}
	// Prepare a context for current connection.
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.tlvMgr = newTLVMapMgr()
	return s
}

// Returns a pointer to the Switch mapped to dpid.
func getSwitch(dpid net.HardwareAddr) *OFSwitch {
	sw, _ := switchDb.Get(dpid.String())
	if sw == nil {
		return nil
	}
	return sw.(*OFSwitch)
}

// Returns the dpid of Switch s.
func (self *OFSwitch) DPID() net.HardwareAddr {
	return self.dpid
}

// Sends an OpenFlow message to this Switch.
func (self *OFSwitch) Send(req util.Message) error {
	select {
	case <-time.After(messageTimeout):
		return fmt.Errorf("message send timeout")
	case self.stream.Outbound <- req:
		return nil
	case <-self.ctx.Done():
		return fmt.Errorf("message is canceled because of disconnection from the Switch")
	}
}

func (self *OFSwitch) Disconnect() {
	self.stream.Shutdown <- true
	self.switchDisconnected(false)
}

func (self *OFSwitch) changeStatus(status bool) {
	self.statusMux.Lock()
	defer self.statusMux.Unlock()
	self.ready = status
}

func (self *OFSwitch) IsReady() bool {
	self.statusMux.Lock()
	defer self.statusMux.Unlock()
	return self.ready
}

// Handle switch connected event
func (self *OFSwitch) switchConnected() error {
	if err := self.clearGroups(); err != nil {
		return fmt.Errorf("fails to clear groups: %v", err)
	}
	// Main receive loop for the switch
	go self.receive()
	// Periodically sends echo request message on the connection.
	go func() {
		timer := time.NewTicker(heartbeatInterval)
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				if err := self.Send(openflow15.NewEchoRequest()); err != nil {
					log.Errorf("Failed to send echo request, and retry after %s: %v", heartbeatInterval.String(), err)
				}
			case <-self.ctx.Done():
				log.Infof("Canceling sending echo request on the connection because switch is diconnected")
				return
			}
		}
	}()
	if err := self.requestTlvMap(); err != nil {
		log.Errorf("Failed to query tlv-map configurations on the OpenFlow switch: %v", err)
		return err
	}
	// Send SwitchConfig message.
	swConfig := openflow15.NewSetConfig()
	swConfig.MissSendLen = 128
	if err := self.Send(swConfig); err != nil {
		log.Errorf("Failed to set switch config: %v", err)
		return err
	}
	// Set controller ID on the Switch.
	if err := self.Send(openflow15.NewSetControllerID(self.ctrlID)); err != nil {
		log.Errorf("Failed to set controller ID: %v", err)
		return err
	}
	self.changeStatus(true)
	self.app.SwitchConnected(self)
	return nil
}

// Handle switch disconnected event
func (self *OFSwitch) switchDisconnected(reconnect bool) {
	self.changeStatus(false)
	self.cancel()
	switchDb.Remove(self.DPID().String())
	self.app.SwitchDisconnected(self)
	if reconnect && self.connCh != nil {
		self.connCh <- ReConnection
	}
}

// Receive loop for each Switch.
func (self *OFSwitch) receive() {
	for {
		select {
		case msg := <-self.stream.Inbound:
			// New message has been received from message
			// stream.
			self.handleMessages(self.dpid, msg)
		case err := <-self.stream.Error:
			log.Warnf("Received ERROR message from switch %v. Err: %v", self.dpid, err)

			// send Switch disconnected callback
			self.switchDisconnected(true)
			return
		}
	}
}

// Handle openflow messages from the switch
func (self *OFSwitch) handleMessages(dpid net.HardwareAddr, msg util.Message) {
	log.Debugf("Received message: %+v, on switch: %s", msg, dpid.String())

	switch t := msg.(type) {
	case *common.Header:
		switch t.Header().Type {
		case openflow15.Type_Hello:
			// Send Hello response
			h, _ := common.NewHello(6)
			if err := self.Send(h); err != nil {
				log.Errorf("Error sending hello message")
			}
		case openflow15.Type_EchoRequest:
			// Send echo reply
			res := openflow15.NewEchoReply()
			if err := self.Send(res); err != nil {
				log.Errorf("Failed to send echo reply: %v", err)
			}

		case openflow15.Type_EchoReply:
			self.lastUpdate = time.Now()

		case openflow15.Type_FeaturesRequest:

		case openflow15.Type_GetConfigRequest:

		case openflow15.Type_BarrierRequest:

		case openflow15.Type_BarrierReply:

		}
	case *openflow15.ErrorMsg:
		// Get the original message type from the error message data field.
		errMsg := GetErrorMessage(t.Type, t.Code, 0)
		msgType := GetErrorMessageType(t.Data)
		log.Errorf("Received OpenFlow1.5 error: %s on message %s", errMsg, msgType)
		result := MessageResult{
			succeed: false,
			errType: t.Type,
			errCode: t.Code,
			xID:     t.Xid,
			msgType: UnknownMessage,
		}
		var tid uint32
		errData := t.Data.Buffer.Bytes()
		switch t.Data.Bytes()[1] {
		case openflow15.Type_BundleControl:
			result.msgType = BundleControlMessage
			tid = binary.BigEndian.Uint32(errData[8:12])
		case openflow15.Type_BundleAddMessage:
			result.msgType = BundleAddMessage
			log.Debugf("handleMessages: Type_BundleAddMessage: Data Bytes(%d): %v", len(t.Data.Bytes()), t.Data.Bytes())
			tid = binary.BigEndian.Uint32(errData[8:12])
		default:
			tid = t.Xid
		}

		self.publishMessage(tid, result)

	case *openflow15.VendorHeader:
		log.Debugf("Received Experimenter message, VendorType: %d, ExperimenterType: %d, VendorData: %+v", t.Vendor, t.ExperimenterType, t.VendorData)
		switch t.ExperimenterType {
		case openflow15.Type_TlvTableReply:
			reply := t.VendorData.(*openflow15.TLVTableReply)
			status := TLVTableStatus(*reply)
			self.tlvMgr.TLVMapReplyRcvd(self, &status)
		}

	case *openflow15.BundleCtrl:
		result := MessageResult{
			xID:     t.Header.Xid,
			succeed: true,
			msgType: BundleControlMessage,
		}
		self.publishMessage(t.BundleId, result)

	case *openflow15.SwitchFeatures:

	case *openflow15.SwitchConfig:
		switch t.Header.Type {
		case openflow15.Type_GetConfigReply:

		case openflow15.Type_SetConfig:

		}
	case *openflow15.PacketIn:
		log.Debugf("Received packet(ofctrl): %+v", t)
		// send packet rcvd callback
		self.app.PacketRcvd(self, (*PacketIn)(t))

	case *openflow15.FlowRemoved:

	case *openflow15.PortStatus:
		// FIXME: This needs to propagated to the app.
	case *openflow15.PacketOut:

	case *openflow15.FlowMod:

	case *openflow15.PortMod:

	case *openflow15.MultipartRequest:

	case *openflow15.MultipartReply:
		log.Debugf("Received MultipartReply")
		rep := (*openflow15.MultipartReply)(t)
		if self.monitorEnabled {
			key := fmt.Sprintf("%d", rep.Xid)
			ch, found := monitoredFlows.Get(key)
			if found {
				replyChan := ch.(chan *openflow15.MultipartReply)
				replyChan <- rep
			}
		}
		// send packet rcvd callback
		self.app.MultipartReply(self, rep)
	case *openflow15.VendorError:
		errData := t.ErrorMsg.Data.Bytes()
		result := MessageResult{
			succeed:      false,
			errType:      t.Type,
			errCode:      t.Code,
			experimenter: int32(t.ExperimenterID),
			xID:          t.Xid,
		}
		experimenterID := binary.BigEndian.Uint32(errData[8:12])
		errMsg := GetErrorMessage(t.Type, t.Code, experimenterID)
		experimenterType := binary.BigEndian.Uint32(errData[12:16])
		switch experimenterID {
		case openflow15.ONF_EXPERIMENTER_ID:
			switch experimenterType {
			case openflow15.Type_BundleCtrl:
				bundleID := binary.BigEndian.Uint32(errData[16:20])
				result.msgType = BundleControlMessage
				self.publishMessage(bundleID, result)
				log.Errorf("Received Vendor error: %s on ONFT_BUNDLE_CONTROL message", errMsg)
			case openflow15.Type_BundleAdd:
				bundleID := binary.BigEndian.Uint32(errData[16:20])
				result.msgType = BundleAddMessage
				self.publishMessage(bundleID, result)
				log.Errorf("Received Vendor error: %s on ONFT_BUNDLE_ADD_MESSAGE message", errMsg)
			}
		default:
			log.Errorf("Received Vendor error: %s", errMsg)
		}
	}
}

func (self *OFSwitch) getMPReq() *openflow15.MultipartRequest {
	mp := &openflow15.MultipartRequest{}
	mp.Type = openflow15.MultipartType_FlowDesc
	mp.Header = openflow15.NewOfp15Header()
	mp.Header.Type = openflow15.Type_MultiPartRequest
	return mp
}

func (self *OFSwitch) EnableMonitor() {
	if self.monitorEnabled {
		return
	}

	if self.mQueue == nil {
		self.mQueue = make(chan *openflow15.MultipartRequest)
	}

	go func() {
		for {
			mp := <-self.mQueue
			self.Send(mp)
			log.Debugf("Send flow stats request")
		}
	}()
	self.monitorEnabled = true
}

func (self *OFSwitch) DumpFlowStats(cookieID uint64, cookieMask *uint64, flowMatch *FlowMatch, tableID *uint8) ([]*openflow15.FlowDesc, error) {
	mp := self.getMPReq()
	replyChan := make(chan *openflow15.MultipartReply)
	go func() {
		log.Debug("Add flow into monitor queue")
		flowMonitorReq := openflow15.NewFlowStatsRequest()
		if tableID != nil {
			flowMonitorReq.TableId = *tableID
		} else {
			flowMonitorReq.TableId = 0xff
		}
		flowMonitorReq.Cookie = cookieID
		if cookieMask != nil {
			flowMonitorReq.CookieMask = *cookieMask
		} else {
			flowMonitorReq.CookieMask = ^uint64(0)
		}
		if flowMatch != nil {
			f := &Flow{Match: *flowMatch}
			flowMonitorReq.Match = f.xlateMatch()
		}
		mp.Body = []util.Message{flowMonitorReq}
		monitoredFlows.Set(fmt.Sprintf("%d", mp.Xid), replyChan)
		self.mQueue <- mp
	}()

	select {
	case reply := <-replyChan:
		flowStates := make([]*openflow15.FlowDesc, 0)
		if reply.Type == openflow15.MultipartType_FlowDesc {
			flowArr := reply.Body
			for _, entry := range flowArr {
				flowStates = append(flowStates, entry.(*openflow15.FlowDesc))
			}
			return flowStates, nil
		}

	case <-time.After(2 * time.Second):
		return nil, errors.New("timeout to wait for MultipartReply message")
	}
	return nil, nil
}

func (self *OFSwitch) CheckStatus(timeout time.Duration) bool {
	return self.lastUpdate.Add(heartbeatInterval).After(time.Now())
}

func (self *OFSwitch) EnableOFPortForwarding(port int, portMAC net.HardwareAddr) error {
	config := 0
	config &^= openflow15.PC_NO_FWD
	mask := openflow15.PC_NO_FWD
	return self.sendModPortMessage(port, portMAC, config, mask)
}

func (self *OFSwitch) DisableOFPortForwarding(port int, portMAC net.HardwareAddr) error {
	config := openflow15.PC_NO_FWD
	mask := openflow15.PC_NO_FWD
	return self.sendModPortMessage(port, portMAC, config, mask)
}

func (self *OFSwitch) subscribeMessage(xID uint32, msgChan chan MessageResult) {
	self.txLock.Lock()
	self.txChans[xID] = msgChan
	self.txLock.Unlock()
}

func (self *OFSwitch) publishMessage(xID uint32, result MessageResult) {
	go func() {
		self.txLock.Lock()
		defer self.txLock.Unlock()
		ch, found := self.txChans[xID]
		if found {
			ch <- result
		}
	}()
}

func (self *OFSwitch) unSubscribeMessage(xID uint32) {
	self.txLock.Lock()
	defer self.txLock.Unlock()
	_, found := self.txChans[xID]
	if found {
		delete(self.txChans, xID)
	}
}

func (self *OFSwitch) sendModPortMessage(port int, mac net.HardwareAddr, config int, mask int) error {
	msg := openflow15.NewPortMod(port)
	msg.Header.Version = 0x6
	msg.HWAddr = mac
	msg.Config = uint32(config)
	msg.Mask = uint32(mask)
	return self.Send(msg)
}

func (self *OFSwitch) GetControllerID() uint16 {
	return self.ctrlID
}
