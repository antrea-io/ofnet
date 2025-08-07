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
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	cmap "github.com/orcaman/concurrent-map/v2"
	log "github.com/sirupsen/logrus"
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

var (
	switchDb       = cmap.New[*OFSwitch]()
	monitoredFlows = cmap.New[chan *openflow15.MultipartReply]()
)

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
		if app.FlowGraphEnabledOnSwitch() {
			s.initFgraph()
		}

		// Save it
		switchDb.Set(dpid.String(), s)

	} else {
		log.Infoln("Openflow re-connection for switch:", dpid)
		s.stream = stream
		s.dpid = dpid
	}
	// Prepare a context for current connection.
	s.ctx, s.cancel = context.WithCancel(context.Background())
	if app.TLVMapEnabledOnSwitch() {
		s.tlvMgr = newTLVMapMgr()
	}
	return s
}

// Returns a pointer to the Switch mapped to dpid.
func getSwitch(dpid net.HardwareAddr) *OFSwitch {
	sw, ok := switchDb.Get(dpid.String())
	if !ok {
		return nil
	}
	return sw
}

// Returns the dpid of Switch s.
func (s *OFSwitch) DPID() net.HardwareAddr {
	return s.dpid
}

// Sends an OpenFlow message to this Switch.
func (s *OFSwitch) Send(req util.Message) error {
	select {
	case <-time.After(messageTimeout):
		return fmt.Errorf("message send timeout")
	case s.stream.Outbound <- req:
		return nil
	case <-s.ctx.Done():
		return fmt.Errorf("message is canceled because of disconnection from the Switch")
	}
}

func (s *OFSwitch) Disconnect() {
	s.stream.Shutdown <- true
	s.switchDisconnected(false)
}

func (s *OFSwitch) changeStatus(status bool) {
	s.statusMux.Lock()
	defer s.statusMux.Unlock()
	s.ready = status
}

func (s *OFSwitch) IsReady() bool {
	s.statusMux.Lock()
	defer s.statusMux.Unlock()
	return s.ready
}

// Handle switch connected event
func (s *OFSwitch) switchConnected() error {
	// Main receive loop for the switch
	go s.receive()
	// Periodically sends echo request message on the connection.
	go func() {
		timer := time.NewTicker(heartbeatInterval)
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				if err := s.Send(openflow15.NewEchoRequest()); err != nil {
					log.Errorf("Failed to send echo request, and retry after %s: %v", heartbeatInterval.String(), err)
				}
			case <-s.ctx.Done():
				log.Infof("Canceling sending echo request on the connection because switch is diconnected")
				return
			}
		}
	}()
	if err := s.requestTlvMap(); err != nil {
		log.Errorf("Failed to query tlv-map configurations on the OpenFlow switch: %v", err)
		return err
	}
	// Send SwitchConfig message.
	swConfig := openflow15.NewSetConfig()
	swConfig.MissSendLen = 128
	if err := s.Send(swConfig); err != nil {
		log.Errorf("Failed to set switch config: %v", err)
		return err
	}
	// Set controller ID on the Switch.
	if err := s.Send(openflow15.NewSetControllerID(s.ctrlID)); err != nil {
		log.Errorf("Failed to set controller ID: %v", err)
		return err
	}
	s.changeStatus(true)
	s.app.SwitchConnected(s)
	return nil
}

// Handle switch disconnected event
func (s *OFSwitch) switchDisconnected(reconnect bool) {
	s.changeStatus(false)
	s.cancel()
	switchDb.Remove(s.DPID().String())
	s.app.SwitchDisconnected(s)
	if reconnect && s.connCh != nil {
		s.connCh <- ReConnection
	}
}

// Receive loop for each Switch.
func (s *OFSwitch) receive() {
	for {
		select {
		case msg := <-s.stream.Inbound:
			// New message has been received from message
			// stream.
			s.handleMessages(s.dpid, msg)
		case err := <-s.stream.Error:
			log.Warnf("Received ERROR message from switch %v. Err: %v", s.dpid, err)

			// send Switch disconnected callback
			s.switchDisconnected(true)
			return
		}
	}
}

// Handle openflow messages from the switch
func (s *OFSwitch) handleMessages(dpid net.HardwareAddr, msg util.Message) {
	log.Debugf("Received message: %+v, on switch: %s", msg, dpid.String())

	switch t := msg.(type) {
	case *common.Header:
		switch t.Header().Type {
		case openflow15.Type_Hello:
			// Send Hello response
			h, _ := common.NewHello(6)
			if err := s.Send(h); err != nil {
				log.Errorf("Error sending hello message")
			}
		case openflow15.Type_EchoRequest:
			// Send echo reply
			res := openflow15.NewEchoReply()
			if err := s.Send(res); err != nil {
				log.Errorf("Failed to send echo reply: %v", err)
			}

		case openflow15.Type_EchoReply:
			s.lastUpdate = time.Now()

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
		errData := t.Data.Bytes()
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

		s.publishMessage(tid, result)

	case *openflow15.VendorHeader:
		log.Debugf("Received Experimenter message, VendorType: %d, ExperimenterType: %d, VendorData: %+v", t.Vendor, t.ExperimenterType, t.VendorData)
		switch t.ExperimenterType {
		case openflow15.Type_TlvTableReply:
			reply := t.VendorData.(*openflow15.TLVTableReply)
			status := TLVTableStatus(*reply)
			s.tlvMgr.TLVMapReplyRcvd(s, &status)
		case openflow15.Type_PacketIn2:
			pktInMsg := t.VendorData.(*openflow15.PacketIn2)
			pktIn := parsePacktInFromNXPacketIn2(pktInMsg)
			s.app.PacketRcvd(s, pktIn)
		}

	case *openflow15.BundleCtrl:
		result := MessageResult{
			xID:     t.Xid,
			succeed: true,
			msgType: BundleControlMessage,
		}
		s.publishMessage(t.BundleId, result)

	case *openflow15.SwitchFeatures:

	case *openflow15.SwitchConfig:
		switch t.Type {
		case openflow15.Type_GetConfigReply:

		case openflow15.Type_SetConfig:

		}
	case *openflow15.PacketIn:
		log.Debugf("Received packet(ofctrl): %+v", t)
		// send packet rcvd callback
		pktIn := &PacketIn{PacketIn: t}
		s.app.PacketRcvd(s, pktIn)

	case *openflow15.FlowRemoved:

	case *openflow15.PortStatus:
		// Propagate the PortStatus message to the app.
		s.app.PortStatusRcvd(t)
	case *openflow15.PacketOut:

	case *openflow15.FlowMod:

	case *openflow15.PortMod:

	case *openflow15.MultipartRequest:

	case *openflow15.MultipartReply:
		log.Debugf("Received MultipartReply")
		switch t.Type {
		case openflow15.MultipartType_FlowDesc:
			key := fmt.Sprintf("%d", t.Xid)
			replyChan, found := monitoredFlows.Get(key)
			if found {
				if s.monitorEnabled {
					replyChan <- t
				}
				monitoredFlows.Remove(key)
			}
		}
		// send packet rcvd callback
		s.app.MultipartReply(s, t)
	case *openflow15.VendorError:
		errData := t.Data.Bytes()
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
				s.publishMessage(bundleID, result)
				log.Errorf("Received Vendor error: %s on ONFT_BUNDLE_CONTROL message", errMsg)
			case openflow15.Type_BundleAdd:
				bundleID := binary.BigEndian.Uint32(errData[16:20])
				result.msgType = BundleAddMessage
				s.publishMessage(bundleID, result)
				log.Errorf("Received Vendor error: %s on ONFT_BUNDLE_ADD_MESSAGE message", errMsg)
			}
		default:
			log.Errorf("Received Vendor error: %s", errMsg)
		}
	}
}

func (s *OFSwitch) getMPReq() *openflow15.MultipartRequest {
	mp := &openflow15.MultipartRequest{}
	mp.Type = openflow15.MultipartType_FlowDesc
	mp.Header = openflow15.NewOfp15Header()
	mp.Header.Type = openflow15.Type_MultiPartRequest
	return mp
}

func (s *OFSwitch) EnableMonitor() {
	if s.monitorEnabled {
		return
	}

	if s.mQueue == nil {
		s.mQueue = make(chan *openflow15.MultipartRequest)
	}

	go func() {
		for {
			mp := <-s.mQueue
			s.Send(mp)
			log.Debugf("Send flow stats request")
		}
	}()
	s.monitorEnabled = true
}

func (s *OFSwitch) DumpFlowStats(cookieID uint64, cookieMask *uint64, flowMatch *FlowMatch, tableID *uint8) ([]*openflow15.FlowDesc, error) {
	mp := s.getMPReq()
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
		s.mQueue <- mp
	}()

	select {
	case reply := <-replyChan:
		flowStates := make([]*openflow15.FlowDesc, 0)
		flowArr := reply.Body
		for _, entry := range flowArr {
			flowStates = append(flowStates, entry.(*openflow15.FlowDesc))
		}
		return flowStates, nil
	case <-time.After(2 * time.Second):
		return nil, errors.New("timeout to wait for MultipartReply message")
	}
}

func (s *OFSwitch) CheckStatus(timeout time.Duration) bool {
	return s.lastUpdate.Add(heartbeatInterval).After(time.Now())
}

func (s *OFSwitch) EnableOFPortForwarding(port int, portMAC net.HardwareAddr) error {
	config := 0
	config &^= openflow15.PC_NO_FWD
	mask := openflow15.PC_NO_FWD
	return s.sendModPortMessage(port, portMAC, config, mask)
}

func (s *OFSwitch) DisableOFPortForwarding(port int, portMAC net.HardwareAddr) error {
	config := openflow15.PC_NO_FWD
	mask := openflow15.PC_NO_FWD
	return s.sendModPortMessage(port, portMAC, config, mask)
}

func (s *OFSwitch) subscribeMessage(xID uint32, msgChan chan MessageResult) {
	s.txLock.Lock()
	s.txChans[xID] = msgChan
	s.txLock.Unlock()
}

func (s *OFSwitch) publishMessage(xID uint32, result MessageResult) {
	go func() {
		s.txLock.Lock()
		defer s.txLock.Unlock()
		ch, found := s.txChans[xID]
		if found {
			ch <- result
		}
	}()
}

func (s *OFSwitch) unSubscribeMessage(xID uint32) {
	s.txLock.Lock()
	defer s.txLock.Unlock()
	_, found := s.txChans[xID]
	if found {
		delete(s.txChans, xID)
	}
}

func (s *OFSwitch) sendModPortMessage(port int, mac net.HardwareAddr, config int, mask int) error {
	msg := openflow15.NewPortMod(port)
	msg.Version = 0x6
	msg.HWAddr = mac
	msg.Config = uint32(config)
	msg.Mask = uint32(mask)
	return s.Send(msg)
}

func (s *OFSwitch) GetControllerID() uint16 {
	return s.ctrlID
}

func (s *OFSwitch) SetPacketInFormat(format uint32) error {
	msg := openflow15.NewSetPacketInFormat(format)
	return s.Send(msg)
}

func (s *OFSwitch) ResumePacket(pktIn *PacketIn) error {
	var resumeProps []openflow15.Property
	if pktIn.Data == nil {
		return fmt.Errorf("no Ethernet packet in the message")
	}
	eth := protocol.NewEthernet()
	pktBytes, err := pktIn.Data.MarshalBinary()
	if err != nil {
		return err
	}
	if err = eth.UnmarshalBinary(pktBytes); err != nil {
		return err
	}
	packetProp := &openflow15.PacketIn2PropPacket{
		Packet: *eth,
		PropHeader: &openflow15.PropHeader{
			Type: openflow15.NXPINT_PACKET,
		},
	}
	packetProp.Length = packetProp.Len()
	cookieProp := &openflow15.PacketIn2PropCookie{
		Cookie: pktIn.Cookie,
		PropHeader: &openflow15.PropHeader{
			Type:   openflow15.NXPINT_COOKIE,
			Length: 16,
		},
	}
	bufferProp := &openflow15.PacketIn2PropBufferID{
		BufferID: pktIn.BufferId,
		PropHeader: &openflow15.PropHeader{
			Type:   openflow15.NXPINT_BUFFER_ID,
			Length: 8,
		},
	}
	if pktIn.TotalLen > 0 {
		lenProp := &openflow15.PacketIn2PropFullLen{
			FullLen: uint32(pktIn.TotalLen),
			PropHeader: &openflow15.PropHeader{
				Type:   openflow15.NXPINT_FULL_LEN,
				Length: 8,
			},
		}
		resumeProps = append(resumeProps, lenProp)
	}
	tableProp := &openflow15.PacketIn2PropTableID{
		TableID: pktIn.TableId,
		PropHeader: &openflow15.PropHeader{
			Type:   openflow15.NXPINT_TABLE_ID,
			Length: 8,
		},
	}
	reasonProp := &openflow15.PacketIn2PropReason{
		Reason: pktIn.Reason,
		PropHeader: &openflow15.PropHeader{
			Type:   openflow15.NXPINT_REASON,
			Length: 8,
		},
	}
	matchProp := &openflow15.PacketIn2PropMetadata{
		Fields: pktIn.Match.Fields,
		PropHeader: &openflow15.PropHeader{
			Type: openflow15.NXPINT_METADATA,
		},
	}
	matchProp.Length = matchProp.Len()
	continueProp := &openflow15.PacketIn2PropContinuation{
		Continuation: make([]byte, len(pktIn.Continuation)),
		PropHeader: &openflow15.PropHeader{
			Type: openflow15.NXPINT_CONTINUATION,
		},
	}
	copy(continueProp.Continuation, pktIn.Continuation)
	continueProp.Length = continueProp.Len()
	resumeProps = append(resumeProps, packetProp, cookieProp, bufferProp, tableProp, reasonProp, matchProp, continueProp)
	resumeMsg := openflow15.NewResume(resumeProps)
	return s.Send(resumeMsg)
}
